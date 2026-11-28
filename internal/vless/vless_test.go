package vless

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/xtls/reality"
	utls "github.com/xtls/utls"
)

func selfSignedTLSConfig(t *testing.T, dnsName string) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
		}},
	}
}

type loopbackDialer struct{}

func (loopbackDialer) ResolveTarget(_ context.Context, host, _ string) ([]net.IP, int) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, 0
	}
	return []net.IP{net.ParseIP("127.0.0.1")}, 0
}

func (loopbackDialer) DialTargetTCP(ctx context.Context, ips []net.IP, port string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, "tcp4", net.JoinHostPort(ips[0].String(), port))
}

func (loopbackDialer) DialTargetUDP(ip net.IP, port int) (*net.UDPConn, error) {
	return net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip, Port: port})
}

// dialRealityTestClient 使用标准 uTLS 构建完整 REALITY 客户端握手（支持 Chrome PQ 与 iOS X25519），
// 与 Xray-core / Shadowrocket 协议完全一致。
func dialRealityTestClient(t *testing.T, addr, sni, pubB64, sidHex string, helloID utls.ClientHelloID) (*utls.UConn, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	pubRaw, err := decodeB64Flexible(pubB64)
	if err != nil {
		raw.Close()
		return nil, err
	}
	serverPub, err := ecdh.X25519().NewPublicKey(pubRaw)
	if err != nil {
		raw.Close()
		return nil, err
	}
	shortID, err := ParseShortID(sidHex)
	if err != nil {
		raw.Close()
		return nil, err
	}

	var authKey []byte
	uConn := utls.UClient(raw, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("empty server cert")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			edPub, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("server cert is not REALITY Ed25519 temp cert")
			}
			mac := hmac.New(sha512.New, authKey)
			mac.Write(edPub)
			if !hmac.Equal(mac.Sum(nil), cert.Signature) {
				return errors.New("invalid reality cert hmac")
			}
			return nil
		},
	}, helloID)
	if err := uConn.BuildHandshakeState(); err != nil {
		raw.Close()
		return nil, err
	}
	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:71], hello.SessionId)

	// 与 reality/tls.go 一致：优先独立 X25519 KeyShare，否则取 X25519MLKEM768 中的 X25519 分量
	ks := uConn.HandshakeState.State13.KeyShareKeys
	var privKey *ecdh.PrivateKey
	if ks != nil && ks.Ecdhe != nil && ks.Ecdhe.Curve() == ecdh.X25519() {
		privKey = ks.Ecdhe
	} else if ks != nil && ks.MlkemEcdhe != nil && ks.MlkemEcdhe.Curve() == ecdh.X25519() {
		privKey = ks.MlkemEcdhe
	}
	if privKey == nil {
		raw.Close()
		return nil, errors.New("no x25519 keyshare found in utls ClientHello")
	}
	shared, err := privKey.ECDH(serverPub)
	if err != nil {
		raw.Close()
		return nil, err
	}
	authKey, err = hkdf.Key(sha256.New, shared, hello.Random[:20], "REALITY", 32)
	if err != nil {
		raw.Close()
		return nil, err
	}

	// 填充 16 字节明文: ClientVer(3) + 0 + UnixTime(4) + ShortId(8)，用 AES-GCM 加密写入 SessionId(32)
	plain := make([]byte, 16)
	plain[0], plain[1], plain[2] = 1, 8, 24
	binary.BigEndian.PutUint32(plain[4:8], uint32(time.Now().Unix()))
	copy(plain[8:16], shortID[:])

	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	aead.Seal(hello.SessionId[:0], hello.Random[20:32], plain, hello.Raw)
	copy(hello.Raw[39:71], hello.SessionId)

	if err := uConn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return uConn, nil
}

func TestKeyAndShareURL(t *testing.T) {
	id := GenerateUUID()
	u, err := ParseUUID(id)
	if err != nil || u == ([16]byte{}) {
		t.Fatalf("ParseUUID(%q) failed: %v", id, err)
	}
	priv, pub, err := GenerateRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	derivedPub, err := RealityPublicKey(priv)
	if err != nil || derivedPub != pub {
		t.Fatalf("derived pub %q != %q (%v)", derivedPub, pub, err)
	}
	sid := GenerateShortID()
	if _, err := ParseShortID(sid); err != nil {
		t.Fatalf("ParseShortID(%q): %v", sid, err)
	}
	if _, err := ParseShortID("abc"); err == nil {
		t.Fatal("odd-length short id should fail")
	}
	if got, err := NormalizeSNI("https://iTunes.Apple.com:443/"); err != nil || got != "itunes.apple.com" {
		t.Fatalf("NormalizeSNI got %q err %v", got, err)
	}
	if _, err := NormalizeSNI("1.2.3.4"); err == nil {
		t.Fatal("IP should not be allowed as REALITY SNI")
	}
	link := ShareURL(id, "203.0.113.5", 443, DefaultRealitySNI, pub, sid, "节点 iOS")
	parsed, err := url.Parse(link)
	if err != nil || parsed.Scheme != "vless" || parsed.User.Username() != id || parsed.Host != "203.0.113.5:443" {
		t.Fatalf("invalid share url %q: %v", link, err)
	}
	q := parsed.Query()
	if q.Get("security") != "reality" || q.Get("flow") != FlowVision || q.Get("pbk") != pub || q.Get("sid") != sid || q.Get("sni") != DefaultRealitySNI {
		t.Fatalf("missing query params in %q", link)
	}
}

func TestProtocolRoundTrip(t *testing.T) {
	uid, _ := ParseUUID(GenerateUUID())
	cases := []Request{
		{UUID: uid, Flow: FlowVision, Command: CommandTCP, Host: "1.1.1.1", Port: 443},
		{UUID: uid, Flow: FlowVision, Command: CommandTCP, Host: "example.com", Port: 8443},
		{UUID: uid, Flow: "", Command: CommandUDP, Host: "2001:db8::1", Port: 53},
		{UUID: uid, Flow: FlowVision, Command: CommandMux},
	}
	for _, want := range cases {
		var buf bytes.Buffer
		if err := WriteRequest(&buf, want, []byte("hello")); err != nil {
			t.Fatal(err)
		}
		got, err := ReadRequest(&buf)
		if err != nil {
			t.Fatalf("ReadRequest failed: %v", err)
		}
		if got.UUID != want.UUID || got.Flow != want.Flow || got.Command != want.Command || got.Host != want.Host || got.Port != want.Port {
			t.Fatalf("got %+v want %+v", got, want)
		}
		rest, _ := io.ReadAll(&buf)
		if string(rest) != "hello" {
			t.Fatalf("trailing payload = %q", rest)
		}
	}
}

func TestVisionPlainTCPAndTLS13DirectSplice(t *testing.T) {
	uid, _ := ParseUUID(GenerateUUID())
	outerTLS := selfSignedTLSConfig(t, "outer.test")
	innerTLS := selfSignedTLSConfig(t, "inner.test")

	// 建立外层 *tls.Conn TCP 回路，再在两端包装 VisionConn 验证真实内层 TLS 1.3 直通剥离
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvVCCh := make(chan *VisionConn, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		tc := tls.Server(raw, outerTLS)
		if err := tc.Handshake(); err != nil {
			raw.Close()
			return
		}
		vc, err := NewVisionConn(tc, tc, uid)
		if err != nil {
			raw.Close()
			return
		}
		srvVCCh <- vc
	}()

	cliRaw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cliOuter := tls.Client(cliRaw, &tls.Config{ServerName: "outer.test", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err := cliOuter.Handshake(); err != nil {
		t.Fatal(err)
	}
	cliVC, err := NewVisionConn(cliOuter, cliOuter, uid)
	if err != nil {
		t.Fatal(err)
	}
	srvVC := <-srvVCCh
	defer cliVC.Close()
	defer srvVC.Close()

	// 在 VisionConn 内部跑完整的内层 TLS 1.3 双向 256 KiB 数据传输
	payload := make([]byte, 256<<10)
	_, _ = rand.Read(payload)

	var wg sync.WaitGroup
	wg.Add(1)
	errCh := make(chan error, 1)
	go func() {
		defer wg.Done()
		innerSrv := tls.Server(srvVC, innerTLS)
		if err := innerSrv.Handshake(); err != nil {
			errCh <- err
			return
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(innerSrv, got); err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(got, payload) {
			errCh <- errors.New("server payload mismatch")
			return
		}
		if _, err := innerSrv.Write(got); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	innerCli := tls.Client(cliVC, &tls.Config{ServerName: "inner.test", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err := innerCli.Handshake(); err != nil {
		t.Fatalf("inner TLS 1.3 handshake over Vision failed: %v", err)
	}
	if _, err := innerCli.Write(payload); err != nil {
		t.Fatalf("inner write failed: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(innerCli, echo); err != nil {
		t.Fatalf("inner read failed: %v", err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatal("echoed 256KiB inner TLS 1.3 payload mismatch")
	}
	wg.Wait()
	if err := <-errCh; err != nil {
		t.Fatalf("inner server error: %v", err)
	}
	if !cliVC.IsReadDirect() || !cliVC.IsWriteDirect() || !srvVC.IsReadDirect() || !srvVC.IsWriteDirect() {
		t.Fatalf("expected Vision direct splice on both ends: cli(r=%v,w=%v) srv(r=%v,w=%v)",
			cliVC.IsReadDirect(), cliVC.IsWriteDirect(), srvVC.IsReadDirect(), srvVC.IsWriteDirect())
	}
}

func TestEndToEndRealityVisionTCPUDPAndFallback(t *testing.T) {
	const sni = "itunes.apple.com"

	// 1. 启动本地模拟真实伪装网站（支持 TLS 1.3，供 REALITY 握手借壳与非法探测透明回落）
	destTLS := selfSignedTLSConfig(t, sni)
	destLn, err := tls.Listen("tcp", "127.0.0.1:0", destTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer destLn.Close()
	go func() {
		for {
			c, err := destLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 512)
				n, err := conn.Read(buf)
				if err == nil && n > 0 {
					_, _ = conn.Write([]byte("MOCK_REAL_DEST_OK"))
				}
			}(c)
		}
	}()

	// 预置 offline PostHandshakeRecordsLens，避免单测等待外部探测
	destAddr := destLn.Addr().String()
	for _, alpn := range []string{"0", "1", "2"} {
		reality.GlobalPostHandshakeRecordsLens.Store(destAddr+" "+sni+" "+alpn, []int{})
	}

	// 2. 启动目标上游 TCP Echo（带内层 TLS 1.3）和 UDP Echo
	innerTLS := selfSignedTLSConfig(t, "target.test")
	upTCPLn, err := tls.Listen("tcp", "127.0.0.1:0", innerTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer upTCPLn.Close()
	go func() {
		for {
			c, err := upTCPLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	upTCPPort := uint16(upTCPLn.Addr().(*net.TCPAddr).Port)

	upUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer upUDP.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, raddr, err := upUDP.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = upUDP.WriteToUDP(append([]byte("UDP:"), buf[:n]...), raddr)
		}
	}()
	upUDPPort := uint16(upUDP.LocalAddr().(*net.UDPAddr).Port)

	// 3. 创建 VLESS + REALITY 服务端
	uidStr := GenerateUUID()
	uidBytes, _ := ParseUUID(uidStr)
	priv, pub, err := GenerateRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sid := GenerateShortID()

	srv, err := NewServer(ServerConfig{
		UUID:        uidStr,
		PrivateKey:  priv,
		ShortID:     sid,
		Dest:        destAddr,
		ServerNames: []string{sni},
		Dialer:      loopbackDialer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.HandleConn(ctx, c)
		}
	}()

	// 4. 真实 TCP + Vision (Chrome PQ & iOS X25519) 完整收发校验
	plainLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plainLn.Close()
	go func() {
		for {
			c, err := plainLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	plainPort := uint16(plainLn.Addr().(*net.TCPAddr).Port)

	for _, tc := range []struct {
		name  string
		hello utls.ClientHelloID
	}{
		{"Chrome_PQ", utls.HelloChrome_Auto},
		{"iOS_X25519", utls.HelloIOS_Auto},
	} {
		t.Run(tc.name+"_Vision_Echo", func(t *testing.T) {
			rc, err := dialRealityTestClient(t, ln.Addr().String(), sni, pub, sid, tc.hello)
			if err != nil {
				t.Fatalf("REALITY handshake (%s) failed: %v", tc.name, err)
			}
			defer rc.Close()

			want := []byte("REALITY_VISION_ECHO_" + tc.name)
			var firstBlock bytes.Buffer
			firstBlock.Write(uidBytes[:])
			firstBlock.Write([]byte{visionCmdEnd, 0, byte(len(want)), 0, 24})
			firstBlock.Write(want)
			firstBlock.Write(make([]byte, 24))

			if err := WriteRequest(rc, Request{
				UUID:    uidBytes,
				Flow:    FlowVision,
				Command: CommandTCP,
				Host:    "127.0.0.1",
				Port:    plainPort,
			}, firstBlock.Bytes()); err != nil {
				t.Fatal(err)
			}
			if err := ReadResponse(rc); err != nil {
				t.Fatalf("ReadResponse failed: %v", err)
			}
			// 解析服务端返回的 Vision 首块：[UUID(16)][cmd(1)][contentLen(2)][padLen(2)][content][pad]
			var hdr [21]byte
			if _, err := io.ReadFull(rc, hdr[:]); err != nil {
				t.Fatalf("read server vision header: %v", err)
			}
			if !bytes.Equal(hdr[:16], uidBytes[:]) {
				t.Fatal("server vision response missing UUID prefix")
			}
			cLen := int(binary.BigEndian.Uint16(hdr[17:19]))
			pLen := int(binary.BigEndian.Uint16(hdr[19:21]))
			got := make([]byte, cLen)
			if _, err := io.ReadFull(rc, got); err != nil {
				t.Fatal(err)
			}
			if pLen > 0 {
				_, _ = io.CopyN(io.Discard, rc, int64(pLen))
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("got %q want %q", got, want)
			}
		})
	}

	// 5. 测试 VLESS UDP (cmd=2)
	t.Run("REALITY_UDP_cmd2", func(t *testing.T) {
		rc, err := dialRealityTestClient(t, ln.Addr().String(), sni, pub, sid, utls.HelloChrome_Auto)
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		pkt := []byte("PING_UDP_CMD2")
		var framed bytes.Buffer
		_ = binary.Write(&framed, binary.BigEndian, uint16(len(pkt)))
		framed.Write(pkt)
		if err := WriteRequest(rc, Request{
			UUID:    uidBytes,
			Command: CommandUDP,
			Host:    "127.0.0.1",
			Port:    upUDPPort,
		}, framed.Bytes()); err != nil {
			t.Fatal(err)
		}
		if err := ReadResponse(rc); err != nil {
			t.Fatal(err)
		}
		var rlen uint16
		if err := binary.Read(rc, binary.BigEndian, &rlen); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, rlen)
		if _, err := io.ReadFull(rc, got); err != nil {
			t.Fatal(err)
		}
		if string(got) != "UDP:PING_UDP_CMD2" {
			t.Fatalf("udp echo got %q", got)
		}
	})

	// 6. 测试 VLESS XUDP / Mux (cmd=3，含 8 字节 GlobalID)
	t.Run("REALITY_XUDP_cmd3", func(t *testing.T) {
		rc, err := dialRealityTestClient(t, ln.Addr().String(), sni, pub, sid, utls.HelloIOS_Auto)
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		addrBytes, _ := appendPortThenAddress(nil, "127.0.0.1", upUDPPort)
		globalID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
		metaBody := make([]byte, 0, 2+1+1+1+len(addrBytes)+len(globalID))
		metaBody = binary.BigEndian.AppendUint16(metaBody, 1) // sid=1
		metaBody = append(metaBody, 1, 1, 2)                  // status=New, opt=Data, net=UDP
		metaBody = append(metaBody, addrBytes...)
		metaBody = append(metaBody, globalID[:]...)
		payload := []byte("PING_XUDP")
		var muxFrame bytes.Buffer
		_ = binary.Write(&muxFrame, binary.BigEndian, uint16(len(metaBody)))
		muxFrame.Write(metaBody)
		_ = binary.Write(&muxFrame, binary.BigEndian, uint16(len(payload)))
		muxFrame.Write(payload)

		if err := WriteRequest(rc, Request{
			UUID:    uidBytes,
			Command: CommandMux,
		}, muxFrame.Bytes()); err != nil {
			t.Fatal(err)
		}
		if err := ReadResponse(rc); err != nil {
			t.Fatal(err)
		}
		var mlen uint16
		if err := binary.Read(rc, binary.BigEndian, &mlen); err != nil {
			t.Fatal(err)
		}
		meta := make([]byte, mlen)
		if _, err := io.ReadFull(rc, meta); err != nil {
			t.Fatal(err)
		}
		var plen uint16
		if err := binary.Read(rc, binary.BigEndian, &plen); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, plen)
		if _, err := io.ReadFull(rc, got); err != nil {
			t.Fatal(err)
		}
		if string(got) != "UDP:PING_XUDP" {
			t.Fatalf("xudp echo got %q", got)
		}
	})

	// 7. 测试主动探测器（无 REALITY 密钥、相同 SNI）必须透明回落至伪装网站
	t.Run("UnauthorizedProbeFallsBackToRealDest", func(t *testing.T) {
		c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		})
		if err != nil {
			t.Fatalf("fallback TLS dial failed: %v", err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: " + sni + "\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 64)
		n, err := c.Read(got)
		if err != nil {
			t.Fatalf("read from fallback dest failed: %v", err)
		}
		if string(got[:n]) != "MOCK_REAL_DEST_OK" {
			t.Fatalf("fallback returned %q, want MOCK_REAL_DEST_OK", string(got[:n]))
		}
	})

	if srv.cfg.Uploaded.Load() == 0 || srv.cfg.Downloaded.Load() == 0 {
		t.Fatalf("expected non-zero shared traffic counters, got up=%d down=%d",
			srv.cfg.Uploaded.Load(), srv.cfg.Downloaded.Load())
	}
	_ = strconv.Itoa(int(upTCPPort))
}

type vlessClientRespConn struct {
	net.Conn
}
