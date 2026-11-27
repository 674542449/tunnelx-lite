package pulse

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	mathrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/674542449/tunnelx-lite/internal/config"
	"github.com/674542449/tunnelx-lite/internal/pki"
)

// loopbackDialer 供单元测试允许拨号本机回环目标，并拒绝 127.0.0.1:9（模拟私网拦截）。
type loopbackDialer struct{}

func (loopbackDialer) ResolveTarget(_ context.Context, host, target string) ([]net.IP, int) {
	if target == "127.0.0.1:9" {
		return nil, 403
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 502
	}
	return []net.IP{ip}, 0
}

func (loopbackDialer) DialTargetTCP(ctx context.Context, ips []net.IP, port string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, "tcp4", net.JoinHostPort(ips[0].String(), port))
}

func (loopbackDialer) DialTargetUDP(ip net.IP, port int) (*net.UDPConn, error) {
	return net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip, Port: port})
}

type testEnv struct {
	certFile string
	keyFile  string
	certDER  []byte
	certPin  string
	token    string
	obfsKey  string
	srv      *Server
	port     int
	cancel   context.CancelFunc
	done     chan error
}

func startTestServer(t *testing.T, extraPorts int) *testEnv {
	t.Helper()
	dir := t.TempDir()
	certPEM, keyPEM, err := pki.SelfSigned([]string{"pulse-test.local"}, 10)
	if err != nil {
		t.Fatalf("SelfSigned: %v", err)
	}
	certFile := filepath.Join(dir, "pulse-cert.pem")
	keyFile := filepath.Join(dir, "pulse-key.pem")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	tokBytes := make([]byte, 32)
	_, _ = rand.Read(tokBytes)
	token := base64.RawURLEncoding.EncodeToString(tokBytes)
	obfs := GenerateObfsKey()

	conns := make([]*net.UDPConn, 0, 1+extraPorts)
	for i := 0; i < 1+extraPorts; i++ {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	mainPort := conns[0].LocalAddr().(*net.UDPAddr).Port

	srv, err := NewServer(ServerConfig{
		Listen:      net.JoinHostPort("127.0.0.1", strconv.Itoa(mainPort)),
		Network:     "udp4",
		CertFile:    certFile,
		KeyFile:     keyFile,
		Token:       token,
		ObfsKey:     obfs,
		DialTimeout: 5 * time.Second,
		IdleTimeout: 30 * time.Second,
		Dialer:      loopbackDialer{},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- srv.ServePacketConns(ctx, conns)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return &testEnv{
		certFile: certFile,
		keyFile:  keyFile,
		certDER:  blk.Bytes,
		certPin:  config.CertPin(cert),
		token:    token,
		obfsKey:  obfs,
		srv:      srv,
		port:     mainPort,
		cancel:   cancel,
		done:     done,
	}
}

// TestSecurityHandshakePinProbeAndReplay 验证自签证书固定、抗 MITM、抗主动探测静默丢弃与防重放。
func TestSecurityHandshakePinProbeAndReplay(t *testing.T) {
	env := startTestServer(t, 0)

	// 1. 合法客户端 1-RTT 握手与探活
	cli, err := NewClient(ClientConfig{
		ServerIP:       "127.0.0.1",
		Port:           env.port,
		Token:          env.token,
		ObfsKey:        env.obfsKey,
		CertPin:        env.certPin,
		ConnectTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	rtt, err := cli.Probe(context.Background())
	if err != nil {
		t.Fatalf("valid probe failed: %v", err)
	}
	if rtt <= 0 {
		t.Fatalf("expected positive RTT, got %v", rtt)
	}

	// 2. 错误的自签证书指纹（模拟 MITM 中间人替换证书）必须被严格拒绝
	badPin := make([]byte, 32)
	_, _ = rand.Read(badPin)
	mitmCli, err := NewClient(ClientConfig{
		ServerIP:       "127.0.0.1",
		Port:           env.port,
		Token:          env.token,
		ObfsKey:        env.obfsKey,
		CertPin:        base64.RawURLEncoding.EncodeToString(badPin),
		ConnectTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mitmCli.Close()
	if _, err := mitmCli.Probe(context.Background()); err == nil {
		t.Fatal("expected cert_pin mismatch to fail, but succeeded")
	}

	// 3. 主动探测（QUIC Initial / 随机字节 / 错误密钥）：服务端必须静默丢弃（0 字节回应）
	probeSock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer probeSock.Close()
	srvAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: env.port}

	// 构造标准 QUIC v1 Initial 探测包（首字节 0xC0 + 版本 0x00000001 + 1200B）
	quicProbe := make([]byte, 1200)
	quicProbe[0] = 0xC3
	quicProbe[4] = 0x01
	_, _ = probeSock.WriteToUDP(quicProbe, srvAddr)
	// 发送随机垃圾包
	garbage := make([]byte, 96)
	_, _ = rand.Read(garbage)
	_, _ = probeSock.WriteToUDP(garbage, srvAddr)

	_ = probeSock.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	rbuf := make([]byte, 2048)
	if n, _, rerr := probeSock.ReadFromUDP(rbuf); rerr == nil {
		t.Fatalf("active probe received %d unexpected bytes; expected silent drop", n)
	}

	// 4. 抓包校验无 QUIC 魔数、无明文证书泄露，且重放合法 ClientHello 必须静默丢弃
	tokB, obfsB, _ := DecodeKeyMaterial(env.token, env.obfsKey)
	hs, _ := newHandshakeCipher(tokB, obfsB)
	priv, _ := generateX25519()
	var cPub [32]byte
	copy(cPub[:], priv.PublicKey().Bytes())
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	chPlain := encodeClientHello(clientHelloPayload{
		Version:     ProtocolVersion,
		ClientPub:   cPub,
		ClientNonce: nonce,
		Timestamp:   time.Now().Unix(),
		Caps:        CapHyBBR | CapUDPFrag,
	})
	chWire := hs.seal(obfsB, PacketHeader{
		Prefix:    makeCamouflagePrefix(),
		Type:      PktClientHello,
		Flags:     0,
		SessionID: 0,
		PktNum:    42,
	}, chPlain)

	if chWire[0]&0xF0 != 0x80 {
		t.Fatalf("unexpected camouflage lead byte: 0x%02x", chWire[0])
	}
	if len(chWire) >= 1000 {
		t.Fatalf("ClientHello should not imitate QUIC 1200B size, got %d", len(chWire))
	}

	// 第一次发送合法 ClientHello -> 应收到加密 ServerHello（且不可含明文证书 DER）
	_, _ = probeSock.WriteToUDP(chWire, srvAddr)
	_ = probeSock.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, _, err := probeSock.ReadFromUDP(rbuf)
	if err != nil {
		t.Fatalf("expected ServerHello on first valid ClientHello: %v", err)
	}
	if bytes.Contains(rbuf[:n], env.certDER[:32]) {
		t.Fatal("server certificate bytes leaked in plaintext inside ServerHello")
	}
	if n > MaxPacketSize {
		t.Fatalf("ServerHello exceeds safe MTU (%d > %d)", n, MaxPacketSize)
	}

	// 第二次原样重放同一 ClientHello -> 必须被防重放缓存静默丢弃！
	_, _ = probeSock.WriteToUDP(chWire, srvAddr)
	_ = probeSock.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if rn, _, rerr := probeSock.ReadFromUDP(rbuf); rerr == nil {
		t.Fatalf("replayed ClientHello received %d bytes; expected silent drop", rn)
	}
}

// TestMultiplexedTCPStreamsAndForbidden 验证 16 路并发流、大数据完整校验、半关闭与私网目标拦截。
func TestMultiplexedTCPStreamsAndForbidden(t *testing.T) {
	env := startTestServer(t, 0)

	// 启动本机 TCP Echo 目标服务
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
				if tcp, ok := conn.(*net.TCPConn); ok {
					_ = tcp.CloseWrite()
				}
			}(c)
		}
	}()

	cli, err := NewClient(ClientConfig{
		ServerIP:       "127.0.0.1",
		Port:           env.port,
		Token:          env.token,
		ObfsKey:        env.obfsKey,
		CertPin:        env.certPin,
		ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// 验证禁止访问私网目标 127.0.0.1:9 返回 OpenStreamError(OpenStatusForbidden)
	ctx := context.Background()
	_, err = cli.OpenStream(ctx, "127.0.0.1:9", true)
	var openErr *OpenStreamError
	if !errors.As(err, &openErr) || openErr.Status != OpenStatusForbidden {
		t.Fatalf("expected OpenStatusForbidden for 127.0.0.1:9, got %v", err)
	}

	// 16 路并发流同时双向传输 256 KB 随机数据并校验 SHA-256
	const numStreams = 16
	const chunkSize = 256 * 1024
	var wg sync.WaitGroup
	errCh := make(chan error, numStreams)
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, err := cli.OpenStream(ctx, ln.Addr().String(), false)
			if err != nil {
				errCh <- err
				return
			}
			defer st.Close()
			payload := make([]byte, chunkSize)
			_, _ = rand.Read(payload)
			wantSum := sha256.Sum256(payload)

			writeErr := make(chan error, 1)
			go func() {
				_, werr := st.Write(payload)
				_ = st.CloseWrite()
				writeErr <- werr
			}()
			got, rerr := io.ReadAll(st)
			werr := <-writeErr
			if werr != nil {
				errCh <- werr
				return
			}
			if rerr != nil {
				errCh <- rerr
				return
			}
			if sha256.Sum256(got) != wantSum {
				errCh <- errors.New("sha256 mismatch on echoed stream")
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Fatalf("concurrent stream failed: %v", e)
	}
}

// TestLossyReorderedWANTransfer 在模拟 8% 随机丢包 + 35ms RTT + 乱序抖动网络下验证零错误传输与 HyBBR 恢复。
func TestLossyReorderedWANTransfer(t *testing.T) {
	env := startTestServer(t, 0)

	// 启动单向吞吐测试目标（服务端收到连接即全速发送 1.5 MiB 随机数据后关闭）
	const totalBytes = 1536 * 1024
	data := make([]byte, totalBytes)
	_, _ = rand.Read(data)
	wantHash := sha256.Sum256(data)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write(data)
			}(c)
		}
	}()

	// 构建模拟弱网 UDP 中继：8% 丢包 + 15~25ms 单程延迟（30~50ms RTT）+ 乱序
	relayConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	toServer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer toServer.Close()

	srvAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: env.port}
	var cliAddr atomic.Pointer[net.UDPAddr]
	var dropped atomic.Int64

	relayCtx, relayCancel := context.WithCancel(context.Background())
	defer relayCancel()

	forwardImpaired := func(dstSock *net.UDPConn, getDst func() *net.UDPAddr, pkt []byte, seed int64) {
		rng := mathrand.New(mathrand.NewSource(seed))
		// 8% 双向随机丢包
		if rng.Intn(100) < 8 {
			dropped.Add(1)
			return
		}
		// 12ms..26ms 随机单程延迟（自然产生数据包乱序）
		delay := time.Duration(12+rng.Intn(15)) * time.Millisecond
		time.AfterFunc(delay, func() {
			if relayCtx.Err() != nil {
				return
			}
			if dst := getDst(); dst != nil {
				_, _ = dstSock.WriteToUDP(pkt, dst)
			}
		})
	}

	var seq atomic.Int64
	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, err := relayConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			cliAddr.Store(src)
			cp := append([]byte(nil), buf[:n]...)
			forwardImpaired(toServer, func() *net.UDPAddr { return srvAddr }, cp, seq.Add(1)*7919)
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := toServer.ReadFromUDP(buf)
			if err != nil {
				return
			}
			cp := append([]byte(nil), buf[:n]...)
			forwardImpaired(relayConn, func() *net.UDPAddr { return cliAddr.Load() }, cp, seq.Add(1)*104729)
		}
	}()

	relayPort := relayConn.LocalAddr().(*net.UDPAddr).Port
	cli, err := NewClient(ClientConfig{
		ServerIP:       "127.0.0.1",
		Port:           relayPort,
		Token:          env.token,
		ObfsKey:        env.obfsKey,
		CertPin:        env.certPin,
		ConnectTimeout: 8 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	start := time.Now()
	st, err := cli.OpenStream(context.Background(), ln.Addr().String(), true)
	if err != nil {
		t.Fatalf("OpenStream over lossy WAN failed: %v", err)
	}
	defer st.Close()
	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("ReadAll over lossy WAN failed: %v", err)
	}
	elapsed := time.Since(start)
	if len(got) != totalBytes || sha256.Sum256(got) != wantHash {
		t.Fatalf("data corruption under 8%% loss: got %d bytes, want %d", len(got), totalBytes)
	}
	t.Logf("8%% loss + 40ms RTT + reorder: transferred %.2f MiB in %v (dropped %d pkts, stats=%+v)",
		float64(totalBytes)/(1024*1024), elapsed.Round(time.Millisecond), dropped.Load(), cli.CCStats())
}

// TestNativeUDPFragmentation 验证原生不可靠 UDP 转发及超大 UDP 报文（> MTU）自动分片重组。
func TestNativeUDPFragmentation(t *testing.T) {
	env := startTestServer(t, 0)

	// 本机 UDP Echo 目标
	echoSock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer echoSock.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := echoSock.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echoSock.WriteToUDP(buf[:n], src)
		}
	}()

	cli, err := NewClient(ClientConfig{
		ServerIP:       "127.0.0.1",
		Port:           env.port,
		Token:          env.token,
		ObfsKey:        env.obfsKey,
		CertPin:        env.certPin,
		ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	u, err := cli.OpenUDP(context.Background(), echoSock.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	for _, sz := range []int{64, 1400, 4500, 12000} {
		want := make([]byte, sz)
		_, _ = rand.Read(want)
		if err := u.Send(want); err != nil {
			t.Fatalf("UDP Send(%d): %v", sz, err)
		}
		rctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		got, err := u.Receive(rctx)
		cancel()
		if err != nil {
			t.Fatalf("UDP Receive(%d): %v", sz, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("UDP payload mismatch for size %d (got %d bytes)", sz, len(got))
		}
	}
}

// TestConnectionMigrationAndPortHopping 验证客户端切换源端口（模拟 Wi-Fi <-> 5G 迁移）与服务端多端口跳跃不断流。
func TestConnectionMigrationAndPortHopping(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM, err := pki.SelfSigned([]string{"pulse-hop.local"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certFile, certPEM, 0600)
	_ = os.WriteFile(keyFile, keyPEM, 0600)
	blk, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(blk.Bytes)

	tokB := make([]byte, 32)
	_, _ = rand.Read(tokB)
	token := base64.RawURLEncoding.EncodeToString(tokB)
	obfs := GenerateObfsKey()

	// 绑定 3 个独立服务端 UDP 端口模拟原生端口跳跃
	var conns []*net.UDPConn
	var ports []int
	for i := 0; i < 3; i++ {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		ports = append(ports, c.LocalAddr().(*net.UDPAddr).Port)
	}

	srv, err := NewServer(ServerConfig{
		Listen:      net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0])),
		Network:     "udp4",
		CertFile:    certFile,
		KeyFile:     keyFile,
		Token:       token,
		ObfsKey:     obfs,
		DialTimeout: 5 * time.Second,
		IdleTimeout: 30 * time.Second,
		Dialer:      loopbackDialer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ServePacketConns(ctx, conns) }()
	t.Cleanup(func() { cancel(); <-done })

	// Echo server
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	cli, err := NewClient(ClientConfig{
		ServerIP:       "127.0.0.1",
		Port:           ports[0],
		Token:          token,
		ObfsKey:        obfs,
		CertPin:        config.CertPin(cert),
		ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	st, err := cli.OpenStream(context.Background(), ln.Addr().String(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	roundTrip := func(tag string, sz int) {
		t.Helper()
		msg := make([]byte, sz)
		_, _ = rand.Read(msg)
		if _, err := st.Write(msg); err != nil {
			t.Fatalf("%s write: %v", tag, err)
		}
		got := make([]byte, sz)
		if _, err := io.ReadFull(st, got); err != nil {
			t.Fatalf("%s read: %v", tag, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("%s echo mismatch", tag)
		}
	}

	// 1. 初始端口传输
	roundTrip("initial", 32*1024)

	// 2. 端口跳跃到服务端第 2 个 UDP 端口，不断流继续传输！
	cli.SwitchTargetPort(ports[1])
	roundTrip("after-hop-1", 64*1024)

	// 3. 客户端迁移本地源 UDP Socket（模拟 Wi-Fi -> 5G），不断流继续传输！
	if err := cli.MigrateSocket(context.Background()); err != nil {
		t.Fatalf("MigrateSocket: %v", err)
	}
	roundTrip("after-migrate", 64*1024)

	// 4. 再跳到服务端第 3 个 UDP 端口，依然无缝不断流！
	cli.SwitchTargetPort(ports[2])
	roundTrip("after-hop-2", 64*1024)
}
