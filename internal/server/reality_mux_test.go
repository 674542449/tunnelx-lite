package server

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/674542449/tunnelx-lite/internal/config"
	"github.com/674542449/tunnelx-lite/internal/pki"
	"github.com/674542449/tunnelx-lite/internal/vless"
	"github.com/xtls/reality"
	utls "github.com/xtls/utls"
)

func TestSamePortSNIDemuxTxliteAndRealityCoexist(t *testing.T) {
	const realitySNI = "itunes.apple.com"
	dir := t.TempDir()

	// 1. 生成 txlite 证书与 ECH 密钥
	innerName := "edge-test.txlite.invalid"
	pubName := "gw-test.txlite.invalid"
	certPEM, keyPEM, err := pki.SelfSigned([]string{innerName, pubName}, 1)
	if err != nil {
		t.Fatal(err)
	}
	echKey, _, err := pki.ECH(pubName)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	echPath := filepath.Join(dir, "ech.json")
	_ = os.WriteFile(certPath, certPEM, 0600)
	_ = os.WriteFile(keyPath, keyPEM, 0600)
	echRaw, _ := json.Marshal(echKey)
	_ = os.WriteFile(echPath, echRaw, 0600)

	// 2. 启动本地模拟伪装站点（TLS 1.3）
	dKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: realitySNI},
		DNSNames:     []string{realitySNI},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	dDER, _ := x509.CreateCertificate(rand.Reader, dTmpl, dTmpl, &dKey.PublicKey, dKey)
	destLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{{Certificate: [][]byte{dDER}, PrivateKey: dKey}},
	})
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
				buf := make([]byte, 256)
				if n, err := conn.Read(buf); err == nil && n > 0 {
					_, _ = conn.Write([]byte("FALLBACK_SITE_OK"))
				}
			}(c)
		}
	}()
	destAddr := destLn.Addr().String()
	for _, alpn := range []string{"0", "1", "2"} {
		reality.GlobalPostHandshakeRecordsLens.Store(destAddr+" "+realitySNI+" "+alpn, []int{})
	}

	// 3. 启动一个本地目标 echo 服务，同时验证私网放行与关闭时的私网拦截
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	echoPort := uint16(echoLn.Addr().(*net.TCPAddr).Port)

	// 分配一个空闲 TCP 端口给主 server.Server（Vision + REALITY 共用同一端口）
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sharedAddr := probeLn.Addr().String()
	probeLn.Close()

	uidStr := vless.GenerateUUID()
	uidBytes, _ := vless.ParseUUID(uidStr)
	privB64, pubB64, err := vless.GenerateRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sid := vless.GenerateShortID()
	tok := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	srv, err := New(config.Server{
		Listen:              sharedAddr,
		CertFile:            certPath,
		KeyFile:             keyPath,
		ECHKeyFile:          echPath,
		InnerName:           innerName,
		InnerCertFile:       certPath,
		InnerKeyFile:        keyPath,
		Tokens:              []string{tok},
		OutboundIP:            "ipv4",
		AllowedPrivateTargets: []string{echoLn.Addr().String()},
		RealityUUID:           uidStr,
		RealityPrivateKey:   privB64,
		RealityShortID:      sid,
		RealityDest:         destAddr,
		RealityNames:        []string{realitySNI},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	// 等待监听就绪
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", sharedAddr, 100*time.Millisecond); err == nil {
			c.Close()
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	// 验证 A：原 txlite HTTPS /health 在共用端口正常工作
	hc := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: innerName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
		},
	}
	req, _ := http.NewRequest("GET", "https://"+sharedAddr+"/health", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("txlite /health on shared port failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte(`"status":"ok"`)) {
		t.Fatalf("txlite /health unexpected response %d %q", resp.StatusCode, body)
	}

	// 验证 B：iOS VLESS + REALITY + Vision 在同一个端口正常工作并累计共享流量
	raw, err := net.DialTimeout("tcp", sharedAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	pubRaw, _ := base64.RawURLEncoding.DecodeString(pubB64)
	serverPub, _ := ecdh.X25519().NewPublicKey(pubRaw)
	shortID, _ := vless.ParseShortID(sid)

	uConn := utls.UClient(raw, &utls.Config{ServerName: realitySNI, InsecureSkipVerify: true}, utls.HelloIOS_Auto)
	if err := uConn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:71], hello.SessionId)
	ks := uConn.HandshakeState.State13.KeyShareKeys
	privKey := ks.Ecdhe
	if privKey == nil {
		privKey = ks.MlkemEcdhe
	}
	shared, err := privKey.ECDH(serverPub)
	if err != nil {
		t.Fatal(err)
	}
	authKey, err := hkdf.Key(sha256.New, shared, hello.Random[:20], "REALITY", 32)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, 16)
	plain[0], plain[1], plain[2] = 1, 8, 24
	binary.BigEndian.PutUint32(plain[4:8], uint32(time.Now().Unix()))
	copy(plain[8:16], shortID[:])
	blk, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(blk)
	aead.Seal(hello.SessionId[:0], hello.Random[20:32], plain, hello.Raw)
	copy(hello.Raw[39:71], hello.SessionId)
	if err := uConn.Handshake(); err != nil {
		t.Fatalf("REALITY handshake on shared port failed: %v", err)
	}

	msg := []byte("COEXIST_PORT_OK")
	var vblk bytes.Buffer
	vblk.Write(uidBytes[:])
	vblk.Write([]byte{0x01, 0, byte(len(msg)), 0, 8})
	vblk.Write(msg)
	vblk.Write(make([]byte, 8))
	if err := vless.WriteRequest(uConn, vless.Request{
		UUID:    uidBytes,
		Flow:    vless.FlowVision,
		Command: vless.CommandTCP,
		Host:    "127.0.0.1",
		Port:    echoPort,
	}, vblk.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := vless.ReadResponse(uConn); err != nil {
		t.Fatalf("VLESS ReadResponse on shared port failed: %v", err)
	}
	var vh [21]byte
	if _, err := io.ReadFull(uConn, vh[:]); err != nil {
		t.Fatal(err)
	}
	cLen := int(binary.BigEndian.Uint16(vh[17:19]))
	got := make([]byte, cLen)
	if _, err := io.ReadFull(uConn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("shared port VLESS echo got %q want %q", got, msg)
	}
	if srv.Uploaded.Load() == 0 || srv.Downloaded.Load() == 0 {
		t.Fatalf("shared server counters not updated: up=%d down=%d", srv.Uploaded.Load(), srv.Downloaded.Load())
	}

	// 验证 C：同一端口上携带 REALITY SNI 但无凭证的探测器透明回落至伪装网站
	probe, err := tls.Dial("tcp", sharedAddr, &tls.Config{ServerName: realitySNI, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("fallback probe failed: %v", err)
	}
	defer probe.Close()
	_, _ = probe.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	pbuf := make([]byte, 64)
	n, err := probe.Read(pbuf)
	if err != nil || string(pbuf[:n]) != "FALLBACK_SITE_OK" {
		t.Fatalf("fallback probe got %q err=%v", string(pbuf[:n]), err)
	}
}
