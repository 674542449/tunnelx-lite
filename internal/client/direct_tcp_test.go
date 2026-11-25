package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/674542449/tunnelx-lite/internal/config"
)

func TestDirectTCPBulkTransferAndPrewarm(t *testing.T) {
	payload := make([]byte, 2<<20) // 2 MiB
	_, _ = rand.Read(payload)
	wantHash := sha256.Sum256(payload)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	link := tcpTestServer(t, ln.Addr().String())
	m := tcpTestMux(t, link, "tcp")
	m.Prewarm()

	// Wait briefly for standby TLS connections to populate the pool.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		m.direct.mu.Lock()
		n := len(m.direct.idle)
		m.direct.mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if m.ActiveTransport() != "tcp" {
		t.Fatalf("expected active transport tcp, got %s", m.ActiveTransport())
	}

	// Run 4 parallel 2 MiB round-trips over dedicated TLS 1.3 TCP tunnels.
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			tun, e := m.OpenTCPFast(ctx, ln.Addr().String())
			if e != nil {
				errs <- e
				return
			}
			defer tun.Close()
			if tun.Transport() != "tcp" {
				t.Errorf("expected tcp transport, got %s", tun.Transport())
			}
			go func() {
				_, _ = io.Copy(tun, bytes.NewReader(payload))
				_ = tun.CloseWrite()
			}()
			got, e := io.ReadAll(tun)
			if e != nil {
				errs <- e
				return
			}
			if sha256.Sum256(got) != wantHash {
				t.Errorf("bulk payload corrupted: got %d bytes", len(got))
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	if m.Stats.TCPStreams.Load() != 4 {
		t.Fatalf("expected 4 direct TCP streams, got %d", m.Stats.TCPStreams.Load())
	}
}

func TestDirectTCPFallsBackToH2OnLegacy505Server(t *testing.T) {
	c := poolServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Tunnelx-Version", config.Version)
		if r.ProtoMajor != 2 {
			http.Error(w, "HTTP Version Not Supported", 505)
			return
		}
		echoConnect(w, r)
	})
	c.Transport = "tcp"
	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := m.OpenTCP(ctx, "legacy.test:443")
	if err != nil {
		t.Fatalf("legacy 505 fallback failed: %v", err)
	}
	defer st.Close()
	if st.Transport() != "h2" {
		t.Fatalf("expected h2 fallback transport, got %s", st.Transport())
	}
	if m.ActiveTransport() != "h2" {
		t.Fatalf("expected ActiveTransport=h2 after 505 fallback, got %s", m.ActiveTransport())
	}
	if _, err = st.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err = io.ReadFull(st, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("fallback data failed: %q %v", string(buf), err)
	}
}

func testInnerCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "inner.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"inner.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type tunnelConn struct {
	*Tunnel
	local, remote net.Addr
}

func (c tunnelConn) LocalAddr() net.Addr                { return c.local }
func (c tunnelConn) RemoteAddr() net.Addr               { return c.remote }
func (c tunnelConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c tunnelConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

// End-to-end test: real inner TLS 1.3 HTTPS stream proxied through txlite
// outer TLS 1.3 + ECH server must negotiate Tunnelx-Vision, peel off outer TLS
// after inner TLS 1.3 handshake, and deliver 4 MiB bit-for-bit over direct TCP.
func TestVisionEndToEndInnerTLS13DirectSpliceAndServerFirst(t *testing.T) {
	payload := make([]byte, 4<<20) // 4 MiB
	_, _ = rand.Read(payload)
	wantHash := sha256.Sum256(payload)

	// 1. Inner TLS 1.3 target server.
	innerCert := testInnerCert(t)
	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{innerCert}})
	if err != nil {
		t.Fatal(err)
	}
	defer tlsLn.Close()
	go func() {
		for {
			c, e := tlsLn.Accept()
			if e != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				req := make([]byte, 4)
				if _, e := io.ReadFull(conn, req); e != nil {
					return
				}
				_, _ = conn.Write(payload)
			}(c)
		}
	}()

	// 2. Server-first plaintext target (sends banner immediately before client writes).
	bannerLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bannerLn.Close()
	go func() {
		for {
			c, e := bannerLn.Accept()
			if e != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("SSH-2.0-TestBanner\r\n"))
			}(c)
		}
	}()

	link := tcpTestServer(t, tlsLn.Addr().String(), bannerLn.Addr().String())
	m := tcpTestMux(t, link, "tcp")

	// Simulate verifyGateway's 127.0.0.1:9 probe which detects Tunnelx-Vision: 1.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = m.OpenTCP(ctx, "127.0.0.1:9")
	if m.ActiveTransport() != "vision" {
		t.Fatalf("expected ActiveTransport=vision after gateway probe, got %s", m.ActiveTransport())
	}

	// Test 1: Inner TLS 1.3 download through Vision fast-open coalesced write -> Direct Splice!
	tun, err := m.OpenTCPFast(ctx, tlsLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if tun.Transport() != "vision" {
		t.Fatalf("expected vision transport, got %s", tun.Transport())
	}
	innerCli := tls.Client(tunnelConn{Tunnel: tun, local: &net.TCPAddr{}, remote: tlsLn.Addr()}, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true})
	if err := innerCli.HandshakeContext(ctx); err != nil {
		t.Fatalf("inner TLS 1.3 handshake over Vision failed: %v", err)
	}
	if _, err := innerCli.Write([]byte("GET!")); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(innerCli)
	if err != nil {
		t.Fatalf("inner TLS 1.3 read over Vision failed: %v", err)
	}
	if sha256.Sum256(got) != wantHash {
		t.Fatalf("Vision direct payload corrupted: got %d bytes", len(got))
	}
	if !tun.VisionDirect() {
		t.Fatal("inner TLS 1.3 flow did not switch both directions to Vision direct zero-copy mode")
	}

	// Test 2: Server-first non-TLS target must NOT stall on prefix coalescing and stays in outer TLS.
	bTun, err := m.OpenTCPFast(ctx, bannerLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer bTun.Close()
	banner, err := io.ReadAll(bTun)
	if err != nil || string(banner) != "SSH-2.0-TestBanner\r\n" {
		t.Fatalf("server-first banner over Vision failed: %q %v", string(banner), err)
	}
	if bTun.VisionDirect() {
		t.Fatal("plaintext server-first flow must not switch to direct raw TCP")
	}
}
