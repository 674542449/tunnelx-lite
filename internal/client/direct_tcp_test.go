package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
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
