package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/674542449/tunnelx-lite/internal/config"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func poolServer(t *testing.T, handler http.HandlerFunc) config.Client {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.EnableHTTP2 = true
	s.StartTLS()
	t.Cleanup(s.Close)
	roots := filepath.Join(t.TempDir(), "ca.pem")
	if e := os.WriteFile(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	host, port, _ := net.SplitHostPort(s.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	return config.Client{ServerName: "example.com", ServerIP: host, Port: p, CAFile: roots,
		Token: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), Transport: "h2", H2Connections: 4, H2RetryNew: true, ConnectTimeout: 1, H2MaxAge: 120}
}
func echoConnect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Tunnelx-Version", config.Version)
	w.WriteHeader(200)
	http.NewResponseController(w).Flush()
	buffer := make([]byte, 4096)
	for {
		n, e := r.Body.Read(buffer)
		if n > 0 {
			w.Write(buffer[:n])
			http.NewResponseController(w).Flush()
		}
		if e != nil {
			return
		}
	}
}
func exchange(t *testing.T, m *Mux, target string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, e := m.OpenTCP(ctx, target)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	if _, e = st.Write([]byte("echo")); e != nil {
		t.Fatal(e)
	}
	reply := make([]byte, 4)
	if _, e = io.ReadFull(st, reply); e != nil || string(reply) != "echo" {
		t.Fatal("business data changed", e, string(reply))
	}
}
func TestH2PoolRotationPreservesActiveBusiness(t *testing.T) {
	c := poolServer(t, echoConnect)
	m, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	active, e := m.OpenTCP(ctx, "active.test:443")
	if e != nil {
		t.Fatal(e)
	}
	defer active.Close()
	active.Write([]byte("a"))
	b := make([]byte, 1)
	if _, e = io.ReadFull(active, b); e != nil {
		t.Fatal(e)
	}
	m.h2Mu.Lock()
	m.h2Pool[0].born = time.Now().Add(-121 * time.Second)
	m.h2Mu.Unlock()
	for i := 0; i < 12; i++ {
		exchange(t, m, "next.test:443")
	}
	if _, e = active.Write([]byte("z")); e != nil {
		t.Fatal("rotation closed active business", e)
	}
	if _, e = io.ReadFull(active, b); e != nil || b[0] != 'z' {
		t.Fatal("active stream failed after rotation", e)
	}
	// Missing carriers are dialed in the background; let the pool fill up.
	for deadline := time.Now().Add(3 * time.Second); m.Stats.H2Dials.Load() < 5 && time.Now().Before(deadline); {
		exchange(t, m, "next.test:443")
		time.Sleep(10 * time.Millisecond)
	}
	if m.Stats.H2Retired.Load() != 1 || m.Stats.H2Dials.Load() != 5 {
		t.Fatal("unexpected carrier lifecycle", m.Stats.H2Retired.Load(), m.Stats.H2Dials.Load())
	}
	m.h2Mu.Lock()
	count := len(m.h2Pool)
	m.h2Mu.Unlock()
	if count > 2*c.H2Connections {
		t.Fatal("unbounded carrier pool", count)
	}
}
func TestH2SlowOriginDoesNotDiscardHealthyCarrier(t *testing.T) {
	var calls atomic.Int64
	c := poolServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "stall.test:443" && calls.Add(1) == 1 {
			<-r.Context().Done()
			return
		}
		echoConnect(w, r)
	})
	c.H2Connections = 1
	m, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	exchange(t, m, "warm.test:443")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, e = m.OpenTCP(ctx, "stall.test:443")
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("slow target deadline not reported", e)
	}
	exchange(t, m, "healthy.test:443")
	if calls.Load() != 1 || m.Stats.H2Retries.Load() != 0 || m.Stats.H2Retired.Load() != 0 {
		t.Fatal("a slow origin discarded a healthy H2 carrier", calls.Load(), m.Stats.H2Retries.Load(), m.Stats.H2Retired.Load())
	}
}

type blockedConn struct {
	net.Conn
	mu   sync.Mutex
	gate chan struct{}
	done chan struct{}
	once sync.Once
}

func (c *blockedConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	c.mu.Lock()
	gate := c.gate
	c.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-c.done:
			return 0, net.ErrClosed
		}
	}
	return n, e
}
func (c *blockedConn) Close() error { c.once.Do(func() { close(c.done) }); return c.Conn.Close() }

type blockedListener struct {
	net.Listener
	mu    sync.Mutex
	first *blockedConn
}

func (l *blockedListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	b := &blockedConn{Conn: c, done: make(chan struct{})}
	l.mu.Lock()
	if l.first == nil {
		l.first = b
	}
	l.mu.Unlock()
	return b, nil
}

func TestH2DeadCarrierRetriedOnFreshConnection(t *testing.T) {
	s := httptest.NewUnstartedServer(http.HandlerFunc(echoConnect))
	l := &blockedListener{Listener: s.Listener}
	s.Listener = l
	s.EnableHTTP2 = true
	s.StartTLS()
	defer s.Close()
	roots := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600)
	host, port, _ := net.SplitHostPort(s.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	c := config.Client{ServerName: "example.com", ServerIP: host, Port: pn, CAFile: roots, Token: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), Transport: "h2", H2RetryNew: true, ConnectTimeout: 1, H2PingTimeout: 1}
	m, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	exchange(t, m, "warm.test:443")
	l.mu.Lock()
	first := l.first
	l.mu.Unlock()
	first.mu.Lock()
	gate := make(chan struct{})
	first.gate = gate
	first.mu.Unlock()
	defer close(gate)
	exchange(t, m, "next.test:443")
	if m.Stats.H2Retries.Load() != 1 || m.Stats.H2Retired.Load() != 1 || m.Stats.H2Dials.Load() != 2 {
		t.Fatal("dead carrier did not recover on exactly one fresh connection")
	}
}
func TestH2CallerCancellationAndAuthDoNotRetireCarrier(t *testing.T) {
	c := poolServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case "cancel.test:443":
			<-r.Context().Done()
			return
		case "reject.test:443":
			w.WriteHeader(405)
			return
		}
		echoConnect(w, r)
	})
	c.H2Connections = 1
	m, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	exchange(t, m, "warm.test:443")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, e = m.OpenTCP(ctx, "cancel.test:443")
	cancel()
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("caller deadline not preserved", e)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, e = m.OpenTCP(ctx, "reject.test:443")
	var re *RequestError
	if !errors.As(e, &re) || re.Status != 405 {
		t.Fatal("auth error not preserved", e)
	}
	exchange(t, m, "healthy.test:443")
	if m.Stats.H2Retired.Load() != 0 || m.Stats.H2Retries.Load() != 0 || m.Stats.H2Dials.Load() != 1 {
		t.Fatal("caller cancellation or auth response retried / discarded a healthy carrier")
	}
}
