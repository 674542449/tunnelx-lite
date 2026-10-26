package client

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/674542449/tunnelx-lite/internal/config"
)

// The first bytes must travel with CONNECT, before the server has answered.
func TestFastOpenSendsEarlyData(t *testing.T) {
	got := make(chan string, 1)
	c := poolServer(t, func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 5)
		io.ReadFull(r.Body, b) // the payload is already here before we answer
		got <- string(b)
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Tunnelx-Version", config.Version)
		w.WriteHeader(200)
		w.Write(b)
		http.NewResponseController(w).Flush()
		io.Copy(io.Discard, r.Body)
	})
	m, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tun, e := m.OpenTCPFast(ctx, "early.test:443")
	if e != nil {
		t.Fatal(e)
	}
	defer tun.Close()
	if _, e = tun.Write([]byte("hello")); e != nil {
		t.Fatal(e)
	}
	select {
	case s := <-got:
		if s != "hello" {
			t.Fatal("early data changed", s)
		}
	case <-ctx.Done():
		t.Fatal("early data waited for the CONNECT response")
	}
	reply := make([]byte, 5)
	if _, e = io.ReadFull(tun, reply); e != nil || string(reply) != "hello" {
		t.Fatal("response lost", e, string(reply))
	}
}

func TestFastOpenRefusalIsAReadError(t *testing.T) {
	c := poolServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Tunnelx-Version", config.Version)
		w.WriteHeader(502)
	})
	m, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tun, e := m.OpenTCPFast(ctx, "down.test:443")
	if e != nil {
		t.Fatal(e)
	}
	defer tun.Close()
	done := make(chan error, 1)
	go func() { _, e := tun.Read(make([]byte, 1)); done <- e }()
	select {
	case e = <-done:
		if e == nil {
			t.Fatal("refused CONNECT returned data")
		}
	case <-ctx.Done():
		t.Fatal("refused CONNECT left the reader hanging")
	}
}

func TestFastOpenCloseBeforeAnswer(t *testing.T) {
	release := make(chan struct{})
	c := poolServer(t, func(w http.ResponseWriter, r *http.Request) { <-release })
	defer close(release)
	m, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	tun, e := m.OpenTCPFast(context.Background(), "slow.test:443")
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := tun.Read(make([]byte, 1)); done <- e }()
	tun.Close()
	select {
	case e = <-done:
		if e == nil {
			t.Fatal("closed tunnel returned data")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not release a reader waiting for the answer")
	}
}

// An answer that arrives while Close is running must not leak its body.
func TestPendingBodyClosesLateBody(t *testing.T) {
	p := &pendingBody{ready: make(chan struct{})}
	p.closed = true // Close has marked the tunnel but not yet resolved it
	body := &closeTracker{}
	p.resolve(body, nil)
	if !body.closed {
		t.Fatal("late response body was not closed")
	}
	if _, e := p.Read(make([]byte, 1)); e == nil {
		t.Fatal("closed tunnel returned data")
	}
}

type closeTracker struct{ closed bool }

func (c *closeTracker) Read([]byte) (int, error) { return 0, io.EOF }
func (c *closeTracker) Close() error             { c.closed = true; return nil }
