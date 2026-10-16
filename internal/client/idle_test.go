package client

import (
	"context"
	"net"
	"testing"
	"time"
)

// A flow whose app half-closed while the target stays silent must not hold its
// slot forever; otherwise the proxy eventually refuses every connection.
func TestHalfOpenFlowIsReleased(t *testing.T) {
	old := halfCloseIdle
	halfCloseIdle = 300 * time.Millisecond
	defer func() { halfCloseIdle = old }()
	origin, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer origin.Close()
	go func() {
		for {
			c, e := origin.Accept()
			if e != nil {
				return
			}
			defer c.Close() // never answers, never closes
		}
	}()
	target, e := net.Dial("tcp", origin.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	tunnel := &Tunnel{Reader: target, Writer: target, close: target.Close, closeWrite: target.(*net.TCPConn).CloseWrite}
	app, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer app.Close()
	client, e := net.Dial("tcp", app.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	server, e := app.Accept()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Proxy{Mux: &Mux{}, ctx: ctx}
	done := make(chan struct{})
	go func() { p.relayFlow(server, server, tunnel, nil); close(done) }()
	client.(*net.TCPConn).CloseWrite()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("half-open flow was never released")
	}
	if p.Mux.Stats.Active.Load() != 0 {
		t.Fatal("active flow count leaked")
	}
}

func TestIdleWatchKeepsBusyFlows(t *testing.T) {
	fired := make(chan struct{}, 1)
	w := newIdleWatch(200*time.Millisecond, func() { fired <- struct{}{} })
	defer w.stop()
	for i := 0; i < 8; i++ {
		time.Sleep(50 * time.Millisecond)
		w.touch()
	}
	select {
	case <-fired:
		t.Fatal("busy flow closed as idle")
	default:
	}
	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("idle flow not closed")
	}
}
