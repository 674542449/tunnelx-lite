package client

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// A target that answers and closes must give the client EOF even while the
// client keeps its own side open (close-delimited HTTP responses need it).
func TestTargetCloseReachesClient(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			c.Write([]byte("HTTP/1.0 200 OK\r\n\r\nbody until close"))
			c.Close()
		}
	}()
	link := quicServer(t, true, ln.Addr().String())
	for _, transport := range []string{"h2", "quic"} {
		m := quicMux(t, link, transport)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		tun, e := m.OpenTCPFast(ctx, ln.Addr().String())
		if e != nil {
			t.Fatal(transport, e)
		}
		tun.Write([]byte("GET / HTTP/1.0\r\n\r\n")) // write side stays open
		done := make(chan error, 1)
		go func() { _, e := io.ReadAll(tun); done <- e }()
		select {
		case e = <-done:
			if e != nil {
				t.Fatal(transport, e)
			}
		case <-time.After(6 * time.Second):
			t.Fatal(transport, "target closed but the client never saw EOF")
		}
		tun.Close()
		cancel()
	}
}
