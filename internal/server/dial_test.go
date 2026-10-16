package server

import (
	"context"
	"net"
	"testing"
	"time"
)

// A dead first address (e.g. broken IPv6) must not use up the dial timeout.
func TestDialTargetFallsBackQuickly(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	c, e := dialTarget(ctx, []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("127.0.0.1")}, port)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if d := time.Since(start); d > 3*time.Second {
		t.Fatal("fallback took", d)
	}
	if _, e = dialTarget(ctx, []net.IP{net.ParseIP("127.0.0.1")}, "1"); e == nil {
		t.Fatal("closed port accepted")
	}
}
