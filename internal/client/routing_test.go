package client

import (
	"bufio"
	"bytes"
	"context"
	"github.com/674542449/tunnelx-lite/internal/routing"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestBypassHTTPAndSOCKSReachOriginWithoutTunnel(t *testing.T) {
	var tunneled atomic.Int32
	cfg := poolServer(t, func(w http.ResponseWriter, r *http.Request) { tunneled.Add(1); w.WriteHeader(502) })
	m, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	m.Config.SOCKSListen = "127.0.0.1:0"
	m.Config.HTTPListen = "127.0.0.1:0"
	p := NewProxy(m)
	defer p.Close()
	rules, e := routing.Builtin()
	if e != nil {
		t.Fatal(e)
	}
	p.Router, e = routing.New(rules, "")
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Start(); e != nil {
		t.Fatal(e)
	}
	payload := bytes.Repeat([]byte("direct-download-"), 65536)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(payload) }))
	defer origin.Close()
	front := httptest.NewServer(p)
	defer front.Close()
	u, _ := url.Parse(front.URL)
	tr := &http.Transport{Proxy: http.ProxyURL(u)}
	defer tr.CloseIdleConnections()
	h := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, e := h.Get(origin.URL)
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(resp.Body)
	resp.Body.Close()
	if e != nil || !bytes.Equal(b, payload) {
		t.Fatal("direct HTTP corrupted", e)
	}
	c, e := net.DialTimeout("tcp", p.socks.Addr().String(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{5, 1, 0})
	greeting := make([]byte, 2)
	if _, e = io.ReadFull(c, greeting); e != nil || greeting[1] != 0 {
		t.Fatal(e)
	}
	target, _ := url.Parse(origin.URL)
	address, _ := encodeAddress(target.Host)
	c.Write(append([]byte{5, 1, 0}, address...))
	reply := make([]byte, 3)
	if _, e = io.ReadFull(c, reply); e != nil || reply[1] != 0 {
		t.Fatal(reply, e)
	}
	if _, _, e = readAddress(c); e != nil {
		t.Fatal(e)
	}
	c.Write([]byte("GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"))
	response, e := http.ReadResponse(bufio.NewReader(c), nil)
	if e != nil {
		t.Fatal(e)
	}
	b, e = io.ReadAll(response.Body)
	response.Body.Close()
	if e != nil || !bytes.Equal(b, payload) {
		t.Fatal("direct SOCKS corrupted", e)
	}
	if tunneled.Load() != 0 {
		t.Fatal("direct flow reached remote tunnel")
	}
	// Same target in global mode must reach the tunnel handler, not the origin.
	global := NewProxy(m)
	defer global.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stream, _ := global.openTCP(ctx, target.Host)
	if stream != nil {
		stream.Close()
	}
	if tunneled.Load() == 0 {
		t.Fatal("global mode bypassed tunnel")
	}
}
func TestBypassUDPAndShutdown(t *testing.T) {
	cfg := poolServer(t, func(w http.ResponseWriter, r *http.Request) { t.Error("UDP direct used tunnel"); w.WriteHeader(502) })
	m, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	p := NewProxy(m)
	defer p.Close()
	rules, _ := routing.Builtin()
	p.Router, _ = routing.New(rules, "")
	origin, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer origin.Close()
	go func() {
		b := make([]byte, 2048)
		n, a, e := origin.ReadFrom(b)
		if e == nil {
			origin.WriteTo(b[:n], a)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, e := p.openUDP(ctx, origin.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer stream.Close()
	if e = stream.Send([]byte("dns-like-payload")); e != nil {
		t.Fatal(e)
	}
	b, e := stream.Receive(ctx)
	if e != nil || string(b) != "dns-like-payload" {
		t.Fatal(string(b), e)
	}
	cancel()
	if _, e = stream.Receive(ctx); e == nil {
		t.Fatal("cancellation ignored")
	}
}
