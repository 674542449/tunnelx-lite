package client

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/674542449/tunnelx-lite/internal/config"
	"github.com/674542449/tunnelx-lite/internal/pki"
	"github.com/674542449/tunnelx-lite/internal/server"
	"github.com/674542449/tunnelx-lite/internal/share"
)

func echoTCP(t *testing.T) string {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func echoUDP(t *testing.T) string {
	pc, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, e := pc.ReadFrom(b)
			if e != nil {
				return
			}
			pc.WriteTo(b[:n], a)
		}
	}()
	return pc.LocalAddr().String()
}

// quicServer runs a real txlite server; with withQUIC it also serves QUIC.
func quicServer(t *testing.T, withQUIC bool, allowed ...string) share.Link {
	dir := t.TempDir()
	inner, public := "edge.txlite.invalid", "gate.txlite.invalid"
	certPEM, keyPEM, _ := pki.SelfSigned([]string{inner, public}, 1)
	key, list, _ := pki.ECH(public)
	keyJSON, _ := json.Marshal(key)
	for n, b := range map[string][]byte{"c.pem": certPEM, "k.pem": keyPEM, "e.json": keyJSON} {
		os.WriteFile(filepath.Join(dir, n), b, 0600)
	}
	tok := make([]byte, 32)
	rand.Read(tok)
	token := base64.RawURLEncoding.EncodeToString(tok)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	listen := l.Addr().String()
	l.Close()
	s, err := server.New(config.Server{Listen: listen, CertFile: filepath.Join(dir, "c.pem"), KeyFile: filepath.Join(dir, "k.pem"), ECHKeyFile: filepath.Join(dir, "e.json"), InnerName: inner, InnerCertFile: filepath.Join(dir, "c.pem"), InnerKeyFile: filepath.Join(dir, "k.pem"), Tokens: []string{token}, AllowedPrivateTargets: allowed, QUIC: withQUIC})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx)
	if withQUIC {
		go s.ServeQUIC(ctx)
	}
	time.Sleep(200 * time.Millisecond)
	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	_, port, _ := net.SplitHostPort(listen)
	p, _ := strconv.Atoi(port)
	return share.Link{Name: "q", Host: "127.0.0.1", Port: p, Token: token, ServerName: inner, ECHConfig: base64.StdEncoding.EncodeToString(list), CertPin: config.CertPin(leaf)}
}

func quicMux(t *testing.T, link share.Link, transport string) *Mux {
	c := link.Client("127.0.0.1")
	c.Transport = transport
	c.ConnectTimeout = 3
	m, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func roundTrip(t *testing.T, tun *Tunnel, msg string) {
	t.Helper()
	if _, e := tun.Write([]byte(msg)); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, len(msg))
	if _, e := io.ReadFull(tun, b); e != nil || string(b) != msg {
		t.Fatal("echo failed", e, string(b))
	}
}

func TestQUICCarriesTCPAndUDPWithECH(t *testing.T) {
	tcpEcho, udpEcho := echoTCP(t), echoUDP(t)
	link := quicServer(t, true, tcpEcho, udpEcho)
	m := quicMux(t, link, "quic")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tun, e := m.OpenTCP(ctx, tcpEcho)
	if e != nil {
		t.Fatal(e)
	}
	roundTrip(t, tun, "over quic")
	tun.Close()
	if m.ActiveTransport() != "quic" || !m.LastECH.Load() {
		t.Fatal("flow did not use QUIC with ECH", m.ActiveTransport(), m.LastECH.Load())
	}
	fast, e := m.OpenTCPFast(ctx, tcpEcho)
	if e != nil {
		t.Fatal(e)
	}
	roundTrip(t, fast, "fast open")
	if e = fast.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	if _, e = fast.Read(make([]byte, 1)); e != io.EOF {
		t.Fatal("half close not propagated", e)
	}
	fast.Close()
	udp, e := m.OpenUDP(ctx, udpEcho)
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	if e = udp.Send([]byte("datagram")); e != nil {
		t.Fatal(e)
	}
	if b, e := udp.Receive(ctx); e != nil || string(b) != "datagram" {
		t.Fatal("UDP over QUIC failed", e, string(b))
	}
	// A public-looking but private target that is not allowed is refused, not hung.
	_, e = m.OpenTCP(ctx, "10.255.255.1:80")
	var refused *RequestError
	if !errors.As(e, &refused) || refused.Status != 403 {
		t.Fatal("forbidden target not refused", e)
	}
}

func TestQUICWrongKeyIsRejected(t *testing.T) {
	echo := echoTCP(t)
	link := quicServer(t, true, echo)
	tok := make([]byte, 32)
	rand.Read(tok)
	link.Token = base64.RawURLEncoding.EncodeToString(tok)
	m := quicMux(t, link, "quic")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if tun, e := m.OpenTCP(ctx, echo); e == nil {
		tun.Close()
		t.Fatal("wrong key accepted over QUIC")
	}
}

// Auto mode must keep working through HTTP/2 when UDP does not get through,
// and must never make a flow wait for the QUIC handshake.
func TestAutoFallsBackToHTTP2(t *testing.T) {
	echo := echoTCP(t)
	link := quicServer(t, false, echo)
	m := quicMux(t, link, "auto")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	tun, e := m.OpenTCPFast(ctx, echo)
	if e != nil {
		t.Fatal(e)
	}
	roundTrip(t, tun, "fallback")
	tun.Close()
	if time.Since(start) > 2*time.Second || m.ActiveTransport() != "h2" {
		t.Fatal("auto mode waited for QUIC or did not fall back", time.Since(start), m.ActiveTransport())
	}
}

func TestAutoUpgradesToQUIC(t *testing.T) {
	echo := echoTCP(t)
	link := quicServer(t, true, echo)
	m := quicMux(t, link, "auto")
	m.PrewarmQUIC()
	deadline := time.Now().Add(5 * time.Second)
	for m.ActiveTransport() != "quic" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if m.ActiveTransport() != "quic" {
		t.Fatal("auto mode never switched to QUIC")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tun, e := m.OpenTCPFast(ctx, echo)
	if e != nil {
		t.Fatal(e)
	}
	defer tun.Close()
	roundTrip(t, tun, "upgraded")
	if tun.Transport() != "quic" {
		t.Fatal("flow did not use QUIC", tun.Transport())
	}
}

// A client that declares its bandwidth switches the server to Brutal; flows
// keep working and a refused setting does not break the connection.
func TestQUICBrutalControl(t *testing.T) {
	echo := echoTCP(t)
	link := quicServer(t, true, echo)
	for _, mbps := range []int{50, 5000} {
		c := link.Client("127.0.0.1")
		c.Transport, c.ConnectTimeout, c.QUICCongestion, c.DownMbps = "quic", 3, "brutal", mbps
		m, e := New(c)
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		tun, e := m.OpenTCP(ctx, echo)
		if e != nil {
			t.Fatal(mbps, e)
		}
		roundTrip(t, tun, "brutal")
		tun.Close()
		cancel()
		if m.congestionSettings() == "" {
			t.Fatal("bandwidth not sent")
		}
		m.Close()
	}
}
