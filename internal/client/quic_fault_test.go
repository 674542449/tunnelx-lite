package client

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
	"github.com/674542449/tunnelx-lite/internal/wire"
	"github.com/apernet/quic-go"
)

// faultServer runs the real HTTP/2 server on TCP and a fake QUIC endpoint on
// the UDP port of the same number, so auto mode has somewhere to fall back.
func faultServer(t *testing.T, allowed string, stream func(*quic.Conn, *quic.Stream)) share.Link {
	dir := t.TempDir()
	inner, public := "edge.txlite.invalid", "gate.txlite.invalid"
	certPEM, keyPEM, _ := pki.SelfSigned([]string{inner, public}, 1)
	key, list, _ := pki.ECH(public)
	keyJSON, _ := json.Marshal(key)
	for n, b := range map[string][]byte{"c.pem": certPEM, "k.pem": keyPEM, "e.json": keyJSON} {
		os.WriteFile(filepath.Join(dir, n), b, 0600)
	}
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	listen := l.Addr().String()
	l.Close()
	cfg := config.Server{Listen: listen, CertFile: filepath.Join(dir, "c.pem"), KeyFile: filepath.Join(dir, "k.pem"), ECHKeyFile: filepath.Join(dir, "e.json"), InnerName: inner, InnerCertFile: filepath.Join(dir, "c.pem"), InnerKeyFile: filepath.Join(dir, "k.pem"), Tokens: []string{token}, AllowedPrivateTargets: []string{allowed}}
	s, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx)
	tlsCfg, _ := cfg.TLS()
	tlsCfg.NextProtos = []string{wire.QUICALPN}
	ln, err := quic.ListenAddr(listen, tlsCfg, wire.QUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, e := ln.Accept(ctx)
			if e != nil {
				return
			}
			go func() {
				for {
					st, e := c.AcceptStream(ctx)
					if e != nil {
						return
					}
					go stream(c, st)
				}
			}()
		}
	}()
	time.Sleep(200 * time.Millisecond)
	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	_, port, _ := net.SplitHostPort(listen)
	p, _ := strconv.Atoi(port)
	return share.Link{Name: "f", Host: "127.0.0.1", Port: p, Token: token, ServerName: inner, ECHConfig: base64.StdEncoding.EncodeToString(list), CertPin: config.CertPin(leaf)}
}

// UDP that stops getting through mid-session must not stall every new flow.
func TestAutoLeavesSilentQUIC(t *testing.T) {
	echo := echoTCP(t)
	link := faultServer(t, echo, func(*quic.Conn, *quic.Stream) {}) // accepts, never answers
	m := quicMux(t, link, "auto")
	m.PrewarmQUIC()
	for i := 0; i < 50 && m.ActiveTransport() != "quic"; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stuck, e := m.OpenTCPFast(ctx, echo)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = stuck.Read(make([]byte, 1)); e == nil {
		t.Fatal("silent server answered")
	}
	stuck.Close()
	if m.ActiveTransport() != "h2" {
		t.Fatal("silent QUIC connection still used for new flows")
	}
	tun, e := m.OpenTCPFast(ctx, echo)
	if e != nil {
		t.Fatal(e)
	}
	defer tun.Close()
	roundTrip(t, tun, "back on tcp")
}

// Servers before v0.2.1 close the connection on the bandwidth message; the
// client must stop sending it instead of losing QUIC for good.
func TestOldServerWithoutControlStream(t *testing.T) {
	link := faultServer(t, "127.0.0.1:1", func(c *quic.Conn, st *quic.Stream) {
		kind, _, _, e := wire.ReadQUICHeader(st)
		if e != nil || kind == wire.QUICControl {
			c.CloseWithError(0, "") // what an old server does with an unknown kind
			return
		}
		st.Write([]byte{wire.QUICOK})
		io.Copy(st, st)
		st.Close()
	})
	c := link.Client("127.0.0.1")
	c.Transport, c.ConnectTimeout, c.QUICCongestion, c.DownMbps = "quic", 3, "brutal", 50
	m, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var tun *Tunnel
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if tun, e = m.OpenTCP(ctx, "example.test:80"); e == nil {
			// The first connection may be closed right after the control message.
			if _, e = tun.Write([]byte("ok")); e == nil {
				b := make([]byte, 2)
				if _, e = io.ReadFull(tun, b); e == nil {
					break
				}
			}
			tun.Close()
		}
	}
	if e != nil {
		t.Fatal("QUIC never recovered on an old server", e)
	}
	tun.Close()
	m.quic.mu.Lock()
	skipped := m.quic.noControl
	m.quic.mu.Unlock()
	if !skipped {
		t.Fatal("control stream still sent to an old server")
	}
}

// A malformed or abandoned stream on an authenticated connection must not
// close the connection and every other flow on it.
func TestBadStreamKeepsConnection(t *testing.T) {
	echo := echoTCP(t)
	link := quicServer(t, true, echo)
	m := quicMux(t, link, "quic")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	live, e := m.OpenTCP(ctx, echo)
	if e != nil {
		t.Fatal(e)
	}
	defer live.Close()
	roundTrip(t, live, "before")
	st, e := m.quic.conn.OpenStreamSync(ctx)
	if e != nil {
		t.Fatal(e)
	}
	st.Write([]byte{9, 9}) // garbage, then abandon the stream
	st.CancelWrite(0)
	time.Sleep(300 * time.Millisecond)
	roundTrip(t, live, "after")
	if m.ActiveTransport() != "quic" {
		t.Fatal("connection closed by one bad stream")
	}
}
