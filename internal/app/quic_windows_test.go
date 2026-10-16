package app

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/674542449/tunnelx-lite/internal/config"
	"github.com/674542449/tunnelx-lite/internal/pki"
	"github.com/674542449/tunnelx-lite/internal/routing"
	"github.com/674542449/tunnelx-lite/internal/server"
	"github.com/674542449/tunnelx-lite/internal/share"
)

func quicTestServer(t *testing.T, allowed string) share.Link {
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
	listen := freeAddr(t)
	s, err := server.New(config.Server{Listen: listen, CertFile: filepath.Join(dir, "c.pem"), KeyFile: filepath.Join(dir, "k.pem"), ECHKeyFile: filepath.Join(dir, "e.json"), InnerName: inner, InnerCertFile: filepath.Join(dir, "c.pem"), InnerKeyFile: filepath.Join(dir, "k.pem"), Tokens: []string{token}, AllowedPrivateTargets: []string{allowed}, QUIC: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx)
	go s.ServeQUIC(ctx)
	time.Sleep(200 * time.Millisecond)
	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	_, port, _ := net.SplitHostPort(listen)
	p, _ := strconv.Atoi(port)
	return share.Link{Name: "q", Host: "127.0.0.1", Port: p, Token: token, ServerName: inner, ECHConfig: base64.StdEncoding.EncodeToString(list), CertPin: config.CertPin(leaf)}
}

func TestQUICTransportPreference(t *testing.T) {
	site := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello over quic") })}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go site.Serve(ln)
	defer site.Close()
	link := quicTestServer(t, ln.Addr().String())
	for _, transport := range []string{"quic", "auto"} {
		e, err := New(t.TempDir(), Settings{SOCKS: freeAddr(t), HTTP: freeAddr(t), Web: freeAddr(t)})
		if err != nil {
			t.Fatal(err)
		}
		if err = e.SaveTransport("bogus"); err == nil {
			t.Fatal("invalid transport accepted")
		}
		e.Import(link.String())
		e.SaveProxyMode(routing.Global, "")
		if err = e.SaveTransport(transport); err != nil {
			t.Fatal(err)
		}
		if err = e.Connect(e.Servers()[0].ID, false); err != nil {
			t.Fatal(transport, err)
		}
		if err = e.SaveTransport("h2"); err == nil {
			t.Fatal("transport changed while connected")
		}
		deadline := time.Now().Add(5 * time.Second)
		for e.Status()["transport"] != "quic" && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if e.Status()["transport"] != "quic" {
			t.Fatal(transport, "mode is not using QUIC", e.Status()["transport"])
		}
		// Loopback targets go direct through the local proxy, so use the tunnel itself.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		tun, err := e.mux.OpenTCPFast(ctx, ln.Addr().String())
		if err != nil {
			t.Fatal(transport, err)
		}
		io.WriteString(tun, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		res, err := http.ReadResponse(bufio.NewReader(tun), nil)
		if err != nil {
			t.Fatal(transport, err)
		}
		b, _ := io.ReadAll(res.Body)
		tun.Close()
		cancel()
		if string(b) != "hello over quic" || tun.Transport() != "quic" {
			t.Fatal(transport, "response or transport changed", string(b), tun.Transport())
		}
		e.Close()
	}
}
