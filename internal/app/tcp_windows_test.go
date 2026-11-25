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

func tcpTestServer(t *testing.T, allowed string) share.Link {
	dir := t.TempDir()
	inner, public := "edge.txlite.invalid", "gate.txlite.invalid"
	certPEM, keyPEM, _ := pki.SelfSigned([]string{inner, public}, 1)
	key, list, _ := pki.ECH(public)
	keyJSON, _ := json.Marshal(key)
	for n, b := range map[string][]byte{"c.pem": certPEM, "k.pem": keyPEM, "e.json": keyJSON} {
		_ = os.WriteFile(filepath.Join(dir, n), b, 0600)
	}
	tok := make([]byte, 32)
	_, _ = rand.Read(tok)
	token := base64.RawURLEncoding.EncodeToString(tok)
	listen := freeAddr(t)
	s, err := server.New(config.Server{
		Listen:                listen,
		CertFile:              filepath.Join(dir, "c.pem"),
		KeyFile:               filepath.Join(dir, "k.pem"),
		ECHKeyFile:            filepath.Join(dir, "e.json"),
		InnerName:             inner,
		InnerCertFile:         filepath.Join(dir, "c.pem"),
		InnerKeyFile:          filepath.Join(dir, "k.pem"),
		Tokens:                []string{token},
		AllowedPrivateTargets: []string{allowed},
		DNSCacheTTL:           60,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx)
	time.Sleep(200 * time.Millisecond)
	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	_, port, _ := net.SplitHostPort(listen)
	p, _ := strconv.Atoi(port)
	return share.Link{Name: "t", Host: "127.0.0.1", Port: p, Token: token, ServerName: inner, ECHConfig: base64.StdEncoding.EncodeToString(list), CertPin: config.CertPin(leaf)}
}

func TestTCPTransportPreferencesAndLegacyMigration(t *testing.T) {
	site := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello over fast tcp") })}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go site.Serve(ln)
	defer site.Close()
	link := tcpTestServer(t, ln.Addr().String())

	for _, transport := range []string{"tcp", "h2"} {
		e, err := New(t.TempDir(), Settings{SOCKS: freeAddr(t), HTTP: freeAddr(t), Web: freeAddr(t)})
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"quic", "auto", "bogus"} {
			if err = e.SaveTransport(bad); err == nil {
				t.Fatalf("invalid transport %q accepted", bad)
			}
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
		wantTransport := transport
		if transport == "tcp" {
			wantTransport = "vision"
		}
		if got := e.Status()["transport"]; got != wantTransport {
			t.Fatalf("expected active transport %q, got %v", wantTransport, got)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		tun, err := e.mux.OpenTCPFast(ctx, ln.Addr().String())
		if err != nil {
			t.Fatal(transport, err)
		}
		_, _ = io.WriteString(tun, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		res, err := http.ReadResponse(bufio.NewReader(tun), nil)
		if err != nil {
			t.Fatal(transport, err)
		}
		b, _ := io.ReadAll(res.Body)
		tun.Close()
		cancel()
		if string(b) != "hello over fast tcp" || tun.Transport() != wantTransport {
			t.Fatalf("%s response or transport mismatch: %q %q", transport, string(b), tun.Transport())
		}
		e.Close()
	}

	// Legacy preferences containing removed QUIC/auto fields must migrate cleanly without warning.
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	_ = os.MkdirAll(stateDir, 0700)
	_ = os.WriteFile(filepath.Join(stateDir, "preferences.json"), []byte(`{"proxy_mode":"bypass_cn","transport":"quic","down_mbps":300}`), 0600)
	e, err := New(root, Settings{SOCKS: freeAddr(t), HTTP: freeAddr(t), Web: freeAddr(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	st := e.Status()
	if st["startup_warning"] != "" {
		t.Fatalf("legacy QUIC preferences produced warning: %v", st["startup_warning"])
	}
	if st["transport_preference"] != "tcp" {
		t.Fatalf("legacy QUIC preference did not migrate to tcp: %v", st["transport_preference"])
	}
}
