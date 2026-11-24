package client

import (
	"context"
	"crypto/rand"
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
)

func tcpTestServer(t *testing.T, allowed ...string) share.Link {
	t.Helper()
	dir := t.TempDir()
	inner, public := "edge.txlite.invalid", "gate.txlite.invalid"
	certPEM, keyPEM, err := pki.SelfSigned([]string{inner, public}, 1)
	if err != nil {
		t.Fatal(err)
	}
	key, list, err := pki.ECH(public)
	if err != nil {
		t.Fatal(err)
	}
	keyJSON, _ := json.Marshal(key)
	for n, b := range map[string][]byte{"c.pem": certPEM, "k.pem": keyPEM, "e.json": keyJSON} {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	tok := make([]byte, 32)
	_, _ = rand.Read(tok)
	token := base64.RawURLEncoding.EncodeToString(tok)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := ln.Addr().String()
	ln.Close()

	s, err := server.New(config.Server{
		Listen:                listen,
		CertFile:              filepath.Join(dir, "c.pem"),
		KeyFile:               filepath.Join(dir, "k.pem"),
		ECHKeyFile:            filepath.Join(dir, "e.json"),
		InnerName:             inner,
		InnerCertFile:         filepath.Join(dir, "c.pem"),
		InnerKeyFile:          filepath.Join(dir, "k.pem"),
		Tokens:                []string{token},
		AllowedPrivateTargets: allowed,
		DNSCacheTTL:           60,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c, e := net.DialTimeout("tcp", listen, 100*time.Millisecond); e == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	_, port, _ := net.SplitHostPort(listen)
	p, _ := strconv.Atoi(port)
	return share.Link{
		Name:       "t",
		Host:       "127.0.0.1",
		Port:       p,
		Token:      token,
		ServerName: inner,
		ECHConfig:  base64.StdEncoding.EncodeToString(list),
		CertPin:    config.CertPin(leaf),
	}
}

func tcpTestMux(t *testing.T, link share.Link, transport string) *Mux {
	t.Helper()
	c := link.Client("127.0.0.1")
	c.Transport = transport
	c.ConnectTimeout = 5
	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

// A target that answers and closes must give the client EOF even while the
// client keeps its own side open (close-delimited HTTP responses need it).
func TestTargetCloseReachesClient(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
	link := tcpTestServer(t, ln.Addr().String())
	for _, transport := range []string{"tcp", "h2"} {
		m := tcpTestMux(t, link, transport)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		tun, e := m.OpenTCPFast(ctx, ln.Addr().String())
		if e != nil {
			t.Fatal(transport, e)
		}
		if _, e = tun.Write([]byte("GET / HTTP/1.0\r\n\r\n")); e != nil { // write side stays open
			t.Fatal(transport, e)
		}
		done := make(chan struct {
			data []byte
			err  error
		}, 1)
		go func() {
			b, err := io.ReadAll(tun)
			done <- struct {
				data []byte
				err  error
			}{b, err}
		}()
		select {
		case res := <-done:
			if res.err != nil {
				t.Fatal(transport, res.err)
			}
			if string(res.data) != "HTTP/1.0 200 OK\r\n\r\nbody until close" {
				t.Fatalf("%s unexpected payload: %q", transport, string(res.data))
			}
		case <-time.After(6 * time.Second):
			t.Fatal(transport, "target closed but the client never saw EOF")
		}
		tun.Close()
		cancel()
	}
}
