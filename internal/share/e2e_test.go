package share

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

	"github.com/674542449/tunnelx-lite/internal/client"
	"github.com/674542449/tunnelx-lite/internal/config"
	"github.com/674542449/tunnelx-lite/internal/pki"
	"github.com/674542449/tunnelx-lite/internal/server"
)

func freePort(t *testing.T) int {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func token(t *testing.T) string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// startServer runs a self-signed, ECH-only server and returns its share link.
func startServer(t *testing.T, echo string) Link {
	dir := t.TempDir()
	inner, public := "edge.txlite.invalid", "gate.txlite.invalid"
	certPEM, keyPEM, err := pki.SelfSigned([]string{inner, public}, 10)
	if err != nil {
		t.Fatal(err)
	}
	key, echList, err := pki.ECH(public)
	if err != nil {
		t.Fatal(err)
	}
	keyJSON, _ := json.Marshal(key)
	for name, data := range map[string][]byte{"cert.pem": certPEM, "key.pem": keyPEM, "ech.json": keyJSON} {
		os.WriteFile(filepath.Join(dir, name), data, 0600)
	}
	port, tok := freePort(t), token(t)
	cfg := config.Server{Listen: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem"), ECHKeyFile: filepath.Join(dir, "ech.json"), InnerName: inner, InnerCertFile: filepath.Join(dir, "cert.pem"), InnerKeyFile: filepath.Join(dir, "key.pem"), Tokens: []string{tok}, AllowedPrivateTargets: []string{echo}}
	s, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx)
	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	for i := 0; i < 50; i++ {
		if c, e := net.Dial("tcp", cfg.Listen); e == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return Link{Name: "测试 服务器", Host: "127.0.0.1", Port: port, Token: tok, ServerName: inner, ECHConfig: base64.StdEncoding.EncodeToString(echList), CertPin: config.CertPin(leaf)}
}

func echoServer(t *testing.T) string {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return l.Addr().String()
}

func TestShareLinkConnectsThroughPinnedECHServer(t *testing.T) {
	echo := echoServer(t)
	link := startServer(t, echo)
	parsed, err := Parse(link.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsed != link {
		t.Fatalf("round trip changed the link:\n%+v\n%+v", parsed, link)
	}
	cfg := parsed.Client("127.0.0.1")
	m, err := client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := m.OpenTCP(ctx, echo)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.Write([]byte("txlite"))
	buf := make([]byte, 6)
	if _, err = io.ReadFull(st, buf); err != nil || string(buf) != "txlite" {
		t.Fatal("echo through tunnel failed", err, string(buf))
	}
	if !m.LastECH.Load() {
		t.Fatal("connection did not use ECH")
	}

	wrong := parsed
	other, _, _ := pki.SelfSigned([]string{"x.invalid"}, 1)
	block, _ := pem.Decode(other)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	wrong.CertPin = config.CertPin(leaf)
	bad, err := client.New(wrong.Client("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	if st, err := bad.OpenTCP(ctx2, echo); err == nil {
		st.Close()
		t.Fatal("client accepted a server whose certificate does not match the pin")
	}
}

func TestParseRejectsBrokenLinksAndKeepsIPv6(t *testing.T) {
	link := Link{Name: "v6", Host: "2001:db8::1", Port: 443, Token: token(t), ServerName: "edge.txlite.invalid", ECHConfig: base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")), CertPin: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	s := link.String()
	got, err := Parse(s)
	if err != nil || got.Host != "2001:db8::1" || got.Port != 443 {
		t.Fatal("IPv6 link did not round trip", s, err)
	}
	for _, bad := range []string{"", "vless://x@1.2.3.4:1", s[:len(s)-40], "txlite://short@1.2.3.4:443?sni=a&ech=AAAAAAAAAAA&pin=x"} {
		if _, err := Parse(bad); err == nil {
			t.Fatal("accepted broken link", bad)
		}
	}
}
