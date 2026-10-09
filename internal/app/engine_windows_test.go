package app

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/674542449/tunnelx-lite/internal/config"
	"github.com/674542449/tunnelx-lite/internal/pki"
	"github.com/674542449/tunnelx-lite/internal/routing"
	"github.com/674542449/tunnelx-lite/internal/server"
	"github.com/674542449/tunnelx-lite/internal/share"
)

func freeAddr(t *testing.T) string {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().String()
}

func testServer(t *testing.T, allowed string) share.Link {
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
	s, err := server.New(config.Server{Listen: listen, CertFile: filepath.Join(dir, "c.pem"), KeyFile: filepath.Join(dir, "k.pem"), ECHKeyFile: filepath.Join(dir, "e.json"), InnerName: inner, InnerCertFile: filepath.Join(dir, "c.pem"), InnerKeyFile: filepath.Join(dir, "k.pem"), Tokens: []string{token}, AllowedPrivateTargets: []string{allowed}})
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
	return share.Link{Name: "测试", Host: "127.0.0.1", Port: p, Token: token, ServerName: inner, ECHConfig: base64.StdEncoding.EncodeToString(list), CertPin: config.CertPin(leaf)}
}

func TestImportConnectProxyAndWrongKey(t *testing.T) {
	site := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello txlite") })}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go site.Serve(ln)
	defer site.Close()
	link := testServer(t, ln.Addr().String())

	e, err := New(t.TempDir(), Settings{SOCKS: freeAddr(t), HTTP: freeAddr(t), Web: freeAddr(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, _, err = e.Import("随便一段文字"); err == nil {
		t.Fatal("text without a link was imported")
	}
	added, _, err := e.Import("  " + link.String() + "\n")
	if err != nil || added != 1 {
		t.Fatal("import failed", added, err)
	}
	if _, updated, _ := e.Import(link.String()); updated != 1 || len(e.Servers()) != 1 {
		t.Fatal("re-importing the same link created a duplicate")
	}
	id := e.Servers()[0].ID
	if strings.Contains(e.Servers()[0].Name+e.Servers()[0].Host, link.Token) {
		t.Fatal("token leaked into the UI view")
	}
	if err = e.SaveProxyMode(routing.Global, ""); err != nil {
		t.Fatal(err)
	}
	if ms, err := e.Probe(id); err != nil || ms <= 0 {
		t.Fatal("probe failed", ms, err)
	}
	if err = e.Connect(id, false); err != nil {
		t.Fatal(err)
	}
	proxyURL, _ := url.Parse("http://" + e.Settings().HTTP)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 10 * time.Second}
	res, err := c.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "hello txlite" {
		t.Fatal("unexpected body through proxy", string(body))
	}
	if st := e.Status(); st["connection_state"] != "connected" || st["ech"] != true {
		t.Fatal("status does not report an ECH connection", st)
	}
	if err = e.Disconnect(); err != nil {
		t.Fatal(err)
	}

	wrong := link
	tok := make([]byte, 32)
	rand.Read(tok)
	wrong.Token = base64.RawURLEncoding.EncodeToString(tok)
	wrong.Name = "旧密钥"
	e.Import(wrong.String())
	var wrongID string
	for _, s := range e.Servers() {
		if s.Name == "旧密钥" {
			wrongID = s.ID
		}
	}
	err = e.Connect(wrongID, false)
	if err == nil || !strings.Contains(err.Error(), "密钥认证失败") {
		t.Fatal("wrong key must report an authentication failure", err)
	}
	if e.Remove(wrongID) != nil || len(e.Servers()) != 1 {
		t.Fatal("remove failed")
	}

	// A second engine on the same directory reads the DPAPI-protected list back.
	again, err := New(e.root, e.Settings())
	if err != nil || len(again.Servers()) != 1 || again.startupWarning != "" {
		t.Fatal("server list did not survive a restart", err, again.startupWarning)
	}
}
