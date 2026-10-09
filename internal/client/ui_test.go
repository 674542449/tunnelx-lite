package client

import (
	"bytes"
	"encoding/base64"
	"github.com/674542449/tunnelx-lite/internal/config"
	"github.com/674542449/tunnelx-lite/internal/systemproxy"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlAPIHostAndCSRF(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{71}, 32))
	m, e := New(config.Client{ServerName: "proxy.test", ServerIP: "127.0.0.1", Port: 8443, Token: token})
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	u := &UI{Mux: m, Proxy: &systemproxy.Manager{Path: filepath.Join(t.TempDir(), "state.json")}, host: m.Config.WebListen, csrf: "test-request-nonce"}
	cases := []struct {
		name, host, origin, csrf string
		status                   int
	}{
		{"foreign host", "evil.example", "http://" + u.host, u.csrf, 403},
		{"missing origin", u.host, "", u.csrf, 403},
		{"foreign origin", u.host, "https://evil.example", u.csrf, 403},
		{"missing nonce", u.host, "http://" + u.host, "", 403},
		{"wrong nonce", u.host, "http://" + u.host, "incorrect", 403},
		{"authorized", u.host, "http://" + u.host, u.csrf, 404},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://"+u.host+"/api/mode", strings.NewReader(`{"mode":"h2"}`))
			r.Host = c.host
			r.Header.Set("Origin", c.origin)
			r.Header.Set("X-CSRF-Token", c.csrf)
			w := httptest.NewRecorder()
			u.ServeHTTP(w, r)
			if w.Code != c.status {
				t.Fatalf("status %d", w.Code)
			}
			if c.status == 403 && m.Mode() != "h2" {
				t.Fatal("rejected request changed transport")
			}
		})
	}
	r := httptest.NewRequest("GET", "http://"+u.host+"/api/status", nil)
	w := httptest.NewRecorder()
	u.ServeHTTP(w, r)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), token) {
		t.Fatal("status leaked credential or failed")
	}
}
