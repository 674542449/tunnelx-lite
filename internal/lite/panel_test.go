package lite

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/674542449/tunnelx-lite/internal/share"
)

func panelFixture(t *testing.T) (*Runtime, *httptest.Server, *http.Client, string, string) {
	detectIPs = func(context.Context) (string, string) { return "203.0.113.5", "2001:db8::5" }
	d := Dir(t.TempDir())
	c, password, err := Init(d, "测试服务器", 18443, 18444)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	r.Restart = func() {}
	s := httptest.NewTLSServer(r)
	t.Cleanup(s.Close)
	jar, _ := cookiejar.New(nil)
	cl := s.Client()
	cl.Jar = jar
	return r, s, cl, s.URL + "/" + c.PanelPath + "/", password
}

func call(t *testing.T, cl *http.Client, method, url string, body any, status int) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, url, &buf)
	if method == "POST" {
		req.Header.Set("X-TXL", "1")
	}
	res, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d", method, url, res.StatusCode, status)
	}
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	return out
}

func TestPanelLoginSettingsAndKeyReset(t *testing.T) {
	r, s, cl, base, password := panelFixture(t)
	res, _ := cl.Get(s.URL + "/")
	if res.StatusCode != 404 {
		t.Fatal("panel path is discoverable at /")
	}
	call(t, cl, "GET", base+"api/status", nil, 401)
	req, _ := http.NewRequest("POST", base+"api/login", strings.NewReader(`{"password":"`+password+`"}`))
	if res, _ := cl.Do(req); res.StatusCode != 403 {
		t.Fatal("POST without the panel header was accepted")
	}
	for i := 0; i < 5; i++ {
		call(t, cl, "POST", base+"api/login", map[string]string{"password": "wrong-password"}, 401)
	}
	call(t, cl, "POST", base+"api/login", map[string]string{"password": password}, 429)
	r.auth.failures = map[string][]time.Time{}
	call(t, cl, "POST", base+"api/login", map[string]string{"password": password}, 200)
	status := call(t, cl, "GET", base+"api/status", nil, 200)
	if status["name"] != "测试服务器" || status["ipv6"] != "2001:db8::5" {
		t.Fatal("status incomplete", status)
	}

	var links []ShareLink
	res, _ = cl.Get(base + "api/links")
	json.NewDecoder(res.Body).Decode(&links)
	res.Body.Close()
	if len(links) != 2 || links[0].Label != "IPv4" || links[1].Label != "IPv6" {
		t.Fatal("expected IPv4 and IPv6 links", links)
	}
	old, err := share.Parse(links[0].URL)
	if err != nil || old.Host != "203.0.113.5" || old.Port != 18443 {
		t.Fatal("link does not describe this server", links[0].URL, err)
	}
	if res, _ := cl.Get(base + "api/qr?i=1"); res.StatusCode != 200 || res.Header.Get("Content-Type") != "image/png" {
		t.Fatal("QR code unavailable")
	}

	call(t, cl, "POST", base+"api/settings", map[string]any{"name": "bad#name", "port": 18443, "outbound_ip": "", "bandwidth_mbps": 0, "hosts": []string{}}, 400)
	out := call(t, cl, "POST", base+"api/settings", map[string]any{"name": "新名称", "port": 18443, "outbound_ip": "prefer_ipv6", "bandwidth_mbps": 10, "hosts": []string{"vpn.example.com"}}, 200)
	if out["restart"] != true {
		t.Fatal("outbound and speed changes must restart the proxy")
	}
	saved, _ := Load(r.Dir)
	if saved.OutboundIP != "prefer_ipv6" || saved.BandwidthLimit != 1250000 || saved.Hosts[0] != "vpn.example.com" {
		t.Fatal("settings not persisted", saved)
	}

	call(t, cl, "POST", base+"api/token/reset", map[string]any{}, 200)
	res, _ = cl.Get(base + "api/links")
	links = nil
	json.NewDecoder(res.Body).Decode(&links)
	res.Body.Close()
	fresh, _ := share.Parse(links[0].URL)
	if len(links) != 1 || fresh.Host != "vpn.example.com" || fresh.Token == old.Token {
		t.Fatal("key reset or custom host not reflected in links", links)
	}

	call(t, cl, "POST", base+"api/password", map[string]string{"current": "wrong-password", "new": "another-password"}, 400)
	call(t, cl, "POST", base+"api/password", map[string]string{"current": password, "new": "another-password"}, 200)
	if c, _ := Load(r.Dir); !CheckPassword(c.PanelHash, "another-password") {
		t.Fatal("password not changed")
	}
	call(t, cl, "POST", base+"api/logout", map[string]any{}, 200)
	call(t, cl, "GET", base+"api/status", nil, 401)
}
