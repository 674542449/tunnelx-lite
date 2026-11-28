package lite

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/674542449/tunnelx-lite/internal/share"
	"github.com/674542449/tunnelx-lite/internal/vless"
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
	if status["name"] != "测试服务器" || status["ipv6"] != "2001:db8::5" || status["reality_enabled"] != true || status["reality_sni"] != vless.DefaultRealitySNI {
		t.Fatal("status incomplete", status)
	}

	var links []ShareLink
	res, _ = cl.Get(base + "api/links")
	json.NewDecoder(res.Body).Decode(&links)
	res.Body.Close()
	if len(links) != 6 || links[0].Protocol != "txlite" || links[2].Protocol != "txpulse" || links[4].Protocol != "vless" {
		t.Fatal("expected IPv4/IPv6 Vision, TXPulse and iOS VLESS/REALITY links", links)
	}
	old, err := share.Parse(links[0].URL)
	if err != nil || old.Host != "203.0.113.5" || old.Port != 18443 || old.IsPulse() {
		t.Fatal("Vision link does not describe this server", links[0].URL, err)
	}
	oldPulse, err := share.Parse(links[2].URL)
	if err != nil || oldPulse.Host != "203.0.113.5" || !oldPulse.IsPulse() || oldPulse.ObfsKey == "" {
		t.Fatal("TXPulse link does not describe this server", links[2].URL, err)
	}
	oldVless, err := url.Parse(links[4].URL)
	if err != nil || oldVless.Scheme != "vless" || oldVless.Host != "203.0.113.5:18443" {
		t.Fatal("VLESS/REALITY link invalid", links[4].URL, err)
	}
	if q := oldVless.Query(); q.Get("security") != "reality" || q.Get("flow") != vless.FlowVision || q.Get("sni") != vless.DefaultRealitySNI || q.Get("pbk") == "" || q.Get("sid") == "" {
		t.Fatal("VLESS/REALITY query incomplete", links[4].URL)
	}
	if res, _ := cl.Get(base + "api/qr?i=4"); res.StatusCode != 200 || res.Header.Get("Content-Type") != "image/png" {
		t.Fatal("QR code for vless:// unavailable")
	}

	call(t, cl, "POST", base+"api/settings", map[string]any{"name": "bad#name", "port": 18443, "outbound_ip": "ipv4", "bandwidth_mbps": 0, "hosts": []string{}}, 400)
	call(t, cl, "POST", base+"api/settings", map[string]any{"name": "新名称", "port": 18443, "outbound_ip": "prefer_ipv6", "bandwidth_mbps": 10, "hosts": []string{"vpn.example.com"}}, 400)
	call(t, cl, "POST", base+"api/settings", map[string]any{"name": "新名称", "port": 18443, "pulse_hop": "20000-20999", "outbound_ip": "ipv4", "bandwidth_mbps": 10, "hosts": []string{"vpn.example.com"}}, 400)
	call(t, cl, "POST", base+"api/settings", map[string]any{"name": "新名称", "port": 18443, "reality_sni": "1.1.1.1", "outbound_ip": "ipv4", "bandwidth_mbps": 10, "hosts": []string{"vpn.example.com"}}, 400)
	out := call(t, cl, "POST", base+"api/settings", map[string]any{"name": "新名称", "port": 18443, "pulse_hop": "20000-20015", "reality_enabled": true, "reality_sni": "https://updates.cdn-apple.com/", "outbound_ip": "ipv4", "bandwidth_mbps": 10, "hosts": []string{"vpn.example.com"}}, 200)
	if out["restart"] != true {
		t.Fatal("settings changes must restart the proxy")
	}
	saved, _ := Load(r.Dir)
	if saved.OutboundIP != "ipv4" || saved.BandwidthLimit != 1250000 || saved.Hosts[0] != "vpn.example.com" || saved.PulseHopStart != 20000 || saved.PulseHopEnd != 20015 || saved.RealitySNI != "updates.cdn-apple.com" || !saved.IsRealityEnabled() {
		t.Fatal("settings not persisted or outbound not locked to ipv4", saved)
	}

	call(t, cl, "POST", base+"api/token/reset", map[string]any{}, 200)
	res, _ = cl.Get(base + "api/links")
	links = nil
	json.NewDecoder(res.Body).Decode(&links)
	res.Body.Close()
	if len(links) != 3 {
		t.Fatal("expected 3 custom-host links (Vision + TXPulse + VLESS)", links)
	}
	fresh, _ := share.Parse(links[0].URL)
	freshPulse, _ := share.Parse(links[1].URL)
	freshVless, _ := url.Parse(links[2].URL)
	if fresh.Host != "vpn.example.com" || fresh.Token == old.Token || !freshPulse.IsPulse() || freshPulse.ObfsKey == oldPulse.ObfsKey || freshPulse.HopStart != 20000 {
		t.Fatal("key reset or custom host not reflected in Vision + TXPulse links", links)
	}
	if freshVless.User.Username() == oldVless.User.Username() || freshVless.Query().Get("pbk") == oldVless.Query().Get("pbk") || freshVless.Query().Get("sid") == oldVless.Query().Get("sid") || freshVless.Query().Get("sni") != "updates.cdn-apple.com" {
		t.Fatal("key reset or custom SNI not reflected in VLESS/REALITY link", links[2].URL)
	}

	// 关闭 iOS REALITY 后分享链接不再输出 vless://
	disableOut := call(t, cl, "POST", base+"api/settings", map[string]any{"name": "新名称", "port": 18443, "pulse_hop": "20000-20015", "reality_enabled": false, "reality_sni": "updates.cdn-apple.com", "outbound_ip": "ipv4", "bandwidth_mbps": 10, "hosts": []string{"vpn.example.com"}}, 200)
	if disableOut["restart"] != true {
		t.Fatal("toggling REALITY must restart the proxy")
	}
	res, _ = cl.Get(base + "api/links")
	links = nil
	json.NewDecoder(res.Body).Decode(&links)
	res.Body.Close()
	if len(links) != 2 {
		t.Fatal("expected VLESS link hidden when REALITY disabled", links)
	}

	call(t, cl, "POST", base+"api/password", map[string]string{"current": "wrong-password", "new": "another-password"}, 400)
	call(t, cl, "POST", base+"api/password", map[string]string{"current": password, "new": "another-password"}, 200)
	if c, _ := Load(r.Dir); !CheckPassword(c.PanelHash, "another-password") {
		t.Fatal("password not changed")
	}
	call(t, cl, "POST", base+"api/logout", map[string]any{}, 200)
	call(t, cl, "GET", base+"api/status", nil, 401)
}

func TestLegacyUpgradeAutoProvisionsRealityIdentity(t *testing.T) {
	detectIPs = func(context.Context) (string, string) { return "203.0.113.5", "" }
	d := Dir(t.TempDir())
	c, _, err := Init(d, "旧版节点", 18543, 18544)
	if err != nil {
		t.Fatal(err)
	}
	// 模拟 v0.6.x 遗留配置（不含任何 REALITY 字段）
	c.RealityEnabled = nil
	c.RealityUUID = ""
	c.RealityPrivateKey = ""
	c.RealityShortID = ""
	c.RealitySNI = ""
	if err := Save(d, c); err != nil {
		t.Fatal(err)
	}
	r, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	got := r.config()
	if !got.IsRealityEnabled() || got.RealityUUID == "" || got.RealityPrivateKey == "" || got.RealityShortID == "" || got.RealitySNI != vless.DefaultRealitySNI {
		t.Fatalf("Open() did not auto-provision REALITY identity: %+v", got)
	}
}
