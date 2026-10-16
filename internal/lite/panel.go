package lite

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"rsc.io/qr"
)

//go:embed web/*
var web embed.FS

const sessionCookie = "txl_session"

// detectIPs is replaced in tests to keep them offline.
var detectIPs = PublicIPs

type sessions struct {
	mu       sync.Mutex
	live     map[string]time.Time
	failures map[string][]time.Time
}

func newSessions() sessions {
	return sessions{live: map[string]time.Time{}, failures: map[string][]time.Time{}}
}

func (s *sessions) create() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := randomToken(32)
	s.live[t] = time.Now().Add(12 * time.Hour)
	return t
}

func (s *sessions) valid(t string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.live {
		if time.Now().After(exp) {
			delete(s.live, k)
		}
	}
	for k := range s.live {
		if subtle.ConstantTimeCompare([]byte(k), []byte(t)) == 1 {
			return true
		}
	}
	return false
}

func (s *sessions) keepOnly(t string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.live {
		if k != t {
			delete(s.live, k)
		}
	}
}

func (s *sessions) drop(t string) { s.mu.Lock(); delete(s.live, t); s.mu.Unlock() }

// limited allows 5 failed logins per address per 10 minutes.
func (s *sessions) limited(ip string, failed bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	recent := s.failures[ip][:0]
	for _, t := range s.failures[ip] {
		if time.Since(t) < 10*time.Minute {
			recent = append(recent, t)
		}
	}
	if failed {
		recent = append(recent, time.Now())
	}
	s.failures[ip] = recent
	return len(recent) >= 5
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, msg string) {
	reply(w, status, map[string]string{"error": msg})
}

func (r *Runtime) config() Config { r.mu.Lock(); defer r.mu.Unlock(); return r.cfg }

func (r *Runtime) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	c := r.config()
	prefix := "/" + c.PanelPath + "/"
	if req.URL.Path == strings.TrimSuffix(prefix, "/") {
		http.Redirect(w, req, prefix, http.StatusFound)
		return
	}
	if !strings.HasPrefix(req.URL.Path, prefix) {
		http.NotFound(w, req)
		return
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'")
	sub := strings.TrimPrefix(req.URL.Path, prefix)
	switch sub {
	case "", "app.js", "style.css":
		name := map[string]string{"": "index.html", "app.js": "app.js", "style.css": "style.css"}[sub]
		b, _ := web.ReadFile("web/" + name)
		h.Set("Content-Type", map[string]string{"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "style.css": "text/css; charset=utf-8"}[name])
		w.Write(b)
		return
	}
	if !strings.HasPrefix(sub, "api/") {
		http.NotFound(w, req)
		return
	}
	if req.Method == "POST" && req.Header.Get("X-TXL") != "1" {
		fail(w, 403, "请求来源无效")
		return
	}
	api := strings.TrimPrefix(sub, "api/")
	if api == "login" && req.Method == "POST" {
		r.login(w, req, prefix)
		return
	}
	cookie, e := req.Cookie(sessionCookie)
	if e != nil || !r.auth.valid(cookie.Value) {
		fail(w, 401, "请先登录")
		return
	}
	r.api(w, req, api, cookie.Value, prefix)
}

func clientIP(req *http.Request) string {
	host, _, e := net.SplitHostPort(req.RemoteAddr)
	if e != nil {
		return req.RemoteAddr
	}
	return host
}

func decode(w http.ResponseWriter, req *http.Request, v any) bool {
	d := json.NewDecoder(io.LimitReader(req.Body, 1<<16))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		fail(w, 400, "请求格式无效")
		return false
	}
	return true
}

func (r *Runtime) login(w http.ResponseWriter, req *http.Request, prefix string) {
	ip := clientIP(req)
	if r.auth.limited(ip, false) {
		fail(w, 429, "失败次数过多，请 10 分钟后再试")
		return
	}
	var b struct {
		Password string `json:"password"`
	}
	if !decode(w, req, &b) {
		return
	}
	if !CheckPassword(r.config().PanelHash, b.Password) {
		r.auth.limited(ip, true)
		log.Printf("面板登录失败：%s", ip)
		fail(w, 401, "密码错误")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: r.auth.create(), Path: prefix, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: 12 * 3600})
	reply(w, 200, map[string]bool{"ok": true})
}

type settings struct {
	Name          string   `json:"name"`
	Hosts         []string `json:"hosts"`
	Port          int      `json:"port"`
	Inbound       string   `json:"inbound"`
	OutboundIP    string   `json:"outbound_ip"`
	BandwidthMbps float64  `json:"bandwidth_mbps"`
	QUIC          *bool    `json:"quic,omitempty"` // nil keeps the current setting
}

func (r *Runtime) api(w http.ResponseWriter, req *http.Request, api, session, prefix string) {
	switch {
	case api == "status" && req.Method == "GET":
		c := r.config()
		t := r.Totals()
		ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
		v4, v6 := detectIPs(ctx)
		cancel()
		reply(w, 200, map[string]any{"version": Version, "name": c.Name, "uptime": int64(time.Since(r.started).Seconds()), "active": r.srv.Active.Load(), "uploaded": t.Uploaded, "downloaded": t.Downloaded, "port": c.Port, "panel_port": c.PanelPort, "inbound": c.Inbound, "outbound_ip": c.OutboundIP, "bandwidth_limit": c.BandwidthLimit, "ipv4": v4, "ipv6": v6, "system": systemInfo(), "proxy_error": r.ProxyError(), "quic": !c.NoQUIC, "quic_error": r.QUICError()})
	case api == "links" && req.Method == "GET":
		reply(w, 200, r.links(req.Context()))
	case api == "qr" && req.Method == "GET":
		links := r.links(req.Context())
		i, e := strconv.Atoi(req.URL.Query().Get("i"))
		if e != nil || i < 0 || i >= len(links) {
			http.NotFound(w, req)
			return
		}
		code, e := qr.Encode(links[i].URL, qr.M)
		if e != nil {
			fail(w, 500, "二维码生成失败")
			return
		}
		code.Scale = 6
		w.Header().Set("Content-Type", "image/png")
		w.Write(code.PNG())
	case api == "settings" && req.Method == "GET":
		c := r.config()
		reply(w, 200, settings{Name: c.Name, Hosts: append([]string{}, c.Hosts...), Port: c.Port, Inbound: c.Inbound, OutboundIP: c.OutboundIP, BandwidthMbps: float64(c.BandwidthLimit) / 125000, QUIC: &[]bool{!c.NoQUIC}[0]})
	case api == "settings" && req.Method == "POST":
		r.saveSettings(w, req)
	case api == "token/reset" && req.Method == "POST":
		r.update(w, func(c *Config) bool { c.Token = NewToken(); return true }, "密钥已重置，旧分享链接已失效")
	case api == "password" && req.Method == "POST":
		var b struct {
			Current string `json:"current"`
			New     string `json:"new"`
		}
		if !decode(w, req, &b) {
			return
		}
		if !CheckPassword(r.config().PanelHash, b.Current) {
			fail(w, 400, "当前密码错误")
			return
		}
		hash, e := HashPassword(b.New)
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		r.update(w, func(c *Config) bool { c.PanelHash = hash; return false }, "面板密码已修改")
		r.auth.keepOnly(session)
	case api == "traffic/reset" && req.Method == "POST":
		r.resetTraffic()
		reply(w, 200, map[string]any{"ok": true, "message": "流量统计已清零"})
	case api == "logs" && req.Method == "GET":
		reply(w, 200, r.logs.Lines())
	case api == "restart" && req.Method == "POST":
		reply(w, 200, map[string]any{"ok": true, "restart": true, "message": "服务正在重启"})
		r.scheduleRestart()
	case api == "logout" && req.Method == "POST":
		r.auth.drop(session)
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: prefix, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		reply(w, 200, map[string]bool{"ok": true})
	default:
		fail(w, 404, "接口不存在")
	}
}

func (r *Runtime) links(ctx context.Context) []ShareLink {
	c := r.config()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	v4, v6 := detectIPs(ctx)
	return Links(c, r.id, v4, v6)
}

func (r *Runtime) saveSettings(w http.ResponseWriter, req *http.Request) {
	var b settings
	if !decode(w, req, &b) {
		return
	}
	if math.IsNaN(b.BandwidthMbps) || b.BandwidthMbps < 0 || b.BandwidthMbps > 8589 {
		fail(w, 400, "限速需在 0–8589 Mbps 之间")
		return
	}
	old := r.config()
	// A listener the kernel refuses would leave the proxy down after the
	// restart, so try the new port and address family first.
	network := map[string]string{"ipv4": "tcp4", "ipv6": "tcp6"}[b.Inbound]
	if network == "" {
		network = "tcp"
	}
	if b.Port != old.Port || b.Inbound != old.Inbound {
		addr := ":0"
		if b.Port != old.Port {
			addr = ":" + strconv.Itoa(b.Port)
		}
		l, e := net.Listen(network, addr)
		if e != nil {
			if b.Port != old.Port {
				fail(w, 400, "端口 "+strconv.Itoa(b.Port)+" 已被占用或无权使用")
			} else {
				fail(w, 400, "本机系统不支持所选的入站方式")
			}
			return
		}
		l.Close()
	}
	noQUIC := old.NoQUIC
	if b.QUIC != nil {
		noQUIC = !*b.QUIC
	}
	if !noQUIC && (old.NoQUIC || b.Port != old.Port || b.Inbound != old.Inbound) {
		udp := map[string]string{"ipv4": "udp4", "ipv6": "udp6"}[b.Inbound]
		if udp == "" {
			udp = "udp"
		}
		addr := ":0"
		if b.Port != old.Port || old.NoQUIC {
			addr = ":" + strconv.Itoa(b.Port)
		}
		pc, e := net.ListenPacket(udp, addr)
		if e != nil {
			fail(w, 400, "UDP 端口 "+strconv.Itoa(b.Port)+" 已被占用，无法开启 QUIC")
			return
		}
		pc.Close()
	}
	hosts := []string{}
	for _, h := range b.Hosts {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	// IPv6-only modes on a server without working public IPv6 would cut off
	// every client; refuse them unless the owner supplies their own address.
	if (b.Inbound == "ipv6" && b.Inbound != old.Inbound && len(hosts) == 0) || (b.OutboundIP == "ipv6" && b.OutboundIP != old.OutboundIP) {
		ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
		_, v6 := detectIPs(ctx)
		cancel()
		if v6 == "" {
			fail(w, 400, "没有检测到可用的公网 IPv6，不能设为仅 IPv6；如确有 IPv6，请先在自定义分享地址填写")
			return
		}
	}
	limit := int64(math.Round(b.BandwidthMbps * 125000))
	r.update(w, func(c *Config) bool {
		restart := c.Port != b.Port || c.Inbound != b.Inbound || c.OutboundIP != b.OutboundIP || c.BandwidthLimit != limit || c.NoQUIC != noQUIC
		c.Name, c.Hosts, c.Port, c.Inbound, c.OutboundIP, c.BandwidthLimit, c.NoQUIC = b.Name, hosts, b.Port, b.Inbound, b.OutboundIP, limit, noQUIC
		return restart
	}, "设置已保存")
}

// update validates and saves a change; changes the proxy must reload restart the service.
func (r *Runtime) update(w http.ResponseWriter, change func(*Config) bool, message string) {
	r.mu.Lock()
	next := r.cfg
	next.Hosts = append([]string(nil), r.cfg.Hosts...)
	restart := change(&next)
	e := Save(r.Dir, next)
	if e == nil {
		r.cfg = next
	}
	r.mu.Unlock()
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	log.Print(message)
	if restart {
		message += "，服务将在 2 秒内重启生效"
	}
	reply(w, 200, map[string]any{"ok": true, "restart": restart, "message": message})
	if restart {
		r.scheduleRestart()
	}
}

func (r *Runtime) scheduleRestart() {
	go func() {
		time.Sleep(800 * time.Millisecond)
		r.Restart()
	}()
}
