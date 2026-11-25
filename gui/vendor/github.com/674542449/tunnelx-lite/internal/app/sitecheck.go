package app

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/674542449/tunnelx-lite/internal/client"
	"github.com/674542449/tunnelx-lite/internal/routing"
)

// ExitIPInfo reports the live physical direct IPv4, the proxied node IPv4, and
// whether the node's outbound egress cleanly blocks IPv6 (IPv4-only landing).
type ExitIPInfo struct {
	DirectIP         string `json:"direct_ip,omitempty"`
	DirectError      string `json:"direct_error,omitempty"`
	ProxyIP          string `json:"proxy_ip,omitempty"`
	ProxyError       string `json:"proxy_error,omitempty"`
	ProxyIPv6        string `json:"proxy_ipv6,omitempty"`
	ProxyIPv6Blocked bool   `json:"proxy_ipv6_blocked"`
}

// SiteCheckItem is the live routing + connectivity + exit-IP result for one site.
type SiteCheckItem struct {
	Name       string `json:"name"`
	Category   string `json:"category"` // "ip" | "cn" | "global" | "custom"
	Domain     string `json:"domain"`
	URL        string `json:"url"`
	Route      string `json:"route"`                 // "direct" | "proxy"
	Rule       string `json:"rule"`                  // Human-readable matched rule
	ExitIP     string `json:"exit_ip,omitempty"`     // Returned IP (for IP-echo sites) or verified exit IP
	ExitKind   string `json:"exit_kind,omitempty"`   // "proxy" | "direct" | "other"
	VerifiedIP bool   `json:"verified_ip,omitempty"` // True when ExitIP came directly from the site's HTTP response
	Status     int    `json:"status,omitempty"`
	LatencyMs  int64  `json:"latency_ms,omitempty"`
	OK         bool   `json:"ok"`
	Preview    bool   `json:"preview,omitempty"` // True when disconnected and only showing rule classification
	Error      string `json:"error,omitempty"`
}

// SiteCheckReport aggregates exit IP probes and common-site split-routing checks.
type SiteCheckReport struct {
	CheckedAt int64           `json:"checked_at"`
	Connected bool            `json:"connected"`
	NodeName  string          `json:"node_name,omitempty"`
	ProxyMode string          `json:"proxy_mode"`
	TUNActive bool            `json:"tun_active"`
	Exit      ExitIPInfo      `json:"exit"`
	Items     []SiteCheckItem `json:"items"`
}

type siteTarget struct {
	name     string
	category string
	domain   string
	url      string
	ipEcho   bool
}

var builtinCheckSites = []siteTarget{
	// IP echo sites: parse real returned exit IP directly from HTTP response.
	{name: "IPIP.net（国内测 IP）", category: "ip", domain: "myip.ipip.net", url: "https://myip.ipip.net/ip", ipEcho: true},
	{name: "IPW.cn（国内 IPv4）", category: "ip", domain: "4.ipw.cn", url: "https://4.ipw.cn", ipEcho: true},
	{name: "ipify（海外测 IP）", category: "ip", domain: "api.ipify.org", url: "https://api.ipify.org", ipEcho: true},
	{name: "Cloudflare Trace", category: "ip", domain: "www.cloudflare.com", url: "https://www.cloudflare.com/cdn-cgi/trace", ipEcho: true},
	{name: "IP.SB（海外 IPv4）", category: "ip", domain: "api-ipv4.ip.sb", url: "https://api-ipv4.ip.sb/ip", ipEcho: true},

	// Common domestic websites (expected direct under Bypass CN, proxy under Global).
	{name: "百度", category: "cn", domain: "www.baidu.com", url: "https://www.baidu.com/"},
	{name: "哔哩哔哩", category: "cn", domain: "www.bilibili.com", url: "https://www.bilibili.com/"},
	{name: "淘宝", category: "cn", domain: "www.taobao.com", url: "https://www.taobao.com/"},
	{name: "腾讯网", category: "cn", domain: "www.qq.com", url: "https://www.qq.com/"},
	{name: "网易", category: "cn", domain: "www.163.com", url: "https://www.163.com/"},
	{name: "知乎", category: "cn", domain: "www.zhihu.com", url: "https://www.zhihu.com/"},

	// Common overseas websites (expected proxy under both Bypass CN and Global).
	{name: "Google", category: "global", domain: "www.google.com", url: "https://www.google.com/generate_204"},
	{name: "YouTube", category: "global", domain: "www.youtube.com", url: "https://www.youtube.com/generate_204"},
	{name: "GitHub", category: "global", domain: "github.com", url: "https://github.com/robots.txt"},
	{name: "ChatGPT / OpenAI", category: "global", domain: "chatgpt.com", url: "https://chatgpt.com/robots.txt"},
	{name: "Netflix", category: "global", domain: "www.netflix.com", url: "https://www.netflix.com/robots.txt"},
	{name: "X (Twitter)", category: "global", domain: "x.com", url: "https://x.com/robots.txt"},
	{name: "Telegram", category: "global", domain: "telegram.org", url: "https://telegram.org/robots.txt"},
	{name: "Disney+", category: "global", domain: "www.disneyplus.com", url: "https://www.disneyplus.com/"},
}

var (
	directEchoURLs = []string{
		"https://4.ipw.cn",
		"https://myip.ipip.net/ip",
		"https://api-ipv4.ip.sb/ip",
		"https://ipv4.icanhazip.com",
	}
	proxyEchoURLs = []string{
		"https://api.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://api-ipv4.ip.sb/ip",
		"https://www.cloudflare.com/cdn-cgi/trace",
	}
)

type tunnelNetConn struct {
	t      *client.Tunnel
	remote string
}

func (c tunnelNetConn) Read(b []byte) (int, error)         { return c.t.Read(b) }
func (c tunnelNetConn) Write(b []byte) (int, error)        { return c.t.Write(b) }
func (c tunnelNetConn) Close() error                       { return c.t.Close() }
func (c tunnelNetConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c tunnelNetConn) RemoteAddr() net.Addr               { return dummyAddr(c.remote) }
func (c tunnelNetConn) SetDeadline(t time.Time) error      { return c.t.SetDeadline(t) }
func (c tunnelNetConn) SetReadDeadline(t time.Time) error  { return c.t.SetDeadline(t) }
func (c tunnelNetConn) SetWriteDeadline(t time.Time) error { return c.t.SetDeadline(t) }

type dummyAddr string

func (a dummyAddr) Network() string { return "tcp" }
func (a dummyAddr) String() string  { return string(a) }

func ruleReasonLabel(reason string, direct bool) string {
	switch reason {
	case "global_proxy":
		return "全局代理"
	case "default_proxy":
		return "海外默认代理"
	case "proxy_domain":
		return "海外代理域名"
	case "domain_direct":
		return "大陆/例外域名直连"
	case "ip_direct":
		return "大陆/内网 IP 直连"
	case "resolved_cn_ip":
		return "解析为大陆 IP 直连"
	case "resolved_private_ip", "local_network":
		return "局域网直连"
	default:
		if direct {
			return "直连规则"
		}
		return "代理规则"
	}
}

// extractIPFromBody pulls a valid IP address from common plain-text echo
// services, Cloudflare trace output (`ip=x.x.x.x`), or cip.cc (`IP : x.x.x.x`).
func extractIPFromBody(body string, wantV4, wantV6 bool) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "ip=") {
			line = strings.TrimSpace(line[3:])
		} else if strings.HasPrefix(strings.ToUpper(line), "IP") && strings.Contains(line, ":") {
			if _, after, ok := strings.Cut(line, ":"); ok {
				line = strings.TrimSpace(after)
			}
		}
		for _, tok := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ' ' || r == '\t' || r == ',' || r == ';' || r == '"' || r == '\'' || r == '<' || r == '>'
		}) {
			a, err := netip.ParseAddr(strings.Trim(tok, "[]"))
			if err != nil {
				continue
			}
			a = a.Unmap()
			if a.IsLoopback() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsPrivate() {
				continue
			}
			if a.Is4() && wantV4 {
				return a.String()
			}
			if a.Is6() && wantV6 {
				return a.String()
			}
		}
	}
	return ""
}

func (e *Engine) snapshotCheckEnv() (connected, tunActive bool, nodeName, mode, httpAddr string, mux *client.Mux, liveProxy *client.Proxy, fallbackRouter *routing.Router) {
	e.mu.Lock()
	mux = e.mux
	liveProxy = e.proxy
	connected = mux != nil && liveProxy != nil
	tunActive = liveProxy != nil && liveProxy.TUN
	nodeName = e.nodeName
	mode = e.preferences.ProxyMode
	if mode != routing.Global {
		mode = routing.Bypass
	}
	httpAddr = e.settings.HTTP
	rules := e.rules
	exceptions := joinLines(e.preferences.DirectDomains)
	dnsOn := e.preferences.dnsConfig().Enabled
	e.mu.Unlock()
	if !connected {
		fallbackRouter, _ = buildRouter(mode, rules, exceptions, nil, dnsOn)
	}
	return
}

func (e *Engine) probeExitIPs(ctx context.Context, connected bool, mux *client.Mux, liveProxy *client.Proxy) ExitIPInfo {
	var info ExitIPInfo
	var wg sync.WaitGroup

	// 1. Physical direct IPv4 (always via direct physical uplink, bypassing TUN/proxy).
	wg.Add(1)
	go func() {
		defer wg.Done()
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		dialFn := func(dctx context.Context, _, addr string) (net.Conn, error) {
			if liveProxy != nil {
				return liveProxy.DirectDialContext(dctx, "tcp4", addr)
			}
			return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(dctx, "tcp4", addr)
		}
		ip, err := raceEchoIP(cctx, dialFn, directEchoURLs, true, false)
		if err != nil {
			info.DirectError = shortNetError(err)
		} else {
			info.DirectIP = ip
		}
	}()

	// 2. Node proxied IPv4 + IPv6 landing verification (only when connected).
	if connected && mux != nil {
		wg.Add(2)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
			defer cancel()
			dialFn := func(dctx context.Context, _, addr string) (net.Conn, error) {
				t, err := mux.OpenTCP(dctx, addr)
				if err != nil {
					return nil, err
				}
				return tunnelNetConn{t: t, remote: addr}, nil
			}
			ip, err := raceEchoIP(cctx, dialFn, proxyEchoURLs, true, false)
			if err != nil {
				info.ProxyError = shortNetError(err)
			} else {
				info.ProxyIP = ip
			}
		}()
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			t, err := mux.OpenTCP(cctx, "[2606:4700:4700::1111]:443")
			if err != nil {
				// Expected with IPv4-only server landing: IPv6 egress is blocked.
				info.ProxyIPv6Blocked = true
				return
			}
			_ = t.Close()
			// Older server still has IPv6 egress; best-effort inspect what IPv6 it exposes.
			info.ProxyIPv6Blocked = false
			dialFn := func(dctx context.Context, _, addr string) (net.Conn, error) {
				t, err := mux.OpenTCP(dctx, addr)
				if err != nil {
					return nil, err
				}
				return tunnelNetConn{t: t, remote: addr}, nil
			}
			if v6, err := raceEchoIP(cctx, dialFn, []string{"https://api6.ipify.org", "https://ipv6.icanhazip.com"}, false, true); err == nil {
				info.ProxyIPv6 = v6
			}
		}()
	}

	wg.Wait()
	return info
}

func raceEchoIP(ctx context.Context, dialFn func(context.Context, string, string) (net.Conn, error), urls []string, wantV4, wantV6 bool) (string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         dialFn,
		TLSHandshakeTimeout: 4 * time.Second,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives:   true,
	}
	defer tr.CloseIdleConnections()
	hc := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	type res struct {
		ip  string
		err error
	}
	ch := make(chan res, len(urls))
	for _, raw := range urls {
		go func(u string) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				ch <- res{err: err}
				return
			}
			req.Header.Set("User-Agent", "curl/8.7.1")
			resp, err := hc.Do(req)
			if err != nil {
				ch <- res{err: err}
				return
			}
			b, rerr := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if rerr != nil {
				ch <- res{err: rerr}
				return
			}
			if ip := extractIPFromBody(string(b), wantV4, wantV6); ip != "" {
				ch <- res{ip: ip}
				return
			}
			ch <- res{err: errors.New("未返回有效 IP")}
		}(raw)
	}
	var lastErr error
	for range urls {
		r := <-ch
		if r.ip != "" {
			return r.ip, nil
		}
		if r.err != nil {
			lastErr = r.err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("探测失败")
	}
	return "", lastErr
}

func shortNetError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(s, "timeout") || strings.Contains(s, "Timeout"):
		return "连接超时"
	case strings.Contains(s, "no such host"):
		return "域名解析失败"
	case strings.Contains(s, "connection refused") || strings.Contains(s, "actively refused"):
		return "连接被拒绝"
	case strings.Contains(s, "reset by peer") || strings.Contains(s, "forcibly closed") || strings.Contains(s, "EOF"):
		return "连接被重置"
	case strings.Contains(s, "502") || strings.Contains(s, "Proxy"):
		return "代理转发失败"
	default:
		if len(s) > 64 {
			return s[:64] + "…"
		}
		return s
	}
}

func classifyRoute(ctx context.Context, domain string, liveProxy *client.Proxy, fallbackRouter *routing.Router) (route, rule string) {
	target := net.JoinHostPort(domain, "443")
	var d routing.Decision
	if liveProxy != nil {
		d = liveProxy.RouteDecision(ctx, target)
	} else if fallbackRouter != nil {
		d = fallbackRouter.Decide(ctx, target)
	} else {
		d = routing.Decision{Address: target, Direct: false, Reason: "default_proxy"}
	}
	if d.Direct {
		return "direct", ruleReasonLabel(d.Reason, true)
	}
	return "proxy", ruleReasonLabel(d.Reason, false)
}

func probeSingleSite(ctx context.Context, st siteTarget, connected bool, httpAddr string, liveProxy *client.Proxy, fallbackRouter *routing.Router) SiteCheckItem {
	item := SiteCheckItem{
		Name:     st.name,
		Category: st.category,
		Domain:   st.domain,
		URL:      st.url,
	}
	item.Route, item.Rule = classifyRoute(ctx, st.domain, liveProxy, fallbackRouter)

	// When disconnected, still allow direct connectivity probe for direct-routed
	// targets and return a clean rule preview for proxy-routed targets.
	if !connected && item.Route == "proxy" {
		item.Preview = true
		return item
	}

	tr := &http.Transport{
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 6 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     true,
	}
	if connected && httpAddr != "" {
		if u, err := url.Parse("http://" + httpAddr); err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	} else {
		tr.Proxy = nil
		tr.DialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	defer tr.CloseIdleConnections()

	hc := &http.Client{
		Transport: tr,
		Timeout:   7 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	pctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	method := http.MethodHead
	if st.ipEcho || st.category == "custom" || strings.HasSuffix(st.url, "generate_204") || strings.HasSuffix(st.url, "robots.txt") {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(pctx, method, st.url, nil)
	if err != nil {
		item.Error = shortNetError(err)
		return item
	}
	if st.ipEcho || st.category == "custom" {
		req.Header.Set("User-Agent", "curl/8.7.1")
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	}

	start := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		item.Error = shortNetError(err)
		return item
	}
	var body []byte
	if method == http.MethodGet {
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 4096))
	}
	resp.Body.Close()

	item.LatencyMs = max(1, time.Since(start).Milliseconds())
	item.Status = resp.StatusCode
	item.OK = resp.StatusCode >= 200 && resp.StatusCode < 500
	if !item.OK {
		item.Error = "HTTP " + http.StatusText(resp.StatusCode)
	}
	if len(body) > 0 && (st.ipEcho || st.category == "custom") {
		if ip := extractIPFromBody(string(body), true, true); ip != "" {
			item.ExitIP = ip
			item.VerifiedIP = true
		}
	}
	return item
}

func fillExitKind(item *SiteCheckItem, exit ExitIPInfo) {
	if item.ExitIP == "" {
		if item.Route == "direct" && exit.DirectIP != "" {
			item.ExitIP = exit.DirectIP
		} else if item.Route == "proxy" && exit.ProxyIP != "" {
			item.ExitIP = exit.ProxyIP
		}
	}
	if item.ExitIP == "" {
		return
	}
	switch {
	case exit.ProxyIP != "" && item.ExitIP == exit.ProxyIP:
		item.ExitKind = "proxy"
	case exit.DirectIP != "" && item.ExitIP == exit.DirectIP:
		item.ExitKind = "direct"
	default:
		item.ExitKind = "other"
	}
}

// CheckSites runs live exit IP probes (direct IPv4, node IPv4, IPv6-blocked check)
// alongside concurrent routing & reachability checks across common websites.
func (e *Engine) CheckSites() SiteCheckReport {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	connected, tunActive, nodeName, mode, httpAddr, mux, liveProxy, fallbackRouter := e.snapshotCheckEnv()
	report := SiteCheckReport{
		CheckedAt: time.Now().Unix(),
		Connected: connected,
		NodeName:  nodeName,
		ProxyMode: mode,
		TUNActive: tunActive,
		Items:     make([]SiteCheckItem, len(builtinCheckSites)),
	}

	var exit ExitIPInfo
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		exit = e.probeExitIPs(ctx, connected, mux, liveProxy)
	}()

	sem := make(chan struct{}, 8)
	for i, st := range builtinCheckSites {
		wg.Add(1)
		go func(idx int, target siteTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			report.Items[idx] = probeSingleSite(ctx, target, connected, httpAddr, liveProxy, fallbackRouter)
		}(i, st)
	}
	wg.Wait()

	report.Exit = exit
	for i := range report.Items {
		fillExitKind(&report.Items[i], exit)
	}
	return report
}

// parseCustomCheckTarget accepts a bare domain ("cip.cc"), host:port, or full URL
// ("https://cip.cc/foo") and returns normalized (domain, probeURL).
func parseCustomCheckTarget(raw string) (string, string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", errors.New("请输入要检查的域名或网址")
	}
	probeURL := s
	if !strings.Contains(s, "://") {
		probeURL = "https://" + s
	}
	u, err := url.Parse(probeURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "", "", errors.New("域名或网址格式无效，例如 cip.cc 或 https://www.google.com")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if _, ipErr := netip.ParseAddr(host); ipErr != nil {
		if host, err = routing.Domain(host); err != nil {
			return "", "", err
		}
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return host, u.String(), nil
}

// CheckDomain inspects live routing classification, reachability, and exit IP
// for a single user-entered domain or URL.
func (e *Engine) CheckDomain(raw string) (SiteCheckItem, error) {
	domain, probeURL, err := parseCustomCheckTarget(raw)
	if err != nil {
		return SiteCheckItem{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	connected, _, _, _, httpAddr, mux, liveProxy, fallbackRouter := e.snapshotCheckEnv()
	st := siteTarget{name: domain, category: "custom", domain: domain, url: probeURL}

	var item SiteCheckItem
	var exit ExitIPInfo
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		item = probeSingleSite(ctx, st, connected, httpAddr, liveProxy, fallbackRouter)
	}()
	go func() {
		defer wg.Done()
		exit = e.probeExitIPs(ctx, connected, mux, liveProxy)
	}()
	wg.Wait()

	fillExitKind(&item, exit)
	return item, nil
}
