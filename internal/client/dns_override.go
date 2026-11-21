package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DNSConfig controls split-horizon anti-pollution DNS override.
// Domestic upstreams resolve mainland CN domains directly over encrypted DoH
// (default: Alibaba Public DNS 223.5.5.5/223.6.6.6 + DNSPod 1.12.12.12) to
// avoid ISP UDP/53 hijacking while preserving fast domestic CDN IPs.
// Remote upstreams always travel inside the encrypted proxy tunnel.
type DNSConfig struct {
	Enabled  bool
	Domestic []string
	Remote   []string
}

var (
	DefaultDomesticDNS = []string{
		"https://223.5.5.5/dns-query",
		"https://223.6.6.6/dns-query",
		"https://1.12.12.12/dns-query",
	}
	DefaultRemoteDNS = []string{
		"1.1.1.1:53",
		"8.8.8.8:53",
		"https://1.1.1.1/dns-query",
		"https://8.8.8.8/dns-query",
	}
)

// wellKnownDoH maps popular DoH hostnames to literal bootstrap IPs so DoH
// works inside TUN mode without circular system DNS lookups.
var wellKnownDoH = map[string]struct {
	ips []string
	sni string
}{
	"dns.alidns.com":     {ips: []string{"223.5.5.5", "223.6.6.6"}, sni: "dns.alidns.com"},
	"223.5.5.5":          {ips: []string{"223.5.5.5"}, sni: "223.5.5.5"},
	"223.6.6.6":          {ips: []string{"223.6.6.6"}, sni: "223.6.6.6"},
	"doh.pub":            {ips: []string{"1.12.12.12", "120.53.53.53"}, sni: "doh.pub"},
	"sm2.doh.pub":        {ips: []string{"1.12.12.12", "120.53.53.53"}, sni: "sm2.doh.pub"},
	"1.12.12.12":         {ips: []string{"1.12.12.12"}, sni: "1.12.12.12"},
	"120.53.53.53":       {ips: []string{"120.53.53.53"}, sni: "120.53.53.53"},
	"doh.360.cn":         {ips: []string{"101.226.4.6", "218.30.118.6"}, sni: "doh.360.cn"},
	"cloudflare-dns.com": {ips: []string{"1.1.1.1", "1.0.0.1"}, sni: "cloudflare-dns.com"},
	"one.one.one.one":    {ips: []string{"1.1.1.1", "1.0.0.1"}, sni: "one.one.one.one"},
	"1.1.1.1":            {ips: []string{"1.1.1.1"}, sni: "cloudflare-dns.com"},
	"1.0.0.1":            {ips: []string{"1.0.0.1"}, sni: "cloudflare-dns.com"},
	"dns.google":         {ips: []string{"8.8.8.8", "8.8.4.4"}, sni: "dns.google"},
	"8.8.8.8":            {ips: []string{"8.8.8.8"}, sni: "dns.google"},
	"8.8.4.4":            {ips: []string{"8.8.4.4"}, sni: "dns.google"},
	"dns.quad9.net":      {ips: []string{"9.9.9.9", "149.112.112.112"}, sni: "dns.quad9.net"},
	"9.9.9.9":            {ips: []string{"9.9.9.9"}, sni: "dns.quad9.net"},
}

// ParseDNSUpstreams validates and normalizes a list of DoH URLs or IP[:port] servers.
func ParseDNSUpstreams(list []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, raw := range list {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if len(out) >= 8 {
			return nil, errors.New("最多配置 8 个 DNS 上游服务器")
		}
		norm, err := normalizeDNSUpstream(s)
		if err != nil {
			return nil, err
		}
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	return out, nil
}

func normalizeDNSUpstream(s string) (string, error) {
	if strings.HasPrefix(strings.ToLower(s), "https://") {
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			return "", errors.New("DoH 地址格式无效，请使用如 https://223.5.5.5/dns-query")
		}
		if u.Path == "" {
			u.Path = "/dns-query"
		}
		host := strings.ToLower(u.Hostname())
		if _, err := netip.ParseAddr(host); err != nil {
			if _, ok := wellKnownDoH[host]; !ok {
				// Allow other valid hostnames for non-TUN or fallback resolution,
				// while checking basic hostname characters.
				if strings.ContainsAny(host, " /\\:@?#\r\n\t*") {
					return "", errors.New("DoH 域名格式无效：" + s)
				}
			}
		}
		return u.String(), nil
	}
	if strings.Contains(s, "://") {
		return "", errors.New("仅支持 https:// (DoH) 或纯 IP[:端口] 格式的 DNS 服务器")
	}
	if addr, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return net.JoinHostPort(addr.Unmap().String(), "53"), nil
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", errors.New("DNS 服务器地址无效：" + s)
	}
	addr, err := netip.ParseAddr(h)
	if err != nil {
		return "", errors.New("明文 DNS 必须填写 IP 地址，或使用 https:// DoH 地址：" + s)
	}
	port, err := net.LookupPort("tcp", p)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("DNS 端口无效：" + s)
	}
	return net.JoinHostPort(addr.Unmap().String(), p), nil
}

func (p *Proxy) SetDNSConfig(cfg DNSConfig) {
	cp := DNSConfig{
		Enabled:  cfg.Enabled,
		Domestic: append([]string(nil), cfg.Domestic...),
		Remote:   append([]string(nil), cfg.Remote...),
	}
	p.dnsCfg.Store(&cp)
	p.FlushDNSCache()
}

func (p *Proxy) getDNSConfig() DNSConfig {
	if c := p.dnsCfg.Load(); c != nil {
		return *c
	}
	return DNSConfig{Enabled: true}
}

func (p *Proxy) domesticUpstreams() []string {
	cfg := p.getDNSConfig()
	if len(cfg.Domestic) > 0 {
		return cfg.Domestic
	}
	return DefaultDomesticDNS
}

func (p *Proxy) remoteUpstreams() []string {
	cfg := p.getDNSConfig()
	if len(cfg.Remote) > 0 {
		return cfg.Remote
	}
	return DefaultRemoteDNS
}

func (p *Proxy) directHTTPClient() *http.Client {
	p.directDoHMu.Lock()
	defer p.directDoHMu.Unlock()
	if p.directDoHClient != nil {
		return p.directDoHClient
	}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err == nil {
				if wk, ok := wellKnownDoH[strings.ToLower(host)]; ok && len(wk.ips) > 0 {
					addr = net.JoinHostPort(wk.ips[0], port)
				}
			}
			return p.directDialer(3*time.Second).DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 3 * time.Second,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
	}
	p.directDoHClient = &http.Client{Transport: tr}
	return p.directDoHClient
}

func (p *Proxy) resetDirectDoHClient() {
	p.directDoHMu.Lock()
	c := p.directDoHClient
	p.directDoHClient = nil
	p.directDoHMu.Unlock()
	if c != nil {
		if tr, ok := c.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
}

func (p *Proxy) queryDirectDoH(ctx context.Context, rawURL string, query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	res, err := p.directHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("domestic DoH status")
	}
	if !strings.EqualFold(strings.TrimSpace(strings.Split(res.Header.Get("Content-Type"), ";")[0]), "application/dns-message") {
		return nil, errors.New("invalid domestic DoH media type")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 65536))
	if len(data) >= 65536 {
		return nil, errors.New("domestic DoH response too large")
	}
	return data, err
}

func (p *Proxy) queryRemoteUpstream(ctx context.Context, upstream string, query []byte) ([]byte, error) {
	if strings.HasPrefix(strings.ToLower(upstream), "https://") {
		u, err := url.Parse(upstream)
		if err != nil {
			return nil, err
		}
		host := strings.ToLower(u.Hostname())
		ip := host
		sni := host
		if wk, ok := wellKnownDoH[host]; ok {
			ip = wk.ips[0]
			sni = wk.sni
		}
		path := u.RequestURI()
		if path == "" {
			path = "/dns-query"
		}
		return p.tunnelHTTPS(ctx, ip, sni, path, query)
	}
	return p.queryDNS(ctx, upstream, query)
}

// LookupDomesticIPs resolves host via the configured encrypted domestic DoH
// upstreams (default: AliDNS 223.5.5.5 / 223.6.6.6 + DNSPod 1.12.12.12).
// Used by Bypass CN Router.Lookup and non-TUN direct dials to defeat ISP UDP/53 hijacking.
func (p *Proxy) LookupDomesticIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	fqdn := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".") + "."
	name, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x5458, RecursionDesired: true})
	b.StartQuestions()
	q := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	if err = b.Question(q); err != nil {
		return nil, err
	}
	query, err := b.Finish()
	if err != nil {
		return nil, err
	}
	h := dnsmessage.Header{ID: 0x5458, RecursionDesired: true}
	ans := p.queryDomesticUpstreams(ctx, h, q, query)
	if len(ans) == 0 {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	ips := extractAnswerIPs(ans)
	if len(ips) == 0 {
		return nil, errors.New("no DNS A records")
	}
	return ips, nil
}

func extractAnswerIPs(answer []byte) []netip.Addr {
	var msg dnsmessage.Message
	if msg.Unpack(answer) != nil || msg.RCode != dnsmessage.RCodeSuccess {
		return nil
	}
	var ips []netip.Addr
	for _, a := range msg.Answers {
		switch body := a.Body.(type) {
		case *dnsmessage.AResource:
			ips = append(ips, netip.AddrFrom4(body.A))
		case *dnsmessage.AAAAResource:
			ips = append(ips, netip.AddrFrom16(body.AAAA).Unmap())
		}
	}
	return ips
}

// allAnswersAreCN reports whether a DNS response contains at least one valid IP
// and every returned IP is inside geoip:cn (used for TUN unknown-domain anti-pollution).
func (p *Proxy) allAnswersAreCN(answer []byte) bool {
	r := p.getRouter()
	if r == nil || r.Rules == nil {
		return false
	}
	ips := extractAnswerIPs(answer)
	if len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		if !r.Rules.MatchIP(ip) {
			return false
		}
	}
	return true
}
