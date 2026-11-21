// Package routing classifies destinations without changing the H2 wire protocol.
package routing

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
)

const Bypass = "bypass_cn"
const Global = "global"
const TUN = "tun"

//go:embed data/*
var data embed.FS

// Rules follow MetaCubeX meta-rules-dat (the geosite/geoip data shipped with
// Clash Verge Rev). The receiver holds geosite:cn + geoip:cn; private holds
// geosite:private + geoip:private; proxy holds geosite:geolocation-!cn.
type Rules struct {
	suffix, exact map[string]bool
	patterns      []*regexp.Regexp
	prefixes      map[netip.Prefix]bool
	proxy         *Rules
	private       *Rules
}

// ParseList reads Clash domain lists: "+.example.com" (domain and subdomains),
// ".example.com" / "*.example.com" (treated as subdomains too) and
// "example.com" (exact). Addresses are CIDR prefixes.
func ParseList(domains, addresses []byte) (*Rules, error) {
	var converted strings.Builder
	s := bufio.NewScanner(strings.NewReader(string(domains)))
	s.Buffer(make([]byte, 64<<10), 1<<20)
	for s.Scan() {
		v := strings.TrimSpace(s.Text())
		switch {
		case v == "" || strings.HasPrefix(v, "#"):
			continue
		case strings.HasPrefix(v, "+."):
			converted.WriteString("domain:" + v[2:])
		case strings.HasPrefix(v, "*."):
			converted.WriteString("domain:" + v[2:])
		case strings.HasPrefix(v, "."):
			converted.WriteString("domain:" + v[1:])
		default:
			converted.WriteString("full:" + v)
		}
		converted.WriteByte('\n')
	}
	if e := s.Err(); e != nil {
		return nil, e
	}
	return Parse([]byte(converted.String()), addresses)
}

func ValidMode(s string) bool { return s == Bypass || s == Global || s == TUN }
func Domain(s string) (string, error) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	var err error
	if strings.IndexFunc(s, func(c rune) bool { return c > 127 }) >= 0 {
		s, err = idna.Lookup.ToASCII(s)
	}
	if err != nil || s == "" || len(s) > 253 || strings.ContainsAny(s, " /\\:#?@\r\n\t*") {
		return "", errors.New("请输入域名，不要包含协议、端口或路径")
	}
	for _, part := range strings.Split(s, ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return "", errors.New("域名格式无效")
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", errors.New("域名格式无效")
			}
		}
	}
	return s, nil
}
func Parse(domains, addresses []byte) (*Rules, error) {
	r := &Rules{suffix: map[string]bool{}, exact: map[string]bool{}, prefixes: map[netip.Prefix]bool{}}
	s := bufio.NewScanner(strings.NewReader(string(domains)))
	for s.Scan() {
		v := strings.TrimSpace(s.Text())
		if v == "" || strings.HasPrefix(v, "#") {
			continue
		}
		if strings.HasPrefix(v, "regexp:") {
			p, e := regexp.Compile(strings.TrimPrefix(v, "regexp:"))
			if e != nil {
				return nil, e
			}
			r.patterns = append(r.patterns, p)
			continue
		}
		full := strings.HasPrefix(v, "full:")
		v = strings.TrimPrefix(strings.TrimPrefix(v, "full:"), "domain:")
		d, e := Domain(v)
		if e != nil {
			return nil, fmt.Errorf("routing domain %q: %w", v, e)
		}
		if full {
			r.exact[d] = true
		} else {
			r.suffix[d] = true
		}
	}
	if e := s.Err(); e != nil {
		return nil, e
	}
	s = bufio.NewScanner(strings.NewReader(string(addresses)))
	for s.Scan() {
		v := strings.TrimSpace(s.Text())
		if v == "" || strings.HasPrefix(v, "#") {
			continue
		}
		p, e := netip.ParsePrefix(v)
		if e != nil {
			return nil, e
		}
		if p.Bits() == 0 {
			return nil, errors.New("refusing catch-all IP rule")
		}
		r.prefixes[p.Masked()] = true
	}
	return r, s.Err()
}
func (r *Rules) MatchDomain(s string) bool {
	return r.MatchDomainDepth(s) > 0
}

// MatchDomainDepth returns the specificity of the longest matching domain rule:
// exact matches score len(domain)+1, suffix matches score len(suffix), regex
// matches score 1, and misses return 0. Comparing depths lets a more specific
// subdomain rule (e.g. cn.bing.com in geosite:cn) win over a broader parent
// rule (e.g. bing.com in geosite:geolocation-!cn) and vice versa.
func (r *Rules) MatchDomainDepth(s string) int {
	if r == nil {
		return 0
	}
	d, e := Domain(s)
	if e != nil {
		return 0
	}
	if r.exact[d] {
		return len(d) + 1
	}
	for v := d; v != ""; {
		if r.suffix[v] {
			return len(v)
		}
		i := strings.IndexByte(v, '.')
		if i < 0 {
			break
		}
		v = v[i+1:]
	}
	for _, p := range r.patterns {
		if p.MatchString(d) {
			return 1
		}
	}
	return 0
}
func (r *Rules) MatchIP(a netip.Addr) bool {
	if r == nil {
		return false
	}
	a = a.Unmap()
	for bits := a.BitLen(); bits > 0; bits-- {
		if r.prefixes[netip.PrefixFrom(a, bits).Masked()] {
			return true
		}
	}
	return false
}

var builtOnce sync.Once
var built *Rules
var builtErr error

func Builtin() (*Rules, error) {
	builtOnce.Do(func() {
		files := map[string][]byte{}
		for _, name := range ruleFiles {
			files[name], _ = data.ReadFile("data/" + name)
		}
		built, builtErr = assemble(files)
	})
	return built, builtErr
}

// ruleFiles are the meta-rules-dat lists, bundled under data/ and downloaded by Download.
var ruleFiles = []string{"geosite-cn.list", "geosite-geolocation-not-cn.list", "geosite-private.list", "geoip-cn.list", "geoip-private.list"}

func assemble(files map[string][]byte) (*Rules, error) {
	r, e := ParseList(files["geosite-cn.list"], files["geoip-cn.list"])
	if e != nil {
		return nil, e
	}
	if r.private, e = ParseList(files["geosite-private.list"], files["geoip-private.list"]); e != nil {
		return nil, e
	}
	if r.proxy, e = ParseList(files["geosite-geolocation-not-cn.list"], nil); e != nil {
		return nil, e
	}
	if len(r.suffix) < 1000 || len(r.prefixes) < 1000 || len(r.proxy.suffix)+len(r.proxy.exact) < 100 || len(r.private.prefixes) < 5 {
		return nil, errors.New("规则数量异常，保留原有规则")
	}
	return r, nil
}
func Metadata() any {
	b, _ := data.ReadFile("data/manifest.json")
	var v any
	json.Unmarshal(b, &v)
	return v
}
func ParseExceptions(text string) (*Rules, []string, error) {
	if len(text) > 32768 {
		return nil, nil, errors.New("直连例外过长")
	}
	var domains, ips strings.Builder
	var normalized []string
	for _, s := range strings.FieldsFunc(text, func(c rune) bool { return c == '\n' || c == '\r' || c == ',' }) {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if len(normalized) >= 256 {
			return nil, nil, errors.New("最多添加 256 条直连例外")
		}
		if p, e := netip.ParsePrefix(s); e == nil {
			if p.Bits() == 0 {
				return nil, nil, errors.New("不能把全部 IP 添加为直连例外")
			}
			s = p.Masked().String()
			ips.WriteString(s + "\n")
		} else if a, e := netip.ParseAddr(s); e == nil {
			s = netip.PrefixFrom(a, a.BitLen()).String()
			ips.WriteString(s + "\n")
		} else {
			var e error
			s, e = Domain(strings.TrimPrefix(s, "*."))
			if e != nil {
				return nil, nil, e
			}
			domains.WriteString(s + "\n")
		}
		normalized = append(normalized, s)
	}
	r, e := Parse([]byte(domains.String()), []byte(ips.String()))
	return r, normalized, e
}

type Decision struct {
	Direct          bool
	Address, Reason string
}
type cached struct {
	direct bool
	reason string
	until  time.Time
}
type Router struct {
	Rules, Exceptions *Rules
	Global            bool // When true, only local/private targets and explicit exceptions go direct.
	Lookup            func(context.Context, string) ([]netip.Addr, error)
	mu                sync.Mutex
	cache             map[string]cached
}

var (
	cgnatPrefix  = netip.MustParsePrefix("100.64.0.0/10")
	fakeIPPrefix = netip.MustParsePrefix("198.18.0.0/15")
	docPrefix1   = netip.MustParsePrefix("192.0.2.0/24")
	docPrefix2   = netip.MustParsePrefix("198.51.100.0/24")
	docPrefix3   = netip.MustParsePrefix("203.0.113.0/24")
)

func New(r *Rules, exceptions string) (*Router, error) {
	extra, _, e := ParseExceptions(exceptions)
	if e != nil {
		return nil, e
	}
	return &Router{Rules: r, Exceptions: extra, Lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}, cache: map[string]cached{}}, nil
}

func NewGlobal(r *Rules, exceptions string) (*Router, error) {
	rt, e := New(r, exceptions)
	if e != nil {
		return nil, e
	}
	rt.Global = true
	return rt, nil
}

// IsLocalIP reports loopback, RFC1918/ULA private, link-local, multicast,
// unspecified and CGNAT addresses (excluding RFC 5737 documentation ranges).
func IsLocalIP(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() || cgnatPrefix.Contains(a)
}

// IsLocalDomain reports hostnames reserved for local or LAN resolution.
func IsLocalDomain(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".lan") || strings.HasSuffix(host, ".home.arpa") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".localdomain")
}

// isBogusResolvedIP filters out DNS-poisoned or non-routable resolved answers
// (such as 127.0.0.1, 0.0.0.0, Fake-IP 198.18.0.0/15, multicast, or doc ranges)
// so a poisoned foreign domain is never mistakenly routed direct.
func isBogusResolvedIP(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || fakeIPPrefix.Contains(a) || docPrefix1.Contains(a) || docPrefix2.Contains(a) || docPrefix3.Contains(a)
}

func (r *Router) IsLocalOrPrivateDomain(host string) bool {
	if r == nil {
		return IsLocalDomain(host)
	}
	d, e := Domain(host)
	if e != nil {
		return IsLocalDomain(host)
	}
	if IsLocalDomain(d) || r.Exceptions.MatchDomain(d) {
		return true
	}
	return r.Rules != nil && r.Rules.private.MatchDomain(d)
}

// IsDomesticDomain reports whether host matches geosite:cn with higher
// specificity than geosite:geolocation-!cn (used for TUN split-horizon DNS).
func (r *Router) IsDomesticDomain(host string) bool {
	if r == nil || r.Global || r.Rules == nil {
		return false
	}
	d, e := Domain(host)
	if e != nil {
		return false
	}
	cnDepth := r.Rules.MatchDomainDepth(d)
	if cnDepth == 0 {
		return false
	}
	return cnDepth > r.Rules.proxy.MatchDomainDepth(d)
}

// IsProxyDomain reports whether host explicitly matches geosite:geolocation-!cn
// with specificity greater than or equal to geosite:cn.
func (r *Router) IsProxyDomain(host string) bool {
	if r == nil || r.Rules == nil {
		return false
	}
	if r.Global {
		return !r.IsLocalOrPrivateDomain(host)
	}
	d, e := Domain(host)
	if e != nil {
		return false
	}
	proxyDepth := r.Rules.proxy.MatchDomainDepth(d)
	return proxyDepth > 0 && proxyDepth >= r.Rules.MatchDomainDepth(d)
}

func (r *Router) Decide(ctx context.Context, target string) Decision {
	proxyReason := "default_proxy"
	if r.Global {
		proxyReason = "global_proxy"
	}
	proxy := Decision{Address: target, Reason: proxyReason}
	host, _, e := net.SplitHostPort(target)
	if e != nil {
		return proxy
	}
	if a, e := netip.ParseAddr(host); e == nil {
		a = a.Unmap()
		if IsLocalIP(a) || r.Exceptions.MatchIP(a) {
			return Decision{true, target, "ip_direct"}
		}
		if r.Global {
			return proxy
		}
		if r.Rules != nil && (r.Rules.private.MatchIP(a) || r.Rules.MatchIP(a)) {
			return Decision{true, target, "ip_direct"}
		}
		return proxy
	}
	host, e = Domain(host)
	if e != nil {
		return proxy
	}
	// Priority: local/LAN, user exceptions, GEOSITE private.
	if IsLocalDomain(host) || r.Exceptions.MatchDomain(host) || (r.Rules != nil && r.Rules.private.MatchDomain(host)) {
		return Decision{true, target, "domain_direct"}
	}
	if r.Global || r.Rules == nil {
		return proxy
	}
	// Compare specificity between GEOSITE cn and GEOSITE geolocation-!cn so
	// specific subdomains (e.g. cn.bing.com, download.microsoft.com, 1drv.ms)
	// win over broader parent entries; ties go to proxy (!cn).
	proxyDepth := r.Rules.proxy.MatchDomainDepth(host)
	cnDepth := r.Rules.MatchDomainDepth(host)
	if cnDepth > 0 || proxyDepth > 0 {
		if cnDepth > proxyDepth {
			return Decision{true, target, "domain_direct"}
		}
		return Decision{false, target, "proxy_domain"}
	}
	r.mu.Lock()
	c, ok := r.cache[host]
	r.mu.Unlock()
	if ok && time.Now().Before(c.until) {
		return Decision{Direct: c.direct, Address: target, Reason: c.reason}
	}
	resolve, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	ips, e := r.Lookup(resolve, host)
	if ctx.Err() != nil {
		return proxy
	}
	if e != nil || len(ips) == 0 {
		// Do not poison the cache for 60s on transient DNS failures.
		return proxy
	}
	allCN, allPrivate := true, true
	for _, ip := range ips {
		ip = ip.Unmap()
		if isBogusResolvedIP(ip) {
			allCN, allPrivate = false, false
			break
		}
		if !r.Rules.MatchIP(ip) {
			allCN = false
		}
		if !ip.IsPrivate() {
			allPrivate = false
		}
	}
	decision := proxy
	if allCN {
		// Keep target (hostname:port) instead of pinning ips[0] so direct dials
		// retain Happy Eyeballs and IPv4/IPv6 failover.
		decision = Decision{true, target, "resolved_cn_ip"}
	} else if allPrivate {
		decision = Decision{true, target, "resolved_private_ip"}
	}
	r.mu.Lock()
	if len(r.cache) >= 4096 {
		clear(r.cache)
	}
	r.cache[host] = cached{direct: decision.Direct, reason: decision.Reason, until: time.Now().Add(time.Minute)}
	r.mu.Unlock()
	return decision
}

// Counts reports direct domains (cn + private) and direct IP prefixes.
func (r *Rules) Counts() (domains, prefixes int) {
	domains, prefixes = len(r.suffix)+len(r.exact), len(r.prefixes)
	if r.private != nil {
		domains += len(r.private.suffix) + len(r.private.exact)
		prefixes += len(r.private.prefixes)
	}
	return
}
