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

type Rules struct {
	suffix, exact map[string]bool
	patterns      []*regexp.Regexp
	prefixes      map[netip.Prefix]bool
	proxy         *Rules
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
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
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
	d, e := Domain(s)
	if e != nil {
		return false
	}
	if r.exact[d] {
		return true
	}
	for v := d; v != ""; {
		if r.suffix[v] {
			return true
		}
		i := strings.IndexByte(v, '.')
		if i < 0 {
			break
		}
		v = v[i+1:]
	}
	for _, p := range r.patterns {
		if p.MatchString(d) {
			return true
		}
	}
	return false
}
func (r *Rules) MatchIP(a netip.Addr) bool {
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
		d, _ := data.ReadFile("data/direct-list.txt")
		v4, _ := data.ReadFile("data/china.txt")
		v6, _ := data.ReadFile("data/china6.txt")
		built, builtErr = Parse(d, append(append(v4, '\n'), v6...))
		if builtErr != nil {
			return
		}
		if len(built.suffix) < 1000 || len(built.prefixes) < 1000 {
			builtErr = errors.New("bundled routing rules incomplete")
			return
		}
		p, _ := data.ReadFile("data/proxy-list.txt")
		built.proxy, builtErr = Parse(p, nil)
	})
	return built, builtErr
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
	value Decision
	until time.Time
}
type Router struct {
	Rules, Exceptions *Rules
	Lookup            func(context.Context, string) ([]netip.Addr, error)
	mu                sync.Mutex
	cache             map[string]cached
}

func New(r *Rules, exceptions string) (*Router, error) {
	extra, _, e := ParseExceptions(exceptions)
	if e != nil {
		return nil, e
	}
	return &Router{Rules: r, Exceptions: extra, Lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}, cache: map[string]cached{}}, nil
}
func local(a netip.Addr) bool { return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() }
func (r *Router) Decide(ctx context.Context, target string) Decision {
	proxy := Decision{Address: target, Reason: "default_proxy"}
	host, port, e := net.SplitHostPort(target)
	if e != nil {
		return proxy
	}
	if a, e := netip.ParseAddr(host); e == nil {
		if local(a) || r.Exceptions.MatchIP(a) || r.Rules.MatchIP(a) {
			return Decision{true, target, "ip_direct"}
		}
		return proxy
	}
	host, e = Domain(host)
	if e != nil {
		return proxy
	}
	if host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".lan") || strings.HasSuffix(host, ".home.arpa") || r.Exceptions.MatchDomain(host) || r.Rules.MatchDomain(host) {
		return Decision{true, target, "domain_direct"}
	}
	if r.Rules.proxy != nil && r.Rules.proxy.MatchDomain(host) {
		return proxy
	}
	r.mu.Lock()
	c, ok := r.cache[target]
	r.mu.Unlock()
	if ok && time.Now().Before(c.until) {
		return c.value
	}
	resolve, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	ips, e := r.Lookup(resolve, host)
	decision := proxy
	if e == nil && len(ips) > 0 {
		allCN := true
		for _, ip := range ips {
			if local(ip) || !r.Rules.MatchIP(ip) {
				allCN = false
				break
			}
		}
		if allCN {
			decision = Decision{true, net.JoinHostPort(ips[0].String(), port), "resolved_cn_ip"}
		}
	}
	r.mu.Lock()
	if len(r.cache) >= 4096 {
		clear(r.cache)
	}
	r.cache[target] = cached{decision, time.Now().Add(time.Minute)}
	r.mu.Unlock()
	return decision
}
