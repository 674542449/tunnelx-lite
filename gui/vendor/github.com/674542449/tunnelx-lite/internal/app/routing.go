package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/674542449/tunnelx-lite/internal/client"
	"github.com/674542449/tunnelx-lite/internal/fsutil"
	"github.com/674542449/tunnelx-lite/internal/routing"
	"github.com/674542449/tunnelx-lite/internal/tunmode"
)

func buildRouter(mode string, rules *routing.Rules, exceptions string, liveProxy *client.Proxy, dnsOverride bool) (*routing.Router, error) {
	var r *routing.Router
	var err error
	if mode == routing.Global {
		r, err = routing.NewGlobal(rules, exceptions)
	} else {
		r, err = routing.New(rules, exceptions)
	}
	if err != nil {
		return nil, err
	}
	if liveProxy != nil && dnsOverride {
		r.Lookup = liveProxy.LookupDomesticIPs
	}
	return r, nil
}

// SaveProxyMode updates routing mode (bypass_cn / global) and direct exceptions.
// Switching between bypass_cn and global (or updating direct exceptions) applies
// immediately even while connected; legacy mode="tun" toggles TUN while disconnected.
func (e *Engine) SaveProxyMode(mode, exceptions string) error {
	if !routing.ValidMode(mode) {
		return errors.New("代理模式无效")
	}
	_, normalized, err := routing.ParseExceptions(exceptions)
	if err != nil {
		return err
	}
	e.mu.Lock()
	if e.connecting || e.recovering || e.stopping > 0 {
		e.mu.Unlock()
		return errors.New("正在切换连接状态，请稍后再试")
	}
	if mode == routing.TUN && e.mux != nil {
		e.mu.Unlock()
		return errors.New("请先断开连接，再开启 TUN 模式")
	}
	prevMode, prevDomains := e.preferences.ProxyMode, joinLines(e.preferences.DirectDomains)
	p := e.preferences
	if mode == routing.TUN {
		p.TUNEnabled = true
	} else {
		p.ProxyMode = mode
	}
	p.DirectDomains = normalized
	nextDomains := joinLines(normalized)
	routingChanged := prevMode != p.ProxyMode || prevDomains != nextDomains
	var liveRouter *routing.Router
	if e.proxy != nil {
		liveRouter, err = buildRouter(p.ProxyMode, e.rules, nextDomains, e.proxy, p.dnsConfig().Enabled)
		if err != nil {
			e.mu.Unlock()
			return err
		}
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	if err = fsutil.WriteFile(filepath.Join(e.root, "state", "preferences.json"), b); err != nil {
		e.mu.Unlock()
		return err
	}
	e.preferences = p
	liveProxy := e.proxy
	e.mu.Unlock()
	if liveProxy != nil && liveRouter != nil {
		liveProxy.SetRouter(liveRouter)
		if routingChanged {
			liveProxy.ResetConnections()
		}
		if liveProxy.TUN {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = tunmode.FlushDNS(ctx)
			}()
		}
	}
	return nil
}

// SaveTUN enables or disables TUN mode (orthogonal to bypass_cn / global).
func (e *Engine) SaveTUN(enabled bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.mux != nil || e.connecting || e.recovering || e.stopping > 0 {
		return errors.New("请先断开连接，再开启或关闭 TUN 模式")
	}
	p := e.preferences
	p.TUNEnabled = enabled
	return e.savePreferencesLocked(p)
}

func splitDNSLines(text string) []string {
	return strings.FieldsFunc(text, func(c rune) bool { return c == '\n' || c == '\r' || c == ',' })
}

// SaveDNS updates split-horizon anti-pollution DNS override settings.
// Changes apply immediately even while connected.
func (e *Engine) SaveDNS(enabled bool, domesticText, remoteText string) error {
	domestic, err := client.ParseDNSUpstreams(splitDNSLines(domesticText))
	if err != nil {
		return errors.New("国内 DNS 配置有误：" + err.Error())
	}
	remote, err := client.ParseDNSUpstreams(splitDNSLines(remoteText))
	if err != nil {
		return errors.New("远端 DNS 配置有误：" + err.Error())
	}
	e.mu.Lock()
	if e.connecting || e.recovering || e.stopping > 0 {
		e.mu.Unlock()
		return errors.New("正在切换连接状态，请稍后再试")
	}
	p := e.preferences
	en := enabled
	p.DNSOverride = &en
	p.DomesticDNS = domestic
	p.RemoteDNS = remote
	var liveRouter *routing.Router
	if e.proxy != nil {
		liveRouter, err = buildRouter(p.ProxyMode, e.rules, joinLines(p.DirectDomains), e.proxy, enabled)
		if err != nil {
			e.mu.Unlock()
			return err
		}
	}
	if err = e.savePreferencesLocked(p); err != nil {
		e.mu.Unlock()
		return err
	}
	liveProxy := e.proxy
	cfg := p.dnsConfig()
	e.mu.Unlock()
	if liveProxy != nil {
		liveProxy.SetDNSConfig(cfg)
		if liveRouter != nil {
			liveProxy.SetRouter(liveRouter)
		}
		if liveProxy.TUN {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = tunmode.FlushDNS(ctx)
			}()
		}
	}
	return nil
}

func (e *Engine) UpdateRoutingRules() error {
	if !e.rulesUpdate.TryLock() {
		return errors.New("规则正在更新，请稍候")
	}
	defer e.rulesUpdate.Unlock()
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second}
	e.mu.Lock()
	if e.mux != nil {
		u, _ := url.Parse("http://" + e.settings.HTTP)
		transport.Proxy = http.ProxyURL(u)
	}
	e.mu.Unlock()
	defer transport.CloseIdleConnections()
	h := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("规则源不允许重定向") }}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	snapshot, err := routing.Download(ctx, h)
	if err != nil {
		return errors.New("规则更新失败，原规则已保留。可先连接可用线路再重试。")
	}
	r, err := snapshot.Parse()
	if err != nil {
		return err
	}
	b, _ := json.Marshal(snapshot)
	e.mu.Lock()
	if err = fsutil.WriteFile(filepath.Join(e.root, "state", "routing-rules.json"), b); err != nil {
		e.mu.Unlock()
		return err
	}
	e.rules = r
	domains, prefixes := r.Counts()
	e.ruleInfo = map[string]any{"source": "updated", "updated_at": snapshot.UpdatedAt, "domains": domains, "ip_prefixes": prefixes, "sources": snapshot.Sources}
	liveProxy := e.proxy
	var liveRouter *routing.Router
	if liveProxy != nil {
		liveRouter, _ = buildRouter(e.preferences.ProxyMode, r, joinLines(e.preferences.DirectDomains), liveProxy, e.preferences.dnsConfig().Enabled)
	}
	e.mu.Unlock()
	if liveProxy != nil && liveRouter != nil {
		liveProxy.SetRouter(liveRouter)
	}
	return nil
}
