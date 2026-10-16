package app

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/674542449/tunnelx-lite/internal/fsutil"
	"github.com/674542449/tunnelx-lite/internal/routing"
	"net/http"
	"net/url"
	"path/filepath"
	"time"
)

func (e *Engine) SaveProxyMode(mode, exceptions string) error {
	if !routing.ValidMode(mode) {
		return errors.New("代理模式无效")
	}
	_, normalized, err := routing.ParseExceptions(exceptions)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.mux != nil || e.connecting || e.recovering || e.stopping > 0 {
		return errors.New("请先断开连接，再修改代理模式或直连例外")
	}
	p := e.preferences
	p.ProxyMode = mode
	p.DirectDomains = normalized
	b, _ := json.MarshalIndent(p, "", "  ")
	if err = fsutil.WriteFile(filepath.Join(e.root, "state", "preferences.json"), b); err != nil {
		return err
	}
	e.preferences = p
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
	defer e.mu.Unlock()
	if err = fsutil.WriteFile(filepath.Join(e.root, "state", "routing-rules.json"), b); err != nil {
		return err
	}
	e.rules = r
	domains, prefixes := r.Counts()
	e.ruleInfo = map[string]any{"source": "updated", "updated_at": snapshot.UpdatedAt, "domains": domains, "ip_prefixes": prefixes, "sources": snapshot.Sources}
	return nil
}
