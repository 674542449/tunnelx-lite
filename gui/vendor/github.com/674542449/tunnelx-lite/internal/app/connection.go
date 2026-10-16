package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/674542449/tunnelx-lite/internal/client"
	"github.com/674542449/tunnelx-lite/internal/config"
	"github.com/674542449/tunnelx-lite/internal/diagnostics"
	"github.com/674542449/tunnelx-lite/internal/routing"
	"github.com/674542449/tunnelx-lite/internal/share"
	"github.com/674542449/tunnelx-lite/internal/tunmode"
)

func (e *Engine) CancelConnect() error {
	e.mu.Lock()
	e.stopRecoveryLocked()
	if cancel := e.connectCancel; cancel != nil {
		e.stage = "cancelling"
		cancel()
	}
	e.mu.Unlock()
	return nil
}

func (e *Engine) connectionStage(ctx context.Context, attempt uint64, stage string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.connectID != attempt || !e.connecting {
		return context.Canceled
	}
	if e.stage != "cancelling" {
		e.stage = stage
	}
	return ctx.Err()
}

// RecoverProxy is the user's explicit recovery request.
func (e *Engine) RecoverProxy() error { return e.recoverIdle(true) }

// RestoreProxyAtStartup never discards a snapshot when another program has
// replaced the proxy; only an explicit RecoverProxy may do that.
func (e *Engine) RestoreProxyAtStartup() error { return e.recoverIdle(false) }

func (e *Engine) recoverIdle(confirmed bool) error {
	if !e.lifecycle.TryLock() {
		return errors.New("请先断开或取消连接")
	}
	defer e.lifecycle.Unlock()
	e.mu.Lock()
	active := e.mux != nil || e.connecting || e.recovering
	e.mu.Unlock()
	if active {
		return errors.New("请先断开连接再恢复系统代理")
	}
	if !confirmed {
		return e.recoverProxy()
	}
	err := errors.Join(e.system.RecoverOrphan(), tunmode.Recover(e.statePath("tun-state.json")))
	e.setProxyError(err)
	return err
}

func (e *Engine) recoverProxy() error {
	err := errors.Join(e.system.RestoreOrphan(), tunmode.Recover(e.statePath("tun-state.json")))
	e.setProxyError(err)
	return err
}

func (e *Engine) setProxyError(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.proxyRecoveryError = ""
	if err != nil {
		e.proxyRecoveryError = err.Error()
	}
}

// resolveHost keeps literal addresses and resolves a domain once, locally.
func resolveHost(ctx context.Context, host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("无法解析服务器域名 %s，请检查本地网络或改用 IP 分享链接", host)
	}
	return addrs[0], nil
}

func (e *Engine) clientConfig(ctx context.Context, link share.Link) (config.Client, error) {
	ip, err := resolveHost(ctx, link.Host)
	if err != nil {
		return config.Client{}, err
	}
	e.mu.Lock()
	c := link.Client(ip)
	c.SOCKSListen, c.HTTPListen, c.WebListen, c.DeviceID = e.settings.SOCKS, e.settings.HTTP, e.settings.Web, e.deviceID
	c.Transport = e.preferences.transport()
	e.mu.Unlock()
	return c, nil
}

// verifyGateway proves TLS, the pinned certificate, ECH and the key in one go.
// An authenticated request for a forbidden loopback target is refused by the
// server with its protocol header; a wrong key only ever sees the decoy site.
func verifyGateway(ctx context.Context, m *client.Mux) error {
	// QUIC-only mode does not need the TCP port; its handshake checks ECH itself.
	if m.Config.Transport != "quic" {
		probe, stop := context.WithTimeout(ctx, 15*time.Second)
		defer stop()
		res, err := m.PublicGET(probe)
		if res != nil {
			io.Copy(io.Discard, io.LimitReader(res.Body, 8192))
			res.Body.Close()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil || res.StatusCode != 200 {
			return errors.New("无法与服务器建立安全连接：请检查地址和端口是否放行，或分享链接是否来自这台服务器")
		}
		if !m.LastECH.Load() {
			return errors.New("服务器没有接受 ECH 加密握手，请确认分享链接与服务器一致")
		}
	}
	admit, stopAdmit := context.WithTimeout(ctx, 10*time.Second)
	defer stopAdmit()
	t, err := m.OpenTCP(admit, "127.0.0.1:9")
	if err == nil {
		t.Close()
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var rejected *client.RequestError
	if errors.As(err, &rejected) && rejected.Known {
		return nil
	}
	if errors.As(err, &rejected) {
		return errors.New("密钥认证失败：服务器的密钥可能已被重置，请从面板复制新的分享链接重新导入")
	}
	if m.Config.Transport == "quic" {
		return err
	}
	return errors.New("服务器响应超时，请稍后重试或更换服务器")
}

func (e *Engine) Connect(id string, systemProxy bool) error {
	e.mu.Lock()
	e.stopRecoveryLocked()
	e.mu.Unlock()
	return e.connect(id, systemProxy, 0)
}

func (e *Engine) connect(id string, systemProxy bool, recovery uint64) (result error) {
	if !e.lifecycle.TryLock() {
		return errors.New("正在处理连接，请稍后重试")
	}
	defer e.lifecycle.Unlock()
	e.mu.Lock()
	if recovery != 0 && (!e.recovering || e.recoveryEpoch != recovery || e.recoveryContext.Err() != nil) {
		e.mu.Unlock()
		return context.Canceled
	}
	if e.mux != nil || e.connecting || e.stopping > 0 {
		e.mu.Unlock()
		return errors.New("请先断开当前连接")
	}
	server := e.findLocked(id)
	if server == nil {
		e.mu.Unlock()
		return errors.New("请先选择一个服务器")
	}
	link := server.Link
	ctx, cancel := context.WithCancel(context.Background())
	if recovery != 0 {
		stop := context.AfterFunc(e.recoveryContext, cancel)
		defer stop()
	}
	e.connectID++
	attempt := e.connectID
	e.connectCancel, e.connecting, e.stage, e.health = cancel, true, "restoring_proxy", Health{}
	e.nodeID, e.nodeName = id, link.Name
	mode, rules, exceptions := e.preferences.ProxyMode, e.rules, joinLines(e.preferences.DirectDomains)
	e.mu.Unlock()
	var m *client.Mux
	var p *client.Proxy
	var l *diagnostics.Logger
	var tun *tunmode.Manager
	enabled, committed := false, false
	defer func() {
		cancel()
		if !committed {
			if tun != nil {
				result = errors.Join(result, tun.Close())
			}
			if enabled {
				err := e.system.Restore()
				e.setProxyError(err)
				result = errors.Join(result, err)
			}
			if p != nil {
				p.Close()
			} else if m != nil {
				m.Close()
			}
			if l != nil {
				l.Close()
			}
		}
		e.mu.Lock()
		if e.connectID == attempt {
			e.connecting, e.connectCancel = false, nil
			if !committed {
				e.stage, e.nodeID, e.nodeName = "disconnected", "", ""
			}
		}
		e.mu.Unlock()
	}()
	if err := e.recoverProxy(); err != nil {
		return err
	}
	if mode == routing.TUN {
		if !tunmode.Elevated() {
			return errors.New("TUN 模式需要管理员权限，请退出客户端后右键选择“以管理员身份运行”")
		}
		if err := tunmode.CheckAssets(tunmode.RuntimeDir()); err != nil {
			return err
		}
		systemProxy = false
	}
	if err := e.connectionStage(ctx, attempt, "verifying_tls"); err != nil {
		return err
	}
	c, err := e.clientConfig(ctx, link)
	if err != nil {
		return err
	}
	if m, err = client.New(c); err != nil {
		return err
	}
	if err = e.connectionStage(ctx, attempt, "authenticating"); err != nil {
		return err
	}
	if err = verifyGateway(ctx, m); err != nil {
		return err
	}
	checked := time.Now().Unix()
	if err = e.connectionStage(ctx, attempt, "starting_proxy"); err != nil {
		return err
	}
	p = client.NewProxy(m)
	if mode == routing.TUN {
		if err = e.connectionStage(ctx, attempt, "checking_tun_network"); err != nil {
			return err
		}
		p.TUN = true
		p.TUNIPv6.Store(m.ProbeTUNIPv6(ctx))
		if err = ctx.Err(); err != nil {
			return err
		}
	}
	if mode == routing.Bypass {
		if p.Router, err = routing.New(rules, exceptions); err != nil {
			return err
		}
	}
	if err = p.Start(); err != nil {
		return fmt.Errorf("本地代理端口被占用，请先退出其他代理软件：%w", err)
	}
	if l, err = diagnostics.New(filepath.Join(e.root, "logs"), diagnostics.Options{}); err != nil {
		return err
	}
	m.SetDiagnostics(l)
	if err = ctx.Err(); err != nil {
		return err
	}
	if systemProxy {
		if err = e.system.Enable(); err != nil {
			return err
		}
		enabled = true
	}
	if mode == routing.TUN {
		if err = e.connectionStage(ctx, attempt, "starting_tun"); err != nil {
			return err
		}
		tun = &tunmode.Manager{}
		if err = tun.Start(ctx, e.statePath("tun-state.json"), e.settings.SOCKS, []string{c.ServerIP}); err != nil {
			return err
		}
	}
	e.mu.Lock()
	if ctx.Err() != nil || e.stopping > 0 {
		e.mu.Unlock()
		return context.Canceled
	}
	live, stop := context.WithCancel(context.Background())
	e.cancel, e.finish = stop, m.RunDiagnostics(live, 30*time.Second)
	e.logger, e.mux, e.proxy, e.tun = l, m, p, tun
	e.nodeID, e.nodeName = id, link.Name
	e.connectedAt, e.priorTime = time.Now(), time.Now()
	e.priorUp, e.priorDown, e.upRate, e.downRate = 0, 0, 0, 0
	e.stage = "connected"
	e.health = Health{CheckedAt: checked, LastSuccess: checked}
	e.healthDone = e.startHealth(live, m)
	e.connecting, e.connectCancel = false, nil
	committed = true
	e.mu.Unlock()
	m.PrewarmQUIC()
	if tun != nil {
		go func() {
			<-tun.Done()
			if tun.NetworkChanged() {
				e.recoverTUN(m)
			} else {
				_ = e.disconnectSession(m)
			}
		}()
	}
	l.Record("client_started", map[string]any{"scope": "client", "client_version": Version, "proxy_mode": mode, "pid": os.Getpid()})
	e.recordConn("connect", id, link.Name, mode)
	return nil
}

func joinLines(v []string) string {
	out := ""
	for _, s := range v {
		out += s + "\n"
	}
	return out
}

func (e *Engine) Disconnect() error {
	e.beginStop()
	e.lifecycle.Lock()
	defer e.endStop()
	return e.disconnect()
}

func (e *Engine) beginStop() {
	e.mu.Lock()
	e.stopRecoveryLocked()
	e.stopping++
	if cancel := e.connectCancel; cancel != nil {
		e.stage = "cancelling"
		cancel()
	}
	e.mu.Unlock()
}

func (e *Engine) endStop() { e.mu.Lock(); e.stopping--; e.mu.Unlock(); e.lifecycle.Unlock() }

// A delayed failure may only tear down its original connection.
func (e *Engine) disconnectSession(expected *client.Mux) error {
	e.lifecycle.Lock()
	defer e.lifecycle.Unlock()
	e.mu.Lock()
	current := e.mux == expected
	e.mu.Unlock()
	if !current {
		return nil
	}
	return e.disconnect()
}

// disconnect is called with lifecycle held, never while mu is held.
func (e *Engine) disconnect() error {
	e.mu.Lock()
	m, p, l, cancel, finish, healthDone := e.mux, e.proxy, e.logger, e.cancel, e.finish, e.healthDone
	tun, nodeID, nodeName := e.tun, e.nodeID, e.nodeName
	e.tun, e.mux, e.proxy, e.logger, e.cancel, e.finish, e.healthDone = nil, nil, nil, nil, nil, nil, nil
	e.nodeID, e.nodeName, e.stage = "", "", "disconnected"
	e.mu.Unlock()
	if m == nil {
		return e.recoverProxy()
	}
	e.recordConn("disconnect", nodeID, nodeName, "")
	var tunErr error
	if tun != nil {
		tunErr = tun.Close()
	}
	err := errors.Join(tunErr, e.system.Restore())
	e.setProxyError(err)
	if cancel != nil {
		cancel()
	}
	if finish != nil {
		finish()
	}
	if healthDone != nil {
		<-healthDone
	}
	if p != nil {
		p.Close()
	} else {
		m.Close()
	}
	m.FinishDiagnostics()
	if l != nil {
		l.Record("client_stopped", map[string]any{"scope": "client", "reason": "requested_shutdown"})
		l.Close()
	}
	return err
}

// Probe measures the time to a verified TLS + ECH response from the server.
func (e *Engine) Probe(id string) (int64, error) {
	e.mu.Lock()
	server := e.findLocked(id)
	e.mu.Unlock()
	if server == nil {
		return 0, errors.New("服务器不存在")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	c, err := e.clientConfig(ctx, server.Link)
	if err != nil {
		return 0, err
	}
	m, err := client.New(c)
	if err != nil {
		return 0, err
	}
	defer m.Close()
	started := time.Now()
	r, err := m.PublicGET(ctx)
	if err != nil {
		return 0, errors.New("超时或无法连接")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 || !m.LastECH.Load() {
		return 0, errors.New("握手失败")
	}
	if _, err = io.Copy(io.Discard, io.LimitReader(r.Body, 8192)); err != nil {
		return 0, errors.New("响应中断")
	}
	return time.Since(started).Milliseconds(), nil
}

type ProbeResult struct {
	ID    string `json:"id"`
	Ms    int64  `json:"ms"`
	Error string `json:"error,omitempty"`
}

func (e *Engine) ProbeAll() []ProbeResult {
	e.mu.Lock()
	ids := make([]string, 0, len(e.servers))
	for _, s := range e.servers {
		ids = append(ids, s.ID)
	}
	e.mu.Unlock()
	results := make([]ProbeResult, len(ids))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, id := range ids {
		results[i].ID = id
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ms, err := e.Probe(id)
			if err != nil {
				results[i].Error, results[i].Ms = err.Error(), -1
			} else {
				results[i].Ms = ms
			}
		}()
	}
	wg.Wait()
	return results
}
