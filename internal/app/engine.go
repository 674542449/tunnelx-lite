// Package app is the Windows client engine: imported servers, the local
// proxy, system proxy and TUN. There are no accounts; a share link is enough.
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/674542449/tunnelx-lite/internal/client"
	"github.com/674542449/tunnelx-lite/internal/diagnostics"
	"github.com/674542449/tunnelx-lite/internal/fsutil"
	"github.com/674542449/tunnelx-lite/internal/routing"
	"github.com/674542449/tunnelx-lite/internal/systemproxy"
	"github.com/674542449/tunnelx-lite/internal/tunmode"
)

const Version = "v0.1.6"

type Settings struct {
	SOCKS string `json:"socks_listen"`
	HTTP  string `json:"http_listen"`
	Web   string `json:"web_listen"`
}

type Preferences struct {
	SelectedID    string   `json:"selected_id"`
	ProxyMode     string   `json:"proxy_mode"`
	DirectDomains []string `json:"direct_domains"`
}

type Health struct {
	CheckedAt           int64       `json:"checked_at"`
	LastSuccess         int64       `json:"last_success"`
	ConsecutiveFailures int         `json:"consecutive_failures"`
	ErrorKind           string      `json:"error_kind"`
	Gateway             HealthLayer `json:"gateway"`
	DNS                 HealthLayer `json:"dns"`
	Egress              HealthLayer `json:"egress"`
}

type HealthLayer struct {
	CheckedAt   int64  `json:"checked_at"`
	LastSuccess int64  `json:"last_success"`
	Failures    int    `json:"consecutive_failures"`
	ErrorKind   string `json:"error_kind"`
}

type Engine struct {
	// lifecycle serializes changes to the live proxy; network waits never hold mu.
	lifecycle                            sync.Mutex
	mu                                   sync.Mutex
	root                                 string
	settings                             Settings
	preferences                          Preferences
	servers                              []Server
	deviceID                             string
	mux                                  *client.Mux
	proxy                                *client.Proxy
	system                               *systemproxy.Manager
	cancel                               context.CancelFunc
	finish                               func()
	healthDone                           <-chan struct{}
	logger                               *diagnostics.Logger
	connectCancel                        context.CancelFunc
	connectID                            uint64
	connecting                           bool
	stopping                             int
	stage                                string
	health                               Health
	healthInterval                       time.Duration
	healthTimeout                        time.Duration
	nodeID, nodeName                     string
	connectedAt, priorTime               time.Time
	priorUp, priorDown, upRate, downRate int64
	proxyRecoveryError, startupWarning   string
	tun                                  *tunmode.Manager
	rules                                *routing.Rules
	ruleInfo                             map[string]any
	tunInfo                              map[string]any
	rulesUpdate                          sync.Mutex
	recoveryCancel                       context.CancelFunc
	recoveryContext                      context.Context
	recoveryEpoch                        uint64
	recovering                           bool
	recoveryAttempt                      int
	connLogs                             []ConnLog
}

func (e *Engine) statePath(name string) string { return filepath.Join(e.root, "state", name) }

func New(root string, settings Settings) (*Engine, error) {
	if settings.SOCKS == "" {
		settings.SOCKS = "127.0.0.1:1080"
	}
	if settings.HTTP == "" {
		settings.HTTP = "127.0.0.1:8088"
	}
	if settings.Web == "" {
		settings.Web = "127.0.0.1:9080"
	}
	e := &Engine{root: root, settings: settings, preferences: Preferences{ProxyMode: routing.Bypass}, stage: "disconnected", healthInterval: 30 * time.Second, healthTimeout: 5 * time.Second}
	var err error
	e.rules, e.ruleInfo, err = routing.Load(e.statePath("routing-rules.json"))
	if err != nil {
		return nil, err
	}
	e.tunInfo = tunmode.Availability()
	if err = e.loadServers(); err != nil {
		e.startupWarning = "本机保存的服务器列表无法读取（可能来自另一台电脑或另一个 Windows 用户），请重新导入分享链接。"
	}
	if b, err := os.ReadFile(e.statePath("preferences.json")); err == nil {
		p := e.preferences
		if json.Unmarshal(b, &p) == nil && routing.ValidMode(p.ProxyMode) {
			e.preferences = p
		} else {
			e.startupWarning += " 本机偏好无法读取，已使用默认设置。"
		}
	}
	if b, err := os.ReadFile(e.statePath("device-id")); err == nil && len(b) == 32 {
		e.deviceID = string(b)
	} else {
		id := make([]byte, 16)
		if _, err = rand.Read(id); err != nil {
			return nil, err
		}
		e.deviceID = hex.EncodeToString(id)
		_ = fsutil.WriteFile(e.statePath("device-id"), []byte(e.deviceID))
	}
	e.system = &systemproxy.Manager{Path: e.statePath("system-proxy.json"), Proxy: settings.HTTP}
	return e, nil
}

func (e *Engine) savePreferencesLocked(p Preferences) error {
	b, _ := json.MarshalIndent(p, "", "  ")
	if err := fsutil.WriteFile(e.statePath("preferences.json"), b); err != nil {
		return err
	}
	e.preferences = p
	return nil
}

func (e *Engine) SavePreferences(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if id != "" && e.findLocked(id) == nil {
		return errors.New("服务器不存在")
	}
	p := e.preferences
	p.SelectedID = id
	return e.savePreferencesLocked(p)
}

func (e *Engine) Settings() Settings { e.mu.Lock(); defer e.mu.Unlock(); return e.settings }

func (e *Engine) Status() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	state := "disconnected"
	if e.connecting || e.recovering {
		state = "connecting"
	} else if e.mux != nil {
		state = "connected"
		if e.health.ConsecutiveFailures > 0 {
			state = "degraded"
		}
	}
	s := map[string]any{"version": Version, "connected": e.mux != nil, "connection_state": state, "connection_stage": e.stage, "health": e.health, "preferences": e.preferences, "startup_warning": e.startupWarning, "node_name": e.nodeName, "node_id": e.nodeID, "system_proxy": e.system.Enabled(), "socks": e.settings.SOCKS, "http": e.settings.HTTP, "logs": filepath.Join(e.root, "logs"), "proxy_recovery_error": e.proxyRecoveryError, "server_count": len(e.servers)}
	s["routing_rules"] = e.ruleInfo
	s["recovering"] = e.recovering
	s["recovery_attempt"] = e.recoveryAttempt
	s["tun"] = e.tunInfo
	if e.proxy != nil && e.proxy.TUN {
		info := map[string]any{}
		for k, v := range e.tunInfo {
			info[k] = v
		}
		info["ipv6_available"] = e.proxy.TUNIPv6.Load()
		s["tun"] = info
	}
	if e.mux != nil {
		up, down := e.mux.Stats.Uploaded.Load(), e.mux.Stats.Downloaded.Load()
		if seconds := time.Since(e.priorTime).Seconds(); seconds >= .8 {
			e.upRate = int64(float64(up-e.priorUp) / seconds)
			e.downRate = int64(float64(down-e.priorDown) / seconds)
			e.priorUp, e.priorDown, e.priorTime = up, down, time.Now()
		}
		s["upload"], s["download"] = up, down
		s["upload_rate"], s["download_rate"] = e.upRate, e.downRate
		s["active"] = e.mux.Stats.Active.Load()
		s["connected_at"] = e.connectedAt.Unix()
		s["ech"] = e.mux.LastECH.Load()
		s["logging"] = e.mux.LoggingStatus()
	}
	return s
}

type ConnLog struct {
	Time     string `json:"time"`
	Event    string `json:"event"`
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	Detail   string `json:"detail,omitempty"`
}

func (e *Engine) recordConn(event, id, name, detail string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.connLogs = append(e.connLogs, ConnLog{Time: time.Now().UTC().Format(time.RFC3339), Event: event, NodeID: id, NodeName: name, Detail: detail})
	if len(e.connLogs) > 200 {
		e.connLogs = append([]ConnLog(nil), e.connLogs[len(e.connLogs)-200:]...)
	}
}

func (e *Engine) ConnLogs() []ConnLog {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]ConnLog(nil), e.connLogs...)
}

func (e *Engine) Close() error { return e.Disconnect() }
