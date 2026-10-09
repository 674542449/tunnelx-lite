//go:build windows

package systemproxy

import (
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
)

const regPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

type Value struct {
	Present bool   `json:"present"`
	String  string `json:"string,omitempty"`
	Number  uint32 `json:"number,omitempty"`
}
type Snapshot struct {
	Values   map[string]Value `json:"values"`
	OurProxy string           `json:"our_proxy"`
}
type Manager struct {
	Path  string
	Proxy string
	// KeyPath is used by registry-isolation tests; empty selects Windows Internet Settings.
	KeyPath string
	mu      sync.Mutex
}

func (m *Manager) keyPath() string {
	if m.KeyPath != "" {
		return m.KeyPath
	}
	return regPath
}
func (m *Manager) Enable() (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, e := os.Stat(m.Path); e == nil {
		return errors.New("saved proxy state exists; restore it before enabling again")
	}
	k, e := registry.OpenKey(registry.CURRENT_USER, m.keyPath(), registry.QUERY_VALUE|registry.SET_VALUE)
	if e != nil {
		return e
	}
	defer k.Close()
	s := Snapshot{Values: map[string]Value{}, OurProxy: m.Proxy}
	n, _, e := k.GetIntegerValue("ProxyEnable")
	s.Values["ProxyEnable"] = Value{Present: e == nil, Number: uint32(n)}
	for _, name := range []string{"ProxyServer", "ProxyOverride", "AutoConfigURL"} {
		v, _, e := k.GetStringValue(name)
		s.Values[name] = Value{Present: e == nil, String: v}
	}
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(m.Path), 0700); e != nil {
		return e
	}
	if e = os.WriteFile(m.Path, b, 0600); e != nil {
		return e
	}
	defer func() {
		if err != nil {
			if restoreErr := restoreValues(k, s); restoreErr == nil {
				os.Remove(m.Path)
			}
		}
	}()
	if e = k.SetStringValue("ProxyServer", m.Proxy); e != nil {
		return e
	}
	if e = k.SetStringValue("ProxyOverride", "localhost;127.*;[::1]"); e != nil {
		return e
	}
	if e = k.DeleteValue("AutoConfigURL"); e != nil && e != registry.ErrNotExist {
		return e
	}
	if e = k.SetDWordValue("ProxyEnable", 1); e != nil {
		return e
	}
	if m.KeyPath == "" {
		refresh()
	}
	return nil
}
func (m *Manager) Restore() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restore(false, false)
}

// RestoreOrphan reserves the saved loopback endpoint before restoring it. A
// different live client can therefore keep its proxy even during our startup
// or shutdown, before this process has established a tunnel of its own.
func (m *Manager) RestoreOrphan() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restore(true, false)
}

// RecoverOrphan is the user-confirmed recovery. When another program has
// since replaced the proxy, its settings stay untouched and only our stale
// snapshot is dropped, so recovery can never be blocked permanently.
func (m *Manager) RecoverOrphan() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restore(true, true)
}

func (m *Manager) restore(orphanOnly, keepExternal bool) error {
	b, e := os.ReadFile(m.Path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	var s Snapshot
	if e = json.Unmarshal(b, &s); e != nil {
		return e
	}
	if orphanOnly {
		host, port, err := net.SplitHostPort(s.OurProxy)
		p, portErr := strconv.Atoi(port)
		if err != nil || portErr != nil || p < 1 || p > 65535 || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("保存的代理地址无效，请检查系统代理恢复文件")
		}
		listener, err := net.Listen("tcp", s.OurProxy)
		if err != nil {
			return errors.New("另一个程序仍在使用代理端口，已保留系统代理；请先退出该程序后重试恢复")
		}
		defer listener.Close()
	}
	k, e := registry.OpenKey(registry.CURRENT_USER, m.keyPath(), registry.QUERY_VALUE|registry.SET_VALUE)
	if e != nil {
		return e
	}
	defer k.Close()
	current, _, e := k.GetStringValue("ProxyServer")
	if e == nil && current != s.OurProxy {
		if keepExternal {
			return os.Remove(m.Path)
		}
		return errors.New("系统代理已被其他程序修改，为避免覆盖其设置已暂停自动恢复；请在设置中点击「恢复系统代理」确认")
	}
	if e = restoreValues(k, s); e != nil {
		return e
	}
	if m.KeyPath == "" {
		refresh()
	}
	return os.Remove(m.Path)
}
func restoreValues(k registry.Key, s Snapshot) error {
	var e error
	for name, v := range s.Values {
		if !v.Present {
			e = k.DeleteValue(name)
			if e == registry.ErrNotExist {
				e = nil
			}
		} else if name == "ProxyEnable" {
			e = k.SetDWordValue(name, v.Number)
		} else {
			e = k.SetStringValue(name, v.String)
		}
		if e != nil {
			return e
		}
	}
	return nil
}
func (m *Manager) Enabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, e := os.Stat(m.Path)
	return e == nil
}
func refresh() {
	p := windows.NewLazySystemDLL("wininet.dll").NewProc("InternetSetOptionW")
	p.Call(0, 39, 0, 0)
	p.Call(0, 37, 0, 0)
}
func OpenBrowser(url string) error {
	u, e := windows.UTF16PtrFromString(url)
	if e != nil {
		return e
	}
	op, _ := windows.UTF16PtrFromString("open")
	return windows.ShellExecute(0, op, u, nil, nil, windows.SW_SHOWNORMAL)
}
func ShowError(message string) {
	m, _ := windows.UTF16PtrFromString(message)
	t, _ := windows.UTF16PtrFromString("tunnelX")
	windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptrPointer(m), uintptrPointer(t), 0x10)
	runtime.KeepAlive(m)
	runtime.KeepAlive(t)
}
