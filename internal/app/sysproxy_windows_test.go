package app

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/674542449/tunnelx-lite/internal/routing"
)

func TestSystemProxySwitchAppliesWhileConnected(t *testing.T) {
	keyPath := fmt.Sprintf(`Software\txlite-tests\%d`, time.Now().UnixNano())
	k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.DeleteKey(registry.CURRENT_USER, keyPath)
	defer k.Close()
	k.SetStringValue("ProxyServer", "old.example:3128")
	k.SetDWordValue("ProxyEnable", 0)
	proxyServer := func() string { v, _, _ := k.GetStringValue("ProxyServer"); return v }

	site := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go site.Serve(ln)
	defer site.Close()
	link := testServer(t, ln.Addr().String())
	e, err := New(t.TempDir(), Settings{SOCKS: freeAddr(t), HTTP: freeAddr(t), Web: freeAddr(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.system.KeyPath = keyPath
	e.Import(link.String())
	id := e.Servers()[0].ID
	e.SaveProxyMode(routing.Global, "")

	if err = e.SetSystemProxy(true); err != nil || proxyServer() != "old.example:3128" {
		t.Fatal("switch while disconnected must only save the preference", err, proxyServer())
	}
	if err = e.Connect(id, false); err != nil {
		t.Fatal(err)
	}
	if proxyServer() != "old.example:3128" {
		t.Fatal("connect without system proxy changed the registry")
	}
	if err = e.SetSystemProxy(true); err != nil {
		t.Fatal(err)
	}
	override, _, _ := k.GetStringValue("ProxyOverride")
	if enabled, _, _ := k.GetIntegerValue("ProxyEnable"); proxyServer() != e.Settings().HTTP || enabled != 1 || !strings.Contains(override, "192.168.*") || !strings.Contains(override, "<local>") {
		t.Fatal("system proxy not applied immediately or LAN not excluded", proxyServer(), override)
	}
	if err = e.SetSystemProxy(false); err != nil || proxyServer() != "old.example:3128" {
		t.Fatal("clearing the system proxy did not restore the original", err, proxyServer())
	}
	if e.Status()["preferences"].(Preferences).SystemProxy {
		t.Fatal("preference not saved")
	}
	e.SetSystemProxy(true)
	if err = e.Disconnect(); err != nil || proxyServer() != "old.example:3128" || e.system.Enabled() {
		t.Fatal("disconnect did not restore the original proxy", err, proxyServer())
	}
}

func TestAnotherProxyToolNeverBlocksConnect(t *testing.T) {
	keyPath := fmt.Sprintf(`Software\txlite-tests\%d`, time.Now().UnixNano())
	k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.DeleteKey(registry.CURRENT_USER, keyPath)
	defer k.Close()
	k.SetStringValue("ProxyServer", "old.example:3128")
	proxyServer := func() string { v, _, _ := k.GetStringValue("ProxyServer"); return v }
	link := testServer(t, "127.0.0.1:9")
	e, err := New(t.TempDir(), Settings{SOCKS: freeAddr(t), HTTP: freeAddr(t), Web: freeAddr(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.system.KeyPath = keyPath
	e.Import(link.String())
	id := e.Servers()[0].ID
	e.SaveProxyMode(routing.Global, "")
	if err = e.Connect(id, true); err != nil || proxyServer() != e.Settings().HTTP {
		t.Fatal("system proxy not set", err)
	}
	k.SetStringValue("ProxyServer", "127.0.0.1:10809") // another proxy tool takes over
	if err = e.Disconnect(); err != nil {
		t.Fatal("disconnect reported an error for another tool's proxy", err)
	}
	if proxyServer() != "127.0.0.1:10809" {
		t.Fatal("disconnect overwrote the other tool's proxy", proxyServer())
	}
	if err = e.Connect(id, true); err != nil {
		t.Fatal("connect blocked after another tool changed the system proxy", err)
	}
	if err = e.Disconnect(); err != nil || proxyServer() != "127.0.0.1:10809" {
		t.Fatal("the other tool's proxy was not handed back", err, proxyServer())
	}
	if st := e.Status(); st["proxy_recovery_error"] != "" {
		t.Fatal("a stale recovery warning is still shown", st["proxy_recovery_error"])
	}
}
