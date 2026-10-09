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
