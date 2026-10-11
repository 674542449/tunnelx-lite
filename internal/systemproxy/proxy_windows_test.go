//go:build windows

package systemproxy

import (
	"fmt"
	"golang.org/x/sys/windows/registry"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRegistrySnapshotRestoreAndCrashRecovery(t *testing.T) {
	path := fmt.Sprintf(`Software\tunnelX-tests\%d`, time.Now().UnixNano())
	k, _, e := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	if e != nil {
		t.Fatal(e)
	}
	defer registry.DeleteKey(registry.CURRENT_USER, path)
	defer k.Close()
	k.SetStringValue("ProxyServer", "old.example:1234")
	k.SetDWordValue("ProxyEnable", 0)
	k.SetStringValue("AutoConfigURL", "https://old.example/config.pac")
	state := filepath.Join(t.TempDir(), "proxy.json")
	m := &Manager{Path: state, Proxy: "127.0.0.1:8088", KeyPath: path}
	if e = m.Enable(); e != nil {
		t.Fatal(e)
	}
	v, _, _ := k.GetStringValue("ProxyServer")
	if v != m.Proxy {
		t.Fatal("proxy not set")
	}
	if _, _, e = k.GetStringValue("AutoConfigURL"); e != registry.ErrNotExist {
		t.Fatal("PAC not suspended")
	}
	restarted := &Manager{Path: state, KeyPath: path}
	if e = restarted.Restore(); e != nil {
		t.Fatal(e)
	}
	v, _, _ = k.GetStringValue("ProxyServer")
	if v != "old.example:1234" {
		t.Fatal("original proxy not restored")
	}
	if _, _, e = k.GetStringValue("ProxyOverride"); e != registry.ErrNotExist {
		t.Fatal("absent original field not restored")
	}
	pac, _, _ := k.GetStringValue("AutoConfigURL")
	if pac != "https://old.example/config.pac" {
		t.Fatal("PAC not restored")
	}
	if e = m.Enable(); e != nil {
		t.Fatal(e)
	}
	k.SetStringValue("ProxyServer", "external.example:3333")
	if e = m.Restore(); e != nil {
		t.Fatal("an external takeover must not be an error", e)
	}
	v, _, _ = k.GetStringValue("ProxyServer")
	if v != "external.example:3333" || m.Enabled() {
		t.Fatal("external value overwritten or stale snapshot kept")
	}
}

func TestExternalTakeoverNeverBlocks(t *testing.T) {
	path := fmt.Sprintf(`Software	xlite-tests\%d`, time.Now().UnixNano())
	k, _, e := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	if e != nil {
		t.Fatal(e)
	}
	defer registry.DeleteKey(registry.CURRENT_USER, path)
	defer k.Close()
	k.SetStringValue("ProxyServer", "old.example:1234")
	m := &Manager{Path: filepath.Join(t.TempDir(), "proxy.json"), Proxy: "127.0.0.1:1", KeyPath: path}
	if e = m.Enable(); e != nil {
		t.Fatal(e)
	}
	k.SetStringValue("ProxyServer", "127.0.0.1:7890") // e.g. another proxy tool takes over
	if e = m.RestoreOrphan(); e != nil {
		t.Fatal("startup recovery blocked by another program's proxy", e)
	}
	if v, _, _ := k.GetStringValue("ProxyServer"); v != "127.0.0.1:7890" || m.Enabled() {
		t.Fatal("other program's proxy overwritten or stale snapshot kept", v)
	}
	if e = m.Enable(); e != nil {
		t.Fatal("enabling stayed blocked after an external takeover", e)
	}
	if e = m.Restore(); e != nil {
		t.Fatal(e)
	}
	if v, _, _ := k.GetStringValue("ProxyServer"); v != "127.0.0.1:7890" {
		t.Fatal("restore did not hand the proxy back to the other program", v)
	}
	if e = os.WriteFile(m.Path, []byte("{broken"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = m.RestoreOrphan(); e != nil || m.Enabled() {
		t.Fatal("a corrupt snapshot must not block connecting", e)
	}
}
