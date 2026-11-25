//go:build windows

package tunmode

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Verifies the PowerShell TUN helper launches well below Windows' 32 KiB
// CreateProcess command-line limit and cleanly parses + executes watch.ps1
// streamed over stdin followed by the JSON config line.
func TestPowerShellWatchBootstrapExecutesCleanly(t *testing.T) {
	if n := len(encodedBootstrap()); n > 2048 {
		t.Fatalf("bootstrap EncodedCommand unexpectedly large: %d chars", n)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := commandContext(ctx)
	cfg, _ := json.Marshal(settings{
		State:   filepath.Join(t.TempDir(), "nonexistent-tun-state.json"),
		Runtime: t.TempDir(),
		Restore: true,
	})
	c.Stdin = strings.NewReader(encodedScriptLine() + string(cfg) + "\n")
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("powershell watch bootstrap failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "TUN_RESTORED") {
		t.Fatalf("expected TUN_RESTORED from watch.ps1, got: %q", string(out))
	}
}

// Verifies a 0-byte empty tun-state.json (left by v0.5.1) self-heals cleanly
// and a valid tun-state.json is parsed and removed cleanly with UTF-8 output.
func TestPowerShellWatchSelfHealsEmptyAndRestoresValidState(t *testing.T) {
	dir := t.TempDir()

	// 1. Empty 0-byte state file must be auto-removed without failing.
	emptyState := filepath.Join(dir, "empty-state.json")
	if err := os.WriteFile(emptyState, nil, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := commandContext(ctx)
	cfg, _ := json.Marshal(settings{State: emptyState, Runtime: dir, Restore: true})
	c.Stdin = strings.NewReader(encodedScriptLine() + string(cfg) + "\n")
	out, err := c.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "TUN_RESTORED") {
		t.Fatalf("empty state self-heal failed: %v out=%q", err, string(out))
	}
	if _, err := os.Stat(emptyState); !os.IsNotExist(err) {
		t.Fatalf("empty state file was not removed")
	}

	// 2. Valid saved state file must be restored and removed cleanly.
	validState := filepath.Join(dir, "valid-state.json")
	payload := `{"Alias":"tunnelX-abcdef012345","GUID":"{12345678-1234-1234-1234-123456789abc}","Routes":[],"ChildPID":0,"ChildStart":""}`
	if err := os.WriteFile(validState, []byte(payload), 0600); err != nil {
		t.Fatal(err)
	}
	c2 := commandContext(ctx)
	cfg2, _ := json.Marshal(settings{State: validState, Runtime: dir, Restore: true})
	c2.Stdin = strings.NewReader(encodedScriptLine() + string(cfg2) + "\n")
	out2, err2 := c2.CombinedOutput()
	if err2 != nil || !strings.Contains(string(out2), "TUN_RESTORED") {
		t.Fatalf("valid state restore failed: %v out=%q", err2, string(out2))
	}
	if _, err := os.Stat(validState); !os.IsNotExist(err) {
		t.Fatalf("valid state file was not removed")
	}
}

// Verifies watch.ps1's virtual-adapter filter classifies common VPN/TUN NICs as
// virtual while keeping hardware Ethernet/Wi-Fi adapters preferred as uplink.
func TestWatchScriptVirtualAdapterFilterAndUplink(t *testing.T) {
	start := strings.Index(script, "function Test-IsVirtualAdapter")
	end := strings.Index(script, "function Save-State")
	if start < 0 || end <= start {
		t.Fatal("could not locate Test-IsVirtualAdapter/Get-UplinkInfo in watch.ps1")
	}
	helper := script[start:end] + `
$cases = @(
    @{ Name='singbox_tun'; InterfaceDescription='sing-tun Tunnel'; HardwareInterface=$false; Want=$true },
    @{ Name='Clash'; InterfaceDescription='Wintun Userspace Tunnel'; HardwareInterface=$false; Want=$true },
    @{ Name='tunnelX-abcdef012345'; InterfaceDescription='Wintun'; HardwareInterface=$false; Want=$true },
    @{ Name='以太网'; InterfaceDescription='Red Hat VirtIO Ethernet Adapter'; HardwareInterface=$true; Want=$false },
    @{ Name='WLAN'; InterfaceDescription='Intel(R) Wi-Fi 6 AX201'; HardwareInterface=$true; Want=$false }
)
foreach ($c in $cases) {
    $nic = [PSCustomObject]@{ Name=$c.Name; InterfaceDescription=$c.InterfaceDescription; HardwareInterface=$c.HardwareInterface }
    $got = Test-IsVirtualAdapter $nic
    if ($got -ne $c.Want) { throw ("mismatch for " + $c.Name + ": got " + $got) }
}
$u = Get-UplinkInfo
if ($u.if_v4 -gt 0) {
    $picked = Get-NetAdapter -InterfaceIndex $u.if_v4 -ErrorAction SilentlyContinue
    $hasPhys = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | ForEach-Object {
        Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue
    } | Where-Object { $_ -and -not (Test-IsVirtualAdapter $_) }).Count -gt 0
    if ($hasPhys -and (Test-IsVirtualAdapter $picked)) {
        throw ("Get-UplinkInfo picked virtual adapter " + $picked.Name + " instead of physical NIC")
    }
}
[Console]::Out.WriteLine('UPLINK_FILTER_OK')
`
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := commandContext(ctx)
	encoded := strings.TrimPrefix(helper, "\xef\xbb\xbf")
	c.Stdin = strings.NewReader(base64.StdEncoding.EncodeToString([]byte(encoded)) + "\n")
	out, err := c.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "UPLINK_FILTER_OK") {
		t.Fatalf("uplink filter check failed: %v\noutput: %s", err, string(out))
	}
}
