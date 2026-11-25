//go:build windows

package tunmode

import (
	"context"
	"encoding/json"
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
