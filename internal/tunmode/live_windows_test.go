//go:build windows

package tunmode

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Opt-in elevated test. Capture only documentation/benchmark destinations,
// never a default route or the machine's real DNS policy.
func isolatedScript(t *testing.T) {
	t.Helper()
	if os.Getenv("TUNNELX_TUN_LIVE") != "1" {
		t.Skip("requires explicit isolated Wintun acceptance")
	}
	if !Elevated() {
		t.Fatal("administrator token required")
	}
	original := script
	script = strings.ReplaceAll(script, "@('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')", "@('198.19.77.0/24','fd02:198:19::/64')")
	var lines []string
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses") || strings.Contains(line, "Add-DnsClientNrptRule -Namespace") || strings.Contains(line, "Clear-DnsClientCache") {
			continue
		}
		lines = append(lines, line)
	}
	script = strings.Join(lines, "\n")
	t.Cleanup(func() { script = original })
}
func testSOCKS(t *testing.T) string {
	t.Helper()
	udp, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close(); udp.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			udp.WriteTo(b[:n], a)
		}
	}()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Minute))
				h := make([]byte, 2)
				if _, e := io.ReadFull(c, h); e != nil {
					return
				}
				methods := make([]byte, int(h[1]))
				if _, e := io.ReadFull(c, methods); e != nil {
					return
				}
				c.Write([]byte{5, 0})
				req := make([]byte, 4)
				if _, e := io.ReadFull(c, req); e != nil {
					return
				}
				size := 4
				switch req[3] {
				case 4:
					size = 16
				case 3:
					one := make([]byte, 1)
					if _, e := io.ReadFull(c, one); e != nil {
						return
					}
					size = int(one[0])
				}
				addr := make([]byte, size+2)
				if _, e := io.ReadFull(c, addr); e != nil {
					return
				}
				reply := []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}
				if req[1] == 3 {
					binary.BigEndian.PutUint16(reply[8:], uint16(udp.LocalAddr().(*net.UDPAddr).Port))
				}
				c.Write(reply)
				if req[1] == 3 {
					io.Copy(io.Discard, c)
				} else {
					io.Copy(c, c)
				}
			}()
		}
	}()
	return ln.Addr().String()
}
func TestWintunLiveTrafficAndRecovery(t *testing.T) {
	isolatedScript(t)
	state := filepath.Join(t.TempDir(), "tun.json")
	m := &Manager{}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if e := m.Start(ctx, state, testSOCKS(t), []string{"127.0.0.1"}); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { m.Close(); Recover(state) })
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		t.Run(network, func(t *testing.T) {
			target := "198.19.77.9:43210"
			if strings.HasSuffix(network, "6") {
				target = "[fd02:198:19::9]:43210"
			}
			c, e := net.DialTimeout(network, target, 8*time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(8 * time.Second))
			size := 512
			if strings.HasPrefix(network, "tcp") {
				size = 1 << 20
			}
			payload := bytes.Repeat([]byte{0x5a}, size)
			written := make(chan error, 1)
			go func() { _, e := c.Write(payload); written <- e }()
			received := make([]byte, size)
			_, e = io.ReadFull(c, received)
			if e != nil || !bytes.Equal(received, payload) {
				t.Fatal("Wintun payload mismatch", e)
			}
			if e = <-written; e != nil {
				t.Fatal(e)
			}
		})
	}
	if e := m.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(state); !os.IsNotExist(e) {
		t.Fatal("journal not removed", e)
	}
}
func TestWintunChildCrashRecovery(t *testing.T) {
	isolatedScript(t)
	state := filepath.Join(t.TempDir(), "tun.json")
	m := &Manager{}
	if e := m.Start(context.Background(), state, testSOCKS(t), []string{"127.0.0.1"}); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { m.Close(); Recover(state) })
	b, e := os.ReadFile(state)
	if e != nil {
		t.Fatal(e)
	}
	var journal struct{ ChildPID int }
	if e = json.Unmarshal(b, &journal); e != nil {
		t.Fatal(e)
	}
	p, e := os.FindProcess(journal.ChildPID)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Kill(); e != nil {
		t.Fatal(e)
	}
	select {
	case <-m.Done():
	case <-time.After(15 * time.Second):
		t.Fatal("watcher did not notice network-stack exit")
	}
	if _, e = os.Stat(state); !os.IsNotExist(e) {
		t.Fatal("crashed child left journal", e)
	}
}
func TestWintunNetworkChangeDetectionCleanup(t *testing.T) {
	isolatedScript(t)
	// Fault-inject only the signature provider; run the actual watcher polling,
	// notification, child exit and route/journal cleanup against a real Wintun.
	script = strings.Replace(script, "function Get-UplinkSignature {", "function Get-UplinkSignature {\n    $script:signatureCount++\n    if ($script:signatureCount -ge 2) { return 'simulated-new-uplink' }", 1)
	state := filepath.Join(t.TempDir(), "tun.json")
	m := &Manager{}
	if err := m.Start(context.Background(), state, testSOCKS(t), []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close(); Recover(state) })
	select {
	case <-m.Done():
	case <-time.After(25 * time.Second):
		t.Fatal("changed uplink was not detected")
	}
	if !m.NetworkChanged() {
		t.Fatal("network change was not propagated")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("network change left a journal", err)
	}
}
func TestTUNCrashOwner(t *testing.T) {
	if os.Getenv("TUNNELX_TUN_CRASH_CHILD") == "" {
		t.Skip("helper")
	}
	isolatedScript(t)
	state := os.Getenv("TUNNELX_TUN_CRASH_CHILD")
	m := &Manager{}
	if e := m.Start(context.Background(), state, os.Getenv("TUNNELX_TUN_SOCKS"), []string{"127.0.0.1"}); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(state+".ready", []byte("ready"), 0600)
	select {}
}
func TestWintunOwnerCrashRecovery(t *testing.T) {
	isolatedScript(t)
	state := filepath.Join(t.TempDir(), "tun.json")
	exe, _ := os.Executable()
	c := exec.Command(exe, "-test.run=^TestTUNCrashOwner$", "-test.timeout=90s")
	c.Env = append(os.Environ(), "TUNNELX_TUN_CRASH_CHILD="+state, "TUNNELX_TUN_SOCKS="+testSOCKS(t))
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	if e := c.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Process.Kill(); Recover(state) })
	ready := false
	for deadline := time.Now().Add(50 * time.Second); time.Now().Before(deadline); {
		if _, e := os.Stat(state + ".ready"); e == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		c.Process.Kill()
		c.Wait()
		t.Fatal(fmt.Sprintf("child start failed: %s", out.String()))
	}
	c.Process.Kill()
	c.Wait()
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
		if _, e := os.Stat(state); os.IsNotExist(e) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("owner crash left TUN routes journal")
}
