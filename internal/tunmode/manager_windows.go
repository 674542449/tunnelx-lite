//go:build windows

// Package tunmode owns only tunnelX's adapter, routes and DNS policy.
package tunmode

import (
	"bufio"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

//go:embed watch.ps1
var script string

//go:embed assets.json
var assetManifest []byte

type Manager struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	input   io.WriteCloser
	done    chan struct{}
	err     error
	state   string
	changed bool
}

func Elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }
func RuntimeDir() string {
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "runtime")
}
func CheckAssets(dir string) error {
	var expected map[string]string
	if json.Unmarshal(assetManifest, &expected) != nil || len(expected) != 2 {
		return errors.New("TUN 组件清单无效")
	}
	for name, digest := range expected {
		if name != "tun2socks.exe" && name != "wintun.dll" {
			return errors.New("TUN 组件清单无效")
		}
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			return errors.New("缺少 TUN 组件，请完整解压客户端安装包")
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != digest {
			return errors.New("TUN 组件校验失败，请重新下载完整安装包")
		}
	}
	return nil
}
func Availability() map[string]any {
	e := CheckAssets(RuntimeDir())
	v := map[string]any{"supported": true, "elevated": Elevated(), "assets_ready": e == nil}
	if e != nil {
		v["error"] = e.Error()
	}
	return v
}

type settings struct {
	State   string
	Runtime string
	SOCKS   string
	Exempt  []string
	Restore bool
}

func encodedScript() string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		b[2*i] = byte(c)
		b[2*i+1] = byte(c >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}
func command() *exec.Cmd {
	return commandContext(context.Background())
}
func commandContext(ctx context.Context) *exec.Cmd {
	c := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodedScript())
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return c
}
func (m *Manager) Start(ctx context.Context, state, socks string, exempt []string) error {
	if !Elevated() {
		return errors.New("TUN 需要管理员权限。请退出客户端，右键选择“以管理员身份运行”，再连接。")
	}
	dir := RuntimeDir()
	if e := CheckAssets(dir); e != nil {
		return e
	}
	h, p, e := net.SplitHostPort(socks)
	if e != nil {
		return e
	}
	a, e := netip.ParseAddr(h)
	if e != nil || !a.IsLoopback() {
		return errors.New("TUN SOCKS 地址必须是本机回环地址")
	}
	if _, e = net.LookupPort("tcp", p); e != nil {
		return e
	}
	for _, s := range exempt {
		if _, e = netip.ParseAddr(s); e != nil {
			return errors.New("TUN 出口地址无效")
		}
	}
	if len(exempt) == 0 {
		return errors.New("TUN 缺少节点出口地址")
	}
	c := command()
	input, e := c.StdinPipe()
	if e != nil {
		return e
	}
	out, e := c.StdoutPipe()
	if e != nil {
		return e
	}
	c.Stderr = io.Discard
	if e = c.Start(); e != nil {
		return e
	}
	m.mu.Lock()
	m.cmd = c
	m.input = input
	m.done = make(chan struct{})
	m.state = state
	m.mu.Unlock()
	if e = json.NewEncoder(input).Encode(settings{State: state, Runtime: dir, SOCKS: net.JoinHostPort(a.String(), p), Exempt: exempt}); e != nil {
		input.Close()
		c.Process.Kill()
		c.Wait()
		close(m.done)
		return e
	}
	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(out)
		reported := false
		var detail string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "TUN_READY" && !reported {
				ready <- nil
				reported = true
			}
			if strings.HasPrefix(line, "TUN_ERROR:") {
				detail = strings.TrimPrefix(line, "TUN_ERROR:")
			}
			if strings.HasPrefix(line, "TUN_NETWORK_CHANGED:") {
				m.mu.Lock()
				m.changed = true
				m.mu.Unlock()
			}
		}
		err := c.Wait()
		if detail != "" {
			err = errors.New(detail)
		}
		m.mu.Lock()
		m.err = err
		m.mu.Unlock()
		if !reported {
			if err == nil {
				err = errors.New("TUN 未能启动")
			}
			ready <- err
		}
		close(m.done)
	}()
	select {
	case e := <-ready:
		if e != nil {
			m.Close()
		}
		return e
	case <-ctx.Done():
		m.Close()
		return ctx.Err()
	case <-time.After(45 * time.Second):
		m.Close()
		return errors.New("TUN 启动超时，请检查管理员权限与虚拟网卡")
	}
}
func (m *Manager) Done() <-chan struct{} { return m.done }
func (m *Manager) NetworkChanged() bool  { m.mu.Lock(); defer m.mu.Unlock(); return m.changed }
func FlushDNS(ctx context.Context) error {
	c := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "ipconfig.exe"), "/flushdns")
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return c.Run()
}
func (m *Manager) Close() error {
	m.mu.Lock()
	input, done, c, state := m.input, m.done, m.cmd, m.state
	m.input = nil
	m.mu.Unlock()
	if done == nil {
		return nil
	}
	if input != nil {
		input.Close()
	}
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		if c != nil {
			c.Process.Kill()
		}
		return fmt.Errorf("TUN 清理超时，请以管理员权限使用“恢复网络”：%s", filepath.Base(state))
	}
	m.mu.Lock()
	err := m.err
	m.mu.Unlock()
	if err != nil {
		return errors.Join(err, Recover(state))
	}
	return nil
}
func Recover(state string) error {
	if _, e := os.Stat(state); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	if !Elevated() {
		return errors.New("发现未清理的 TUN 状态，请以管理员权限启动后恢复网络")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := commandContext(ctx)
	b, _ := json.Marshal(settings{State: state, Runtime: RuntimeDir(), Restore: true})
	c.Stdin = strings.NewReader(string(b) + "\n")
	c.WaitDelay = 5 * time.Second
	out, e := c.Output()
	if e != nil {
		return errors.New("TUN 网络恢复未完成，请以管理员权限重试")
	}
	if strings.Contains(string(out), "TUN_ERROR:") {
		return errors.New("TUN 网络恢复未完成，请重试")
	}
	return nil
}
