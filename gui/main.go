//go:build windows

package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/getlantern/systray"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	rt "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/674542449/tunnelx-lite/internal/app"
	"github.com/674542449/tunnelx-lite/internal/config"
	"github.com/674542449/tunnelx-lite/internal/fsutil"
	"github.com/674542449/tunnelx-lite/internal/systemproxy"
)

//go:embed ui/*
var assets embed.FS

//go:embed build/windows/tray.ico
var trayIcon []byte

const webView2URL = "https://developer.microsoft.com/en-us/microsoft-edge/webview2/"

type App struct {
	engine  *app.Engine
	ctx     context.Context
	dataDir string
}

type ImportResult struct {
	Added   int `json:"added"`
	Updated int `json:"updated"`
}

func (a *App) Status() map[string]any {
	s := a.engine.Status()
	s["data_directory"] = a.dataDir
	return s
}
func (a *App) Servers() []app.ServerView { return a.engine.Servers() }
func (a *App) Import(text string) (ImportResult, error) {
	added, updated, err := a.engine.Import(text)
	return ImportResult{added, updated}, err
}
func (a *App) ImportClipboard() (ImportResult, error) {
	text, err := rt.ClipboardGetText(a.ctx)
	if err != nil {
		return ImportResult{}, errors.New("无法读取剪贴板")
	}
	return a.Import(text)
}
func (a *App) CopyShareLink(id string) error {
	link, err := a.engine.ShareLink(id)
	if err != nil {
		return err
	}
	return rt.ClipboardSetText(a.ctx, link)
}
func (a *App) Rename(id, name string) error        { return a.engine.Rename(id, name) }
func (a *App) Remove(id string) error              { return a.engine.Remove(id) }
func (a *App) Connect(id string, proxy bool) error { return a.engine.Connect(id, proxy) }
func (a *App) Disconnect() error                   { return a.engine.Disconnect() }
func (a *App) CancelConnect() error                { return a.engine.CancelConnect() }
func (a *App) Probe(id string) (int64, error)      { return a.engine.Probe(id) }
func (a *App) ProbeAll() []app.ProbeResult         { return a.engine.ProbeAll() }
func (a *App) SavePreferences(id string, proxy bool) error {
	return a.engine.SavePreferences(id, proxy)
}
func (a *App) SetSystemProxy(enabled bool) error { return a.engine.SetSystemProxy(enabled) }
func (a *App) SaveProxyMode(mode, exceptions string) error {
	return a.engine.SaveProxyMode(mode, exceptions)
}
func (a *App) UpdateRoutingRules() error { return a.engine.UpdateRoutingRules() }
func (a *App) RecoverProxy() error       { return a.engine.RecoverProxy() }
func (a *App) ConnLogs() []app.ConnLog   { return a.engine.ConnLogs() }
func (a *App) OpenLogs() error {
	return exec.Command("explorer.exe", filepath.Join(a.dataDir, "logs")).Start()
}
func (a *App) ExportDiagnostics() (string, error) {
	path, err := rt.SaveFileDialog(a.ctx, rt.SaveDialogOptions{Title: "导出脱敏诊断报告", DefaultFilename: "txlite-diagnostics-" + time.Now().Format("20060102-150405") + ".txt", Filters: []rt.FileFilter{{DisplayName: "文本文件 (*.txt)", Pattern: "*.txt"}}, CanCreateDirectories: true})
	if err != nil || path == "" {
		return "", err
	}
	report, err := a.engine.DiagnosticsReport()
	if err != nil {
		return "", err
	}
	if err = fsutil.WriteFile(path, []byte(report)); err != nil {
		return "", fmt.Errorf("诊断报告保存失败，请选择其他位置")
	}
	return path, nil
}
func (a *App) SetTheme(theme string) error {
	if a.ctx == nil {
		return errors.New("窗口尚未就绪")
	}
	switch theme {
	case "light":
		rt.WindowSetLightTheme(a.ctx)
	case "dark":
		rt.WindowSetDarkTheme(a.ctx)
	case "system":
		rt.WindowSetSystemDefaultTheme(a.ctx)
	default:
		return errors.New("不支持的颜色主题")
	}
	return nil
}
func (a *App) Minimize() { rt.WindowHide(a.ctx) }
func (a *App) Quit() error {
	// A failed proxy restore after the tunnel is down must not trap the user:
	// the saved state is kept and restored on the next start.
	if err := a.engine.Disconnect(); err != nil && a.engine.Status()["connected"] == true {
		return err
	}
	a.rememberWindow()
	rt.Quit(a.ctx)
	return nil
}

func (a *App) toggleConnection() {
	s := a.engine.Status()
	if s["connected"] == true {
		_ = a.engine.Disconnect()
		return
	}
	p, _ := s["preferences"].(app.Preferences)
	if p.SelectedID == "" || a.engine.Connect(p.SelectedID, p.SystemProxy) != nil {
		rt.WindowShow(a.ctx)
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	if loadWindowState(a.dataDir).Maximised {
		rt.WindowMaximise(ctx)
	}
	a.engine.RestoreProxyAtStartup()
	go systray.Run(func() {
		systray.SetIcon(trayIcon)
		systray.SetTitle("txlite")
		systray.SetTooltip("txlite")
		show := systray.AddMenuItem("显示主界面", "")
		toggle := systray.AddMenuItem("连接 / 断开", "")
		systray.AddSeparator()
		quit := systray.AddMenuItem("退出", "")
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-show.ClickedCh:
					rt.WindowShow(ctx)
				case <-toggle.ClickedCh:
					a.toggleConnection()
				case <-quit.ClickedCh:
					if a.Quit() != nil {
						rt.WindowShow(ctx)
					} else {
						return
					}
				}
			}
		}()
	}, func() {})
}

func dataDirectory(exeDir, stateDir string) (string, error) {
	if stateDir != "" {
		return filepath.Abs(stateDir)
	}
	// A "portable" folder next to the program keeps everything beside it.
	if info, err := os.Stat(filepath.Join(exeDir, "portable")); err == nil && info.IsDir() {
		return filepath.Join(exeDir, "portable"), nil
	}
	local := os.Getenv("LOCALAPPDATA")
	if strings.TrimSpace(local) == "" {
		return "", errors.New("无法确定本机应用数据目录，请使用 -state-dir 指定可写位置")
	}
	return filepath.Join(local, "txlite"), nil
}

func run() error {
	exe, err := os.Executable()
	if err != nil {
		return errors.New("无法确定程序所在位置")
	}
	stateDir := flag.String("state-dir", "", "independent data directory")
	flag.Parse()
	dir, err := dataDirectory(filepath.Dir(exe), *stateDir)
	if err != nil {
		return err
	}
	var settings app.Settings
	if err = config.Read(filepath.Join(dir, "settings.json"), &settings); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("settings.json 无法读取：%w", err)
	}
	engine, err := app.New(dir, settings)
	if err != nil {
		return err
	}
	defer engine.Close()
	a := &App{engine: engine, dataDir: dir}
	ui, err := fs.Sub(assets, "ui")
	if err != nil {
		return err
	}
	messages := windows.DefaultMessages()
	messages.MissingRequirements, messages.Error = "txlite · 缺少运行环境", "txlite · 启动失败"
	messages.Webview2NotInstalled = "Microsoft Edge WebView2 运行时尚未安装或需要更新"
	messages.ContactAdmin = "txlite 需要 Microsoft Edge WebView2 Runtime。\n请从微软官网安装 Evergreen Runtime 后重新打开：\n" + webView2URL
	geometry := loadWindowState(dir)
	return wails.Run(&options.App{
		Title: "txlite", Width: geometry.Width, Height: geometry.Height, MinWidth: 760, MinHeight: 520,
		AssetServer: &assetserver.Options{Assets: ui}, BackgroundColour: &options.RGBA{R: 245, G: 246, B: 248, A: 255},
		OnStartup: a.startup, OnBeforeClose: func(context.Context) bool { a.rememberWindow(); return false },
		OnShutdown: func(context.Context) { engine.Close(); systray.Quit() }, HideWindowOnClose: true, Bind: []any{a},
		SingleInstanceLock: &options.SingleInstanceLock{UniqueId: "7c8bd4f0-0e3f-4b1b-9f1a-3b1e1d7c6a11", OnSecondInstanceLaunch: func(options.SecondInstanceData) {
			if a.ctx != nil {
				rt.WindowShow(a.ctx)
			}
		}},
		Windows: &windows.Options{Theme: windows.SystemDefault, Messages: messages, WebviewUserDataPath: filepath.Join(dir, "webview2")},
	})
}

func main() {
	if err := run(); err != nil {
		message := "txlite 启动失败。\n" + err.Error() + "\n\n如果提示 WebView2 缺失，请安装：" + webView2URL
		fmt.Fprintln(os.Stderr, message)
		systemproxy.ShowError(message)
		os.Exit(1)
	}
}
