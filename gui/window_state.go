//go:build windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/674542449/tunnelx-lite/internal/fsutil"
	rt "github.com/wailsapp/wails/v2/pkg/runtime"
)

type windowState struct {
	Width     int  `json:"width"`
	Height    int  `json:"height"`
	Maximised bool `json:"maximised"`
}

func loadWindowState(root string) windowState {
	state := windowState{Width: 960, Height: 680}
	data, err := os.ReadFile(filepath.Join(root, "window.json"))
	if err != nil || len(data) > 1024 {
		return state
	}
	var saved windowState
	if json.Unmarshal(data, &saved) == nil && saved.Width >= 700 && saved.Width <= 3840 && saved.Height >= 560 && saved.Height <= 2160 {
		return saved
	}
	return state
}

func (a *App) rememberWindow() {
	if a.ctx == nil || rt.WindowIsMinimised(a.ctx) {
		return
	}
	state := loadWindowState(a.dataDir)
	state.Maximised = rt.WindowIsMaximised(a.ctx)
	if !state.Maximised {
		w, h := rt.WindowGetSize(a.ctx)
		state.Width, state.Height = max(700, min(3840, w)), max(560, min(2160, h))
	}
	if data, err := json.Marshal(state); err == nil {
		// Geometry is optional. A failed write must never prevent quitting or proxy restoration.
		_ = fsutil.WriteFile(filepath.Join(a.dataDir, "window.json"), data)
	}
}
