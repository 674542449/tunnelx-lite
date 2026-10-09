//go:build !windows

package tunmode

import (
	"context"
	"errors"
)

type Manager struct{}

func Elevated() bool           { return false }
func RuntimeDir() string       { return "" }
func CheckAssets(string) error { return errors.New("TUN 仅支持 Windows") }
func Availability() map[string]any {
	return map[string]any{"supported": false, "elevated": false, "assets_ready": false}
}
func (m *Manager) Start(context.Context, string, string, []string) error {
	return errors.New("TUN 仅支持 Windows")
}
func (m *Manager) Close() error          { return nil }
func (m *Manager) Done() <-chan struct{} { return nil }
func Recover(string) error               { return nil }
func (m *Manager) NetworkChanged() bool  { return false }
func FlushDNS(context.Context) error     { return nil }
