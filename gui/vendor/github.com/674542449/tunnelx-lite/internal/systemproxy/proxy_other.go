//go:build !windows

package systemproxy

import (
	"errors"
	"fmt"
)

type Manager struct {
	Path  string
	Proxy string
}

func (m *Manager) Enable() error        { return errors.New("system proxy is available on Windows only") }
func (m *Manager) Restore() error       { return nil }
func (m *Manager) RestoreOrphan() error { return nil }
func (m *Manager) RecoverOrphan() error { return nil }
func (m *Manager) Enabled() bool        { return false }
func OpenBrowser(url string) error      { fmt.Println(url); return nil }
func ShowError(message string)          { fmt.Println(message) }
