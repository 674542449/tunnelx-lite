//go:build !linux

package lite

import "runtime"

func systemInfo() map[string]any { return map[string]any{"os": runtime.GOOS} }
