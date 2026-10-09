//go:build !windows

package fsutil

import "os"

func replaceSnapshot(from, to string) error { return os.Rename(from, to) }
func syncDirectory(path string) {
	if d, err := os.Open(path); err == nil {
		defer d.Close()
		_ = d.Sync()
	}
}
