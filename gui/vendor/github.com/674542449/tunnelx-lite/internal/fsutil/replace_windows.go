//go:build windows

package fsutil

import (
	"errors"
	"golang.org/x/sys/windows"
	"time"
)

func replaceSnapshot(from, to string) error {
	a, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	b, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 6; attempt++ {
		err = windows.MoveFileEx(a, b, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return err
		}
		time.Sleep(time.Duration(1<<attempt) * 20 * time.Millisecond)
	}
	return err
}

// Directory fsync has no Windows equivalent. The file is flushed before replacement.
func syncDirectory(string) {}
