//go:build !windows

package lite

import (
	"os"
	"syscall"
)

func matchOwner(path, dir string) {
	if os.Geteuid() != 0 {
		return
	}
	if info, e := os.Stat(dir); e == nil {
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			os.Chown(path, int(st.Uid), int(st.Gid))
		}
	}
}
