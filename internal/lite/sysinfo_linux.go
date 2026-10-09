package lite

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func readTrim(path string) string {
	b, _ := os.ReadFile(path)
	return strings.TrimSpace(string(b))
}

func systemInfo() map[string]any {
	info := map[string]any{"congestion": readTrim("/proc/sys/net/ipv4/tcp_congestion_control"), "qdisc": readTrim("/proc/sys/net/core/default_qdisc"), "kernel": readTrim("/proc/sys/kernel/osrelease")}
	if f := strings.Fields(readTrim("/proc/loadavg")); len(f) >= 3 {
		info["load"] = f[0] + " " + f[1] + " " + f[2]
	}
	if f, e := os.Open("/proc/meminfo"); e == nil {
		s := bufio.NewScanner(f)
		for s.Scan() {
			p := strings.Fields(s.Text())
			if len(p) >= 2 && (p[0] == "MemTotal:" || p[0] == "MemAvailable:") {
				kb, _ := strconv.ParseInt(p[1], 10, 64)
				info[map[string]string{"MemTotal:": "mem_total", "MemAvailable:": "mem_available"}[p[0]]] = kb * 1024
			}
		}
		f.Close()
	}
	var st syscall.Statfs_t
	if syscall.Statfs("/", &st) == nil {
		info["disk_total"] = int64(st.Blocks) * int64(st.Bsize)
		info["disk_free"] = int64(st.Bavail) * int64(st.Bsize)
	}
	for _, line := range strings.Split(readTrim("/etc/os-release"), "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			info["os"] = strings.Trim(v, `"`)
		}
	}
	return info
}
