//go:build windows

package processowner

import (
	"encoding/binary"
	"github.com/674542449/tunnelx-lite/internal/diagnostics"
	"golang.org/x/sys/windows"
	"net"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"
)

var getTCPTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

// Lookup matches the application's complete loopback TCP tuple, not merely a
// source port. No command line, executable path or account data is recorded.
func Lookup(peer, proxy net.Addr) diagnostics.Owner {
	p, ok := peer.(*net.TCPAddr)
	if !ok {
		return diagnostics.Owner{Error: "not_tcp"}
	}
	s, ok := proxy.(*net.TCPAddr)
	if !ok || !p.IP.IsLoopback() || !s.IP.IsLoopback() {
		return diagnostics.Owner{Error: "not_loopback_tcp"}
	}
	af, stride := uint32(2), 24
	if p.IP.To4() == nil {
		af = 23
		stride = 56
	}
	if e := getTCPTable.Find(); e != nil {
		return diagnostics.Owner{Error: "tcp_table_unavailable"}
	}
	var size uint32
	getTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(af), 5, 0)
	for attempt := 0; attempt < 3; attempt++ {
		if size < 4 || size > 16<<20 {
			return diagnostics.Owner{Error: "tcp_table_size"}
		}
		b := make([]byte, size)
		code, _, _ := getTCPTable.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(af), 5, 0)
		runtime.KeepAlive(b)
		if code == 122 {
			continue
		}
		if code != 0 {
			return diagnostics.Owner{Error: "tcp_table_unavailable"}
		}
		count := int(binary.LittleEndian.Uint32(b))
		if count > (len(b)-4)/stride {
			return diagnostics.Owner{Error: "tcp_table_invalid"}
		}
		for i := 0; i < count; i++ {
			r := b[4+i*stride : 4+(i+1)*stride]
			var local, remote net.IP
			var lp, rp uint16
			var pid uint32
			if af == 2 {
				local = net.IP(r[4:8])
				remote = net.IP(r[12:16])
				lp = binary.BigEndian.Uint16(r[8:10])
				rp = binary.BigEndian.Uint16(r[16:18])
				pid = binary.LittleEndian.Uint32(r[20:24])
			} else {
				local = net.IP(r[:16])
				remote = net.IP(r[24:40])
				lp = binary.BigEndian.Uint16(r[20:22])
				rp = binary.BigEndian.Uint16(r[44:46])
				pid = binary.LittleEndian.Uint32(r[52:56])
			}
			if int(lp) == p.Port && int(rp) == s.Port && local.Equal(p.IP) && remote.Equal(s.IP) && pid != 0 {
				return describe(pid)
			}
		}
		return diagnostics.Owner{Error: "connection_not_found"}
	}
	return diagnostics.Owner{Error: "tcp_table_changed"}
}
func describe(pid uint32) diagnostics.Owner {
	owner := diagnostics.Owner{PID: pid}
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e != nil {
		owner.Error = "process_unavailable"
		return owner
	}
	defer windows.CloseHandle(h)
	b := make([]uint16, 32768)
	size := uint32(len(b))
	if e = windows.QueryFullProcessImageName(h, 0, &b[0], &size); e != nil {
		owner.Error = "process_name_unavailable"
		return owner
	}
	owner.Name = filepath.Base(windows.UTF16ToString(b[:size]))
	owner.Matched = true
	var created, exit, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exit, &kernel, &user) == nil {
		owner.Created = time.Unix(0, created.Nanoseconds()).UTC().Format(time.RFC3339Nano)
	}
	return owner
}
