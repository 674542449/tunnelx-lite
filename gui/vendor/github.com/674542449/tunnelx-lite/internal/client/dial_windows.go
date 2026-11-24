//go:build windows

package client

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/windows"
)

// tuneCarrierTCP optimizes outbound TCP sockets on Windows where the default
// Winsock AFD receive/send buffers can throttle high-BDP cross-border links.
func tuneCarrierTCP(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetReadBuffer(8 << 20)
		_ = tcp.SetWriteBuffer(4 << 20)
	}
}

func tuneLocalTCP(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetReadBuffer(4 << 20)
		_ = tcp.SetWriteBuffer(4 << 20)
	}
}

const (
	ipUnicastIf   = 31 // IP_UNICAST_IF (ws2ipdef.h): expects interface index in network byte order (htonl)
	ipv6UnicastIf = 31 // IPV6_UNICAST_IF (ws2ipdef.h): expects interface index in host byte order
)

func htonl(v uint32) uint32 {
	return (v&0x000000ff)<<24 | (v&0x0000ff00)<<8 | (v&0x00ff0000)>>8 | (v&0xff000000)>>24
}

// uplinkControl returns a net.Dialer.Control callback that binds non-loopback
// outbound sockets to the physical uplink interface so direct traffic and
// domestic DNS queries bypass TUN capture routes instead of looping back.
func uplinkControl(ifV4, ifV6 uint32) func(network, address string, c syscall.RawConn) error {
	if ifV4 == 0 && ifV6 == 0 {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err == nil {
			if addr, err := netip.ParseAddr(host); err == nil && addr.Unmap().IsLoopback() {
				return nil
			}
		}
		var sockErr error
		ctrlErr := c.Control(func(fd uintptr) {
			switch network {
			case "tcp4", "udp4":
				if ifV4 != 0 {
					sockErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, int(htonl(ifV4)))
				}
			case "tcp6", "udp6":
				if ifV6 != 0 {
					sockErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, ipv6UnicastIf, int(ifV6))
				}
			}
		})
		if ctrlErr != nil {
			return ctrlErr
		}
		return sockErr
	}
}
