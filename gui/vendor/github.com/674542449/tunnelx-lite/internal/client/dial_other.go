//go:build !windows

package client

import (
	"net"
	"syscall"
)

func uplinkControl(ifV4, ifV6 uint32) func(network, address string, c syscall.RawConn) error {
	return nil
}

// tuneCarrierTCP disables Nagle without locking SO_RCVBUF/SO_SNDBUF on Unix so
// Linux/macOS dynamic TCP window autotuning can scale to the full sysctl ceiling.
func tuneCarrierTCP(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
}

func tuneLocalTCP(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
}
