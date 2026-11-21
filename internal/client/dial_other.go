//go:build !windows

package client

import "syscall"

func uplinkControl(ifV4, ifV6 uint32) func(network, address string, c syscall.RawConn) error {
	return nil
}
