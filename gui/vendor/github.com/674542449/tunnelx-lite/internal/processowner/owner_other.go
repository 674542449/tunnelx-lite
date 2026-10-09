//go:build !windows

package processowner

import (
	"github.com/674542449/tunnelx-lite/internal/diagnostics"
	"net"
)

func Lookup(peer, proxy net.Addr) diagnostics.Owner {
	return diagnostics.Owner{Error: "unsupported_platform"}
}
