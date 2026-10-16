// Package congestion switches QUIC connections to BBR.
//
// The bbr and common packages are copied from Hysteria
// (github.com/apernet/hysteria core/v2 internal/congestion, MIT licence, see
// LICENSE-hysteria.md). Loss-based controllers collapse on links where the
// ISP drops a share of UDP packets; BBR follows the measured bandwidth.
package congestion

import (
	"github.com/674542449/tunnelx-lite/internal/congestion/bbr"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/congestion"
)

// UseBBR replaces the connection's congestion controller with BBR.
func UseBBR(conn *quic.Conn) {
	conn.SetCongestionControl(bbr.NewBbrSender(
		bbr.DefaultClock{},
		seedPacketSize(conn.InitialPacketSize(), bbr.GetInitialPacketSize(conn.RemoteAddr())),
		bbr.ProfileStandard,
	))
}

// seedPacketSize never seeds the controller above the size QUIC starts at, so
// a later path MTU increase is never seen as a decrease (from Hysteria).
func seedPacketSize(quicSize, byAddr congestion.ByteCount) congestion.ByteCount {
	if quicSize <= 0 {
		return byAddr
	}
	return min(quicSize, byAddr)
}
