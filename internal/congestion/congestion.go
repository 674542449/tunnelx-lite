// Package congestion switches QUIC connections to BBR.
//
// The bbr and common packages are copied from Hysteria
// (github.com/apernet/hysteria core/v2 internal/congestion, MIT licence, see
// LICENSE-hysteria.md). Loss-based controllers collapse on links where the
// ISP drops a share of UDP packets; BBR follows the measured bandwidth.
package congestion

import (
	"github.com/674542449/tunnelx-lite/internal/congestion/bbr"
	"github.com/674542449/tunnelx-lite/internal/congestion/brutal"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/congestion"
)

// UseBBR replaces the connection's congestion controller with BBR.
func UseBBR(conn *quic.Conn) { UseBBRProfile(conn, bbr.ProfileStandard) }

// UseBBRProfile selects a BBR tuning ("standard", "conservative", "aggressive").
func UseBBRProfile(conn *quic.Conn, profile bbr.Profile) {
	conn.SetCongestionControl(bbr.NewBbrSender(
		bbr.DefaultClock{},
		seedPacketSize(conn.InitialPacketSize(), bbr.GetInitialPacketSize(conn.RemoteAddr())),
		profile,
	))
}

// UseBrutal sends at a fixed rate in bytes per second and does not back off
// on loss (Hysteria's Brutal), compensating the rate for measured loss.
func UseBrutal(conn *quic.Conn, bytesPerSecond uint64) {
	conn.SetCongestionControl(brutal.NewBrutalSender(bytesPerSecond, false))
}

// seedPacketSize never seeds the controller above the size QUIC starts at, so
// a later path MTU increase is never seen as a decrease (from Hysteria).
func seedPacketSize(quicSize, byAddr congestion.ByteCount) congestion.ByteCount {
	if quicSize <= 0 {
		return byAddr
	}
	return min(quicSize, byAddr)
}
