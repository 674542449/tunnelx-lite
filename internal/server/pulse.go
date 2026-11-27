package server

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/674542449/tunnelx-lite/internal/pulse"
)

// ResolveTarget 复用主服务端的 DNS 缓存、私网拦截与强制 IPv4 落地出站策略。
func (s *Server) ResolveTarget(ctx context.Context, host, target string) ([]net.IP, int) {
	return s.resolve(ctx, host, target)
}

// DialTargetTCP 复用主服务端的 Happy Eyeballs 拨号与出站 IPv4-only 规范。
func (s *Server) DialTargetTCP(ctx context.Context, ips []net.IP, port string) (net.Conn, error) {
	tcpNet := "tcp"
	if s.Config.OutboundIP == "ipv4" {
		tcpNet = "tcp4"
	} else if s.Config.OutboundIP == "ipv6" {
		tcpNet = "tcp6"
	}
	return dialTarget(ctx, tcpNet, ips, port)
}

// DialTargetUDP 复用主服务端的出站 IPv4-only UDP 落地策略。
func (s *Server) DialTargetUDP(ip net.IP, port int) (*net.UDPConn, error) {
	udpNet := "udp"
	if s.Config.OutboundIP == "ipv4" {
		udpNet = "udp4"
	} else if s.Config.OutboundIP == "ipv6" {
		udpNet = "udp6"
	}
	return net.DialUDP(udpNet, nil, &net.UDPAddr{IP: ip, Port: port})
}

// NewPulseServer 构建与当前 Server 共享流量统计、并发计数、整机限速及仅 IPv4 落地出站的 TXPulse UDP 服务端。
func (s *Server) NewPulseServer() (*pulse.Server, error) {
	if s.Config.PulseListen == "" {
		return nil, errors.New("server: pulse_listen not configured")
	}
	if len(s.Config.Tokens) == 0 {
		return nil, errors.New("server: pulse requires at least one token")
	}
	var upLim, downLim pulse.Limiter
	if s.upLimit != nil {
		upLim = s.upLimit
	}
	if s.downLimit != nil {
		downLim = s.downLimit
	}
	var maxBPS uint64
	if s.Config.BandwidthLimit > 0 {
		maxBPS = uint64(s.Config.BandwidthLimit)
	}
	return pulse.NewServer(pulse.ServerConfig{
		Listen:      s.Config.PulseListen,
		Network:     s.Config.Network,
		HopStart:    s.Config.PulseHopStart,
		HopEnd:      s.Config.PulseHopEnd,
		CertFile:    s.Config.PulseCertFile,
		KeyFile:     s.Config.PulseKeyFile,
		Token:       s.Config.Tokens[0],
		ObfsKey:     s.Config.PulseObfs,
		DialTimeout: time.Duration(s.Config.DialTimeout) * time.Second,
		IdleTimeout: time.Duration(s.Config.IdleTimeout) * time.Second,
		MaxStreams:  s.Config.MaxConnections,
		MaxBPS:      maxBPS,
		UpLimit:     upLim,
		DownLimit:   downLim,
		Dialer:      s,
		Active:      &s.Active,
		Uploaded:    &s.Uploaded,
		Downloaded:  &s.Downloaded,
	})
}
