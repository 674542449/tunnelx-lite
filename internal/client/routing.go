package client

import (
	"context"
	"errors"
	"github.com/674542449/tunnelx-lite/internal/routing"
	"net"
	"net/netip"
	"time"
)

func (p *Proxy) route(ctx context.Context, target string) routing.Decision {
	d := routing.Decision{Address: target, Reason: "global_proxy"}
	if p.Router != nil {
		d = p.Router.Decide(ctx, target)
	} else if localTarget(target) {
		// The server refuses private targets, so LAN devices are only reachable directly.
		d = routing.Decision{Address: target, Direct: true, Reason: "local_network"}
	}
	route := "proxy"
	if d.Direct {
		route = "direct"
	}
	flowFrom(ctx).event("route_selected", map[string]any{"route": route, "rule": d.Reason})
	return d
}
func localTarget(target string) bool {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && (a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified())
}
func (p *Proxy) openTCP(ctx context.Context, target string) (*Tunnel, error) {
	if p.TUN {
		if _, port, _ := net.SplitHostPort(target); port == "53" {
			return p.dnsTCP(ctx), nil
		}
		if p.unsupportedIPv6(target) {
			flowFrom(ctx).failure("tun_ipv6_unavailable", errTUNIPv6Unavailable)
			return nil, errTUNIPv6Unavailable
		}
	}
	d := p.route(ctx, target)
	if !d.Direct {
		return p.Mux.OpenTCPFast(ctx, target)
	}
	c, e := (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", d.Address)
	if e != nil {
		flowFrom(ctx).failure("direct_dial", e)
		return nil, e
	}
	stop := context.AfterFunc(p.ctx, func() { c.Close() })
	t := &Tunnel{Reader: c, Writer: c, close: func() error { stop(); return c.Close() }, closeWrite: func() error {
		if tcp, ok := c.(*net.TCPConn); ok {
			return tcp.CloseWrite()
		}
		return nil
	}, setDeadline: c.SetDeadline, transport: "direct"}
	flowFrom(ctx).openedOn(t)
	return t, nil
}

type packetTransport interface {
	Send([]byte) error
	Receive(context.Context) ([]byte, error)
	Close() error
}
type directPackets struct {
	c    net.Conn
	stop func() bool
}

func (d *directPackets) Send(b []byte) error {
	d.c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, e := d.c.Write(b)
	return e
}
func (d *directPackets) Receive(ctx context.Context) ([]byte, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	d.c.SetReadDeadline(time.Now().Add(120 * time.Second))
	b := make([]byte, 65535)
	n, e := d.c.Read(b)
	return b[:n], e
}
func (d *directPackets) Close() error { d.stop(); return d.c.Close() }
func (p *Proxy) openUDP(ctx context.Context, target string) (packetTransport, error) {
	if p.TUN {
		if _, port, _ := net.SplitHostPort(target); port == "53" {
			return p.dnsUDP(ctx), nil
		}
		if p.unsupportedIPv6(target) {
			flowFrom(ctx).failure("tun_ipv6_unavailable", errTUNIPv6Unavailable)
			return nil, errTUNIPv6Unavailable
		}
	}
	d := p.route(ctx, target)
	if !d.Direct {
		return p.Mux.OpenUDP(ctx, target)
	}
	c, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", d.Address)
	if e != nil {
		flowFrom(ctx).failure("direct_udp_dial", e)
		return nil, e
	}
	flowFrom(ctx).openedOn(&Tunnel{transport: "direct"})
	return &directPackets{c: c, stop: context.AfterFunc(ctx, func() { c.Close() })}, nil
}

var errTUNIPv6Unavailable = errors.New("节点 IPv6 出口不可用，使用 IPv4 连接")

func (p *Proxy) unsupportedIPv6(target string) bool {
	host, _, e := net.SplitHostPort(target)
	if e != nil || p.TUNIPv6.Load() {
		return false
	}
	a, e := netip.ParseAddr(host)
	return e == nil && a.Unmap().Is6()
}
