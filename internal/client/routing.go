package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/674542449/tunnelx-lite/internal/routing"
)

func (p *Proxy) route(ctx context.Context, target string) routing.Decision {
	d := routing.Decision{Address: target, Reason: "global_proxy"}
	if r := p.getRouter(); r != nil {
		d = r.Decide(ctx, target)
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
	if routing.IsLocalDomain(host) {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && routing.IsLocalIP(a)
}

func (p *Proxy) directDialer(timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	if p.TUN {
		u := p.getUplink()
		d.Control = uplinkControl(u.ifV4, u.ifV6)
	}
	return d
}

// dialDirectContext dials a direct destination, optionally using encrypted
// domestic DoH (default AliDNS) for public CN domain names in non-TUN mode so
// ISP UDP/53 hijacking cannot redirect or break direct connections.
func (p *Proxy) dialDirectContext(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	dialer := p.directDialer(timeout)
	if !p.TUN && p.getDNSConfig().Enabled {
		if host, port, err := net.SplitHostPort(addr); err == nil {
			if _, ipErr := netip.ParseAddr(host); ipErr != nil {
				r := p.getRouter()
				if !routing.IsLocalDomain(host) && (r == nil || !r.IsLocalOrPrivateDomain(host)) {
					if ips, lerr := p.LookupDomesticIPs(ctx, host); lerr == nil && len(ips) > 0 {
						var lastErr error
						for _, ip := range ips {
							c, derr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
							if derr == nil {
								return c, nil
							}
							lastErr = derr
						}
						if lastErr != nil {
							// Fall back to system resolver if DoH IPs failed.
							if c, derr := dialer.DialContext(ctx, network, addr); derr == nil {
								return c, nil
							}
							return nil, lastErr
						}
					}
				}
			}
		}
	}
	return dialer.DialContext(ctx, network, addr)
}

func (p *Proxy) openTCP(ctx context.Context, target string) (*Tunnel, error) {
	return p.openTCPWithHint(ctx, target, target)
}

// openTCPWithHint routes using routeTarget (which may be a sniffed SNI/HTTP
// hostname or reverse-DNS domain in TUN mode), dials original target directly
// when direct, and proxies routeTarget when proxied.
func (p *Proxy) openTCPWithHint(ctx context.Context, target, routeTarget string) (*Tunnel, error) {
	if p.TUN {
		if _, port, _ := net.SplitHostPort(target); port == "53" {
			return p.dnsTCP(ctx), nil
		}
		if p.unsupportedIPv6(target) {
			flowFrom(ctx).failure("tun_ipv6_unavailable", errTUNIPv6Unavailable)
			return nil, errTUNIPv6Unavailable
		}
	}
	d := p.route(ctx, routeTarget)
	if !d.Direct {
		proxyTarget := target
		if routeTarget != "" && routeTarget != target {
			proxyTarget = routeTarget
		}
		return p.Mux.OpenTCPFast(ctx, proxyTarget)
	}
	dialAddr := d.Address
	if p.TUN && target != "" {
		// In TUN mode, the app already resolved the literal destination IP; dial it
		// directly via the physical uplink interface without re-resolving through TUN.
		if h, _, err := net.SplitHostPort(target); err == nil {
			if _, err := netip.ParseAddr(h); err == nil {
				dialAddr = target
			}
		}
	}
	c, e := p.dialDirectContext(ctx, "tcp", dialAddr, 10*time.Second)
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
	routeTarget := target
	if p.TUN {
		if h, port, err := net.SplitHostPort(target); err == nil {
			if ip, err := netip.ParseAddr(h); err == nil {
				if rev := p.lookupReverseDNS(ip); rev != "" {
					routeTarget = net.JoinHostPort(rev, port)
				}
			}
		}
	}
	d := p.route(ctx, routeTarget)
	if !d.Direct {
		return p.Mux.OpenUDP(ctx, target)
	}
	dialAddr := d.Address
	if p.TUN {
		dialAddr = target
	}
	c, e := p.dialDirectContext(ctx, "udp", dialAddr, 5*time.Second)
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
