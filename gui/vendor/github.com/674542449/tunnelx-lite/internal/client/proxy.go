package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/674542449/tunnelx-lite/internal/diagnostics"
	"github.com/674542449/tunnelx-lite/internal/processowner"
	"github.com/674542449/tunnelx-lite/internal/routing"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type tunUplink struct {
	ifV4, ifV6 uint32
	dnsServers []string
}

type Proxy struct {
	Mux             *Mux
	Router          *routing.Router // Legacy direct field for tests; prefer SetRouter for runtime updates.
	router          atomic.Pointer[routing.Router]
	TUN             bool // Set before Start; DNS and address-family policy for captured IP traffic.
	ExternalTUN     bool // Set before Start when OS-level VPN bypass (e.g. Android VpnService.addDisallowedApplication) protects our sockets directly.
	TUNIPv6         atomic.Bool
	ipv6Successes   atomic.Int32
	dnsPreferred    atomic.Uint32
	dnsSlots        chan struct{}
	dnsCacheEnabled atomic.Bool
	dnsCacheMu      sync.Mutex
	dnsCache        map[dnsCacheKey]dnsCacheEntry
	dnsInflightMu   sync.Mutex
	dnsInflight     map[dnsCacheKey]*dnsFlight
	revDNSMu        sync.Mutex
	revDNS          map[netip.Addr]revDNSEntry
	uplink          atomic.Pointer[tunUplink]
	dnsCfg          atomic.Pointer[DNSConfig]
	directDoHMu     sync.Mutex
	directDoHClient *http.Client
	directDNSQuery  func(context.Context, string, []byte) ([]byte, error) // tests only
	socks           net.Listener
	http            *http.Server
	slots           chan struct{}
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	connections     map[net.Conn]bool
}

func (p *Proxy) SetRouter(r *routing.Router) {
	p.router.Store(r)
	p.FlushDNSCache()
}

func (p *Proxy) getRouter() *routing.Router {
	if r := p.router.Load(); r != nil {
		return r
	}
	return p.Router
}

func (p *Proxy) EnableDNSCache() { p.dnsCacheEnabled.Store(true) }

func (p *Proxy) SetUplink(ifV4, ifV6 uint32, dnsServers []string) {
	cp := append([]string(nil), dnsServers...)
	p.uplink.Store(&tunUplink{ifV4: ifV4, ifV6: ifV6, dnsServers: cp})
	p.resetDirectDoHClient()
	p.FlushDNSCache()
}

func (p *Proxy) getUplink() tunUplink {
	if u := p.uplink.Load(); u != nil {
		return *u
	}
	return tunUplink{}
}

var clientRelayBufPool = sync.Pool{New: func() any { b := make([]byte, 256<<10); return &b }}

func getClientRelayBuf() *[]byte  { return clientRelayBufPool.Get().(*[]byte) }
func putClientRelayBuf(b *[]byte) { clientRelayBufPool.Put(b) }

func NewProxy(m *Mux) *Proxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &Proxy{Mux: m, slots: make(chan struct{}, m.Config.MaxConnections), dnsSlots: make(chan struct{}, 64), ctx: ctx, cancel: cancel, connections: map[net.Conn]bool{}}
}
func (p *Proxy) Start() error {
	ln, e := net.Listen("tcp", p.Mux.Config.SOCKSListen)
	if e != nil {
		return e
	}
	httpLn, e := net.Listen("tcp", p.Mux.Config.HTTPListen)
	if e != nil {
		ln.Close()
		return e
	}
	p.socks = ln
	p.http = &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, ownerKey{}, processowner.Lookup(c.RemoteAddr(), c.LocalAddr()))
	}}
	go p.http.Serve(httpLn)
	go p.accept()
	return nil
}
func (p *Proxy) track(c net.Conn, add bool) {
	p.mu.Lock()
	if add {
		p.connections[c] = true
	} else {
		delete(p.connections, c)
	}
	p.mu.Unlock()
}

// ResetConnections closes active client sockets (SOCKS5 TCP flows, SOCKS5
// UDP-ASSOCIATE control sockets, and HTTP CONNECT tunnels) so live routing
// switches (e.g. Bypass CN <-> Global) take effect immediately instead of
// letting browsers keep reusing stale direct/proxied keep-alive connections.
func (p *Proxy) ResetConnections() {
	p.mu.Lock()
	conns := make([]net.Conn, 0, len(p.connections))
	for c := range p.connections {
		conns = append(conns, c)
	}
	p.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}
func (p *Proxy) Close() {
	p.cancel()
	if p.socks != nil {
		p.socks.Close()
	}
	if p.http != nil {
		p.http.Close()
	}
	p.mu.Lock()
	for c := range p.connections {
		c.Close()
	}
	p.mu.Unlock()
	p.resetDirectDoHClient()
	p.Mux.Close()
}
func (p *Proxy) accept() {
	for {
		c, e := p.socks.Accept()
		if e != nil {
			return
		}
		tuneLocalTCP(c)
		select {
		case p.slots <- struct{}{}:
			p.track(c, true)
			go func() { defer func() { <-p.slots; p.track(c, false); c.Close() }(); p.socksConn(c) }()
		default:
			c.Close()
		}
	}
}
func readAddress(r io.Reader) (string, []byte, error) {
	b := make([]byte, 1)
	if _, e := io.ReadFull(r, b); e != nil {
		return "", nil, e
	}
	raw := append([]byte{}, b...)
	var host string
	switch b[0] {
	case 1:
		b = make([]byte, 4)
	case 4:
		b = make([]byte, 16)
	case 3:
		n := []byte{0}
		if _, e := io.ReadFull(r, n); e != nil {
			return "", nil, e
		}
		if n[0] == 0 {
			return "", nil, errors.New("empty domain")
		}
		raw = append(raw, n[0])
		b = make([]byte, int(n[0]))
	default:
		return "", nil, errors.New("invalid SOCKS address")
	}
	if _, e := io.ReadFull(r, b); e != nil {
		return "", nil, e
	}
	raw = append(raw, b...)
	if raw[0] == 3 {
		host = string(b)
	} else {
		host = net.IP(b).String()
	}
	port := make([]byte, 2)
	if _, e := io.ReadFull(r, port); e != nil {
		return "", nil, e
	}
	raw = append(raw, port...)
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))), raw, nil
}
func encodeAddress(addr string) ([]byte, error) {
	h, ps, e := net.SplitHostPort(addr)
	if e != nil {
		return nil, e
	}
	port, e := strconv.Atoi(ps)
	if e != nil || port < 0 || port > 65535 {
		return nil, errors.New("invalid port")
	}
	var b []byte
	if ip := net.ParseIP(h); ip != nil {
		if v := ip.To4(); v != nil {
			b = append([]byte{1}, v...)
		} else {
			b = append([]byte{4}, ip.To16()...)
		}
	} else {
		if len(h) == 0 || len(h) > 255 {
			return nil, errors.New("invalid domain")
		}
		b = append([]byte{3, byte(len(h))}, []byte(h)...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}
func socksReply(c net.Conn, code byte, addr string) {
	a, e := encodeAddress(addr)
	if e != nil {
		a = []byte{1, 0, 0, 0, 0, 0, 0}
	}
	c.Write(append([]byte{5, code, 0}, a...))
}
func (p *Proxy) socksConn(c net.Conn) {
	owner := processowner.Lookup(c.RemoteAddr(), c.LocalAddr())
	c.SetDeadline(time.Now().Add(10 * time.Second))
	h := make([]byte, 2)
	if _, e := io.ReadFull(c, h); e != nil || h[0] != 5 || h[1] == 0 {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, e := io.ReadFull(c, methods); e != nil {
		return
	}
	supported := false
	for _, m := range methods {
		if m == 0 {
			supported = true
		}
	}
	if !supported {
		c.Write([]byte{5, 255})
		return
	}
	c.Write([]byte{5, 0})
	h = make([]byte, 3)
	if _, e := io.ReadFull(c, h); e != nil || h[0] != 5 || h[2] != 0 {
		return
	}
	target, _, e := readAddress(c)
	if e != nil {
		socksReply(c, 8, "0.0.0.0:0")
		return
	}
	c.SetDeadline(time.Time{})
	switch h[1] {
	case 1:
		ctx, flow := p.Mux.beginFlow(p.ctx, target, "socks_connect", owner)
		defer flow.end()
		if p.TUN && p.shouldSniffTUN(target) {
			p.socksConnectTUNSniff(ctx, c, target, flow)
			return
		}
		t, e := p.openTCP(ctx, target)
		if e != nil {
			socksReply(c, 1, "0.0.0.0:0")
			return
		}
		defer t.Close()
		socksReply(c, 0, "0.0.0.0:0")
		p.relayFlow(c, c, t, flow)
	case 3:
		p.udpAssociate(context.WithValue(p.ctx, ownerKey{}, owner), c, target)
	default:
		socksReply(c, 7, "0.0.0.0:0")
	}
}

func (p *Proxy) shouldSniffTUN(target string) bool {
	r := p.getRouter()
	if r == nil {
		return false
	}
	// In Global mode without user direct exceptions, non-local IPs always go
	// straight to the proxy so skipping sniffing saves an extra read round-trip.
	if r.Global && !r.HasExceptions() {
		return false
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || port == "53" {
		return false
	}
	_, err = netip.ParseAddr(host)
	return err == nil
}

// socksConnectTUNSniff handles literal-IP TCP connections arriving from
// tun2socks by peeking the initial TLS ClientHello SNI or HTTP Host header
// (falling back to the reverse-DNS cache) so domain rules work in TUN mode.
func (p *Proxy) socksConnectTUNSniff(ctx context.Context, c net.Conn, target string, flow *flowLog) {
	if p.unsupportedIPv6(target) {
		flow.failure("tun_ipv6_unavailable", errTUNIPv6Unavailable)
		socksReply(c, 1, "0.0.0.0:0")
		return
	}
	socksReply(c, 0, "0.0.0.0:0")
	peek := make([]byte, 4096)
	c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	n, readErr := c.Read(peek)
	c.SetReadDeadline(time.Time{})
	if readErr != nil {
		var ne net.Error
		if !(errors.As(readErr, &ne) && ne.Timeout()) && n == 0 {
			return
		}
	}
	host, port, _ := net.SplitHostPort(target)
	routeTarget := target
	if n > 0 {
		if domain := sniffDomain(peek[:n]); domain != "" {
			routeTarget = net.JoinHostPort(domain, port)
		}
	}
	if routeTarget == target {
		if ip, err := netip.ParseAddr(host); err == nil {
			if rev := p.lookupReverseDNS(ip); rev != "" {
				routeTarget = net.JoinHostPort(rev, port)
			}
		}
	}
	t, e := p.openTCPWithHint(ctx, target, routeTarget)
	if e != nil {
		return
	}
	defer t.Close()
	var reader io.Reader = c
	if n > 0 {
		reader = io.MultiReader(bytes.NewReader(peek[:n]), c)
	}
	p.relayFlow(c, reader, t, flow)
}
func (p *Proxy) relay(c net.Conn, r io.Reader, t *Tunnel) {
	p.relayFlow(c, r, t, nil)
}

// Like Xray's connection policy: a flow with no traffic for relayIdle is closed,
// and once one direction has finished the other may stay silent only for
// halfCloseIdle. Without this, half-open flows keep their slot forever and the
// proxy eventually refuses every new connection.
var relayIdle, halfCloseIdle = 5 * time.Minute, 30 * time.Second

type idleWatch struct {
	mu    sync.Mutex
	last  atomic.Int64
	limit time.Duration
	timer *time.Timer
}

func newIdleWatch(limit time.Duration, expire func()) *idleWatch {
	w := &idleWatch{limit: limit}
	w.last.Store(time.Now().UnixNano())
	w.mu.Lock()
	defer w.mu.Unlock()
	w.timer = time.AfterFunc(limit, func() {
		w.mu.Lock()
		elapsed := time.Duration(time.Now().UnixNano() - w.last.Load())
		left := w.limit - elapsed
		if left > 0 {
			w.timer.Reset(left)
		}
		w.mu.Unlock()
		if left <= 0 {
			expire()
		}
	})
	return w
}
func (w *idleWatch) touch() { w.last.Store(time.Now().UnixNano()) }
func (w *idleWatch) shorten(limit time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if limit < w.limit {
		w.limit = limit
		w.last.Store(time.Now().UnixNano())
		w.timer.Reset(limit)
	}
}
func (w *idleWatch) stop() { w.timer.Stop() }

type touchWriter struct {
	io.Writer
	w *idleWatch
}

func (t touchWriter) Write(b []byte) (int, error) { t.w.touch(); return t.Writer.Write(b) }

func (p *Proxy) relayFlow(c net.Conn, r io.Reader, t *Tunnel, flow *flowLog) {
	p.Mux.Stats.Active.Add(1)
	defer p.Mux.Stats.Active.Add(-1)
	cleanup := context.AfterFunc(p.ctx, func() { c.Close(); t.Close() })
	defer cleanup()
	idle := newIdleWatch(relayIdle, func() {
		flow.event("flow_idle_closed", nil)
		c.Close()
		t.Close()
	})
	defer idle.stop()
	up := make(chan error, 1)
	go func() {
		buf := getClientRelayBuf()
		defer putClientRelayBuf(buf)
		_, e := io.CopyBuffer(touchWriter{flow.wrap(meterWriter{t, &p.Mux.Stats.Uploaded}, true), idle}, r, *buf)
		flow.directionEnd("app_to_target", e)
		idle.shorten(halfCloseIdle)
		t.CloseWrite()
		if e != nil {
			t.Close()
			c.Close()
		}
		up <- e
	}()
	downBuf := getClientRelayBuf()
	_, e := io.CopyBuffer(touchWriter{flow.wrap(meterWriter{c, &p.Mux.Stats.Downloaded}, false), idle}, t, *downBuf)
	putClientRelayBuf(downBuf)
	flow.directionEnd("target_to_app", e)
	idle.shorten(halfCloseIdle)
	if tcp, ok := c.(*net.TCPConn); ok {
		tcp.CloseWrite()
	}
	if e != nil {
		t.Close()
		c.Close()
	}
	select {
	case <-up:
	case <-p.ctx.Done():
	}
}

type meterWriter struct {
	io.Writer
	count *atomic.Int64
}

func (w meterWriter) Write(b []byte) (int, error) {
	n, e := w.Writer.Write(b)
	w.count.Add(int64(n))
	return n, e
}
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "CONNECT" {
		p.forwardHTTP(w, r)
		return
	}
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		http.Error(w, "Busy", 503)
		return
	}
	target := r.Host
	if _, _, e := net.SplitHostPort(target); e != nil {
		http.Error(w, "Invalid target", 400)
		return
	}
	owner, _ := r.Context().Value(ownerKey{}).(diagnostics.Owner)
	ctx, flow := p.Mux.beginFlow(r.Context(), target, "http_connect", owner)
	defer flow.end()
	t, e := p.openTCP(ctx, target)
	if e != nil {
		http.Error(w, "Proxy connection failed", 502)
		return
	}
	defer t.Close()
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijack unavailable", 500)
		return
	}
	c, rw, e := hj.Hijack()
	if e != nil {
		return
	}
	tuneLocalTCP(c)
	p.track(c, true)
	defer p.track(c, false)
	defer c.Close()
	fmt.Fprint(rw, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if e = rw.Flush(); e != nil {
		flow.failure("proxy_response", e)
		return
	}
	// Drain any already-buffered bytes from net/http's 4 KiB bufio.Reader, then
	// read directly from the raw TCP conn so uploads use full 256 KiB buffers.
	var upReader io.Reader = c
	if n := rw.Reader.Buffered(); n > 0 {
		if peeked, pe := rw.Reader.Peek(n); pe == nil && len(peeked) > 0 {
			early := append([]byte(nil), peeked...)
			upReader = io.MultiReader(bytes.NewReader(early), c)
		}
	}
	p.relayFlow(c, upReader, t, flow)
}
func (p *Proxy) forwardHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() || r.URL.Scheme != "http" || r.URL.Host == "" {
		http.Error(w, "Use an HTTP proxy request", 400)
		return
	}
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		http.Error(w, "Busy", 503)
		return
	}
	target := r.URL.Host
	if _, _, e := net.SplitHostPort(target); e != nil {
		target = net.JoinHostPort(r.URL.Hostname(), "80")
	}
	owner, _ := r.Context().Value(ownerKey{}).(diagnostics.Owner)
	ctx, flow := p.Mux.beginFlow(r.Context(), target, "http_forward", owner)
	defer flow.end()
	t, e := p.openTCP(ctx, target)
	if e != nil {
		http.Error(w, "Proxy connection failed", 502)
		return
	}
	defer t.Close()
	p.Mux.Stats.Active.Add(1)
	defer p.Mux.Stats.Active.Add(-1)
	stopCancel := context.AfterFunc(r.Context(), func() { t.Close() })
	defer stopCancel()
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Header = out.Header.Clone()
	stripHop(out.Header)
	out.Close = true
	if e = out.Write(flow.wrap(meterWriter{t, &p.Mux.Stats.Uploaded}, true)); e != nil {
		flow.failure("http_request_write", e)
		http.Error(w, "Request failed", 502)
		return
	}
	// HTTP request framing already marks the end of the request body. Keep the
	// TCP write side open until the response is consumed: some CDNs treat an
	// early FIN as an aborted download and close without returning any headers.
	res, e := http.ReadResponse(bufio.NewReader(t), out)
	if e != nil {
		flow.failure("http_response_headers", e)
		http.Error(w, "Response failed", 502)
		return
	}
	defer res.Body.Close()
	flow.event("http_response", map[string]any{"http_status": res.StatusCode})
	stripHop(res.Header)
	for k, v := range res.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(res.StatusCode)
	buf := getClientRelayBuf()
	n, copyError := io.CopyBuffer(flow.wrap(w, false), res.Body, *buf)
	putClientRelayBuf(buf)
	flow.directionEnd("target_to_app", copyError)
	p.Mux.Stats.Downloaded.Add(n)
}
func stripHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, k := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(k))
		}
	}
	for _, k := range []string{"Connection", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(k)
	}
}

type udpFlow struct {
	cancel  context.CancelFunc
	sendCh  chan []byte
	address []byte
	log     *flowLog
	ended   atomic.Bool
}

const maxUDPFlowsPerAssoc = 256

func (p *Proxy) udpAssociate(parent context.Context, control net.Conn, requested string) {
	host, port, _ := net.SplitHostPort(requested)
	if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() {
		socksReply(control, 2, "0.0.0.0:0")
		return
	}
	listenIP := net.IPv4(127, 0, 0, 1)
	if tcpAddr, ok := control.LocalAddr().(*net.TCPAddr); ok && tcpAddr.IP != nil && tcpAddr.IP.IsLoopback() {
		listenIP = tcpAddr.IP
	}
	u, e := net.ListenUDP("udp", &net.UDPAddr{IP: listenIP})
	if e != nil {
		socksReply(control, 1, "0.0.0.0:0")
		return
	}
	defer u.Close()
	socksReply(control, 0, u.LocalAddr().String())
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	go func() { io.Copy(io.Discard, control); cancel(); u.Close() }()
	var peer *net.UDPAddr
	requestedPort, _ := strconv.Atoi(port)
	flows := map[string]*udpFlow{}
	defer func() {
		for _, f := range flows {
			f.cancel()
		}
	}()
	buf := make([]byte, 65535)
	for {
		u.SetReadDeadline(time.Now().Add(120 * time.Second))
		n, src, e := u.ReadFromUDP(buf)
		if e != nil {
			return
		}
		if !src.IP.IsLoopback() || requestedPort != 0 && src.Port != requestedPort {
			continue
		}
		if peer != nil && (!src.IP.Equal(peer.IP) || src.Port != peer.Port) {
			continue
		}
		if n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
			p.Mux.Stats.UDPDropped.Add(1)
			continue
		}
		target, raw, e := readAddress(bytes.NewReader(buf[3:n]))
		if e != nil {
			continue
		}
		payload := append([]byte(nil), buf[3+len(raw):n]...)
		if peer == nil {
			peer = src
		}
		f := flows[target]
		if f != nil && f.ended.Load() {
			f.cancel()
			delete(flows, target)
			f = nil
		}
		if f == nil {
			// Streams closed by the node's idle timeout must not hold slots forever.
			if len(flows) >= maxUDPFlowsPerAssoc {
				for key, old := range flows {
					if old.ended.Load() {
						old.cancel()
						delete(flows, key)
					}
				}
			}
			if len(flows) >= maxUDPFlowsPerAssoc {
				p.Mux.Stats.UDPDropped.Add(1)
				continue
			}
			owner, _ := ctx.Value(ownerKey{}).(diagnostics.Owner)
			flowCtx, flowCancel := context.WithCancel(ctx)
			flowCtx, trace := p.Mux.beginFlow(flowCtx, target, "socks_udp", owner)
			f = &udpFlow{cancel: flowCancel, sendCh: make(chan []byte, 32), address: raw, log: trace}
			flows[target] = f
			go p.runUDPFlow(flowCtx, f, target, u, peer)
		}
		select {
		case f.sendCh <- payload:
		default:
			p.Mux.Stats.UDPDropped.Add(1)
		}
	}
}

func (p *Proxy) runUDPFlow(ctx context.Context, flow *udpFlow, target string, u *net.UDPConn, dest *net.UDPAddr) {
	defer func() {
		flow.ended.Store(true)
		flow.cancel()
		flow.log.end()
	}()
	stream, e := p.openUDP(ctx, target)
	if e != nil {
		p.Mux.Stats.UDPDropped.Add(1)
		return
	}
	defer stream.Close()
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		for {
			select {
			case <-ctx.Done():
				return
			case pkt := <-flow.sendCh:
				if e := stream.Send(pkt); e != nil {
					flow.log.failure("udp_send", e)
					p.Mux.Stats.UDPDropped.Add(1)
					flow.cancel()
					stream.Close()
					return
				}
				flow.log.packet(len(pkt), true)
				p.Mux.Stats.Uploaded.Add(int64(len(pkt)))
			}
		}
	}()
	for {
		b, e := stream.Receive(ctx)
		if e != nil {
			if ctx.Err() == nil {
				flow.log.failure("udp_receive", e)
				flow.log.event("udp_receive_ended", errorFields(e))
			} else {
				flow.log.event("udp_association_ended", map[string]any{"reason": "control_closed_or_idle_timeout"})
			}
			flow.cancel()
			stream.Close()
			<-sendDone
			return
		}
		out := make([]byte, 3+len(flow.address)+len(b))
		copy(out[3:], flow.address)
		copy(out[3+len(flow.address):], b)
		u.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, e = u.WriteToUDP(out, dest); e != nil {
			flow.log.failure("udp_local_write", e)
			flow.cancel()
			stream.Close()
			<-sendDone
			return
		}
		p.Mux.Stats.Downloaded.Add(int64(len(b)))
		flow.log.packet(len(b), false)
	}
}
