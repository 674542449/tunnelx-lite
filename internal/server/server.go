package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/674542449/tunnelx-lite/internal/config"
	"github.com/674542449/tunnelx-lite/internal/wire"
	"golang.org/x/net/http2"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Server struct {
	Config         config.Server
	auth           *config.Auth
	slots          chan struct{}
	HTTP           *http.Server
	TargetAttempts atomic.Int64
	Active         atomic.Int64
	Uploaded       atomic.Int64 // client to target bytes, all streams
	Downloaded     atomic.Int64
	Resolver       func(context.Context, string) ([]net.IP, error)
	Access         AccessController
	dns            *dnsCache
	accessLog      *slog.Logger
	// upLimit and downLimit apply BandwidthLimit to the whole server, so a
	// client cannot exceed it by opening more connections.
	upLimit, downLimit *Limiter
}

func New(c config.Server) (*Server, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	tlsCfg, e := c.TLS()
	if e != nil {
		return nil, e
	}
	s := &Server{Config: c, auth: config.NewAuth(c.Tokens), slots: make(chan struct{}, c.MaxConnections)}
	s.Resolver = DefaultLookup
	if c.DNSCacheTTL > 0 {
		s.dns = &dnsCache{ttl: time.Duration(c.DNSCacheTTL) * time.Second, entries: map[string]dnsCacheEntry{}}
		s.Resolver = s.dns.Lookup
	}
	_ = tlsCfg
	if c.BandwidthLimit > 0 {
		s.upLimit, s.downLimit = NewLimiter(c.BandwidthLimit), NewLimiter(c.BandwidthLimit)
	}
	return s, nil
}

func (s *Server) Serve(ctx context.Context) error {
	if s.Config.AccessLog != "" {
		f, e := os.OpenFile(s.Config.AccessLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			return fmt.Errorf("access log: %w", e)
		}
		defer f.Close()
		s.accessLog = slog.New(slog.NewJSONHandler(f, nil))
	}
	tlsCfg, e := s.Config.TLS()
	if e != nil {
		return e
	}
	tlsCfg.NextProtos = []string{"h2", "http/1.1"}
	s.HTTP = &http.Server{Addr: s.Config.Listen, TLSConfig: tlsCfg, Handler: s, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 16 << 10}
	if e = http2.ConfigureServer(s.HTTP, &http2.Server{MaxConcurrentStreams: 128, MaxUploadBufferPerConnection: 4 << 20, MaxUploadBufferPerStream: 1 << 20, IdleTimeout: 120 * time.Second}); e != nil {
		return e
	}
	errs := make(chan error, 1)
	network := s.Config.Network
	if network == "" {
		network = "tcp"
	}
	ln, e := net.Listen(network, s.Config.Listen)
	if e != nil {
		return e
	}
	go func() { errs <- s.HTTP.ServeTLS(ln, "", "") }()
	select {
	case <-ctx.Done():
	case e = <-errs:
	}
	// Close cancels live tunnels; do not wait indefinitely for long-lived CONNECT streams.
	s.HTTP.Close()
	return e
}
func (s *Server) public(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "GET" && r.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method Not Allowed", 405)
		return
	}
	if s.Config.PublicDir != "" {
		http.FileServer(http.Dir(s.Config.PublicDir)).ServeHTTP(w, r)
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == "GET" {
		io.WriteString(w, "<!doctype html><html><meta charset=utf-8><meta name=viewport content='width=device-width'><title>Network service</title><body><main><h1>Network service</h1><p>This HTTPS service is online.</p></main></body></html>")
	}
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.Config.ManagedOnly || !s.auth.Valid(r.Header.Values("Authorization")) {
		var p Permit
		var ok bool
		if s.Access != nil {
			p, ok = s.Access.Authorize(r.Context(), r.Header.Values("Authorization"), r.Header.Get("Tunnelx-Device"))
		}
		if !ok {
			s.public(w, r)
			return
		}
		defer p.Close()
		r = r.WithContext(context.WithValue(p.Context(), permitKey{}, p))
	}
	// Anonymous probes must see only the public site, never proxy state.
	if r.Method == "GET" && r.URL.Path == "/health" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `{"status":"ok","active":%d}`, s.Active.Load())
		return
	}
	w.Header().Set("Tunnelx-Version", config.Version)
	if r.Header.Get("Tunnelx-Version") != config.Version {
		http.Error(w, "Bad Request", 400)
		return
	}
	if r.Method != "CONNECT" {
		s.public(w, r)
		return
	}
	if r.ProtoMajor != 2 {
		http.Error(w, "HTTP Version Not Supported", 505)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		http.Error(w, "Too Many Requests", 429)
		return
	}
	s.Active.Add(1)
	defer s.Active.Add(-1)
	proto := r.Header.Get(":protocol")
	target := r.Host
	if proto != "" {
		if proto != "connect-udp" {
			http.Error(w, "Not Implemented", 501)
			return
		}
		var e error
		target, e = UDPAddress(r.URL)
		if e != nil {
			http.Error(w, "Bad Request", 400)
			return
		}
		if r.Header.Get("Capsule-Protocol") != "?1" {
			http.Error(w, "Bad Request", 400)
			return
		}
	}
	host, port, e := net.SplitHostPort(target)
	p, pe := strconv.Atoi(port)
	if e != nil || pe != nil || p < 1 || p > 65535 || host == "" {
		http.Error(w, "Bad Request", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.Config.DialTimeout)*time.Second)
	defer cancel()
	addresses, status := s.resolve(ctx, host, target)
	if status != 0 {
		http.Error(w, http.StatusText(status), status)
		return
	}
	if proto == "connect-udp" {
		s.udp(w, r, addresses[0], p)
		return
	}
	conn, e := dialTarget(ctx, addresses, port)
	if e != nil {
		status = 502
		if errors.Is(e, context.DeadlineExceeded) || ctx.Err() != nil {
			status = 504
		}
		http.Error(w, http.StatusText(status), status)
		return
	}
	defer conn.Close()
	if s.Config.MaxLifetime > 0 {
		lt := time.AfterFunc(time.Duration(s.Config.MaxLifetime)*time.Second, func() { conn.Close() })
		defer lt.Stop()
	}
	w.WriteHeader(200)
	http.NewResponseController(w).Flush()
	cleanup := joinCancellation(r.Context(), func() {
		conn.Close()
		if permit(r.Context()) != nil {
			r.Body.Close()
			http.NewResponseController(w).SetWriteDeadline(time.Now())
		}
	})
	defer cleanup()
	idle := time.Duration(s.Config.IdleTimeout) * time.Second
	upLimit, downLimit := s.limiters(r.Context())
	var upBytes, downBytes atomic.Int64
	proxyStart := time.Now()
	up := make(chan error, 1)
	go func() {
		var reader io.Reader = r.Body
		if upLimit != nil {
			reader = throttledReader{r: reader, l: upLimit, ctx: r.Context()}
		}
		if p := permit(r.Context()); p != nil {
			reader = accountReader{reader: reader, access: p, upload: true}
		}
		reader = countReader{r: reader, n: &upBytes, total: &s.Uploaded}
		_, e := io.CopyBuffer(idleConn{Conn: conn, idle: idle}, reader, make([]byte, 32<<10))
		if tcp, ok := conn.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
		up <- e
	}()
	var reader io.Reader = idleConn{Conn: conn, idle: idle}
	if downLimit != nil {
		reader = throttledReader{r: reader, l: downLimit, ctx: r.Context()}
	}
	if p := permit(r.Context()); p != nil {
		reader = accountReader{reader: reader, access: p}
	}
	reader = countReader{r: reader, n: &downBytes, total: &s.Downloaded}
	_, downErr := io.CopyBuffer(flushWriter{w: w}, reader, make([]byte, 32<<10))
	if downErr != nil {
		conn.Close()
		r.Body.Close()
	}
	// HTTP/2 can only end the response by returning, which also stops reading
	// the request. Once the target has finished, the client still gets its EOF
	// promptly (close-delimited HTTP responses rely on it) after a short grace
	// period for the last uploaded bytes.
	select {
	case <-up:
	case <-r.Context().Done():
	case <-time.After(h2EOFGrace):
	}
	if s.accessLog != nil {
		s.accessLog.Info("proxy", "target", target, "proto", "tcp", "upload", upBytes.Load(), "download", downBytes.Load(), "duration_ms", time.Since(proxyStart).Milliseconds())
	}
}

// h2EOFGrace bounds how long an HTTP/2 flow whose target has closed waits for
// the client's upload before ending the response.
var h2EOFGrace = 2 * time.Second

func UDPAddress(u *url.URL) (string, error) {
	p := strings.Split(u.EscapedPath(), "/")
	if len(p) != 7 || p[1] != ".well-known" || p[2] != "masque" || p[3] != "udp" || p[6] != "" {
		return "", errors.New("bad UDP URI")
	}
	host, e := url.PathUnescape(p[4])
	if e != nil || host == "" || strings.ContainsAny(host, "[]/%\\ \t\r\n") {
		return "", errors.New("bad UDP host")
	}
	port, e := url.PathUnescape(p[5])
	if e != nil {
		return "", e
	}
	return net.JoinHostPort(host, port), nil
}
func (s *Server) resolve(ctx context.Context, host, target string) ([]net.IP, int) {
	s.TargetAttempts.Add(1)
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		var e error
		ips, e = s.Resolver(ctx, host)
		if e != nil {
			if ctx.Err() != nil {
				return nil, 504
			}
			return nil, 502
		}
	}
	allow := false
	for _, a := range s.Config.AllowedPrivateTargets {
		if a == target {
			allow = true
		}
	}
	result := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		a = a.Unmap()
		if !allow && (!a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()) {
			continue
		}
		result = append(result, ip)
	}
	if len(result) == 0 {
		return nil, 403
	}
	if result = outboundOrder(result, s.Config.OutboundIP); len(result) == 0 {
		return nil, 502
	}
	// Preferences reorder only addresses returned by the current DNS lookup and
	// already admitted by the target filter. They never add or pin stale addresses.
	preferred := s.Config.PreferredTargetIPs[strings.ToLower(strings.TrimSuffix(host, "."))]
	if len(preferred) != 0 {
		ordered := make([]net.IP, 0, len(result))
		used := make([]bool, len(result))
		for _, address := range preferred {
			ip := net.ParseIP(address)
			for i, candidate := range result {
				if !used[i] && candidate.Equal(ip) {
					ordered = append(ordered, candidate)
					used[i] = true
				}
			}
		}
		for i, candidate := range result {
			if !used[i] {
				ordered = append(ordered, candidate)
			}
		}
		result = ordered
	}
	return result, 0
}

type flushWriter struct{ w http.ResponseWriter }

func (w flushWriter) Write(p []byte) (int, error) {
	n, e := w.w.Write(p)
	if e == nil {
		e = http.NewResponseController(w.w).Flush()
	}
	return n, e
}

type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c idleConn) Read(b []byte) (int, error) {
	c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(b)
}
func (c idleConn) Write(b []byte) (int, error) {
	c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(b)
}

type pairRW struct {
	io.Reader
	io.Writer
}

func (s *Server) udp(w http.ResponseWriter, r *http.Request, ip net.IP, port int) {
	conn, e := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: port})
	if e != nil {
		http.Error(w, "Bad Gateway", 502)
		return
	}
	defer conn.Close()
	if s.Config.MaxLifetime > 0 {
		lt := time.AfterFunc(time.Duration(s.Config.MaxLifetime)*time.Second, func() { conn.Close() })
		defer lt.Stop()
	}
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(200)
	http.NewResponseController(w).Flush()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	ps := wire.NewPacketStream(ctx, pairRW{Reader: r.Body, Writer: flushWriter{w}}, func() { r.Body.Close() })
	defer ps.Close()
	var once sync.Once
	closeAll := func() { once.Do(func() { cancel(); conn.Close(); ps.Close() }) }
	defer closeAll()
	stop := context.AfterFunc(ctx, closeAll)
	defer stop()
	if permit(r.Context()) != nil {
		stopWrite := joinCancellation(ctx, func() { http.NewResponseController(w).SetWriteDeadline(time.Now()) })
		defer stopWrite()
	}
	upLimit, downLimit := s.limiters(r.Context())
	go func() {
		for {
			b, e := ps.Receive(ctx)
			if e != nil {
				closeAll()
				return
			}
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if p := permit(ctx); p != nil {
				if !p.Allowed() {
					closeAll()
					return
				}
				if charge(p, true, len(b)) != len(b) {
					closeAll()
					return
				}
			}
			if upLimit.Wait(ctx, len(b)) != nil {
				closeAll()
				return
			}
			if _, e = conn.Write(b); e != nil {
				closeAll()
				return
			}
			s.Uploaded.Add(int64(len(b)))
		}
	}()
	b := make([]byte, 65535)
	for {
		conn.SetReadDeadline(time.Now().Add(time.Duration(s.Config.IdleTimeout) * time.Second))
		n, e := conn.Read(b)
		if e != nil {
			return
		}
		if p := permit(ctx); p != nil {
			if !p.Allowed() {
				return
			}
			if charge(p, false, n) != n {
				return
			}
		}
		if downLimit.Wait(ctx, n) != nil {
			return
		}
		if e = ps.Send(b[:n]); e != nil {
			return
		}
		s.Downloaded.Add(int64(n))
	}
}
func DefaultLookup(ctx context.Context, host string) ([]net.IP, error) {
	addrs, e := net.DefaultResolver.LookupIPAddr(ctx, host)
	var ips []net.IP
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, e
}
func LogError(e error) {
	if e != nil && !errors.Is(e, http.ErrServerClosed) {
		slog.Error("server stopped", "error", fmt.Sprint(e))
		os.Exit(1)
	}
}

type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]dnsCacheEntry
	ttl     time.Duration
}
type dnsCacheEntry struct {
	ips     []net.IP
	expires time.Time
}

func (c *dnsCache) Lookup(ctx context.Context, host string) ([]net.IP, error) {
	c.mu.RLock()
	if e, ok := c.entries[host]; ok && time.Now().Before(e.expires) {
		c.mu.RUnlock()
		return e.ips, nil
	}
	c.mu.RUnlock()
	ips, err := DefaultLookup(ctx, host)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if len(c.entries) >= 4096 {
		now := time.Now()
		for k, v := range c.entries {
			if now.After(v.expires) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= 4096 {
			for k := range c.entries {
				delete(c.entries, k)
				break
			}
		}
	}
	c.entries[host] = dnsCacheEntry{ips: ips, expires: time.Now().Add(c.ttl)}
	c.mu.Unlock()
	return ips, nil
}

// Limiter is a token bucket in bytes per second. One limiter may be shared by
// every stream of an account so that opening more connections gains no speed.
// The bounded burst stops idle time from accumulating unthrottled credit.
type Limiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func NewLimiter(bytesPerSecond int64) *Limiter {
	rate := float64(bytesPerSecond)
	burst := max(rate/4, 64<<10)
	return &Limiter{rate: rate, burst: burst, tokens: burst, last: time.Now()}
}

func (l *Limiter) Wait(ctx context.Context, n int) error {
	if l == nil || n <= 0 {
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	l.tokens = min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)
	l.last = now
	l.tokens -= float64(n)
	delay := time.Duration(-l.tokens / l.rate * float64(time.Second))
	l.mu.Unlock()
	if delay <= 0 {
		return nil
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type throttledReader struct {
	r   io.Reader
	l   *Limiter
	ctx context.Context
}

func (r throttledReader) Read(b []byte) (int, error) {
	n, e := r.r.Read(b)
	if n > 0 {
		if we := r.l.Wait(r.ctx, n); we != nil && e == nil {
			e = we
		}
	}
	return n, e
}

// limiters returns the upload and download limiters for one stream. Managed
// accounts share theirs across streams; the server-wide limit is shared too.
func (s *Server) limiters(ctx context.Context) (up, down *Limiter) {
	if p := permit(ctx); p != nil {
		if lp, ok := p.(LimitedPermit); ok {
			up, down = lp.Limiter(true), lp.Limiter(false)
		} else if v := p.SpeedLimit(); v > 0 {
			up, down = NewLimiter(v), NewLimiter(v)
		}
		if up != nil || down != nil {
			return up, down
		}
	}
	return s.upLimit, s.downLimit
}

type countReader struct {
	r     io.Reader
	n     *atomic.Int64
	total *atomic.Int64
}

func (c countReader) Read(b []byte) (int, error) {
	n, e := c.r.Read(b)
	if n > 0 {
		c.n.Add(int64(n))
		if c.total != nil {
			c.total.Add(int64(n))
		}
	}
	return n, e
}

// outboundOrder applies the configured address-family policy. "ipv4" and
// "ipv6" drop the other family; the prefer modes keep both but try one first.
func outboundOrder(ips []net.IP, policy string) []net.IP {
	if policy == "" {
		return ips
	}
	var v4, v6 []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	switch policy {
	case "ipv4":
		return v4
	case "ipv6":
		return v6
	case "prefer_ipv6":
		return append(v6, v4...)
	default:
		return append(v4, v6...)
	}
}

// dialTarget races the admitted addresses, starting the next one every 250ms
// (RFC 8305 style) or as soon as all started attempts failed. A blackholed
// IPv6 route therefore costs 250ms instead of the whole dial timeout.
func dialTarget(ctx context.Context, ips []net.IP, port string) (net.Conn, error) {
	if len(ips) > 8 {
		ips = ips[:8]
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan dialResult, len(ips))
	started, failed := 0, 0
	var lastErr error
	next := time.NewTimer(0)
	defer next.Stop()
	for {
		select {
		case <-next.C:
			ip := ips[started]
			started++
			go func() {
				c, e := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
				results <- dialResult{c, e}
			}()
			if started < len(ips) {
				next.Reset(250 * time.Millisecond)
			}
		case r := <-results:
			if r.e == nil {
				go closeLosers(results, started-failed-1)
				return r.c, nil
			}
			failed, lastErr = failed+1, r.e
			if failed == len(ips) {
				return nil, lastErr
			}
			if failed == started {
				next.Reset(0)
			}
		case <-ctx.Done():
			go closeLosers(results, started-failed)
			return nil, ctx.Err()
		}
	}
}

type dialResult struct {
	c net.Conn
	e error
}

// closeLosers closes connections that finished after another address won.
func closeLosers(results <-chan dialResult, pending int) {
	for ; pending > 0; pending-- {
		if r := <-results; r.c != nil {
			r.c.Close()
		}
	}
}
