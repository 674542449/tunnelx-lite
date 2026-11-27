package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/674542449/tunnelx-lite/internal/config"
	"github.com/674542449/tunnelx-lite/internal/wire"
)

const (
	directPoolTarget     = 6
	directPoolMaxAge     = 6 * time.Second
	directPoolMaxDialing = 4
	directMaxHeaderBytes = 8 << 10
)

var errDirectUnsupported = errors.New("server requires HTTP/2 CONNECT")

type directEntry struct {
	conn  *tls.Conn
	exact *wire.ExactRecordConn
	born  time.Time
	id    string
}

type directPoolState struct {
	mu      sync.Mutex
	idle    []directEntry
	dialing int
	reaper  *time.Timer
}

func (m *Mux) wantsDirectTCP() bool {
	return m.Config.Transport == "tcp" && !m.directUnsupported.Load()
}

// ActiveTransport reports what new TCP flows use right now: "txpulse", "vision", "tcp", or "h2".
func (m *Mux) ActiveTransport() string {
	if m.IsPulse() {
		return "txpulse"
	}
	if m.wantsDirectTCP() {
		if m.visionSupported.Load() {
			return "vision"
		}
		return "tcp"
	}
	return "h2"
}

// Prewarm opens a few standby TLS 1.3 connections in the background so the
// first web pages, downloads, or video segments after connecting start with
// zero TCP/TLS handshake latency.
func (m *Mux) Prewarm() {
	if m.IsPulse() || !m.wantsDirectTCP() {
		return
	}
	m.replenishDirectPool(4)
}

func (m *Mux) closeDirectPool() {
	p := &m.direct
	p.mu.Lock()
	idle := p.idle
	p.idle = nil
	if p.reaper != nil {
		p.reaper.Stop()
		p.reaper = nil
	}
	p.mu.Unlock()
	for _, e := range idle {
		_ = e.conn.Close()
	}
}

func (m *Mux) reapDirectPool() {
	p := &m.direct
	p.mu.Lock()
	now := time.Now()
	kept := p.idle[:0]
	var expired []*tls.Conn
	for _, e := range p.idle {
		if now.Sub(e.born) >= directPoolMaxAge {
			expired = append(expired, e.conn)
		} else {
			kept = append(kept, e)
		}
	}
	p.idle = kept
	if len(p.idle) > 0 {
		oldestLeft := directPoolMaxAge - now.Sub(p.idle[0].born)
		if oldestLeft < 100*time.Millisecond {
			oldestLeft = 100 * time.Millisecond
		}
		if p.reaper == nil {
			p.reaper = time.AfterFunc(oldestLeft, m.reapDirectPool)
		} else {
			p.reaper.Reset(oldestLeft)
		}
	} else {
		p.reaper = nil
	}
	p.mu.Unlock()
	for _, c := range expired {
		_ = c.Close()
	}
}

func (m *Mux) replenishDirectPool(target int) {
	if !m.wantsDirectTCP() {
		return
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return
	}
	p := &m.direct
	p.mu.Lock()
	need := target - (len(p.idle) + p.dialing)
	slots := directPoolMaxDialing - p.dialing
	if need > slots {
		need = slots
	}
	if need <= 0 {
		p.mu.Unlock()
		return
	}
	p.dialing += need
	p.mu.Unlock()

	for i := 0; i < need; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), scopeKey{}, "carrier"), m.Config.Timeout())
			entry, err := m.dialDirectTLS(ctx)
			cancel()

			p.mu.Lock()
			p.dialing--
			if err != nil {
				p.mu.Unlock()
				return
			}
			m.mu.Lock()
			closed := m.closed
			m.mu.Unlock()
			if closed || m.directUnsupported.Load() || len(p.idle) >= directPoolTarget {
				p.mu.Unlock()
				_ = entry.conn.Close()
				return
			}
			p.idle = append(p.idle, entry)
			if p.reaper == nil {
				p.reaper = time.AfterFunc(directPoolMaxAge, m.reapDirectPool)
			}
			p.mu.Unlock()
		}()
	}
}

func (m *Mux) popDirectTLS() (directEntry, bool) {
	p := &m.direct
	p.mu.Lock()
	var expired []*tls.Conn
	now := time.Now()
	var picked directEntry
	found := false
	for len(p.idle) > 0 {
		last := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		if now.Sub(last.born) < directPoolMaxAge {
			picked = last
			found = true
			break
		}
		expired = append(expired, last.conn)
	}
	p.mu.Unlock()
	for _, c := range expired {
		_ = c.Close()
	}
	return picked, found
}

func (m *Mux) dialDirectTLS(ctx context.Context) (directEntry, error) {
	t := m.tls.Clone()
	t.NextProtos = []string{"http/1.1"}
	nd := &net.Dialer{LocalAddr: m.bindAddr, KeepAlive: 30 * time.Second, Control: uplinkControl(m.uplinkIfV4, m.uplinkIfV6)}
	raw, e := nd.DialContext(ctx, "tcp", m.address())
	if e != nil {
		fields := errorFields(e)
		fields["transport"] = "tcp"
		fields["stage"] = "tcp_tls_handshake"
		m.event(ctx, "carrier_dial_failed", fields)
		return directEntry{}, e
	}
	tuneCarrierTCP(raw)
	ec := wire.NewExactRecordConn(raw)
	tc := tls.Client(ec, t)
	if e = tc.HandshakeContext(ctx); e != nil {
		_ = raw.Close()
		fields := errorFields(e)
		fields["transport"] = "tcp"
		fields["stage"] = "tcp_tls_handshake"
		m.event(ctx, "carrier_dial_failed", fields)
		return directEntry{}, e
	}
	cs := tc.ConnectionState()
	m.LastECH.Store(cs.ECHAccepted)
	m.TLSVersion.Store(uint32(cs.Version))
	m.CipherSuite.Store(uint32(cs.CipherSuite))
	id := m.recorder.Load().ID("tcp")
	m.event(ctx, "carrier_opened", map[string]any{"transport": "tcp", "carrier_id": id, "ech_accepted": cs.ECHAccepted})
	m.Stats.TCPDials.Add(1)
	return directEntry{conn: tc, exact: ec, born: time.Now(), id: id}, nil
}

func (m *Mux) acquireDirectTLS(ctx context.Context) (directEntry, bool, error) {
	if entry, ok := m.popDirectTLS(); ok {
		m.replenishDirectPool(directPoolTarget)
		return entry, true, nil
	}
	dialCtx, cancel := context.WithTimeout(ctx, m.Config.Timeout())
	entry, err := m.dialDirectTLS(dialCtx)
	cancel()
	if err != nil {
		return directEntry{}, false, err
	}
	m.replenishDirectPool(directPoolTarget)
	return entry, false, nil
}

func (m *Mux) directConnectRequest(target string, vision bool) []byte {
	var b strings.Builder
	b.Grow(224 + len(target)*2 + len(m.Config.Token))
	b.WriteString("CONNECT ")
	b.WriteString(target)
	b.WriteString(" HTTP/1.1\r\nHost: ")
	b.WriteString(target)
	b.WriteString("\r\nAuthorization: Bearer ")
	b.WriteString(m.Config.Token)
	b.WriteString("\r\nTunnelx-Version: ")
	b.WriteString(config.Version)
	if vision {
		b.WriteString("\r\nTunnelx-Vision: 1")
	}
	if m.Config.DeviceID != "" {
		b.WriteString("\r\nTunnelx-Device: ")
		b.WriteString(m.Config.DeviceID)
	}
	b.WriteString("\r\n\r\n")
	return []byte(b.String())
}

var hdrScratchPool = sync.Pool{New: func() any { b := make([]byte, 4096); return &b }}

// readDirectResponse parses the HTTP/1.1 response header from a CONNECT tunnel
// without keeping a bufio.Reader attached to the connection for subsequent I/O.
func readDirectResponse(conn net.Conn) (extra []byte, visionOK bool, err error) {
	bp := hdrScratchPool.Get().(*[]byte)
	buf := *bp
	defer hdrScratchPool.Put(bp)

	total := 0
	hdrEnd := -1
	for {
		if total >= len(buf) {
			if len(buf) >= directMaxHeaderBytes {
				return nil, false, errors.New("proxy response header too large")
			}
			bigger := make([]byte, min(len(buf)*2, directMaxHeaderBytes))
			copy(bigger, buf[:total])
			buf = bigger
		}
		n, re := conn.Read(buf[total:])
		if n > 0 {
			total += n
			if idx := bytes.Index(buf[:total], []byte("\r\n\r\n")); idx >= 0 {
				hdrEnd = idx
				break
			}
		}
		if re != nil {
			return nil, false, re
		}
	}

	head := string(buf[:hdrEnd])
	lines := strings.Split(head, "\r\n")
	if len(lines) == 0 {
		return nil, false, errors.New("empty proxy response")
	}
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/1.") {
		return nil, false, errors.New("invalid HTTP/1.1 proxy response")
	}
	status, se := strconv.Atoi(parts[1])
	if se != nil {
		return nil, false, errors.New("invalid HTTP status code")
	}
	known := false
	for _, line := range lines[1:] {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, val := strings.TrimSpace(k), strings.TrimSpace(v)
		if strings.EqualFold(key, "Tunnelx-Version") && val == config.Version {
			known = true
		} else if strings.EqualFold(key, "Tunnelx-Vision") && val == "1" {
			visionOK = true
		}
	}
	if status == 505 && known {
		return nil, false, errDirectUnsupported
	}
	if status != 200 || !known {
		return nil, visionOK && known, &RequestError{Status: status, Known: known}
	}
	if rest := buf[hdrEnd+4 : total]; len(rest) > 0 {
		extra = append([]byte(nil), rest...)
	}
	return extra, visionOK, nil
}

func (m *Mux) openDirectTCP(ctx context.Context, target string) (*Tunnel, error) {
	reqBytes := m.directConnectRequest(target, true)
	for attempt := 0; attempt < 2; attempt++ {
		var entry directEntry
		var fromPool bool
		var err error
		if attempt == 0 {
			entry, fromPool, err = m.acquireDirectTLS(ctx)
		} else {
			dialCtx, cancel := context.WithTimeout(ctx, m.Config.Timeout())
			entry, err = m.dialDirectTLS(dialCtx)
			cancel()
		}
		if err != nil {
			return nil, err
		}
		stopCancel := context.AfterFunc(ctx, func() { _ = entry.conn.Close() })
		deadline := time.Now().Add(m.Config.Timeout())
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = entry.conn.SetDeadline(deadline)
		_, werr := entry.conn.Write(reqBytes)
		var extra []byte
		var visionOK bool
		var rerr error
		if werr == nil {
			extra, visionOK, rerr = readDirectResponse(entry.conn)
		}
		stopCancel()
		if visionOK {
			m.visionSupported.Store(true)
		}
		err = werr
		if err == nil {
			err = rerr
		}
		if err == nil {
			_ = entry.conn.SetDeadline(time.Time{})
			m.Stats.TCPStreams.Add(1)
			var r io.Reader = entry.conn
			if len(extra) > 0 {
				r = io.MultiReader(bytes.NewReader(extra), entry.conn)
			}
			if visionOK {
				m.Stats.VisionStreams.Add(1)
				vs := wire.NewVisionState()
				vr := wire.NewVisionReader(r, entry.exact, vs, true)
				vw := wire.NewVisionWriter(entry.conn, entry.exact.Raw(), vs, true, nil)
				return &Tunnel{
					Reader:       vr,
					Writer:       vw,
					closeWrite:   vw.CloseWrite,
					close:        entry.exact.Raw().Close,
					setDeadline:  entry.exact.Raw().SetDeadline,
					visionDirect: func() bool { return vr.IsDirect() && vw.IsDirect() },
					transport:    "vision",
					carrierID:    entry.id,
				}, nil
			}
			entry.exact.DisableExact()
			return &Tunnel{
				Reader:      r,
				Writer:      entry.conn,
				closeWrite:  entry.conn.CloseWrite,
				close:       entry.conn.Close,
				setDeadline: entry.conn.SetDeadline,
				transport:   "tcp",
				carrierID:   entry.id,
			}, nil
		}
		_ = entry.conn.Close()
		if errors.Is(err, errDirectUnsupported) {
			m.directUnsupported.Store(true)
			m.closeDirectPool()
			return nil, errDirectUnsupported
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var reqErr *RequestError
		if errors.As(err, &reqErr) || securityError(err) {
			return nil, err
		}
		if fromPool && attempt == 0 {
			m.closeDirectPool()
			continue
		}
		return nil, err
	}
	return nil, errors.New("direct TCP connect failed")
}

// openDirectTCPFast sends HTTP/1.1 CONNECT on a dedicated (often pre-warmed)
// TLS 1.3 connection and returns immediately so the app's first bytes travel
// right behind CONNECT with zero extra RTT and zero HTTP/2 overhead.
// When the server supports Tunnelx-Vision, CONNECT and the padded inner
// ClientHello are coalesced into one outer TLS record, and outer TLS is peeled
// off right after the inner TLS 1.3 handshake for direct zero-copy forwarding.
func (m *Mux) openDirectTCPFast(ctx context.Context, target string) (*Tunnel, error) {
	useVision := m.visionSupported.Load()
	reqBytes := m.directConnectRequest(target, useVision)
	entry, fromPool, err := m.acquireDirectTLS(ctx)
	if err != nil {
		return nil, err
	}

	if useVision {
		m.Stats.TCPStreams.Add(1)
		m.Stats.VisionStreams.Add(1)
		vs := wire.NewVisionState()
		// Coalesce HTTP/1.1 CONNECT + app's first Vision-padded packet into ONE
		// outer TLS 1.3 record / TCP segment (with 15ms auto-flush for server-first protocols).
		vw := wire.NewVisionWriter(entry.conn, entry.exact.Raw(), vs, true, reqBytes)
		vr := &directVisionFastReader{
			conn:     entry.conn,
			exact:    entry.exact,
			state:    vs,
			mux:      m,
			timeout:  m.Config.Timeout(),
			fromPool: fromPool,
		}
		t := &Tunnel{
			Reader:       vr,
			Writer:       vw,
			closeWrite:   vw.CloseWrite,
			close:        func() error { vw.StopTimer(); return entry.exact.Raw().Close() },
			setDeadline:  entry.exact.Raw().SetDeadline,
			visionDirect: func() bool { return vw.IsDirect() && vr.IsDirect() },
			transport:    "vision",
			carrierID:    entry.id,
		}
		flowFrom(ctx).openedOn(t)
		m.LastTCP.Store(1)
		return t, nil
	}

	entry.exact.DisableExact()
	if _, werr := entry.conn.Write(reqBytes); werr != nil {
		_ = entry.conn.Close()
		if fromPool && ctx.Err() == nil {
			m.closeDirectPool()
			dialCtx, cancel := context.WithTimeout(ctx, m.Config.Timeout())
			entry, err = m.dialDirectTLS(dialCtx)
			cancel()
			if err != nil {
				return nil, err
			}
			entry.exact.DisableExact()
			fromPool = false
			if _, werr = entry.conn.Write(reqBytes); werr != nil {
				_ = entry.conn.Close()
				return nil, werr
			}
		} else {
			return nil, werr
		}
	}
	m.Stats.TCPStreams.Add(1)
	r := &directFastReader{
		conn:     entry.conn,
		mux:      m,
		timeout:  m.Config.Timeout(),
		fromPool: fromPool,
	}
	t := &Tunnel{
		Reader:      r,
		Writer:      entry.conn,
		closeWrite:  entry.conn.CloseWrite,
		close:       entry.conn.Close,
		setDeadline: entry.conn.SetDeadline,
		transport:   "tcp",
		carrierID:   entry.id,
	}
	flowFrom(ctx).openedOn(t)
	m.LastTCP.Store(1)
	return t, nil
}

// directVisionFastReader parses the HTTP/1.1 200 CONNECT header on the first
// Read, then delegates to wire.VisionReader (which peels off outer TLS and
// reads straight from the raw *net.TCPConn once inner TLS 1.3 begins).
type directVisionFastReader struct {
	conn     *tls.Conn
	exact    *wire.ExactRecordConn
	state    *wire.VisionState
	mux      *Mux
	timeout  time.Duration
	fromPool bool
	vr       *wire.VisionReader
	ready    bool
}

func (r *directVisionFastReader) IsDirect() bool {
	return r.vr != nil && r.vr.IsDirect()
}

func (r *directVisionFastReader) Read(p []byte) (int, error) {
	if !r.ready {
		_ = r.conn.SetReadDeadline(time.Now().Add(r.timeout))
		extra, visionOK, err := readDirectResponse(r.conn)
		_ = r.conn.SetReadDeadline(time.Time{})
		if err != nil {
			if errors.Is(err, errDirectUnsupported) {
				r.mux.directUnsupported.Store(true)
				r.mux.closeDirectPool()
			} else if r.fromPool && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
				r.mux.closeDirectPool()
			}
			_ = r.exact.Raw().Close()
			return 0, err
		}
		if !visionOK {
			_ = r.exact.Raw().Close()
			return 0, errors.New("server did not confirm Vision")
		}
		var outer io.Reader = r.conn
		if len(extra) > 0 {
			outer = io.MultiReader(bytes.NewReader(extra), r.conn)
		}
		r.vr = wire.NewVisionReader(outer, r.exact, r.state, true)
		r.ready = true
	}
	return r.vr.Read(p)
}

// directFastReader parses the HTTP/1.1 200 CONNECT header on the first Read,
// drains any early trailing bytes, and thereafter reads directly from tls.Conn
// with zero buffering or synchronization overhead.
type directFastReader struct {
	conn     *tls.Conn
	mux      *Mux
	timeout  time.Duration
	fromPool bool
	ready    bool
	extra    []byte
}

func (r *directFastReader) Read(p []byte) (int, error) {
	if !r.ready {
		_ = r.conn.SetReadDeadline(time.Now().Add(r.timeout))
		extra, _, err := readDirectResponse(r.conn)
		_ = r.conn.SetReadDeadline(time.Time{})
		if err != nil {
			if errors.Is(err, errDirectUnsupported) {
				r.mux.directUnsupported.Store(true)
				r.mux.closeDirectPool()
			} else if r.fromPool && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
				r.mux.closeDirectPool()
			}
			_ = r.conn.Close()
			return 0, err
		}
		r.ready = true
		r.extra = extra
	}
	if len(r.extra) > 0 {
		n := copy(p, r.extra)
		r.extra = r.extra[n:]
		if len(r.extra) == 0 {
			r.extra = nil
		}
		return n, nil
	}
	return r.conn.Read(p)
}
