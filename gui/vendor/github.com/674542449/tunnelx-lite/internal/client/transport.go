package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/674542449/tunnelx-lite/internal/config"
	"github.com/674542449/tunnelx-lite/internal/diagnostics"
	"github.com/674542449/tunnelx-lite/internal/pulse"
	"github.com/674542449/tunnelx-lite/internal/wire"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type Stats struct {
	Active        atomic.Int64
	Uploaded      atomic.Int64
	Downloaded    atomic.Int64
	UDPDropped    atomic.Int64
	TCPStreams    atomic.Int64
	TCPDials      atomic.Int64
	VisionStreams atomic.Int64
	H2Streams     atomic.Int64
	H2Dials       atomic.Int64
	H2Retired     atomic.Int64
	H2Retries     atomic.Int64
	PulseStreams  atomic.Int64
	PulseDials    atomic.Int64
}
type Mux struct {
	Config            config.Client
	tls               *tls.Config
	mu                sync.Mutex
	h2Mu              sync.Mutex
	h2Pool            []*h2Carrier
	h2Cursor          uint64
	pulseMu           sync.Mutex
	pulse             *pulse.Client
	closed            bool
	Stats             Stats
	LastECH           atomic.Bool
	TLSVersion        atomic.Uint32
	CipherSuite       atomic.Uint32
	LastTCP           atomic.Uint32
	recorder          atomic.Pointer[diagnostics.Logger]
	flowMu            sync.Mutex
	flows             map[string]*flowLog
	growing           bool // a background carrier dial is in progress; guarded by h2Mu
	direct            directPoolState
	directUnsupported atomic.Bool
	visionSupported   atomic.Bool
	bindAddr          net.Addr // tests only: source address for carrier dials
	uplinkIfV4        uint32
	uplinkIfV6        uint32
}

// SetUplinkInterface binds carrier dials to the physical uplink interface (used
// for latency probes while TUN is active so probes bypass the TUN adapter).
func (m *Mux) SetUplinkInterface(ifV4, ifV6 uint32) {
	m.uplinkIfV4, m.uplinkIfV6 = ifV4, ifV6
}

type h2Carrier struct {
	conn          *http2.ClientConn
	tcp           net.Conn
	born          time.Time
	draining      bool
	id            string
	closeReported bool
}

func New(c config.Client) (*Mux, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	t, e := c.TLS()
	if e != nil {
		return nil, e
	}
	m := &Mux{Config: c, tls: t}
	return m, nil
}
func (m *Mux) address() string {
	return net.JoinHostPort(m.Config.ServerIP, strconv.Itoa(m.Config.Port))
}
func (m *Mux) authority() string {
	return net.JoinHostPort(m.Config.ServerName, strconv.Itoa(m.Config.Port))
}
func (m *Mux) Mode() string {
	if m.IsPulse() {
		return "txpulse"
	}
	if m.Config.Transport == "tcp" {
		return "tcp"
	}
	return "h2"
}

func (m *Mux) h2(ctx context.Context) (*http2.ClientConn, error) {
	// Serialize pool mutation without holding the lifecycle mutex during TCP/TLS dialing.
	m.h2Mu.Lock()
	defer m.h2Mu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	var usable []*h2Carrier
	kept := m.h2Pool[:0]
	for _, entry := range m.h2Pool {
		state := entry.conn.State()
		if state.Closed || (entry.draining && state.StreamsActive == 0 && state.StreamsPending == 0 && state.StreamsReserved == 0) {
			if !entry.closeReported {
				reason := "observed_closed"
				if entry.draining {
					reason = "drain_completed"
				}
				m.event(ctx, "carrier_closed", map[string]any{"transport": "h2", "carrier_id": entry.id, "active_streams": state.StreamsActive, "reason": reason})
			}
			entry.conn.Close()
			entry.tcp.Close()
			continue
		}
		kept = append(kept, entry)
	}
	m.h2Pool = kept
	draining := 0
	for _, entry := range m.h2Pool {
		if entry.draining {
			draining++
		}
	}
	for _, entry := range m.h2Pool {
		// Bound old carriers to one extra pool. Never interrupt an active download
		// merely because its carrier is old; defer rotation when the drain cap is full.
		if !entry.draining && (entry.conn.State().Closing || (m.Config.H2MaxAge > 0 && time.Since(entry.born) >= time.Duration(m.Config.H2MaxAge)*time.Second)) && draining < m.Config.H2Connections {
			entry.draining = true
			reason := "age_rotation"
			if entry.conn.State().Closing {
				reason = "peer_goaway"
			}
			m.event(ctx, "carrier_draining", map[string]any{"transport": "h2", "carrier_id": entry.id, "reason": reason, "active_streams": entry.conn.State().StreamsActive})
			draining++
			m.Stats.H2Retired.Add(1)
		}
		if !entry.draining && entry.conn.CanTakeNewRequest() {
			usable = append(usable, entry)
		}
	}
	// Spreading streams over several carriers keeps one lost packet from
	// stalling every page request (TCP head-of-line blocking). Missing carriers
	// are dialed in the background so a new flow never waits for a handshake
	// while a usable carrier exists. Each carrier admits a limited number of
	// streams (128 on txlite servers), so the pool also grows when all are busy.
	poolCap := max(2*m.Config.H2Connections, 8)
	if len(usable) > 0 && len(usable) < m.Config.H2Connections && len(m.h2Pool) < poolCap && !m.growing {
		m.growing = true
		go m.grow()
	}
	if len(usable) > 0 || len(m.h2Pool) >= poolCap {
		// Least loaded first; the cursor breaks ties so idle carriers share work.
		start := int(m.h2Cursor % uint64(max(len(usable), 1)))
		m.h2Cursor++
		order := make([]*h2Carrier, 0, len(usable))
		order = append(order, usable[start:]...)
		order = append(order, usable[:start]...)
		sort.SliceStable(order, func(i, j int) bool { return order[i].conn.State().StreamsActive < order[j].conn.State().StreamsActive })
		for _, entry := range order {
			if entry.conn.ReserveNewRequest() {
				return entry.conn, nil
			}
		}
		if len(m.h2Pool) >= poolCap {
			return nil, errors.New("H2 connection pool is temporarily full")
		}
	}
	entry, e := m.dialCarrier(ctx)
	if e != nil {
		return nil, e
	}
	m.h2Pool = append(m.h2Pool, entry)
	if !entry.conn.ReserveNewRequest() {
		entry.conn.Close()
		return nil, net.ErrClosed
	}
	return entry.conn, nil
}

// grow adds one carrier without holding h2Mu during the handshake.
func (m *Mux) grow() {
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), scopeKey{}, "carrier"), m.Config.Timeout())
	defer cancel()
	entry, e := m.dialCarrier(ctx)
	m.h2Mu.Lock()
	defer m.h2Mu.Unlock()
	m.growing = false
	if e != nil {
		return
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		entry.conn.Close()
		entry.tcp.Close()
		return
	}
	m.h2Pool = append(m.h2Pool, entry)
}

// dialCarrier opens one TLS + HTTP/2 connection to the server.
func (m *Mux) dialCarrier(ctx context.Context) (*h2Carrier, error) {
	if m.tls == nil {
		return nil, errors.New("TLS configuration unavailable for this transport")
	}
	t := m.tls.Clone()
	t.NextProtos = []string{"h2"}
	nd := &net.Dialer{LocalAddr: m.bindAddr, KeepAlive: 30 * time.Second, Control: uplinkControl(m.uplinkIfV4, m.uplinkIfV6)}
	raw, e := nd.DialContext(ctx, "tcp", m.address())
	if e != nil {
		fields := errorFields(e)
		fields["transport"] = "h2"
		fields["stage"] = "tcp_tls_handshake"
		m.event(ctx, "carrier_dial_failed", fields)
		return nil, e
	}
	tuneCarrierTCP(raw)
	tc := tls.Client(raw, t)
	if e = tc.HandshakeContext(ctx); e != nil {
		raw.Close()
		fields := errorFields(e)
		fields["transport"] = "h2"
		fields["stage"] = "tcp_tls_handshake"
		m.event(ctx, "carrier_dial_failed", fields)
		return nil, e
	}
	var c net.Conn = tc
	if tc.ConnectionState().NegotiatedProtocol != "h2" {
		c.Close()
		return nil, errors.New("server did not negotiate HTTP/2")
	}
	m.LastECH.Store(tc.ConnectionState().ECHAccepted)
	m.TLSVersion.Store(uint32(tc.ConnectionState().Version))
	m.CipherSuite.Store(uint32(tc.ConnectionState().CipherSuite))
	tr := &http2.Transport{MaxReadFrameSize: 256 << 10, MaxHeaderListSize: 16 << 10, ReadIdleTimeout: time.Duration(m.Config.H2ReadIdle) * time.Second, PingTimeout: time.Duration(m.Config.H2PingTimeout) * time.Second}
	cc, e := tr.NewClientConn(c)
	if e != nil {
		c.Close()
		return nil, e
	}
	id := m.recorder.Load().ID("carrier")
	m.event(ctx, "carrier_opened", map[string]any{"transport": "h2", "carrier_id": id, "ech_accepted": tc.ConnectionState().ECHAccepted})
	m.Stats.H2Dials.Add(1)
	return &h2Carrier{conn: cc, tcp: c, born: time.Now(), id: id}, nil
}

func (m *Mux) retireH2(cc *http2.ClientConn) {
	m.h2Mu.Lock()
	defer m.h2Mu.Unlock()
	for i, entry := range m.h2Pool {
		if entry.conn == cc {
			m.event(context.WithValue(context.Background(), scopeKey{}, "carrier"), "carrier_failed", map[string]any{"transport": "h2", "carrier_id": entry.id, "active_streams": entry.conn.State().StreamsActive, "reason": "confirmed_transport_failure"})
			// A transport failure affects every stream on this carrier. Removing it
			// prevents new requests from waiting repeatedly on the same bad socket.
			entry.conn.Close()
			entry.tcp.Close()
			m.h2Pool = append(m.h2Pool[:i], m.h2Pool[i+1:]...)
			m.Stats.H2Retired.Add(1)
			return
		}
	}
}

func (m *Mux) failedH2Carrier(ctx context.Context, cc *http2.ClientConn, err error) bool {
	if !transportFailure(ctx, err, !cc.CanTakeNewRequest()) {
		return false
	}
	// A slow origin can delay CONNECT while the H2 carrier is perfectly healthy.
	// Confirm a header timeout with PING before interrupting unrelated streams.
	if errors.Is(err, context.DeadlineExceeded) && cc.CanTakeNewRequest() {
		pingCtx, cancel := context.WithTimeout(ctx, time.Duration(m.Config.H2PingTimeout)*time.Second)
		defer cancel()
		pingError := cc.Ping(pingCtx)
		fields := errorFields(pingError)
		fields["transport"] = "h2"
		fields["carrier_id"] = m.h2CarrierID(cc)
		fields["healthy"] = pingError == nil
		m.event(ctx, "carrier_ping_result", fields)
		if pingError == nil {
			return false
		}
	}
	return ctx.Err() == nil
}
func securityError(e error) bool {
	var a x509.UnknownAuthorityError
	var b x509.HostnameError
	var c x509.CertificateInvalidError
	var d *tls.CertificateVerificationError
	var f *tls.ECHRejectionError
	return errors.As(e, &a) || errors.As(e, &b) || errors.As(e, &c) || errors.As(e, &d) || errors.As(e, &f)
}
func transportFailure(ctx context.Context, e error, connectionClosed bool) bool {
	var re *RequestError
	var timeout net.Error
	transportFailure := connectionClosed || (errors.As(e, &timeout) && timeout.Timeout()) || errors.Is(e, io.EOF) || errors.Is(e, io.ErrUnexpectedEOF) || errors.Is(e, net.ErrClosed)
	return transportFailure && !errors.As(e, &re) && !securityError(e) && ctx.Err() == nil
}

type Tunnel struct {
	io.Reader
	io.Writer
	closeWrite   func() error
	close        func() error
	setDeadline  func(time.Time) error
	visionDirect func() bool
	transport    string
	carrierID    string
}

func (t *Tunnel) CloseWrite() error { return t.closeWrite() }
func (t *Tunnel) Close() error      { return t.close() }
func (t *Tunnel) SetDeadline(v time.Time) error {
	if t.setDeadline != nil {
		return t.setDeadline(v)
	}
	return nil
}
func (t *Tunnel) Transport() string { return t.transport }

// VisionDirect reports whether both read and write directions of this tunnel
// have peeled off outer TLS and switched to raw TCP direct splice.
func (t *Tunnel) VisionDirect() bool { return t.visionDirect != nil && t.visionDirect() }

type RequestError struct {
	Status int
	Known  bool
}

func (e *RequestError) Error() string {
	if !e.Known {
		return "proxy request rejected; authentication or protocol not confirmed"
	}
	return fmt.Sprintf("proxy request failed: HTTP %d", e.Status)
}
func request(m *Mux, target string, udp bool) *http.Request {
	u := &url.URL{Scheme: "https", Host: m.authority()}
	r := &http.Request{Method: "CONNECT", URL: u, Host: target, Header: make(http.Header)}
	if udp {
		h, p, _ := net.SplitHostPort(target)
		u.Path = "/.well-known/masque/udp/" + h + "/" + p + "/"
		u.RawPath = "/.well-known/masque/udp/" + url.PathEscape(h) + "/" + url.PathEscape(p) + "/"
		r.Host = m.authority()
		r.Header.Set("Capsule-Protocol", "?1")
	}
	r.Header.Set("Authorization", "Bearer "+m.Config.Token)
	r.Header.Set("Tunnelx-Version", config.Version)
	if m.Config.DeviceID != "" {
		r.Header.Set("Tunnelx-Device", m.Config.DeviceID)
	}
	r.Header.Set("Priority", "u=3, i")
	return r
}
func checkResponse(r *http.Response, udp bool) error {
	if r.StatusCode != 200 || r.Header.Get("Tunnelx-Version") != config.Version {
		return &RequestError{Status: r.StatusCode, Known: r.Header.Get("Tunnelx-Version") == config.Version}
	}
	if udp && r.Header.Get("Capsule-Protocol") != "?1" {
		return errors.New("server did not negotiate Capsule protocol")
	}
	return nil
}
func (m *Mux) open(ctx context.Context, target string, udp bool) (*Tunnel, error) {
	if _, p, e := net.SplitHostPort(target); e != nil || p == "" {
		return nil, errors.New("invalid target")
	}
	dialCtx, cancel := context.WithTimeout(ctx, m.Config.Timeout())
	h, e := m.h2(dialCtx)
	cancel()
	if e != nil {
		return nil, e
	}
	t, openErr := m.openH2(ctx, h, request(m, target, udp), udp)
	if openErr == nil {
		return t, nil
	}
	fields := errorFields(openErr)
	fields["transport"], fields["carrier_id"], fields["stage"] = "h2", m.h2CarrierID(h), "connect_headers"
	m.event(ctx, "open_attempt_failed", fields)
	if !m.failedH2Carrier(ctx, h, openErr) {
		return nil, openErr
	}
	m.retireH2(h)
	if !m.Config.H2RetryNew {
		return nil, openErr
	}
	// Retry only the unopened CONNECT. No application bytes have been accepted.
	m.Stats.H2Retries.Add(1)
	m.event(ctx, "new_carrier_retry", map[string]any{"transport": "h2"})
	dialCtx, cancel = context.WithTimeout(ctx, m.Config.Timeout())
	h, e = m.h2(dialCtx)
	cancel()
	if e != nil {
		return nil, e
	}
	t, openErr = m.openH2(ctx, h, request(m, target, udp), udp)
	if openErr != nil && m.failedH2Carrier(ctx, h, openErr) {
		m.retireH2(h)
	}
	return t, openErr
}

func (m *Mux) openH2(ctx context.Context, h *http2.ClientConn, r *http.Request, udp bool) (*Tunnel, error) {
	if udp {
		r.Header.Set(":protocol", "connect-udp")
	}
	reader, writer := io.Pipe()
	r.Body = reader
	r.ContentLength = -1
	live, cancelLive := context.WithCancel(ctx)
	r = r.WithContext(live)
	type result struct {
		r *http.Response
		e error
	}
	ch := make(chan result)
	go func() {
		resp, e := h.RoundTrip(r)
		select {
		case ch <- result{resp, e}:
		case <-live.Done():
			if resp != nil {
				resp.Body.Close()
			}
		}
	}()
	cleanup := func() error { cancelLive(); writer.Close(); reader.Close(); return nil }
	timer := time.NewTimer(m.Config.Timeout())
	defer timer.Stop()
	var res result
	select {
	case res = <-ch:
	case <-ctx.Done():
		cleanup()
		return nil, ctx.Err()
	case <-timer.C:
		cleanup()
		return nil, context.DeadlineExceeded
	}
	if res.e != nil {
		cleanup()
		return nil, res.e
	}
	if e := checkResponse(res.r, udp); e != nil {
		cleanup()
		res.r.Body.Close()
		return nil, e
	}
	m.Stats.H2Streams.Add(1)
	closeFn := func() error { cleanup(); return res.r.Body.Close() }
	t := &Tunnel{Reader: res.r.Body, Writer: writer, closeWrite: writer.Close, close: closeFn, transport: "h2", carrierID: m.h2CarrierID(h)}
	return t, nil
}
func (m *Mux) OpenTCP(ctx context.Context, target string) (*Tunnel, error) {
	if _, p, e := net.SplitHostPort(target); e != nil || p == "" {
		return nil, errors.New("invalid target")
	}
	if m.IsPulse() {
		t, e := m.openPulseTCP(ctx, target, true)
		if e != nil {
			fields := errorFields(e)
			fields["stage"] = "open_tcp"
			m.event(ctx, "connection_open_failed", fields)
			flowFrom(ctx).failure("open_tcp", e)
		}
		return t, e
	}
	if m.wantsDirectTCP() {
		t, e := m.openDirectTCP(ctx, target)
		if !errors.Is(e, errDirectUnsupported) {
			if e == nil {
				flowFrom(ctx).openedOn(t)
				m.LastTCP.Store(1)
			} else {
				fields := errorFields(e)
				fields["stage"] = "open_tcp"
				m.event(ctx, "connection_open_failed", fields)
				flowFrom(ctx).failure("open_tcp", e)
			}
			return t, e
		}
	}
	t, e := m.open(ctx, target, false)
	if e == nil {
		flowFrom(ctx).openedOn(t)
		m.LastTCP.Store(2)
	} else {
		fields := errorFields(e)
		fields["stage"] = "open_tcp"
		m.event(ctx, "connection_open_failed", fields)
		flowFrom(ctx).failure("open_tcp", e)
	}
	return t, e
}
func (m *Mux) OpenUDP(ctx context.Context, target string) (PacketTransport, error) {
	if m.IsPulse() {
		u, e := m.openPulseUDP(ctx, target)
		if e != nil {
			fields := errorFields(e)
			fields["stage"] = "open_udp"
			m.event(ctx, "connection_open_failed", fields)
			flowFrom(ctx).failure("open_udp", e)
			return nil, e
		}
		return u, nil
	}
	t, e := m.open(ctx, target, true)
	if e != nil {
		fields := errorFields(e)
		fields["stage"] = "open_udp"
		m.event(ctx, "connection_open_failed", fields)
		flowFrom(ctx).failure("open_udp", e)
		return nil, e
	}
	flowFrom(ctx).openedOn(t)
	return wire.NewPacketStream(ctx, t, func() { t.Close() }), nil
}
func (m *Mux) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	m.closePulse()
	m.closeDirectPool()
	m.h2Mu.Lock()
	defer m.h2Mu.Unlock()
	for _, entry := range m.h2Pool {
		entry.conn.Close()
		entry.tcp.Close()
	}
	m.h2Pool = nil
	return nil
}
func (m *Mux) PublicGET(ctx context.Context) (*http.Response, error) {
	if m.IsPulse() {
		return nil, errors.New("PublicGET is not supported on TXPulse UDP transport")
	}
	// Connection checks use their own carriers. Closing or canceling a diagnostic
	// response must not disturb long-lived application connections.
	c := m.Config
	c.Transport = "h2"
	ctx = context.WithValue(ctx, scopeKey{}, "manual_probe")
	probe, e := New(c)
	if e != nil {
		return nil, e
	}
	probe.SetUplinkInterface(m.uplinkIfV4, m.uplinkIfV6)
	probe.recorder.Store(m.recorder.Load())
	res, e := probe.publicGET(ctx)
	m.LastECH.Store(probe.LastECH.Load())
	m.TLSVersion.Store(probe.TLSVersion.Load())
	m.CipherSuite.Store(probe.CipherSuite.Load())
	if e != nil {
		m.event(ctx, "manual_probe_failed", errorFields(e))
		probe.Close()
		return nil, e
	}
	m.event(ctx, "manual_probe_result", map[string]any{"http_status": res.StatusCode, "ech_accepted": probe.LastECH.Load()})
	res.Body = &probeBody{ReadCloser: res.Body, closeCarrier: probe.Close}
	return res, nil
}

type probeBody struct {
	io.ReadCloser
	closeCarrier func() error
	once         sync.Once
}

func (b *probeBody) Close() error {
	var err error
	b.once.Do(func() {
		err = b.ReadCloser.Close()
		b.closeCarrier()
	})
	return err
}

func (m *Mux) publicGET(ctx context.Context) (*http.Response, error) {
	dialCtx, cancel := context.WithTimeout(ctx, m.Config.Timeout())
	h, e := m.h2(dialCtx)
	cancel()
	if e != nil {
		return nil, e
	}
	r, e := http.NewRequestWithContext(ctx, "GET", "https://"+m.authority()+"/", nil)
	if e != nil {
		return nil, e
	}
	return h.RoundTrip(r)
}
