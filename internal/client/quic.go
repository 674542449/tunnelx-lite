package client

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/674542449/tunnelx-lite/internal/congestion"
	"github.com/674542449/tunnelx-lite/internal/wire"
	"github.com/apernet/quic-go"
)

// quicState is the client's single QUIC connection. QUIC multiplexes streams
// without head-of-line blocking, so one connection carries every flow.
type quicState struct {
	mu       sync.Mutex
	conn     *quic.Conn
	dialing  bool
	failures int
	retryAt  time.Time
	dialLock sync.Mutex // serializes synchronous dials in forced QUIC mode
}

var errQUICOnly = errors.New("QUIC 连接不可用：请确认服务器已开启 QUIC 并在防火墙 / 安全组放行 UDP 端口，或改用自动 / TCP 传输")

func (m *Mux) wantsQUIC() bool { return m.Config.Transport == "quic" || m.Config.Transport == "auto" }

// ActiveTransport reports what new flows use right now: "quic" or "h2".
func (m *Mux) ActiveTransport() string {
	m.quic.mu.Lock()
	defer m.quic.mu.Unlock()
	if m.quic.conn != nil && m.quic.conn.Context().Err() == nil {
		return "quic"
	}
	return "h2"
}

// PrewarmQUIC starts the QUIC handshake in the background (auto mode) so the
// first page after connecting can already use it.
func (m *Mux) PrewarmQUIC() {
	if m.Config.Transport == "auto" {
		m.quicCarrier(context.Background())
	}
}

// quicCarrier returns a live QUIC connection, or nil when flows should use
// HTTP/2. In auto mode it never waits for a handshake: a missing connection
// is dialed in the background, with backoff while UDP does not get through.
func (m *Mux) quicCarrier(ctx context.Context) (*quic.Conn, error) {
	if !m.wantsQUIC() {
		return nil, nil
	}
	q := &m.quic
	q.mu.Lock()
	if q.conn != nil && q.conn.Context().Err() == nil {
		c := q.conn
		q.mu.Unlock()
		return c, nil
	}
	q.conn = nil
	if m.Config.Transport == "auto" {
		if !q.dialing && time.Now().After(q.retryAt) {
			q.dialing = true
			go func() {
				dial, cancel := context.WithTimeout(context.WithValue(context.Background(), scopeKey{}, "carrier"), m.Config.Timeout())
				defer cancel()
				m.dialQUIC(dial)
			}()
		}
		q.mu.Unlock()
		return nil, nil
	}
	q.mu.Unlock()
	q.dialLock.Lock()
	defer q.dialLock.Unlock()
	q.mu.Lock()
	if q.conn != nil && q.conn.Context().Err() == nil {
		c := q.conn
		q.mu.Unlock()
		return c, nil
	}
	q.mu.Unlock()
	dial, cancel := context.WithTimeout(ctx, m.Config.Timeout())
	defer cancel()
	c, e := m.dialQUIC(dial)
	if e != nil {
		return nil, errQUICOnly
	}
	return c, nil
}

func (m *Mux) dialQUIC(ctx context.Context) (*quic.Conn, error) {
	c, e := m.handshakeQUIC(ctx)
	q := &m.quic
	q.mu.Lock()
	defer q.mu.Unlock()
	q.dialing = false
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if e == nil && closed {
		c.CloseWithError(0, "")
		return nil, net.ErrClosed
	}
	if e != nil {
		q.failures++
		q.retryAt = time.Now().Add(min(30*time.Second<<min(q.failures-1, 5), 10*time.Minute))
		fields := errorFields(e)
		fields["transport"], fields["stage"] = "quic", "quic_handshake"
		m.event(ctx, "carrier_dial_failed", fields)
		return nil, e
	}
	q.failures, q.conn = 0, c
	m.event(ctx, "carrier_opened", map[string]any{"transport": "quic", "ech_accepted": c.ConnectionState().TLS.ECHAccepted})
	return c, nil
}

func (m *Mux) handshakeQUIC(ctx context.Context) (*quic.Conn, error) {
	t := m.tls.Clone()
	t.NextProtos = []string{wire.QUICALPN}
	addr, e := net.ResolveUDPAddr("udp", m.address())
	if e != nil {
		return nil, e
	}
	var pc net.PacketConn
	if m.bindAddr != nil {
		pc, e = net.ListenUDP("udp", &net.UDPAddr{IP: m.bindAddr.(*net.TCPAddr).IP})
	} else {
		pc, e = net.ListenUDP("udp", nil)
	}
	if e != nil {
		return nil, e
	}
	tr := &quic.Transport{Conn: pc}
	c, e := tr.Dial(ctx, addr, t, wire.QUICConfig())
	if e != nil {
		tr.Close()
		pc.Close()
		return nil, e
	}
	congestion.UseBBR(c)
	go func() { <-c.Context().Done(); tr.Close(); pc.Close() }()
	if m.Config.Privacy == "strict" && !c.ConnectionState().TLS.ECHAccepted {
		c.CloseWithError(0, "")
		return nil, errors.New("server did not accept ECH over QUIC")
	}
	m.LastECH.Store(c.ConnectionState().TLS.ECHAccepted)
	return c, nil
}

// dropQUIC forgets a connection that failed so the next flow redials or
// falls back to HTTP/2.
func (m *Mux) dropQUIC(c *quic.Conn) {
	q := &m.quic
	q.mu.Lock()
	if q.conn == c {
		q.conn = nil
		q.failures++
		q.retryAt = time.Now().Add(min(30*time.Second<<min(q.failures-1, 5), 10*time.Minute))
	}
	q.mu.Unlock()
	c.CloseWithError(0, "")
}

func (m *Mux) closeQUIC() {
	q := &m.quic
	q.mu.Lock()
	c := q.conn
	q.conn = nil
	q.mu.Unlock()
	if c != nil {
		c.CloseWithError(0, "")
	}
}

type quicBody struct{ st *quic.Stream }

func (b quicBody) Read(p []byte) (int, error) { return b.st.Read(p) }
func (b quicBody) Close() error               { b.st.CancelRead(0); return nil }

// openQUIC opens one flow. With wait=false the tunnel is returned before the
// server answers (fast open); otherwise it returns after a successful answer.
func (m *Mux) openQUIC(ctx context.Context, c *quic.Conn, kind byte, target string, wait bool) (*Tunnel, error) {
	header, e := wire.QUICHeader(kind, m.Config.Token, target)
	if e != nil {
		return nil, e
	}
	open, cancel := context.WithTimeout(ctx, m.Config.Timeout())
	st, e := c.OpenStreamSync(open)
	cancel()
	if e != nil {
		if c.Context().Err() != nil {
			m.dropQUIC(c)
		}
		return nil, e
	}
	if _, e = st.Write(header); e != nil {
		st.CancelRead(0)
		st.CancelWrite(0)
		return nil, e
	}
	body := &pendingBody{ready: make(chan struct{})}
	go func() {
		st.SetReadDeadline(time.Now().Add(m.Config.Timeout()))
		code := make([]byte, 1)
		_, e := io.ReadFull(st, code)
		st.SetReadDeadline(time.Time{})
		if e == nil && code[0] != wire.QUICOK {
			e = &RequestError{Status: wire.QUICStatus(code[0]), Known: true}
		}
		if e != nil {
			fields := errorFields(e)
			fields["transport"], fields["stage"] = "quic", "stream_answer"
			m.event(ctx, "open_attempt_failed", fields)
			st.CancelRead(0)
			st.CancelWrite(0)
			if c.Context().Err() != nil {
				m.dropQUIC(c)
			}
			body.resolve(nil, e)
			return
		}
		body.resolve(quicBody{st}, nil)
	}()
	t := &Tunnel{Reader: body, Writer: st, closeWrite: st.Close, close: func() error { body.Close(); st.CancelRead(0); return st.Close() }, transport: "quic"}
	if wait {
		<-body.ready
		if body.err != nil {
			t.Close()
			return nil, body.err
		}
	}
	m.LastTCP.Store(3)
	flowFrom(ctx).openedOn(t)
	return t, nil
}

// openOverQUIC tries QUIC first. ok is false when the flow should use HTTP/2
// instead (QUIC off, not ready in auto mode, or a transport failure in auto).
func (m *Mux) openOverQUIC(ctx context.Context, kind byte, target string, wait bool) (t *Tunnel, ok bool, err error) {
	c, err := m.quicCarrier(ctx)
	if err != nil {
		return nil, true, err
	}
	if c == nil {
		return nil, false, nil
	}
	t, err = m.openQUIC(ctx, c, kind, target, wait)
	var refused *RequestError
	if err != nil && m.Config.Transport == "auto" && !errors.As(err, &refused) && ctx.Err() == nil {
		return nil, false, nil
	}
	return t, true, err
}
