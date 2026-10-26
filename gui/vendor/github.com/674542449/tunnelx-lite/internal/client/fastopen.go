package client

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/674542449/tunnelx-lite/internal/wire"
)

// OpenTCPFast sends CONNECT and returns at once, so the application's first
// bytes (usually a TLS ClientHello) travel right behind the request instead
// of one round trip later. A refused or failed CONNECT surfaces as a read
// error on the tunnel, like Hysteria's fastOpen.
func (m *Mux) OpenTCPFast(ctx context.Context, target string) (*Tunnel, error) {
	if _, p, e := net.SplitHostPort(target); e != nil || p == "" {
		return nil, errors.New("invalid target")
	}
	if t, ok, e := m.openOverQUIC(ctx, wire.QUICTCP, target, false); ok {
		if e != nil {
			flowFrom(ctx).failure("open_tcp", e)
		}
		return t, e
	}
	dialCtx, cancel := context.WithTimeout(ctx, m.Config.Timeout())
	h, e := m.h2(dialCtx)
	cancel()
	if e != nil {
		fields := errorFields(e)
		fields["stage"] = "open_tcp"
		m.event(ctx, "connection_open_failed", fields)
		flowFrom(ctx).failure("open_tcp", e)
		return nil, e
	}
	r := request(m, target, false)
	reader, writer := io.Pipe()
	r.Body = reader
	r.ContentLength = -1
	live, cancelLive := context.WithCancel(ctx)
	r = r.WithContext(live)
	body := &pendingBody{ready: make(chan struct{})}
	cleanup := func() { cancelLive(); writer.Close(); reader.Close() }
	carrier := m.h2CarrierID(h)
	go func() {
		timeout := time.AfterFunc(m.Config.Timeout(), func() {
			body.resolve(nil, context.DeadlineExceeded)
			cleanup()
		})
		res, e := h.RoundTrip(r)
		timeout.Stop()
		if e == nil {
			if e = checkResponse(res, false); e != nil {
				res.Body.Close()
			}
		}
		if e != nil {
			fields := errorFields(e)
			fields["transport"], fields["carrier_id"], fields["stage"] = "h2", carrier, "connect_headers"
			m.event(ctx, "open_attempt_failed", fields)
			flowFrom(ctx).failure("open_tcp", e)
			if m.failedH2Carrier(ctx, h, e) {
				m.retireH2(h)
			}
			cleanup()
			body.resolve(nil, e)
			return
		}
		m.Stats.H2Streams.Add(1)
		body.resolve(res.Body, nil)
	}()
	t := &Tunnel{Reader: body, Writer: writer, closeWrite: writer.Close, close: func() error { cleanup(); return body.Close() }, transport: "h2", carrierID: carrier}
	flowFrom(ctx).openedOn(t)
	m.LastTCP.Store(2)
	return t, nil
}

// pendingBody is the response side of a fast-open tunnel: reads wait until
// the server has answered CONNECT.
type pendingBody struct {
	once   sync.Once
	ready  chan struct{}
	mu     sync.Mutex
	body   io.ReadCloser
	err    error
	closed bool
}

func (p *pendingBody) resolve(body io.ReadCloser, err error) {
	used := false
	p.once.Do(func() {
		p.mu.Lock()
		// A body that arrives after Close stays in the parameter so it is closed below.
		if p.closed && body != nil {
			p.body, p.err = nil, net.ErrClosed
		} else {
			p.body, p.err = body, err
			used = body != nil
		}
		p.mu.Unlock()
		close(p.ready)
	})
	if !used && body != nil {
		body.Close()
	}
}

func (p *pendingBody) Read(b []byte) (int, error) {
	<-p.ready
	if p.err != nil {
		return 0, p.err
	}
	return p.body.Read(b)
}

func (p *pendingBody) Close() error {
	p.mu.Lock()
	p.closed = true
	body := p.body
	p.mu.Unlock()
	p.resolve(nil, net.ErrClosed)
	if body != nil {
		return body.Close()
	}
	return nil
}
