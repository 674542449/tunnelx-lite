package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/674542449/tunnelx-lite/internal/congestion"
	"github.com/674542449/tunnelx-lite/internal/wire"
	"github.com/apernet/quic-go"
)

// ServeQUIC listens on the UDP port with the same number as the TCP listener.
func (s *Server) ServeQUIC(ctx context.Context) error {
	tlsCfg, e := s.Config.TLS()
	if e != nil {
		return e
	}
	tlsCfg.NextProtos = []string{wire.QUICALPN}
	network := map[string]string{"tcp4": "udp4", "tcp6": "udp6"}[s.Config.Network]
	if network == "" {
		network = "udp"
	}
	pc, e := net.ListenPacket(network, s.Config.Listen)
	if e != nil {
		return e
	}
	tr := &quic.Transport{Conn: pc}
	ln, e := tr.Listen(tlsCfg, wire.QUICConfig())
	if e != nil {
		pc.Close()
		return e
	}
	stop := context.AfterFunc(ctx, func() { ln.Close(); tr.Close(); pc.Close() })
	defer stop()
	for {
		conn, e := ln.Accept(ctx)
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		congestion.UseBBR(conn)
		go s.quicConn(ctx, conn)
	}
}

func (s *Server) quicConn(ctx context.Context, conn *quic.Conn) {
	var authed atomic.Bool
	// A connection that never presents a valid key is dropped quietly.
	probe := time.AfterFunc(10*time.Second, func() {
		if !authed.Load() {
			conn.CloseWithError(0, "")
		}
	})
	defer probe.Stop()
	for {
		st, e := conn.AcceptStream(ctx)
		if e != nil {
			return
		}
		go s.quicStream(conn, st, &authed)
	}
}

func (s *Server) quicStream(conn *quic.Conn, st *quic.Stream, authed *atomic.Bool) {
	defer st.Close()
	defer st.CancelRead(0)
	st.SetReadDeadline(time.Now().Add(10 * time.Second))
	kind, token, target, e := wire.ReadQUICHeader(st)
	if e != nil || s.Config.ManagedOnly || !s.auth.Valid([]string{"Bearer " + token}) {
		conn.CloseWithError(0, "")
		return
	}
	authed.Store(true)
	st.SetReadDeadline(time.Time{})
	answer := func(code byte) bool { _, e := st.Write([]byte{code}); return e == nil }
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		answer(wire.QUICBusy)
		return
	}
	s.Active.Add(1)
	defer s.Active.Add(-1)
	host, port, e := net.SplitHostPort(target)
	p, pe := strconv.Atoi(port)
	if e != nil || pe != nil || p < 1 || p > 65535 || host == "" {
		answer(wire.QUICBadRequest)
		return
	}
	ctx := conn.Context()
	dial, cancel := context.WithTimeout(ctx, time.Duration(s.Config.DialTimeout)*time.Second)
	defer cancel()
	addresses, status := s.resolve(dial, host, target)
	switch status {
	case 0:
	case 403:
		answer(wire.QUICForbidden)
		return
	case 504:
		answer(wire.QUICTimeout)
		return
	default:
		answer(wire.QUICBadGateway)
		return
	}
	if kind == wire.QUICUDP {
		s.quicUDP(ctx, st, addresses[0], p, answer)
		return
	}
	upstream, e := dialTarget(dial, addresses, port)
	if e != nil {
		if errors.Is(e, context.DeadlineExceeded) || dial.Err() != nil {
			answer(wire.QUICTimeout)
		} else {
			answer(wire.QUICBadGateway)
		}
		return
	}
	defer upstream.Close()
	if s.Config.MaxLifetime > 0 {
		lt := time.AfterFunc(time.Duration(s.Config.MaxLifetime)*time.Second, func() { upstream.Close() })
		defer lt.Stop()
	}
	if !answer(wire.QUICOK) {
		return
	}
	stop := context.AfterFunc(ctx, func() { upstream.Close() })
	defer stop()
	idle := time.Duration(s.Config.IdleTimeout) * time.Second
	upLimit, downLimit := s.limiters(ctx)
	var upBytes, downBytes atomic.Int64
	started := time.Now()
	up := make(chan struct{})
	go func() {
		defer close(up)
		var r io.Reader = st
		if upLimit != nil {
			r = throttledReader{r: r, l: upLimit, ctx: ctx}
		}
		_, e := io.CopyBuffer(idleConn{Conn: upstream, idle: idle}, countReader{r: r, n: &upBytes, total: &s.Uploaded}, make([]byte, 32<<10))
		if tcp, ok := upstream.(*net.TCPConn); ok && e == nil {
			tcp.CloseWrite()
		} else if e != nil {
			upstream.Close()
		}
	}()
	var r io.Reader = idleConn{Conn: upstream, idle: idle}
	if downLimit != nil {
		r = throttledReader{r: r, l: downLimit, ctx: ctx}
	}
	if _, e = io.CopyBuffer(st, countReader{r: r, n: &downBytes, total: &s.Downloaded}, make([]byte, 32<<10)); e != nil {
		st.CancelWrite(0)
		st.CancelRead(0)
	} else {
		st.Close()
	}
	select {
	case <-up:
	case <-ctx.Done():
	}
	if s.accessLog != nil {
		s.accessLog.Info("proxy", slog.String("target", target), slog.String("proto", "tcp/quic"), slog.Int64("upload", upBytes.Load()), slog.Int64("download", downBytes.Load()), slog.Int64("duration_ms", time.Since(started).Milliseconds()))
	}
}

func (s *Server) quicUDP(ctx context.Context, st *quic.Stream, ip net.IP, port int, answer func(byte) bool) {
	conn, e := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: port})
	if e != nil {
		answer(wire.QUICBadGateway)
		return
	}
	defer conn.Close()
	if !answer(wire.QUICOK) {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ps := wire.NewPacketStream(ctx, st, func() { st.CancelRead(0) })
	var once sync.Once
	closeAll := func() { once.Do(func() { cancel(); conn.Close(); ps.Close() }) }
	defer closeAll()
	upLimit, downLimit := s.limiters(ctx)
	go func() {
		for {
			b, e := ps.Receive(ctx)
			if e != nil || upLimit.Wait(ctx, len(b)) != nil {
				closeAll()
				return
			}
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
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
		if e != nil || downLimit.Wait(ctx, n) != nil {
			return
		}
		if e = ps.Send(b[:n]); e != nil {
			return
		}
		s.Downloaded.Add(int64(n))
	}
}
