package client

import (
	"context"
	"errors"
	"fmt"
	"github.com/674542449/tunnelx-lite/internal/diagnostics"
	"golang.org/x/net/http2"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type flowKey struct{}
type scopeKey struct{}
type ownerKey struct{}
type flowLog struct {
	id, target, proxy, scope         string
	owner                            diagnostics.Owner
	started                          time.Time
	logger                           *diagnostics.Logger
	mux                              *Mux
	mu                               sync.Mutex
	transport, carrier, lastError    string
	opened                           bool
	up, down, lastActivity           atomic.Int64
	lastProgressUp, lastProgressDown int64
	once                             sync.Once
}

func safeTarget(target string) string {
	host, port, e := net.SplitHostPort(target)
	p, pe := strconv.Atoi(port)
	if e != nil || pe != nil || p < 1 || p > 65535 || len(host) > 253 || strings.ContainsAny(host, " /\\?#@\r\n\t") {
		return "[invalid target]"
	}
	return net.JoinHostPort(host, port)
}
func scope(ctx context.Context) string {
	if s, ok := ctx.Value(scopeKey{}).(string); ok {
		return s
	}
	return "business"
}
func (m *Mux) beginFlow(ctx context.Context, target, proxy string, owner diagnostics.Owner) (context.Context, *flowLog) {
	l := m.recorder.Load()
	if l == nil {
		return ctx, nil
	}
	f := &flowLog{id: l.ID("flow"), target: safeTarget(target), proxy: proxy, scope: scope(ctx), owner: owner, started: time.Now(), logger: l, mux: m}
	f.lastActivity.Store(time.Now().UnixMilli())
	m.flowMu.Lock()
	if m.flows == nil {
		m.flows = make(map[string]*flowLog)
	}
	m.flows[f.id] = f
	m.flowMu.Unlock()
	f.event("connection_requested", nil)
	return context.WithValue(ctx, flowKey{}, f), f
}
func flowFrom(ctx context.Context) *flowLog { f, _ := ctx.Value(flowKey{}).(*flowLog); return f }
func (f *flowLog) event(event string, fields map[string]any) {
	if f == nil {
		return
	}
	entry := make(map[string]any, len(fields)+10)
	entry["connection_id"] = f.id
	entry["scope"] = f.scope
	entry["target"] = f.target
	entry["proxy"] = f.proxy
	entry["application"] = f.owner
	f.mu.Lock()
	entry["transport"] = f.transport
	entry["carrier_id"] = f.carrier
	f.mu.Unlock()
	for k, v := range fields {
		entry[k] = v
	}
	f.logger.Record(event, entry)
}
func errorFields(e error) map[string]any {
	fields := map[string]any{"error_kind": diagnostics.ErrorKind(e)}
	if e != nil {
		fields["error_type"] = fmt.Sprintf("%T", e)
	}
	var errno syscall.Errno
	if errors.As(e, &errno) {
		fields["os_error_code"] = uint32(errno)
		switch uint32(errno) {
		case 10054, 104:
			fields["error_kind"] = "connection_reset"
		case 10053, 103:
			fields["error_kind"] = "connection_aborted"
		case 10061, 111:
			fields["error_kind"] = "connection_refused"
		case 10060, 110:
			fields["error_kind"] = "timeout"
		}
	}
	var requestError *RequestError
	if errors.As(e, &requestError) {
		fields["error_kind"] = "request_rejected"
		fields["http_status"] = requestError.Status
		fields["protocol_confirmed"] = requestError.Known
	}
	if securityError(e) {
		fields["error_kind"] = "tls_security_rejected"
	}
	var h2Error http2.StreamError
	if errors.As(e, &h2Error) {
		fields["error_kind"] = "h2_stream_reset"
		fields["h2_error_code"] = uint32(h2Error.Code)
	}
	return fields
}
func (m *Mux) SetDiagnostics(l *diagnostics.Logger) { m.recorder.Store(l) }
func (m *Mux) LoggingStatus() map[string]any        { return m.recorder.Load().Status() }
func (m *Mux) FinishDiagnostics() {
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.flowMu.Lock()
		n := len(m.flows)
		m.flowMu.Unlock()
		if n == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	m.SnapshotDiagnostics()
}
func (m *Mux) event(ctx context.Context, event string, fields map[string]any) {
	if f := flowFrom(ctx); f != nil {
		f.event(event, fields)
		return
	}
	l := m.recorder.Load()
	if l == nil {
		return
	}
	entry := make(map[string]any, len(fields)+2)
	for k, v := range fields {
		entry[k] = v
	}
	entry["scope"] = scope(ctx)
	l.Record(event, entry)
}
func (f *flowLog) openedOn(t *Tunnel) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.transport = t.transport
	f.carrier = t.carrierID
	f.opened = true
	f.mu.Unlock()
	f.event("connection_opened", map[string]any{"connect_ms": time.Since(f.started).Milliseconds()})
}
func (f *flowLog) failure(stage string, e error) {
	if f == nil || e == nil {
		return
	}
	fields := errorFields(e)
	fields["stage"] = stage
	f.mu.Lock()
	if f.lastError == "" {
		f.lastError, _ = fields["error_kind"].(string)
	}
	f.mu.Unlock()
	f.event("connection_error", fields)
}
func (f *flowLog) directionEnd(direction string, e error) {
	if f == nil {
		return
	}
	fields := errorFields(e)
	fields["direction"] = direction
	if e == nil {
		if direction == "app_to_target" {
			fields["termination"] = "app_eof"
		} else {
			fields["termination"] = "target_eof"
		}
	} else {
		f.failure(direction, e)
	}
	f.event("stream_direction_ended", fields)
}
func (f *flowLog) end() {
	if f == nil {
		return
	}
	f.once.Do(func() {
		f.mu.Lock()
		opened, lastError := f.opened, f.lastError
		f.mu.Unlock()
		result := "completed_or_eof"
		if !opened {
			result = "not_opened"
		}
		if lastError != "" {
			result = "error_observed"
		}
		f.event("connection_ended", map[string]any{"duration_ms": time.Since(f.started).Milliseconds(), "uploaded_bytes": f.up.Load(), "downloaded_bytes": f.down.Load(), "last_activity_unix_ms": f.lastActivity.Load(), "result": result, "last_error_kind": lastError})
		f.mux.flowMu.Lock()
		delete(f.mux.flows, f.id)
		f.mux.flowMu.Unlock()
	})
}

type flowWriter struct {
	io.Writer
	flow   *flowLog
	upload bool
}

func (w flowWriter) Write(b []byte) (int, error) {
	n, e := w.Writer.Write(b)
	if n > 0 {
		if w.upload {
			w.flow.up.Add(int64(n))
		} else {
			w.flow.down.Add(int64(n))
		}
		w.flow.lastActivity.Store(time.Now().UnixMilli())
	}
	return n, e
}
func (f *flowLog) wrap(w io.Writer, up bool) io.Writer {
	if f == nil {
		return w
	}
	return flowWriter{w, f, up}
}
func (f *flowLog) packet(n int, up bool) {
	if f == nil {
		return
	}
	if up {
		f.up.Add(int64(n))
	} else {
		f.down.Add(int64(n))
	}
	f.lastActivity.Store(time.Now().UnixMilli())
}
func (m *Mux) SnapshotDiagnostics() {
	l := m.recorder.Load()
	if l == nil {
		return
	}
	m.flowMu.Lock()
	flows := make([]*flowLog, 0, len(m.flows))
	for _, f := range m.flows {
		flows = append(flows, f)
	}
	m.flowMu.Unlock()
	s := &m.Stats
	l.Record("heartbeat", map[string]any{"scope": "client", "active_connections": len(flows), "uploaded_bytes": s.Uploaded.Load(), "downloaded_bytes": s.Downloaded.Load(), "h2_streams": s.H2Streams.Load(), "h2_dials": s.H2Dials.Load(), "h2_retired": s.H2Retired.Load(), "h2_retries": s.H2Retries.Load(), "udp_dropped": s.UDPDropped.Load(), "logging": l.Status()})
	for _, f := range flows {
		up, down := f.up.Load(), f.down.Load()
		f.mu.Lock()
		changed := up != f.lastProgressUp || down != f.lastProgressDown
		f.lastProgressUp = up
		f.lastProgressDown = down
		f.mu.Unlock()
		if changed {
			f.event("connection_progress", map[string]any{"duration_ms": time.Since(f.started).Milliseconds(), "uploaded_bytes": up, "downloaded_bytes": down, "last_activity_unix_ms": f.lastActivity.Load()})
		}
	}
}

// Health checks use an independent H2 carrier and do not affect business counters.
func (m *Mux) RunDiagnostics(ctx context.Context, interval time.Duration) func() {
	l := m.recorder.Load()
	if l == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for _, mode := range []string{"h2"} {
			mode := mode
			wg.Add(1)
			go func() {
				defer wg.Done()
				c := m.Config
				c.Transport = mode
				c.H2Connections = 1
				c.H2MaxAge = 0
				probe, e := New(c)
				if e != nil {
					l.Record("path_probe_failed", map[string]any{"scope": "health_probe", "transport": mode, "error_kind": "configuration_error"})
					return
				}
				probe.recorder.Store(l)
				defer probe.Close()
				ticker := time.NewTicker(interval)
				defer ticker.Stop()
				failed := false
				var failureStarted time.Time
				for {
					if ctx.Err() != nil {
						return
					}
					started := time.Now()
					probeCtx, cancel := context.WithTimeout(context.WithValue(ctx, scopeKey{}, "health_probe"), 5*time.Second)
					res, err := probe.publicGET(probeCtx)
					status := 0
					if res != nil {
						status = res.StatusCode
						if err == nil {
							_, err = io.Copy(io.Discard, io.LimitReader(res.Body, 8192))
						}
						res.Body.Close()
					}
					cancel()
					if ctx.Err() != nil {
						return
					}
					fields := errorFields(err)
					fields["scope"] = "health_probe"
					fields["transport"] = mode
					fields["latency_ms"] = time.Since(started).Milliseconds()
					fields["http_status"] = status
					fields["probe_started_at"] = started.UTC().Format(time.RFC3339Nano)
					fields["ech_accepted"] = probe.LastECH.Load()
					if err != nil || status != 200 {
						fields["failure_stage"] = "transport_or_read"
						if err == nil {
							fields["failure_stage"] = "public_http_status"
						}
						if !failed {
							failureStarted = started
						}
						failed = true
						l.Record("path_probe_failed", fields)
					} else {
						if failed {
							fields["observed_failure_window_ms"] = time.Since(failureStarted).Milliseconds()
							l.Record("path_probe_recovered", fields)
						} else {
							l.Record("path_probe_ok", fields)
						}
						failed = false
					}
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
					}
				}
			}()
		}
		ticker := time.NewTicker(interval)
		carrierTicker := time.NewTicker(time.Second)
		defer ticker.Stop()
		defer carrierTicker.Stop()
		m.SnapshotDiagnostics()
		for {
			select {
			case <-ctx.Done():
				wg.Wait()
				m.SnapshotDiagnostics()
				return
			case <-ticker.C:
				m.SnapshotDiagnostics()
			case <-carrierTicker.C:
				m.inspectCarriers()
			}
		}
	}()
	return func() { <-done }
}
func (m *Mux) inspectCarriers() {
	if m.recorder.Load() == nil {
		return
	}
	m.h2Mu.Lock()
	defer m.h2Mu.Unlock()
	for _, entry := range m.h2Pool {
		state := entry.conn.State()
		if state.Closed && !entry.closeReported {
			entry.closeReported = true
			m.event(context.WithValue(context.Background(), scopeKey{}, "carrier"), "carrier_closed", map[string]any{"transport": "h2", "carrier_id": entry.id, "active_streams": state.StreamsActive, "draining": entry.draining, "reason": "observed_closed"})
		}
	}
}
func (m *Mux) h2CarrierID(cc interface{}) string {
	m.h2Mu.Lock()
	defer m.h2Mu.Unlock()
	for _, entry := range m.h2Pool {
		if entry.conn == cc {
			return entry.id
		}
	}
	return ""
}
