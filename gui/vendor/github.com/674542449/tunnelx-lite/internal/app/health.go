package app

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/674542449/tunnelx-lite/internal/client"
	"github.com/674542449/tunnelx-lite/internal/tunmode"
	"io"
	"runtime"
	"time"
)

func probeHealth(ctx context.Context, m *client.Mux) string {
	if m.Config.Transport == "quic" {
		// The gateway answers an authenticated request for a refused target.
		t, err := m.OpenTCP(ctx, "127.0.0.1:9")
		var refused *client.RequestError
		if err == nil {
			t.Close()
			return ""
		}
		if errors.As(err, &refused) && refused.Known {
			return ""
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "timeout"
		}
		return "network_or_tls"
	}
	r, err := m.PublicGET(ctx)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "timeout"
		}
		return "network_or_tls"
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return "http_status"
	}
	if !m.LastECH.Load() {
		return "ech_rejected"
	}
	if _, err = io.Copy(io.Discard, io.LimitReader(r.Body, 8192)); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "timeout"
		}
		return "response_read"
	}
	return ""
}
func (e *Engine) applyHealth(m *client.Mux, checked int64, kind string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.mux != m {
		return
	}
	e.health.CheckedAt = checked
	e.health.ErrorKind = kind
	if kind == "" {
		e.health.LastSuccess = checked
		e.health.ConsecutiveFailures = 0
		e.stage = "connected"
	} else {
		e.health.ConsecutiveFailures++
		e.stage = "degraded"
	}
}

func updateLayer(layer *HealthLayer, checked int64, kind string) {
	layer.CheckedAt = checked
	layer.ErrorKind = kind
	if kind == "" {
		layer.LastSuccess = checked
		layer.Failures = 0
	} else {
		layer.Failures++
	}
}
func (e *Engine) applyLayers(m *client.Mux, checked int64, kinds [3]string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.mux != m {
		return
	}
	updateLayer(&e.health.Gateway, checked, kinds[0])
	updateLayer(&e.health.DNS, checked, kinds[1])
	updateLayer(&e.health.Egress, checked, kinds[2])
	e.health.CheckedAt = checked
	e.health.ErrorKind = ""
	for i, kind := range kinds {
		if kind != "" {
			e.health.ErrorKind = []string{"gateway_unavailable", "dns_unavailable", "egress_unavailable"}[i]
			break
		}
	}
	if e.health.ErrorKind == "" {
		e.health.LastSuccess = checked
		e.health.ConsecutiveFailures = 0
		e.stage = "connected"
	} else {
		e.health.ConsecutiveFailures++
		e.stage = "degraded"
	}
	if e.logger != nil {
		e.logger.Record("network_health", map[string]any{"scope": "client", "gateway": kinds[0], "dns": kinds[1], "egress": kinds[2]})
	}
}

// Health checks only prove reachability of this TLS/ECH gateway endpoint.
// They deliberately make no claim about every possible upstream destination.
func (e *Engine) startHealth(ctx context.Context, m *client.Mux) <-chan struct{} {
	done := make(chan struct{})
	interval, timeout := e.healthInterval, e.healthTimeout
	degradedInterval := interval / 3
	p := e.proxy
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		first := true
		degraded := false
		for {
			if !first || p == nil {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
			first = false
			if p != nil {
				check, cancel := context.WithTimeout(ctx, 9*time.Second)
				results := make(chan struct {
					index int
					kind  string
				}, 3)
				for i, f := range []func(context.Context) string{func(c context.Context) string { return probeHealth(c, m) }, p.CheckDNS, p.CheckEgress} {
					go func(i int, f func(context.Context) string) {
						results <- struct {
							index int
							kind  string
						}{i, f(check)}
					}(i, f)
				}
				var kinds [3]string
				for i := 0; i < 3; i++ {
					r := <-results
					kinds[r.index] = r.kind
				}
				cancel()
				if ctx.Err() != nil {
					return
				}
				e.applyLayers(m, time.Now().Unix(), kinds)
				nowDegraded := kinds[0] != "" || kinds[1] != "" || kinds[2] != ""
				if nowDegraded != degraded {
					degraded = nowDegraded
					if degraded {
						ticker.Reset(degradedInterval)
					} else {
						ticker.Reset(interval)
					}
				}
				if p.TUN && kinds[0] == "" {
					available := m.ProbeTUNIPv6(ctx)
					if ctx.Err() != nil {
						return
					}
					if p.ObserveIPv6(available) {
						next := p.TUNIPv6.Load()
						flush, stop := context.WithTimeout(ctx, 5*time.Second)
						err := tunmode.FlushDNS(flush)
						stop()
						e.mu.Lock()
						if e.mux == m && e.logger != nil {
							e.logger.Record("tun_ipv6_policy_changed", map[string]any{"scope": "client", "ipv6_available": next, "dns_cache_flushed": err == nil})
						}
						e.mu.Unlock()
					}
				}
				continue
			}
			check, cancel := context.WithTimeout(ctx, timeout)
			kind := probeHealth(check, m)
			cancel()
			if ctx.Err() != nil {
				return
			}
			e.applyHealth(m, time.Now().Unix(), kind)
			nowDegraded := kind != ""
			if nowDegraded != degraded {
				degraded = nowDegraded
				if degraded {
					ticker.Reset(degradedInterval)
				} else {
					ticker.Reset(interval)
				}
			}
		}
	}()
	return done
}
func safeStage(s string) string {
	switch s {
	case "disconnected", "restoring_proxy", "fetching_profile", "verifying_tls", "authenticating", "starting_proxy", "checking_tun_network", "starting_tun", "reconnecting", "connected", "degraded", "cancelling":
		return s
	}
	return "unknown"
}
func safeHealthKind(s string) string {
	switch s {
	case "", "timeout", "network_or_tls", "http_status", "ech_rejected", "response_read", "gateway_unavailable", "dns_unavailable", "egress_unavailable", "dns_resolution", "dns_no_address", "egress_https":
		return s
	}
	return "unknown"
}
func (e *Engine) DiagnosticsReport() (string, error) {
	s := e.Status()
	health := s["health"].(Health)
	health.ErrorKind = safeHealthKind(health.ErrorKind)
	health.Gateway.ErrorKind = safeHealthKind(health.Gateway.ErrorKind)
	health.DNS.ErrorKind = safeHealthKind(health.DNS.ErrorKind)
	health.Egress.ErrorKind = safeHealthKind(health.Egress.ErrorKind)
	report := map[string]any{"report_version": 1, "client_version": Version, "platform": runtime.GOOS, "generated_at": time.Now().UTC().Format(time.RFC3339), "transport": "h2", "connection_state": s["connection_state"], "connection_stage": safeStage(s["connection_stage"].(string)), "health": health, "health_scope": "gateway_tls_ech_only", "system_proxy_saved": s["system_proxy"], "redaction": "Keys, server addresses, paths and browsing history are excluded."}
	report["transport_preference"] = s["transport_preference"]
	report["down_mbps"] = s["preferences"].(Preferences).DownMbps
	for _, key := range []string{"upload", "download", "active", "h2_streams", "connected_at", "ech", "transport"} {
		if v, ok := s[key]; ok {
			report[key] = v
		}
	}
	report["health_scope"] = "gateway_dns_https_probes"
	report["recovering"] = s["recovering"]
	report["recovery_attempt"] = s["recovery_attempt"]
	if logging, ok := s["logging"].(map[string]any); ok {
		counts := map[string]any{}
		for _, key := range []string{"enabled", "written_events", "dropped_events", "io_errors", "max_file_bytes", "max_files"} {
			if v, ok := logging[key]; ok {
				counts[key] = v
			}
		}
		report["logging"] = counts
	}
	b, err := json.MarshalIndent(report, "", "  ")
	return string(b) + "\n", err
}
