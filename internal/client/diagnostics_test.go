package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/674542449/tunnelx-lite/internal/diagnostics"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func readDiagnosticEvents(t *testing.T, dir string) []map[string]any {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "events-*.jsonl"))
	var events []map[string]any
	for _, file := range files {
		b, e := os.ReadFile(file)
		if e != nil {
			continue
		}
		last := bytes.LastIndexByte(b, '\n')
		if last < 0 {
			continue
		}
		for _, line := range bytes.Split(b[:last], []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			var event map[string]any
			if json.Unmarshal(line, &event) != nil {
				t.Fatal("invalid event")
			}
			events = append(events, event)
		}
	}
	return events
}
func TestDiagnosticsCorrelateTimeoutAndDoNotLogSecretErrorText(t *testing.T) {
	c := poolServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "slow.test:443" {
			<-r.Context().Done()
			return
		}
		echoConnect(w, r)
	})
	c.H2Connections = 1
	m, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	dir := t.TempDir()
	l, e := diagnostics.New(dir, diagnostics.Options{})
	if e != nil {
		t.Fatal(e)
	}
	m.SetDiagnostics(l)
	exchange(t, m, "warm.test:443")
	ctx, trace := m.beginFlow(context.Background(), "slow.test:443", "http_connect", diagnostics.Owner{PID: 42, Name: "steam.exe", Matched: true})
	_, e = m.OpenTCP(ctx, "slow.test:443")
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	secret := "NEVER_LOG_THIS_SECRET"
	trace.failure("origin_read", errors.New("https://private.example/file?token="+secret))
	trace.end()
	m.Close()
	l.Close()
	events := readDiagnosticEvents(t, dir)
	ping, openFailed, ended := false, false, false
	for _, event := range events {
		b, _ := json.Marshal(event)
		if strings.Contains(string(b), secret) || strings.Contains(string(b), "?token=") {
			t.Fatal("raw error text leaked")
		}
		if event["connection_id"] != trace.id {
			continue
		}
		if event["target"] != "slow.test:443" || event["application"].(map[string]any)["process_name"] != "steam.exe" {
			t.Fatal("connection attribution lost")
		}
		switch event["event"] {
		case "carrier_ping_result":
			ping = event["healthy"] == true
		case "connection_open_failed":
			openFailed = event["error_kind"] == "timeout"
		case "connection_ended":
			ended = true
		}
	}
	if !ping || !openFailed || !ended || m.Stats.H2Retired.Load() != 0 {
		t.Fatal("could not distinguish slow origin from failed carrier", ping, openFailed, ended)
	}
}
func TestHealthProbeRecoveryDoesNotChangeBusinessCounters(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	c := poolServer(t, func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(503)
			return
		}
		io.WriteString(w, "ok")
	})
	m, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	dir := t.TempDir()
	l, e := diagnostics.New(dir, diagnostics.Options{})
	if e != nil {
		t.Fatal(e)
	}
	m.SetDiagnostics(l)
	ctx, cancel := context.WithCancel(context.Background())
	wait := m.RunDiagnostics(ctx, 100*time.Millisecond)
	defer func() { cancel(); wait(); l.Close() }()
	waitEvent := func(name string) {
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			for _, event := range readDiagnosticEvents(t, dir) {
				if event["event"] == name && event["transport"] == "h2" {
					return
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("missing %s", name)
	}
	waitEvent("path_probe_failed")
	fail.Store(false)
	waitEvent("path_probe_recovered")
	if m.Stats.H2Dials.Load() != 0 {
		t.Fatal("health checks affected business counters")
	}
}
