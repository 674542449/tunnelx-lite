// Package diagnostics records metadata only. Never pass request headers, URLs,
// payloads or error messages to it: remote error strings can contain secrets.
package diagnostics

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Owner struct {
	PID     uint32 `json:"pid,omitempty"`
	Name    string `json:"process_name,omitempty"`
	Created string `json:"process_created_at,omitempty"`
	Matched bool   `json:"identified"`
	Error   string `json:"lookup_error,omitempty"`
}

type Options struct {
	MaxBytes  int64
	MaxFiles  int
	QueueSize int
}
type record struct {
	data     []byte
	critical bool
}
type Logger struct {
	dir, session string
	started      time.Time
	options      Options
	mu           sync.Mutex
	closed       bool
	queue        chan record
	done         chan struct{}
	ids          atomic.Uint64
	written      atomic.Uint64
	dropped      atomic.Uint64
	ioErrors     atomic.Uint64
	lastWrite    atomic.Int64
	file         atomic.Value
}

func New(dir string, opt Options) (*Logger, error) {
	if opt.MaxBytes <= 0 {
		opt.MaxBytes = 16 << 20
	}
	if opt.MaxFiles <= 0 {
		opt.MaxFiles = 16
	}
	if opt.QueueSize <= 0 {
		opt.QueueSize = 4096
	}
	absolute, e := filepath.Abs(dir)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(absolute, 0700); e != nil {
		return nil, e
	}
	b := make([]byte, 4)
	if _, e = rand.Read(b); e != nil {
		return nil, e
	}
	l := &Logger{dir: absolute, session: hex.EncodeToString(b), started: time.Now(), options: opt, queue: make(chan record, opt.QueueSize), done: make(chan struct{})}
	f, e := l.open(0)
	if e != nil {
		return nil, e
	}
	l.file.Store(f.Name())
	go l.write(f)
	return l, nil
}
func (l *Logger) ID(prefix string) string {
	if l == nil {
		return ""
	}
	return fmt.Sprintf("%s-%s-%d", l.session, prefix, l.ids.Add(1))
}
func (l *Logger) Record(event string, fields map[string]any) {
	if l == nil {
		return
	}
	entry := make(map[string]any, len(fields)+4)
	for k, v := range fields {
		entry[k] = v
	}
	entry["event"] = event
	entry["session"] = l.session
	entry["time"] = time.Now().UTC().Format(time.RFC3339Nano)
	entry["uptime_ms"] = time.Since(l.started).Milliseconds()
	b, e := json.Marshal(entry)
	if e != nil || len(b) > 16384 {
		l.dropped.Add(1)
		return
	}
	b = append(b, '\n')
	critical := event == "client_started" || event == "client_stopped" || event == "transport_fallback" || event == "path_probe_failed" || event == "path_probe_recovered" || event == "connection_open_failed" || event == "carrier_failed"
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	select {
	case l.queue <- record{b, critical}:
	default:
		l.dropped.Add(1)
	}
}
func (l *Logger) Status() map[string]any {
	if l == nil {
		return map[string]any{"enabled": false}
	}
	return map[string]any{"enabled": true, "directory": l.dir, "current_file": l.file.Load(), "session": l.session, "started_at": l.started.UTC().Format(time.RFC3339Nano), "written_events": l.written.Load(), "dropped_events": l.dropped.Load(), "io_errors": l.ioErrors.Load(), "last_write_unix_ms": l.lastWrite.Load(), "max_file_bytes": l.options.MaxBytes, "max_files": l.options.MaxFiles}
}
func (l *Logger) Close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		close(l.queue)
	}
	l.mu.Unlock()
	<-l.done
}

var filePattern = regexp.MustCompile(`^events-[0-9]{8}-[0-9]{6}-[a-f0-9]{8}-[0-9]{6}\.jsonl$`)

func (l *Logger) open(sequence int) (*os.File, error) {
	name := fmt.Sprintf("events-%s-%s-%06d.jsonl", l.started.UTC().Format("20060102-150405"), l.session, sequence)
	f, e := os.OpenFile(filepath.Join(l.dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, e
	}
	l.prune(f.Name())
	return f, nil
}
func (l *Logger) prune(current string) {
	entries, e := os.ReadDir(l.dir)
	if e != nil {
		l.ioErrors.Add(1)
		return
	}
	type oldFile struct {
		name     string
		modified time.Time
	}
	var old []oldFile
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !filePattern.MatchString(entry.Name()) {
			continue
		}
		info, e := entry.Info()
		if e != nil {
			continue
		}
		old = append(old, oldFile{entry.Name(), info.ModTime()})
	}
	sort.Slice(old, func(i, j int) bool { return old[i].modified.Before(old[j].modified) })
	for _, entry := range old {
		if len(old) <= l.options.MaxFiles {
			break
		}
		target := filepath.Join(l.dir, entry.name)
		if target == current {
			continue
		}
		if e := os.Remove(target); e != nil {
			l.ioErrors.Add(1)
		} else {
			old = old[1:]
		}
	}
}
func (l *Logger) write(f *os.File) {
	defer close(l.done)
	defer func() {
		if f != nil {
			if e := f.Sync(); e != nil {
				l.ioErrors.Add(1)
			}
			f.Close()
		}
	}()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var size int64
	sequence := 0
	for {
		select {
		case r, ok := <-l.queue:
			if !ok {
				return
			}
			if f != nil && size > 0 && size+int64(len(r.data)) > l.options.MaxBytes {
				if e := f.Sync(); e != nil {
					l.ioErrors.Add(1)
				}
				f.Close()
				f = nil
				sequence++
				var e error
				f, e = l.open(sequence)
				size = 0
				if e != nil {
					l.ioErrors.Add(1)
					l.dropped.Add(1)
					continue
				}
				l.file.Store(f.Name())
			}
			if f == nil {
				var e error
				sequence++
				f, e = l.open(sequence)
				if e != nil {
					l.ioErrors.Add(1)
					l.dropped.Add(1)
					continue
				}
				size = 0
				l.file.Store(f.Name())
			}
			n, e := f.Write(r.data)
			size += int64(n)
			if e != nil || n != len(r.data) {
				l.ioErrors.Add(1)
				l.dropped.Add(1)
				continue
			}
			l.written.Add(1)
			l.lastWrite.Store(time.Now().UnixMilli())
			if r.critical {
				if e = f.Sync(); e != nil {
					l.ioErrors.Add(1)
				}
			}
		case <-ticker.C:
			if f != nil {
				if e := f.Sync(); e != nil {
					l.ioErrors.Add(1)
				}
			}
		}
	}
}

// ErrorKind intentionally never includes err.Error(), URLs or remote debug text.
func ErrorKind(e error) string {
	if e == nil {
		return "none"
	}
	if errors.Is(e, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(e, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(e, io.EOF) {
		return "eof"
	}
	if errors.Is(e, io.ErrUnexpectedEOF) {
		return "unexpected_eof"
	}
	if errors.Is(e, io.ErrClosedPipe) {
		return "pipe_closed"
	}
	if errors.Is(e, net.ErrClosed) {
		return "socket_closed"
	}
	var ne net.Error
	if errors.As(e, &ne) && ne.Timeout() {
		return "timeout"
	}
	return "error"
}
