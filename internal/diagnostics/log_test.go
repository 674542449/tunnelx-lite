package diagnostics

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestRotationRetentionAndRestartPreserveUnrelatedFiles(t *testing.T) {
	dir := t.TempDir()
	unrelated := filepath.Join(dir, "notes.jsonl")
	os.WriteFile(unrelated, []byte("keep this"), 0600)
	for run := 0; run < 2; run++ {
		l, e := New(dir, Options{MaxBytes: 1024, MaxFiles: 3, QueueSize: 4096})
		if e != nil {
			t.Fatal(e)
		}
		for i := 0; i < 40; i++ {
			l.Record("sample", map[string]any{"index": i, "run": run})
		}
		l.Close()
		if l.ioErrors.Load() != 0 || l.dropped.Load() != 0 {
			t.Fatal("logging lost data", l.Status())
		}
		files, _ := filepath.Glob(filepath.Join(dir, "events-*.jsonl"))
		if len(files) > 3 || len(files) == 0 {
			t.Fatal("retention failed", len(files))
		}
		for _, file := range files {
			b, e := os.ReadFile(file)
			if e != nil {
				t.Fatal(e)
			}
			for _, line := range bytes.Split(bytes.TrimSpace(b), []byte{'\n'}) {
				var event map[string]any
				if json.Unmarshal(line, &event) != nil || event["session"] == nil || event["time"] == nil {
					t.Fatal("corrupt event", string(line))
				}
			}
		}
	}
	b, _ := os.ReadFile(unrelated)
	if string(b) != "keep this" {
		t.Fatal("retention touched an unrelated file")
	}
}
func TestConcurrentShutdownDoesNotPanicOrCorruptRecords(t *testing.T) {
	dir := t.TempDir()
	l, e := New(dir, Options{QueueSize: 4096})
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for j := 0; j < 8; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				l.Record("sample", map[string]any{"index": i})
			}
		}()
	}
	wg.Wait()
	l.Close()
	l.Close()
	l.Record("after_close", nil)
	files, _ := filepath.Glob(filepath.Join(dir, "events-*.jsonl"))
	b, _ := os.ReadFile(files[0])
	lines := bytes.Split(bytes.TrimSpace(b), []byte{'\n'})
	if len(lines) != 800 || l.written.Load() != 800 || l.dropped.Load() != 0 {
		t.Fatal("concurrent records lost", l.Status())
	}
	for _, line := range lines {
		if !json.Valid(line) {
			t.Fatal("invalid JSONL")
		}
	}
}
