package server

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestLimiterIsSharedAcrossStreams(t *testing.T) {
	l := NewLimiter(256 << 10) // 64 KiB burst
	started := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				l.Wait(context.Background(), 8<<10)
			}
		}()
	}
	wg.Wait()
	// 320 KiB total minus the 64 KiB burst needs about one second at 256 KiB/s.
	if elapsed := time.Since(started); elapsed < 850*time.Millisecond || elapsed > 3*time.Second {
		t.Fatal("parallel streams escaped the shared limit", elapsed)
	}
}

func TestLimiterIdleTimeDoesNotBankCredit(t *testing.T) {
	l := NewLimiter(256 << 10)
	time.Sleep(400 * time.Millisecond)
	started := time.Now()
	for i := 0; i < 10; i++ {
		l.Wait(context.Background(), 32<<10)
	}
	if elapsed := time.Since(started); elapsed < 850*time.Millisecond {
		t.Fatal("idle period allowed an unthrottled burst", elapsed)
	}
}

func TestLimiterWaitStopsOnCancel(t *testing.T) {
	l := NewLimiter(1024)
	l.Wait(context.Background(), 64<<10)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	if l.Wait(ctx, 64<<10) == nil || time.Since(started) > time.Second {
		t.Fatal("throttled stream ignored cancellation")
	}
	var none *Limiter
	if none.Wait(ctx, 1) != nil {
		t.Fatal("nil limiter must not throttle")
	}
}
