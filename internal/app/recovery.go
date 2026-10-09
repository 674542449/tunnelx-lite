package app

import (
	"context"
	"github.com/674542449/tunnelx-lite/internal/client"
	"time"
)

// mu must be held. Advancing the epoch prevents delayed watchers from reviving
// a session after the user cancelled, signed out or selected another node.
func (e *Engine) stopRecoveryLocked() {
	e.recoveryEpoch++
	if e.recoveryCancel != nil {
		e.recoveryCancel()
	}
	e.recoveryCancel = nil
	e.recovering = false
	e.recoveryAttempt = 0
}
func (e *Engine) recoverTUN(expected *client.Mux) {
	e.lifecycle.Lock()
	e.mu.Lock()
	if e.mux != expected || e.stopping > 0 {
		e.mu.Unlock()
		e.lifecycle.Unlock()
		return
	}
	id := e.nodeID
	e.stopRecoveryLocked()
	ctx, cancel := context.WithCancel(context.Background())
	e.recoveryContext = ctx
	e.recoveryCancel = cancel
	e.recovering = true
	epoch := e.recoveryEpoch
	if e.logger != nil {
		e.logger.Record("network_recovery_started", map[string]any{"scope": "client", "reason": "uplink_change_or_resume"})
	}
	e.mu.Unlock()
	err := e.disconnect()
	e.lifecycle.Unlock()
	defer cancel()
	defer func() {
		e.mu.Lock()
		if e.recoveryEpoch == epoch {
			e.recovering = false
			e.recoveryCancel = nil
		}
		e.mu.Unlock()
	}()
	if err != nil {
		return
	} // Never install new routes over incomplete cleanup.
	for attempt := 1; ctx.Err() == nil; attempt++ {
		e.mu.Lock()
		if e.recoveryEpoch != epoch {
			e.mu.Unlock()
			return
		}
		e.recoveryAttempt = attempt
		e.stage = "reconnecting"
		e.mu.Unlock()
		delay := time.Duration(min(attempt*2, 30)) * time.Second
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if err = e.connect(id, false, epoch); err == nil {
			e.mu.Lock()
			if e.recoveryEpoch == epoch && e.logger != nil {
				e.logger.Record("network_recovery_succeeded", map[string]any{"scope": "client", "attempt": attempt})
			}
			e.mu.Unlock()
			return
		}
		e.mu.Lock()
		if e.recoveryEpoch == epoch {
			e.stage = "reconnecting"
		}
		e.mu.Unlock()
	}
}
