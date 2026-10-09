package server

import (
	"context"
	"io"
)

// AccessController optionally admits managed accounts. Static owner tokens retain their existing behavior.
type AccessController interface {
	Authorize(context.Context, []string, string) (Permit, bool)
}
type Permit interface {
	Context() context.Context
	Allowed() bool
	Account(upload bool, n int)
	SpeedLimit() int64
	Close()
}
type permitKey struct{}

// LimitedPermit returns account-wide limiters shared by all of an account's
// streams; nil means the account has no speed limit in that direction.
type LimitedPermit interface{ Limiter(upload bool) *Limiter }

// ChargePermit atomically admits only the bytes covered by a managed quota.
type ChargePermit interface{ Charge(upload bool, n int) int }

func charge(p Permit, upload bool, n int) int {
	if c, ok := p.(ChargePermit); ok {
		return c.Charge(upload, n)
	}
	p.Account(upload, n)
	return n
}

// A ResponseWriter is invalid as soon as ServeHTTP returns. Stop-or-join every
// cancellation callback before returning; stopping alone can race a callback
// that has already started on another goroutine.
func joinCancellation(ctx context.Context, fn func()) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); fn() })
	return func() {
		if !stop() {
			<-done
		}
	}
}

func permit(ctx context.Context) Permit { p, _ := ctx.Value(permitKey{}).(Permit); return p }

type accountReader struct {
	reader io.Reader
	access Permit
	upload bool
}

func (r accountReader) Read(b []byte) (int, error) {
	if !r.access.Allowed() {
		return 0, context.Canceled
	}
	n, e := r.reader.Read(b)
	if n > 0 {
		allowed := charge(r.access, r.upload, n)
		if allowed < n {
			n = allowed
			e = io.EOF
		}
	}
	return n, e
}
