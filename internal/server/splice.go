package server

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// copyDirectTCP copies raw TCP bytes directly between dst and src. When no
// per-stream bandwidth limiter or managed permit is active and both endpoints
// are *net.TCPConn, it streams 4 MiB chunks through (*net.TCPConn).ReadFrom so
// Linux executes kernel-space splice(2) with zero user-space copies.
func copyDirectTCP(dst, src net.Conn, idle time.Duration, counter, total *atomic.Int64, limit *Limiter, p Permit, upload bool, ctx context.Context) error {
	if limit == nil && p == nil {
		dstTCP, okDst := dst.(*net.TCPConn)
		srcTCP, okSrc := src.(*net.TCPConn)
		if okDst && okSrc {
			const spliceChunk = 4 << 20
			var lastDeadline time.Time
			for {
				if idle > 0 {
					now := time.Now()
					if now.Sub(lastDeadline) >= 5*time.Second {
						lastDeadline = now
						dl := now.Add(idle)
						_ = srcTCP.SetReadDeadline(dl)
						_ = dstTCP.SetWriteDeadline(dl)
					}
				}
				n, err := dstTCP.ReadFrom(io.LimitReader(srcTCP, spliceChunk))
				if n > 0 {
					counter.Add(n)
					if total != nil {
						total.Add(n)
					}
				}
				if err != nil {
					return err
				}
				if n == 0 {
					return nil
				}
			}
		}
	}
	icSrc := newIdleConn(src, idle)
	icDst := newIdleConn(dst, idle)
	var reader io.Reader = icSrc
	if limit != nil {
		reader = throttledReader{r: reader, l: limit, ctx: ctx}
	}
	if p != nil {
		reader = accountReader{reader: reader, access: p, upload: upload}
	}
	reader = countReader{r: reader, n: counter, total: total}
	buf := getRelayBuf()
	_, err := io.CopyBuffer(icDst, reader, *buf)
	putRelayBuf(buf)
	return err
}
