package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	VisionCmdEnd      byte = 0x00 // Stop Vision framing; continue over outer TLS 1.3.
	VisionCmdContinue byte = 0x01 // More Vision blocks follow inside outer TLS 1.3.
	VisionCmdDirect   byte = 0x02 // Stop Vision framing & outer TLS; switch to raw TCP direct splice.

	visionHeaderLen    = 5 // cmd(1) + contentLen(2) + paddingLen(2)
	visionMaxContent   = 15360
	visionMaxBlockSize = 16384 // Fits inside a single TLS 1.3 record (<= 16 KiB plaintext).
	visionMaxFilterPkt = 8     // Give up filtering after 8 chunks if TLS 1.3 handshake not seen.
)

// RFC 8446 Section 4.1.3 SHA-256("HelloRetryRequest") magic ServerHello random.
var helloRetryRequestRandom = [32]byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
	0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
	0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

// ExactRecordConn wraps a raw net.Conn underneath *tls.Conn so that while
// exact mode is enabled, tls.Conn never reads ahead past an outer TLS record
// boundary into subsequent raw Vision-direct TCP bytes. This achieves 100%
// deterministic XTLS Vision handoff with zero unsafe/reflect hacks.
type ExactRecordConn struct {
	net.Conn
	exact     atomic.Bool
	hdr       [5]byte
	hdrGot    int
	recRemain int
}

// NewExactRecordConn creates a wrapper starting in exact TLS record boundary mode.
func NewExactRecordConn(raw net.Conn) *ExactRecordConn {
	c := &ExactRecordConn{Conn: raw}
	c.exact.Store(true)
	return c
}

// DisableExact switches Read to pass-through mode for non-Vision / H2 connections.
func (c *ExactRecordConn) DisableExact() { c.exact.Store(false) }

// Raw returns the unwrapped underlying net.Conn (typically *net.TCPConn).
func (c *ExactRecordConn) Raw() net.Conn { return c.Conn }

// RawTCP returns the unwrapped *net.TCPConn when available.
func (c *ExactRecordConn) RawTCP() *net.TCPConn {
	tcp, _ := c.Conn.(*net.TCPConn)
	return tcp
}

func (c *ExactRecordConn) Read(p []byte) (int, error) {
	if !c.exact.Load() || len(p) == 0 {
		return c.Conn.Read(p)
	}
	if c.recRemain > 0 {
		if len(p) > c.recRemain {
			p = p[:c.recRemain]
		}
		n, err := c.Conn.Read(p)
		c.recRemain -= n
		return n, err
	}
	need := 5 - c.hdrGot
	if len(p) < need {
		need = len(p)
	}
	n, err := c.Conn.Read(p[:need])
	if n > 0 {
		copy(c.hdr[c.hdrGot:], p[:n])
		c.hdrGot += n
		if c.hdrGot == 5 {
			c.hdrGot = 0
			// Valid TLS record types are 20..23 with version 0x03 0x00..0x04.
			if c.hdr[0] >= 20 && c.hdr[0] <= 23 && c.hdr[1] == 0x03 && c.hdr[2] <= 0x04 {
				c.recRemain = int(binary.BigEndian.Uint16(c.hdr[3:5]))
			}
		}
	}
	return n, err
}

// VisionState tracks inner TLS 1.3 handshake observations shared between the
// upload and download sides of a single proxied TCP connection.
type VisionState struct {
	clientHello13 atomic.Bool
	serverHello13 atomic.Bool
	notTLS13      atomic.Bool
}

func NewVisionState() *VisionState { return &VisionState{} }

// InspectClientHello checks whether b starts with a TLS ClientHello advertising
// TLS 1.3 (0x0304) in the supported_versions extension. Returns:
//   - matched=true: confirmed TLS 1.3 ClientHello
//   - definite=true, matched=false: definitely not a TLS 1.3 ClientHello
//   - definite=false: record truncated, wait for more bytes
func InspectClientHello(b []byte) (matched, definite bool) {
	if len(b) < 5 {
		if len(b) >= 1 && b[0] != 0x16 {
			return false, true
		}
		if len(b) >= 2 && b[1] != 0x03 {
			return false, true
		}
		return false, false
	}
	if b[0] != 0x16 || b[1] != 0x03 || b[2] > 0x03 {
		return false, true
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen < 42 || recLen > 16384 {
		return false, true
	}
	if len(b) < 5+recLen {
		return false, false
	}
	hs := b[5 : 5+recLen]
	if hs[0] != 0x01 { // HandshakeType ClientHello
		return false, true
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if 4+hsLen > len(hs) {
		return false, true
	}
	body := hs[4 : 4+hsLen]
	// legacy_version(2) + random(32) + session_id_len(1)
	if len(body) < 35 {
		return false, true
	}
	pos := 34
	sidLen := int(body[pos])
	pos += 1 + sidLen
	if pos+2 > len(body) {
		return false, true
	}
	csLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2 + csLen
	if pos+1 > len(body) {
		return false, true
	}
	cmLen := int(body[pos])
	pos += 1 + cmLen
	if pos+2 > len(body) {
		return false, true
	}
	extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+extLen > len(body) {
		return false, true
	}
	exts := body[pos : pos+extLen]
	for len(exts) >= 4 {
		et := binary.BigEndian.Uint16(exts[0:2])
		el := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if el > len(exts) {
			break
		}
		if et == 0x002b && el >= 3 { // supported_versions
			vlen := int(exts[0])
			if 1+vlen <= el {
				for i := 1; i+1 < 1+vlen; i += 2 {
					if exts[i] == 0x03 && exts[i+1] == 0x04 {
						return true, true
					}
				}
			}
			return false, true
		}
		exts = exts[el:]
	}
	return false, true
}

// InspectServerHello checks whether b starts with a non-HRR TLS 1.3 ServerHello
// (supported_versions == 0x0304). If the ServerHello is a HelloRetryRequest,
// hrr is true (caller should stay in Vision filtering for the second handshake).
func InspectServerHello(b []byte) (matched, hrr, definite bool) {
	if len(b) < 5 {
		if len(b) >= 1 && b[0] != 0x16 {
			return false, false, true
		}
		if len(b) >= 2 && b[1] != 0x03 {
			return false, false, true
		}
		return false, false, false
	}
	if b[0] != 0x16 || b[1] != 0x03 || b[2] != 0x03 {
		return false, false, true
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen < 42 || recLen > 16384 {
		return false, false, true
	}
	if len(b) < 5+recLen {
		return false, false, false
	}
	hs := b[5 : 5+recLen]
	if hs[0] != 0x02 { // HandshakeType ServerHello
		return false, false, true
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if 4+hsLen > len(hs) {
		return false, false, true
	}
	body := hs[4 : 4+hsLen]
	if len(body) < 35 {
		return false, false, true
	}
	if bytes.Equal(body[2:34], helloRetryRequestRandom[:]) {
		return false, true, true
	}
	pos := 34
	sidLen := int(body[pos])
	pos += 1 + sidLen
	// cipher_suite(2) + compression_method(1) + extensions_len(2)
	if pos+5 > len(body) {
		return false, false, true
	}
	pos += 3
	extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+extLen > len(body) {
		return false, false, true
	}
	exts := body[pos : pos+extLen]
	for len(exts) >= 4 {
		et := binary.BigEndian.Uint16(exts[0:2])
		el := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if el > len(exts) {
			break
		}
		if et == 0x002b && el == 2 { // supported_versions
			return exts[0] == 0x03 && exts[1] == 0x04, false, true
		}
		exts = exts[el:]
	}
	return false, false, true
}

// tlsRecordTracker tracks inner TLS record boundaries across chunks so Vision
// only switches to raw direct TCP on an exact inner TLS 1.3 record boundary
// (meaning byte 0 on the raw wire is always a valid 0x17 0x03 0x03 record header).
type tlsRecordTracker struct {
	hdr        [5]byte
	hdrGot     int
	remain     int
	sawAppData bool
	broken     bool
}

func (t *tlsRecordTracker) feed(p []byte) {
	for len(p) > 0 && !t.broken {
		if t.remain > 0 {
			step := min(len(p), t.remain)
			t.remain -= step
			p = p[step:]
			continue
		}
		need := 5 - t.hdrGot
		step := min(len(p), need)
		copy(t.hdr[t.hdrGot:], p[:step])
		t.hdrGot += step
		p = p[step:]
		if t.hdrGot == 5 {
			t.hdrGot = 0
			typ, maj, minV := t.hdr[0], t.hdr[1], t.hdr[2]
			rlen := int(binary.BigEndian.Uint16(t.hdr[3:5]))
			if (typ != 0x14 && typ != 0x16 && typ != 0x17) || maj != 0x03 || minV > 0x03 || rlen > 16384+256 {
				t.broken = true
				return
			}
			if typ == 0x17 && minV == 0x03 {
				t.sawAppData = true
			}
			t.remain = rlen
		}
	}
}

func (t *tlsRecordTracker) atBoundary() bool {
	return !t.broken && t.hdrGot == 0 && t.remain == 0
}

type visionMode int32

const (
	visionFiltering visionMode = iota
	visionOuterTLS             // Vision ended (non-TLS-1.3); stay on outer TLS.
	visionDirect               // Outer TLS peeled off; raw TCP direct splice!
)

// VisionWriter frames the initial inner TLS 1.3 handshake with Vision random
// padding inside outer TLS 1.3, then peels off outer TLS and switches to direct
// raw TCP writes once inner TLS 1.3 ApplicationData reaches a record boundary.
type VisionWriter struct {
	mu        sync.Mutex
	outer     io.Writer
	raw       net.Conn
	state     *VisionState
	isClient  bool
	mode      atomic.Int32
	chunks    int
	inspected bool
	helloBuf  []byte
	tracker   tlsRecordTracker

	// Optional prefix (HTTP/1.1 CONNECT request) coalesced with the very first
	// Write() into a single outer TLS record & TCP segment, or flushed by timer
	// for server-first protocols.
	prefix      []byte
	prefixTimer *time.Timer
	prefixErr   error
}

// NewVisionWriter creates a Vision writer. If prefix is non-empty (client fast-open),
// it is coalesced with the first Write() or flushed automatically after 15ms.
func NewVisionWriter(outer io.Writer, raw net.Conn, state *VisionState, isClient bool, prefix []byte) *VisionWriter {
	w := &VisionWriter{
		outer:    outer,
		raw:      raw,
		state:    state,
		isClient: isClient,
		prefix:   prefix,
	}
	if len(prefix) > 0 {
		w.prefixTimer = time.AfterFunc(15*time.Millisecond, w.flushPrefixOnly)
	}
	return w
}

func (w *VisionWriter) flushPrefixOnly() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.prefix) == 0 {
		return
	}
	p := w.prefix
	w.prefix = nil
	_, w.prefixErr = w.outer.Write(p)
}

// IsDirect reports whether this write side has switched to raw direct TCP.
func (w *VisionWriter) IsDirect() bool {
	return visionMode(w.mode.Load()) == visionDirect
}

// IsOuterTLS reports whether Vision permanently settled on outer TLS (non-TLS-1.3).
func (w *VisionWriter) IsOuterTLS() bool {
	return visionMode(w.mode.Load()) == visionOuterTLS
}

// RawConn returns the underlying raw TCP connection for direct splice writes.
func (w *VisionWriter) RawConn() net.Conn { return w.raw }

// CloseWrite half-closes whichever layer is currently active (raw TCP in direct
// mode, or outer TLS close_notify if still inside outer TLS).
func (w *VisionWriter) CloseWrite() error {
	w.mu.Lock()
	if w.prefixTimer != nil {
		w.prefixTimer.Stop()
	}
	if len(w.prefix) > 0 {
		p := w.prefix
		w.prefix = nil
		_, _ = w.outer.Write(p)
	}
	mode := visionMode(w.mode.Load())
	w.mu.Unlock()

	type closeWriter interface{ CloseWrite() error }
	if mode == visionDirect {
		if cw, ok := w.raw.(closeWriter); ok {
			return cw.CloseWrite()
		}
		return nil
	}
	if cw, ok := w.outer.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

// StopTimer cancels any pending fast-open prefix flush timer.
func (w *VisionWriter) StopTimer() {
	w.mu.Lock()
	if w.prefixTimer != nil {
		w.prefixTimer.Stop()
		w.prefixTimer = nil
	}
	w.mu.Unlock()
}

func visionPaddingLen(contentLen int) int {
	maxPad := visionMaxBlockSize - visionHeaderLen - contentLen
	if maxPad <= 0 {
		return 0
	}
	if contentLen < 900 {
		// Hide exact small handshake record sizes (ClientHello / ServerHello / CCS).
		want := 900 - contentLen + rand.IntN(500)
		if want > maxPad {
			want = maxPad
		}
		return want
	}
	limit := min(256, maxPad)
	if limit <= 0 {
		return 0
	}
	return rand.IntN(limit + 1)
}

func fillRandomPad(dst []byte) {
	for i := 0; i < len(dst); {
		v := rand.Uint64()
		for j := 0; j < 8 && i < len(dst); j++ {
			dst[i] = byte(v)
			v >>= 8
			i++
		}
	}
}

func (w *VisionWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Fast lock-free paths once handshake filtering has finished.
	switch visionMode(w.mode.Load()) {
	case visionDirect:
		return w.raw.Write(p)
	case visionOuterTLS:
		return w.outer.Write(p)
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.prefixTimer != nil {
		w.prefixTimer.Stop()
		w.prefixTimer = nil
	}
	if w.prefixErr != nil {
		return 0, w.prefixErr
	}
	switch visionMode(w.mode.Load()) {
	case visionDirect:
		return w.raw.Write(p)
	case visionOuterTLS:
		return w.outer.Write(p)
	}

	w.chunks++
	cmd := VisionCmdContinue

	if w.state.notTLS13.Load() {
		cmd = VisionCmdEnd
	} else {
		if !w.inspected {
			sample := p
			if len(w.helloBuf) > 0 {
				w.helloBuf = append(w.helloBuf, p...)
				sample = w.helloBuf
			}
			if w.isClient {
				matched, definite := InspectClientHello(sample)
				if definite {
					w.inspected = true
					w.helloBuf = nil
					if matched {
						w.state.clientHello13.Store(true)
					} else {
						w.state.notTLS13.Store(true)
						cmd = VisionCmdEnd
					}
				} else if len(w.helloBuf) == 0 && len(p) < 4096 {
					w.helloBuf = append([]byte(nil), p...)
				} else if len(w.helloBuf) >= 16384 {
					w.inspected = true
					w.helloBuf = nil
					w.state.notTLS13.Store(true)
					cmd = VisionCmdEnd
				}
			} else {
				matched, hrr, definite := InspectServerHello(sample)
				if definite {
					w.helloBuf = nil
					if hrr {
						// HelloRetryRequest: wait for the real TLS 1.3 ServerHello next.
					} else {
						w.inspected = true
						if matched {
							w.state.serverHello13.Store(true)
						} else {
							w.state.notTLS13.Store(true)
							cmd = VisionCmdEnd
						}
					}
				} else if len(w.helloBuf) == 0 && len(p) < 4096 {
					w.helloBuf = append([]byte(nil), p...)
				} else if len(w.helloBuf) >= 16384 {
					w.inspected = true
					w.helloBuf = nil
					w.state.notTLS13.Store(true)
					cmd = VisionCmdEnd
				}
			}
		}

		if cmd != VisionCmdEnd {
			w.tracker.feed(p)
			if w.tracker.broken || w.chunks >= visionMaxFilterPkt {
				cmd = VisionCmdEnd
			} else if w.state.clientHello13.Load() && w.state.serverHello13.Load() && w.tracker.sawAppData && w.tracker.atBoundary() {
				// Both sides confirmed TLS 1.3, inner encrypted 0x17 records have
				// started, and this chunk ends on an exact inner TLS record boundary!
				cmd = VisionCmdDirect
			}
		}
	}

	if err := w.writeBlocksLocked(p, cmd); err != nil {
		return 0, err
	}
	switch cmd {
	case VisionCmdDirect:
		w.mode.Store(int32(visionDirect))
	case VisionCmdEnd:
		w.mode.Store(int32(visionOuterTLS))
	}
	return len(p), nil
}

func (w *VisionWriter) writeBlocksLocked(p []byte, finalCmd byte) error {
	prefix := w.prefix
	w.prefix = nil

	for len(p) > 0 {
		chunkLen := min(len(p), visionMaxContent)
		chunk := p[:chunkLen]
		p = p[chunkLen:]
		cmd := VisionCmdContinue
		if len(p) == 0 {
			cmd = finalCmd
		}
		padLen := visionPaddingLen(chunkLen)
		// Never coalesce prefix with VisionCmdDirect so the direct command
		// block always terminates cleanly on its own single outer TLS record.
		if len(prefix) > 0 && (cmd == VisionCmdDirect || len(prefix)+visionHeaderLen+chunkLen+padLen > visionMaxBlockSize) {
			if _, err := w.outer.Write(prefix); err != nil {
				return err
			}
			prefix = nil
		}
		total := len(prefix) + visionHeaderLen + chunkLen + padLen
		buf := make([]byte, total)
		off := copy(buf, prefix)
		prefix = nil
		buf[off] = cmd
		binary.BigEndian.PutUint16(buf[off+1:off+3], uint16(chunkLen))
		binary.BigEndian.PutUint16(buf[off+3:off+5], uint16(padLen))
		copy(buf[off+visionHeaderLen:off+visionHeaderLen+chunkLen], chunk)
		if padLen > 0 {
			fillRandomPad(buf[off+visionHeaderLen+chunkLen:])
		}
		if _, err := w.outer.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

// VisionReader reads Vision-framed blocks during the handshake phase, strips
// random padding, observes inner TLS 1.3 handshake messages to coordinate the
// peer direction, and switches to direct raw TCP reads (or plain outer TLS).
type VisionReader struct {
	outer     io.Reader
	exact     *ExactRecordConn
	raw       net.Conn
	state     *VisionState
	isClient  bool
	mode      atomic.Int32
	inspected bool
	helloBuf  []byte

	pending       []byte // undecoded remainder of current block's content
	pendingCmd    byte   // command to apply once content+padding are consumed
	hasPendingCmd bool
}

func NewVisionReader(outer io.Reader, exact *ExactRecordConn, state *VisionState, isClient bool) *VisionReader {
	var raw net.Conn
	if exact != nil {
		raw = exact.Raw()
	}
	return &VisionReader{
		outer:    outer,
		exact:    exact,
		raw:      raw,
		state:    state,
		isClient: isClient,
	}
}

// IsDirect reports whether this read side has switched to raw direct TCP.
func (r *VisionReader) IsDirect() bool {
	return visionMode(r.mode.Load()) == visionDirect
}

// IsOuterTLS reports whether Vision ended and reads continue over plain outer TLS.
func (r *VisionReader) IsOuterTLS() bool {
	return visionMode(r.mode.Load()) == visionOuterTLS
}

// RawConn returns the underlying raw TCP connection for Linux splice(2).
func (r *VisionReader) RawConn() net.Conn { return r.raw }

func (r *VisionReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	switch visionMode(r.mode.Load()) {
	case visionDirect:
		return r.raw.Read(p)
	case visionOuterTLS:
		return r.outer.Read(p)
	}

	// Serve any buffered content from the current Vision block first.
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		if len(r.pending) == 0 {
			r.pending = nil
			if err := r.finishBlock(); err != nil {
				return n, err
			}
		}
		return n, nil
	}

	// Read next 5-byte Vision block header from outer TLS.
	var hdr [visionHeaderLen]byte
	if _, err := io.ReadFull(r.outer, hdr[:]); err != nil {
		return 0, err
	}
	cmd := hdr[0]
	if cmd != VisionCmdEnd && cmd != VisionCmdContinue && cmd != VisionCmdDirect {
		return 0, errors.New("invalid vision command")
	}
	contentLen := int(binary.BigEndian.Uint16(hdr[1:3]))
	padLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if contentLen > visionMaxBlockSize || padLen > visionMaxBlockSize {
		return 0, errors.New("invalid vision block length")
	}

	// Read content + padding in full so we advance cleanly to the exact end of
	// the outer TLS record before transitioning to VisionCmdDirect.
	total := contentLen + padLen
	block := make([]byte, total)
	if total > 0 {
		if _, err := io.ReadFull(r.outer, block); err != nil {
			return 0, err
		}
	}
	content := block[:contentLen]

	// Observe inner TLS 1.3 handshake on received plaintext so our reverse
	// write direction knows as soon as the peer's ClientHello/ServerHello arrived.
	if !r.inspected && len(content) > 0 {
		sample := content
		if len(r.helloBuf) > 0 {
			r.helloBuf = append(r.helloBuf, content...)
			sample = r.helloBuf
		}
		if r.isClient {
			matched, hrr, definite := InspectServerHello(sample)
			if definite {
				r.helloBuf = nil
				if !hrr {
					r.inspected = true
					if matched {
						r.state.serverHello13.Store(true)
					} else {
						r.state.notTLS13.Store(true)
					}
				}
			} else if len(r.helloBuf) == 0 && len(content) < 4096 {
				r.helloBuf = append([]byte(nil), content...)
			} else if len(r.helloBuf) >= 16384 {
				r.inspected = true
				r.helloBuf = nil
				r.state.notTLS13.Store(true)
			}
		} else {
			matched, definite := InspectClientHello(sample)
			if definite {
				r.inspected = true
				r.helloBuf = nil
				if matched {
					r.state.clientHello13.Store(true)
				} else {
					r.state.notTLS13.Store(true)
				}
			} else if len(r.helloBuf) == 0 && len(content) < 4096 {
				r.helloBuf = append([]byte(nil), content...)
			} else if len(r.helloBuf) >= 16384 {
				r.inspected = true
				r.helloBuf = nil
				r.state.notTLS13.Store(true)
			}
		}
	}

	r.pendingCmd = cmd
	r.hasPendingCmd = true

	if contentLen == 0 {
		if err := r.finishBlock(); err != nil {
			return 0, err
		}
		return r.Read(p)
	}

	n := copy(p, content)
	if n < contentLen {
		r.pending = content[n:]
		return n, nil
	}
	if err := r.finishBlock(); err != nil {
		return n, err
	}
	return n, nil
}

func (r *VisionReader) finishBlock() error {
	if !r.hasPendingCmd {
		return nil
	}
	cmd := r.pendingCmd
	r.hasPendingCmd = false
	switch cmd {
	case VisionCmdDirect:
		if r.raw == nil {
			return errors.New("vision direct unavailable without raw conn")
		}
		r.mode.Store(int32(visionDirect))
	case VisionCmdEnd:
		if r.exact != nil {
			r.exact.DisableExact()
		}
		r.mode.Store(int32(visionOuterTLS))
	}
	return nil
}
