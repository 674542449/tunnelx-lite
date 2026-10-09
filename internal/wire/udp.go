package wire

import (
	"bufio"
	"context"
	"errors"
	"io"
	"sync"
)

const MaxUDP = 65527

type PacketStream struct {
	ctx     context.Context
	cancel  context.CancelFunc
	rw      io.ReadWriter
	close   func()
	once    sync.Once
	mu      sync.Mutex
	packets chan []byte
	errMu   sync.Mutex
	err     error
}

func NewPacketStream(parent context.Context, rw io.ReadWriter, closeFn func()) *PacketStream {
	ctx, cancel := context.WithCancel(parent)
	s := &PacketStream{ctx: ctx, cancel: cancel, rw: rw, close: closeFn, packets: make(chan []byte, 256)}
	go s.readCapsules()
	return s
}
func (s *PacketStream) fail(e error) {
	s.errMu.Lock()
	if s.err == nil {
		s.err = e
	}
	s.errMu.Unlock()
	s.Close()
}
func (s *PacketStream) emit(b []byte) {
	select {
	case s.packets <- b:
	default: /* bounded UDP queue: drop under pressure */
	}
}
func payload(b []byte) ([]byte, error) {
	r := bytesReader(b)
	id, e := readVarint(r)
	if e != nil {
		return nil, e
	}
	if id != 0 {
		return nil, nil
	}
	if len(b)-r.i > MaxUDP {
		return nil, errors.New("UDP payload exceeds RFC 9298 maximum")
	}
	return b[r.i:], nil
}

// A small byte reader avoids allocations when parsing the Capsule context ID.
type byteReader struct {
	b []byte
	i int
}

func bytesReader(b []byte) *byteReader { return &byteReader{b: b} }
func (r *byteReader) Read(p []byte) (int, error) {
	if r.i == len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
func (r *byteReader) ReadByte() (byte, error) {
	if r.i == len(r.b) {
		return 0, io.EOF
	}
	v := r.b[r.i]
	r.i++
	return v, nil
}
func (s *PacketStream) readCapsules() {
	r := bufio.NewReaderSize(s.rw, 4096)
	for {
		typ, e := readVarint(r)
		if e != nil {
			s.fail(e)
			return
		}
		n, e := readVarint(r)
		if e != nil {
			s.fail(e)
			return
		}
		if n > 1<<20 {
			s.fail(errors.New("capsule length exceeds resource limit"))
			return
		}
		if typ != 0 {
			if _, e = io.CopyN(io.Discard, r, int64(n)); e != nil {
				s.fail(e)
				return
			}
			continue
		}
		if n > MaxUDP+8 {
			s.fail(errors.New("oversized DATAGRAM capsule"))
			return
		}
		b := make([]byte, int(n))
		if _, e = io.ReadFull(r, b); e != nil {
			s.fail(e)
			return
		}
		p, e := payload(b)
		if e != nil {
			s.fail(e)
			return
		}
		if p != nil {
			s.emit(p)
		}
	}
}
func (s *PacketStream) Send(b []byte) error {
	if len(b) > MaxUDP {
		return errors.New("UDP payload too large")
	}
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	default:
	}
	n := 1 + len(b)
	frame := make([]byte, 0, 10+len(b))
	frame = appendVarint(frame, 0)
	frame = appendVarint(frame, uint64(n))
	frame = append(frame, 0)
	frame = append(frame, b...)
	s.mu.Lock()
	defer s.mu.Unlock()
	written, e := s.rw.Write(frame)
	if e == nil && written != len(frame) {
		e = io.ErrShortWrite
	}
	return e
}
func (s *PacketStream) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-s.packets:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		s.errMu.Lock()
		e := s.err
		s.errMu.Unlock()
		if e == nil {
			e = io.EOF
		}
		return nil, e
	}
}
func (s *PacketStream) Close() error {
	s.once.Do(func() {
		s.cancel()
		if s.close != nil {
			s.close()
		}
	})
	return nil
}
