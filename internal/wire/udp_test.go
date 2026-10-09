package wire

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func capsule(typ uint64, b []byte) []byte {
	v := appendVarint(nil, typ)
	v = appendVarint(v, uint64(len(b)))
	return append(v, b...)
}

func TestCapsuleExtensionAndContextIsolation(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	s := NewPacketStream(context.Background(), a, func() { a.Close() })
	defer s.Close()
	input := capsule(37, []byte("unknown extension"))
	input = append(input, capsule(0, []byte{1, 'x'})...)
	input = append(input, capsule(0, []byte{0, 'o', 'k'})...)
	go b.Write(input)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	v, e := s.Receive(ctx)
	if e != nil || string(v) != "ok" {
		t.Fatalf("extension or nonzero context entered UDP flow: %q %v", v, e)
	}
}

func TestMalformedCapsulesFailBoundedly(t *testing.T) {
	cases := map[string][]byte{
		"truncated type":    {0x40},
		"truncated length":  {0, 0x40},
		"missing context":   capsule(0, nil),
		"truncated payload": {0, 5, 0, 1},
		"oversized capsule": append(appendVarint(nil, 0), appendVarint(nil, 1<<21)...),
		"oversized UDP":     capsule(0, append([]byte{0}, make([]byte, MaxUDP+1)...)),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			s := NewPacketStream(context.Background(), bytes.NewBuffer(input), nil)
			defer s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, e := s.Receive(ctx); e == nil || ctx.Err() != nil {
				t.Fatalf("malformed frame did not terminate promptly: %v", e)
			}
		})
	}
}
