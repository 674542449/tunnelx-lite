package wire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

func TestCapsuleIntegerRFCVectors(t *testing.T) {
	for _, v := range []struct {
		value   uint64
		encoded string
	}{
		{37, "25"}, {15293, "7bbd"}, {494878333, "9d7f3e7d"}, {151288809941952652, "c2197c5eff14e88c"},
		{63, "3f"}, {64, "4040"}, {16383, "7fff"}, {16384, "80004000"}, {(1 << 62) - 1, "ffffffffffffffff"},
	} {
		encoded, _ := hex.DecodeString(v.encoded)
		if got := appendVarint(nil, v.value); !bytes.Equal(got, encoded) {
			t.Fatalf("encoding %d: %x", v.value, got)
		}
		got, err := readVarint(bytes.NewReader(encoded))
		if err != nil || got != v.value {
			t.Fatalf("decoding %x: %d %v", encoded, got, err)
		}
		for n := 1; n < len(encoded); n++ {
			if _, err := readVarint(bytes.NewReader(encoded[:n])); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("truncated %x: %v", encoded[:n], err)
			}
		}
	}
	// Nonminimal encodings are permitted by the framing standard.
	if got, err := readVarint(bytes.NewReader([]byte{0x40, 0x25})); err != nil || got != 37 {
		t.Fatal(got, err)
	}
}
