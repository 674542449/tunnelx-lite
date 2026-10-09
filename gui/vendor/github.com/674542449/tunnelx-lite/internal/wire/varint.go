package wire

import "io"

// Capsule framing uses RFC 9297's integer encoding (RFC 9000 section 16),
// independently of its HTTP/2 transport. No QUIC implementation is needed.
func readVarint(r io.ByteReader) (uint64, error) {
	first, e := r.ReadByte()
	if e != nil {
		return 0, e
	}
	length := 1 << (first >> 6)
	value := uint64(first & 0x3f)
	for i := 1; i < length; i++ {
		b, e := r.ReadByte()
		if e != nil {
			if e == io.EOF {
				e = io.ErrUnexpectedEOF
			}
			return 0, e
		}
		value = value<<8 | uint64(b)
	}
	return value, nil
}

func appendVarint(dst []byte, value uint64) []byte {
	length, prefix := 1, byte(0)
	switch {
	case value < 1<<6:
	case value < 1<<14:
		length, prefix = 2, 0x40
	case value < 1<<30:
		length, prefix = 4, 0x80
	case value < 1<<62:
		length, prefix = 8, 0xc0
	default:
		panic("Capsule integer exceeds 62 bits")
	}
	start := len(dst)
	dst = append(dst, make([]byte, length)...)
	for i := length - 1; i >= 0; i-- {
		dst[start+i] = byte(value)
		value >>= 8
	}
	dst[start] |= prefix
	return dst
}
