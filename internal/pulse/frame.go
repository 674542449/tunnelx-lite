package pulse

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

// 紧凑二进制帧类型定义（运行在 AES-128-GCM 加密负载内）。
const (
	FramePing          byte = 0x01
	FrameAck           byte = 0x02
	FrameStreamOpen    byte = 0x03
	FrameStreamOpenAck byte = 0x04
	FrameStreamData    byte = 0x05
	FrameStreamWindow  byte = 0x06
	FrameConnWindow    byte = 0x07
	FrameStreamReset   byte = 0x08
	FrameUDPDatagram   byte = 0x09
	FrameUDPClose      byte = 0x0A
	FrameClose         byte = 0x0B
	FramePadding       byte = 0x0C
)

// StreamOpen 状态码
const (
	OpenStatusOK          byte = 0
	OpenStatusRefused     byte = 1
	OpenStatusForbidden   byte = 2
	OpenStatusTimeout     byte = 3
	OpenStatusUnreachable byte = 4
)

// StreamData 标志位
const (
	StreamFlagFIN byte = 0x01
)

// 地址编码类型
const (
	AddrIPv4   byte = 1
	AddrDomain byte = 3
	AddrIPv6   byte = 4
)

// Frame 表示单个解码或待发送的 TXPulse 控制/数据帧。
type Frame struct {
	Type byte

	// ACK 帧字段
	LargestAcked uint32
	AckDelayUs   uint32
	RecvRateBPS  uint64
	AckRanges    []AckRange // 降序不重叠闭区间 [Start, End]

	// Stream 帧字段
	StreamID uint32
	Offset   uint64
	Flags    byte
	Status   byte
	ErrCode  byte
	MaxData  uint64
	Target   string
	Data     []byte

	// UDP 帧字段（不可靠转发 + 分片重组）
	UDPSessionID uint32
	UDPPktID     uint16
	UDPFragIdx   byte
	UDPFragTotal byte
	UDPHasAddr   bool
}

// AckRange 表示已确认的闭区间 [Start, End]（Start <= End）。
type AckRange struct {
	Start uint32
	End   uint32
}

// IsReliable 报告该帧丢失时是否需要可靠重传。
func (f Frame) IsReliable() bool {
	switch f.Type {
	case FrameStreamOpen, FrameStreamOpenAck, FrameStreamData,
		FrameStreamWindow, FrameConnWindow, FrameStreamReset, FrameUDPClose:
		return true
	default:
		return false
	}
}

func appendUvarint(b []byte, v uint64) []byte {
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], v)
	return append(b, tmp[:n]...)
}

func readUvarint(b []byte) (uint64, int, error) {
	v, n := binary.Uvarint(b)
	if n <= 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	return v, n, nil
}

func appendTargetAddr(b []byte, target string) ([]byte, error) {
	host, ps, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("txpulse: invalid target port")
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append(b, AddrIPv4)
			b = append(b, v4...)
		} else {
			b = append(b, AddrIPv6)
			b = append(b, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("txpulse: invalid domain length")
		}
		b = append(b, AddrDomain, byte(len(host)))
		b = append(b, host...)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(port))
	return b, nil
}

func readTargetAddr(b []byte) (string, int, error) {
	if len(b) < 1 {
		return "", 0, io.ErrUnexpectedEOF
	}
	atyp := b[0]
	off := 1
	var host string
	switch atyp {
	case AddrIPv4:
		if len(b) < off+4+2 {
			return "", 0, io.ErrUnexpectedEOF
		}
		host = net.IP(b[off : off+4]).String()
		off += 4
	case AddrIPv6:
		if len(b) < off+16+2 {
			return "", 0, io.ErrUnexpectedEOF
		}
		host = net.IP(b[off : off+16]).String()
		off += 16
	case AddrDomain:
		if len(b) < off+1 {
			return "", 0, io.ErrUnexpectedEOF
		}
		dlen := int(b[off])
		off++
		if dlen == 0 || len(b) < off+dlen+2 {
			return "", 0, io.ErrUnexpectedEOF
		}
		host = string(b[off : off+dlen])
		off += dlen
	default:
		return "", 0, errors.New("txpulse: unknown address type")
	}
	port := binary.BigEndian.Uint16(b[off : off+2])
	off += 2
	return net.JoinHostPort(host, strconv.Itoa(int(port))), off, nil
}

// appendFrame 将单个帧追加编码到 dst。
func appendFrame(dst []byte, f Frame) ([]byte, error) {
	dst = append(dst, f.Type)
	switch f.Type {
	case FramePing:
		return dst, nil

	case FrameAck:
		dst = appendUvarint(dst, uint64(f.LargestAcked))
		dst = appendUvarint(dst, uint64(f.AckDelayUs))
		dst = appendUvarint(dst, f.RecvRateBPS)
		nRanges := len(f.AckRanges)
		if nRanges > 32 {
			nRanges = 32
		}
		dst = appendUvarint(dst, uint64(nRanges))
		for i := 0; i < nRanges; i++ {
			r := f.AckRanges[i]
			dst = appendUvarint(dst, uint64(r.Start))
			dst = appendUvarint(dst, uint64(r.End-r.Start))
		}
		return dst, nil

	case FrameStreamOpen:
		dst = appendUvarint(dst, uint64(f.StreamID))
		var err error
		dst, err = appendTargetAddr(dst, f.Target)
		if err != nil {
			return nil, err
		}
		dst = appendUvarint(dst, uint64(len(f.Data)))
		dst = append(dst, f.Data...)
		return dst, nil

	case FrameStreamOpenAck:
		dst = appendUvarint(dst, uint64(f.StreamID))
		dst = append(dst, f.Status)
		return dst, nil

	case FrameStreamData:
		dst = appendUvarint(dst, uint64(f.StreamID))
		dst = appendUvarint(dst, f.Offset)
		dst = append(dst, f.Flags)
		dst = appendUvarint(dst, uint64(len(f.Data)))
		dst = append(dst, f.Data...)
		return dst, nil

	case FrameStreamWindow:
		dst = appendUvarint(dst, uint64(f.StreamID))
		dst = appendUvarint(dst, f.MaxData)
		return dst, nil

	case FrameConnWindow:
		dst = appendUvarint(dst, f.MaxData)
		return dst, nil

	case FrameStreamReset:
		dst = appendUvarint(dst, uint64(f.StreamID))
		dst = append(dst, f.ErrCode)
		return dst, nil

	case FrameUDPDatagram:
		dst = appendUvarint(dst, uint64(f.UDPSessionID))
		dst = binary.BigEndian.AppendUint16(dst, f.UDPPktID)
		dst = append(dst, f.UDPFragIdx, f.UDPFragTotal)
		if f.UDPHasAddr {
			dst = append(dst, 1)
			var err error
			dst, err = appendTargetAddr(dst, f.Target)
			if err != nil {
				return nil, err
			}
		} else {
			dst = append(dst, 0)
		}
		dst = appendUvarint(dst, uint64(len(f.Data)))
		dst = append(dst, f.Data...)
		return dst, nil

	case FrameUDPClose:
		dst = appendUvarint(dst, uint64(f.UDPSessionID))
		return dst, nil

	case FrameClose:
		dst = append(dst, f.ErrCode)
		return dst, nil

	case FramePadding:
		dst = appendUvarint(dst, uint64(len(f.Data)))
		dst = append(dst, f.Data...)
		return dst, nil

	default:
		return nil, errors.New("txpulse: unknown frame type")
	}
}

// appendAdaptivePadding 根据当前明文包长度动态追加随机填充，打散控制包与短包的固定长度指纹，
// 同时对满 MTU 吞吐大包几乎零开销。
func appendAdaptivePadding(plain []byte) []byte {
	avail := MaxDataPayload - len(plain)
	if avail < 4 {
		return plain
	}
	var r [2]byte
	_, _ = rand.Read(r[:])
	var padLen int
	switch {
	case len(plain) < 120:
		// 小包（ACK / PING / 小请求）填充至更离散的随机区间（约 64..280 字节）
		padLen = 24 + int(r[0])%160
	case len(plain) < 600:
		padLen = int(r[0]) % 64
	default:
		// 大包仅做轻量抖动（0..16 字节），几乎不影响高带宽吞吐
		padLen = int(r[0]) % 17
	}
	if padLen <= 0 {
		return plain
	}
	if padLen+3 > avail {
		padLen = avail - 3
	}
	if padLen <= 0 {
		return plain
	}
	plain = append(plain, FramePadding)
	plain = appendUvarint(plain, uint64(padLen))
	start := len(plain)
	plain = append(plain, make([]byte, padLen)...)
	_, _ = rand.Read(plain[start:])
	return plain
}

// parseFrames 解码单个加密数据报文内的全部帧。
func parseFrames(buf []byte) ([]Frame, error) {
	var out []Frame
	off := 0
	for off < len(buf) {
		typ := buf[off]
		off++
		f := Frame{Type: typ}
		switch typ {
		case FramePing:
			out = append(out, f)

		case FrameAck:
			v, n, err := readUvarint(buf[off:])
			if err != nil {
				return nil, err
			}
			f.LargestAcked = uint32(v)
			off += n

			v, n, err = readUvarint(buf[off:])
			if err != nil {
				return nil, err
			}
			f.AckDelayUs = uint32(v)
			off += n

			v, n, err = readUvarint(buf[off:])
			if err != nil {
				return nil, err
			}
			f.RecvRateBPS = v
			off += n

			cnt, n, err := readUvarint(buf[off:])
			if err != nil || cnt > 64 {
				return nil, errors.New("txpulse: invalid ack range count")
			}
			off += n
			if cnt > 0 {
				f.AckRanges = make([]AckRange, cnt)
				for i := uint64(0); i < cnt; i++ {
					start, n1, err := readUvarint(buf[off:])
					if err != nil {
						return nil, err
					}
					off += n1
					span, n2, err := readUvarint(buf[off:])
					if err != nil {
						return nil, err
					}
					off += n2
					f.AckRanges[i] = AckRange{Start: uint32(start), End: uint32(start + span)}
				}
			}
			out = append(out, f)

		case FrameStreamOpen:
			sid, n, err := readUvarint(buf[off:])
			if err != nil {
				return nil, err
			}
			f.StreamID = uint32(sid)
			off += n

			target, n, err := readTargetAddr(buf[off:])
			if err != nil {
				return nil, err
			}
			f.Target = target
			off += n

			dlen, n, err := readUvarint(buf[off:])
			if err != nil || off+n+int(dlen) > len(buf) {
				return nil, io.ErrUnexpectedEOF
			}
			off += n
			if dlen > 0 {
				f.Data = append([]byte(nil), buf[off:off+int(dlen)]...)
				off += int(dlen)
			}
			out = append(out, f)

		case FrameStreamOpenAck:
			sid, n, err := readUvarint(buf[off:])
			if err != nil {
				return nil, err
			}
			f.StreamID = uint32(sid)
			off += n
			if off >= len(buf) {
				return nil, io.ErrUnexpectedEOF
			}
			f.Status = buf[off]
			off++
			out = append(out, f)

		case FrameStreamData:
			sid, n, err := readUvarint(buf[off:])
			if err != nil {
				return nil, err
			}
			f.StreamID = uint32(sid)
			off += n

			so, n, err := readUvarint(buf[off:])
			if err != nil {
				return nil, err
			}
			f.Offset = so
			off += n

			if off >= len(buf) {
				return nil, io.ErrUnexpectedEOF
			}
			f.Flags = buf[off]
			off++

			dlen, n, err := readUvarint(buf[off:])
			if err != nil || off+n+int(dlen) > len(buf) {
				return nil, io.ErrUnexpectedEOF
			}
			off += n
			if dlen > 0 {
				f.Data = append([]byte(nil), buf[off:off+int(dlen)]...)
				off += int(dlen)
			}
			out = append(out, f)

		case FrameStreamWindow:
			sid, n, err := readUvarint(buf[off:])
			if err != nil {
				return nil, err
			}
			f.StreamID = uint32(sid)
			off += n

			mw, n, err := readUvarint(buf[off:])
			if err != nil {
				return nil, err
			}
			f.MaxData = mw
			off += n
			out = append(out, f)

		case FrameConnWindow:
			mw, n, err := readUvarint(buf[off:])
			if err != nil {
				return nil, err
			}
			f.MaxData = mw
			off += n
			out = append(out, f)

		case FrameStreamReset:
			sid, n, err := readUvarint(buf[off:])
			if err != nil {
				return nil, err
			}
			f.StreamID = uint32(sid)
			off += n
			if off >= len(buf) {
				return nil, io.ErrUnexpectedEOF
			}
			f.ErrCode = buf[off]
			off++
			out = append(out, f)

		case FrameUDPDatagram:
			usid, n, err := readUvarint(buf[off:])
			if err != nil {
				return nil, err
			}
			f.UDPSessionID = uint32(usid)
			off += n
			if off+5 > len(buf) {
				return nil, io.ErrUnexpectedEOF
			}
			f.UDPPktID = binary.BigEndian.Uint16(buf[off : off+2])
			f.UDPFragIdx = buf[off+2]
			f.UDPFragTotal = buf[off+3]
			hasAddr := buf[off+4]
			off += 5
			if hasAddr == 1 {
				f.UDPHasAddr = true
				target, n, err := readTargetAddr(buf[off:])
				if err != nil {
					return nil, err
				}
				f.Target = target
				off += n
			} else if hasAddr != 0 {
				return nil, errors.New("txpulse: invalid udp addr flag")
			}
			dlen, n, err := readUvarint(buf[off:])
			if err != nil || off+n+int(dlen) > len(buf) {
				return nil, io.ErrUnexpectedEOF
			}
			off += n
			if dlen > 0 {
				f.Data = append([]byte(nil), buf[off:off+int(dlen)]...)
				off += int(dlen)
			}
			out = append(out, f)

		case FrameUDPClose:
			usid, n, err := readUvarint(buf[off:])
			if err != nil {
				return nil, err
			}
			f.UDPSessionID = uint32(usid)
			off += n
			out = append(out, f)

		case FrameClose:
			if off >= len(buf) {
				return nil, io.ErrUnexpectedEOF
			}
			f.ErrCode = buf[off]
			off++
			out = append(out, f)

		case FramePadding:
			plen, n, err := readUvarint(buf[off:])
			if err != nil || off+n+int(plen) > len(buf) {
				return nil, io.ErrUnexpectedEOF
			}
			off += n + int(plen)
			// 填充帧仅用于抗长度指纹分析，解码后丢弃。

		default:
			return nil, errors.New("txpulse: unknown frame type in packet")
		}
	}
	return out, nil
}
