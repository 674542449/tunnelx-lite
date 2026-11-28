package vless

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
)

const (
	Version byte = 0x00

	CommandTCP byte = 0x01
	CommandUDP byte = 0x02
	CommandMux byte = 0x03

	AddrIPv4   byte = 0x01
	AddrDomain byte = 0x02
	AddrIPv6   byte = 0x03

	FlowVision       = "xtls-rprx-vision"
	FlowVisionUDP443 = "xtls-rprx-vision-udp443"
)

// Request 描述解析后的标准 VLESS v0 请求头。
type Request struct {
	UUID    [16]byte
	Flow    string
	Command byte
	Host    string
	Port    uint16
}

// Target 返回 host:port 形式的目标地址（CommandMux 时为空）。
func (r *Request) Target() string {
	if r.Host == "" || r.Port == 0 {
		return ""
	}
	return net.JoinHostPort(r.Host, strconv.Itoa(int(r.Port)))
}

// ReadRequest 按 VLESS v0 规范从连接中读取并解析请求头。
func ReadRequest(r io.Reader) (*Request, error) {
	var head [18]byte // version(1) + uuid(16) + addonsLen(1)
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	if head[0] != Version {
		return nil, fmt.Errorf("vless: unsupported version %d", head[0])
	}
	req := &Request{}
	copy(req.UUID[:], head[1:17])

	addonsLen := int(head[17])
	if addonsLen > 0 {
		addonsBuf := make([]byte, addonsLen)
		if _, err := io.ReadFull(r, addonsBuf); err != nil {
			return nil, err
		}
		flow, err := parseAddonsFlow(addonsBuf)
		if err != nil {
			return nil, err
		}
		req.Flow = flow
	}

	var cmdBuf [1]byte
	if _, err := io.ReadFull(r, cmdBuf[:]); err != nil {
		return nil, err
	}
	req.Command = cmdBuf[0]

	switch req.Command {
	case CommandTCP, CommandUDP:
		host, port, err := readPortThenAddress(r)
		if err != nil {
			return nil, err
		}
		req.Host = host
		req.Port = port
	case CommandMux:
		// XUDP / Mux 目标在后续帧头中携带
	default:
		return nil, fmt.Errorf("vless: unsupported command %d", req.Command)
	}
	return req, nil
}

// parseAddonsFlow 解析 VLESS Addons Protobuf 消息中的 field 1 (Flow string) 与 field 2 (Seed bytes)。
func parseAddonsFlow(raw []byte) (string, error) {
	br := bytes.NewReader(raw)
	var flow string
	for br.Len() > 0 {
		tag, err := binary.ReadUvarint(br)
		if err != nil {
			return "", err
		}
		fieldNum := tag >> 3
		wireType := tag & 0x07
		switch wireType {
		case 2: // length-delimited
			n, err := binary.ReadUvarint(br)
			if err != nil || n > uint64(br.Len()) {
				return "", io.ErrUnexpectedEOF
			}
			val := make([]byte, int(n))
			if _, err := io.ReadFull(br, val); err != nil {
				return "", err
			}
			if fieldNum == 1 {
				flow = string(val)
			}
		case 0: // varint
			if _, err := binary.ReadUvarint(br); err != nil {
				return "", err
			}
		case 1: // 64-bit
			if _, err := io.CopyN(io.Discard, br, 8); err != nil {
				return "", err
			}
		case 5: // 32-bit
			if _, err := io.CopyN(io.Discard, br, 4); err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("vless: invalid addons wire type %d", wireType)
		}
	}
	return flow, nil
}

// readPortThenAddress 读取 VLESS/VMess 规范地址：port(2B BE) + atyp(1B) + addr。
func readPortThenAddress(r io.Reader) (string, uint16, error) {
	var head [3]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return "", 0, err
	}
	port := binary.BigEndian.Uint16(head[0:2])
	atyp := head[2]
	switch atyp {
	case AddrIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", 0, err
		}
		return net.IP(ip[:]).String(), port, nil
	case AddrIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", 0, err
		}
		return net.IP(ip[:]).String(), port, nil
	case AddrDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", 0, err
		}
		if l[0] == 0 {
			return "", 0, errors.New("vless: empty domain")
		}
		dom := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, dom); err != nil {
			return "", 0, err
		}
		return string(dom), port, nil
	default:
		return "", 0, fmt.Errorf("vless: unknown address type %d", atyp)
	}
}

func appendPortThenAddress(dst []byte, host string, port uint16) ([]byte, error) {
	dst = binary.BigEndian.AppendUint16(dst, port)
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			dst = append(dst, AddrIPv4)
			dst = append(dst, v4...)
			return dst, nil
		}
		dst = append(dst, AddrIPv6)
		dst = append(dst, ip.To16()...)
		return dst, nil
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, errors.New("vless: invalid domain length")
	}
	dst = append(dst, AddrDomain, byte(len(host)))
	dst = append(dst, host...)
	return dst, nil
}

// WriteRequest 按 VLESS v0 规范编码并写入请求头（可拼接首个 payload 同包发出，用于客户端测试）。
func WriteRequest(w io.Writer, req Request, payload []byte) error {
	var addons []byte
	if req.Flow != "" {
		addons = append(addons, (1<<3)|2)
		addons = binary.AppendUvarint(addons, uint64(len(req.Flow)))
		addons = append(addons, req.Flow...)
	}
	if len(addons) > 255 {
		return errors.New("vless: addons too large")
	}
	buf := make([]byte, 0, 24+len(addons)+len(req.Host)+len(payload))
	buf = append(buf, Version)
	buf = append(buf, req.UUID[:]...)
	buf = append(buf, byte(len(addons)))
	buf = append(buf, addons...)
	buf = append(buf, req.Command)
	if req.Command != CommandMux {
		var err error
		buf, err = appendPortThenAddress(buf, req.Host, req.Port)
		if err != nil {
			return err
		}
	}
	buf = append(buf, payload...)
	_, err := w.Write(buf)
	return err
}

// ReadResponse 读取 VLESS v0 2 字节响应头（version=0 + addonsLen，用于客户端测试）。
func ReadResponse(r io.Reader) error {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return err
	}
	if head[0] != Version {
		return fmt.Errorf("vless: unexpected response version %d", head[0])
	}
	if head[1] > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(head[1])); err != nil {
			return err
		}
	}
	return nil
}

// responseConn 将 VLESS v0 响应头 [0x00, 0x00] 与服务端第一次 Write 合并在同一个 TLS 记录中发出，
// 消除 2 字节独立回包长度特征，且天然位于 Vision 首块填充头之外。
type responseConn struct {
	net.Conn
	mu      sync.Mutex
	written bool
}

func (c *responseConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if !c.written {
		c.written = true
		c.mu.Unlock()
		buf := make([]byte, 2+len(p))
		buf[0] = Version
		buf[1] = 0
		copy(buf[2:], p)
		_, err := c.Conn.Write(buf)
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *responseConn) FlushHeaderIfNeeded() error {
	c.mu.Lock()
	if !c.written {
		c.written = true
		c.mu.Unlock()
		_, err := c.Conn.Write([]byte{Version, 0})
		return err
	}
	c.mu.Unlock()
	return nil
}
