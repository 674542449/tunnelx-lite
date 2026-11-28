package vless

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/xtls/reality"
)

const (
	visionCmdContinue byte = 0x00
	visionCmdEnd      byte = 0x01
	visionCmdDirect   byte = 0x02

	visionMaxBlock  = 8192
	visionHeaderMax = 21 // 16B UUID + 5B block header
)

var (
	tls13SupportedVersions  = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	tlsClientHandshakeStart = []byte{0x16, 0x03}
	tlsServerHandshakeStart = []byte{0x16, 0x03, 0x03}
	tlsApplicationDataStart = []byte{0x17, 0x03, 0x03}

	tls13CipherSuites = map[uint16]bool{
		0x1301: true, // TLS_AES_128_GCM_SHA256
		0x1302: true, // TLS_AES_256_GCM_SHA384
		0x1303: true, // TLS_CHACHA20_POLY1305_SHA256
		0x1304: true, // TLS_AES_128_CCM_SHA256
		// 0x1305 (TLS_AES_128_CCM_8_SHA256) 不开启 XTLS 直通，与 Xray-core 一致
	}
)

type rawUnwrapper interface {
	Unwrap() net.Conn
}

type closeWriteConn interface {
	CloseWrite() error
}

// unwrapRawConn 剥离外层 peekConn 等包装，获取底层裸 TCP 连接（供 Vision 直通与 Linux splice 零拷贝）。
func unwrapRawConn(c net.Conn) net.Conn {
	for c != nil {
		u, ok := c.(rawUnwrapper)
		if !ok {
			return c
		}
		next := u.Unwrap()
		if next == nil || next == c {
			return c
		}
		c = next
	}
	return c
}

// extractTLSBuffers 从 *reality.Conn 或 *tls.Conn 中提取底层裸连接及内部输入缓冲指针，
// 供 Vision 收到 CommandPaddingDirect (0x02) 时零丢包排空 TLS 层已预读的明文/密文，再切换直通裸 TCP。
func extractTLSBuffers(tlsConn net.Conn) (netConn net.Conn, input *bytes.Reader, rawInputPtr **bytes.Buffer, rawInputVal *bytes.Buffer, err error) {
	var rv reflect.Value
	switch c := tlsConn.(type) {
	case *reality.Conn:
		netConn = unwrapRawConn(c.NetConn())
		rv = reflect.ValueOf(c).Elem()
	case *tls.Conn:
		netConn = unwrapRawConn(c.NetConn())
		rv = reflect.ValueOf(c).Elem()
	default:
		return nil, nil, nil, nil, errors.New("vless vision: unsupported outer TLS connection type")
	}
	if !rv.CanAddr() {
		return nil, nil, nil, nil, errors.New("vless vision: TLS conn not addressable")
	}
	base := rv.UnsafeAddr()
	rt := rv.Type()

	if f, ok := rt.FieldByName("input"); ok && f.Type == reflect.TypeOf(bytes.Reader{}) {
		input = (*bytes.Reader)(unsafe.Pointer(base + f.Offset))
	} else {
		return nil, nil, nil, nil, errors.New("vless vision: cannot locate TLS input field")
	}

	if f, ok := rt.FieldByName("rawInput"); ok {
		switch f.Type {
		case reflect.TypeOf((*bytes.Buffer)(nil)):
			rawInputPtr = (**bytes.Buffer)(unsafe.Pointer(base + f.Offset))
		case reflect.TypeOf(bytes.Buffer{}):
			rawInputVal = (*bytes.Buffer)(unsafe.Pointer(base + f.Offset))
		default:
			return nil, nil, nil, nil, errors.New("vless vision: unexpected TLS rawInput field type")
		}
	} else {
		return nil, nil, nil, nil, errors.New("vless vision: cannot locate TLS rawInput field")
	}
	return netConn, input, rawInputPtr, rawInputVal, nil
}

// VisionConn 实现与 Xray-core / Shadowrocket / Sing-box 逐字节互通的标准 xtls-rprx-vision 流控连接。
// 握手阶段对内外层 TLS 进行随机长度填充打散特征；检测到内层 TLS 1.3 ApplicationData 后，
// 通过 CommandPaddingDirect (0x02) 协同剥离外层 REALITY TLS 并切换至裸 TCP 直通（免二次加解密）。
type VisionConn struct {
	conn        net.Conn // 写侧经由 responseConn（服务端）或 tlsConn（客户端）
	tlsConn     net.Conn // 外层 *reality.Conn / *tls.Conn
	rawConn     net.Conn // 底层裸 *net.TCPConn
	input       *bytes.Reader
	rawInputPtr **bytes.Buffer
	rawInputVal *bytes.Buffer
	userUUID    [16]byte

	// 读写双向共享的 TLS 1.3 检测状态（由 stateMu 保护，消除并发数据竞争）
	stateMu                sync.Mutex
	numberOfPacketToFilter int
	isTLS                  bool
	isTLS12orAbove         bool
	enableXTLS             bool
	cipher                 uint16
	remainingServerHello   int32

	// 读侧解填充状态（仅由 Read 协程访问）
	withinPaddingBuffers bool
	readDirect           atomic.Bool
	remainingCommand     int32
	remainingContent     int32
	remainingPadding     int32
	currentCommand       byte
	initPrefixBuf        []byte
	pendingRead          []byte
	readScratch          []byte

	// 写侧填充状态（由 writeMu 保护）
	writeMu     sync.Mutex
	isPadding   bool
	writeUUID   bool
	writeDirect atomic.Bool

	// 一旦任一方向切入裸 TCP 直通，关闭时直接关底层 rawConn，禁止发外层 TLS close_notify 破坏内层 TLS
	suppressCloseNotify atomic.Bool
}

// NewVisionConn 为已通过 REALITY/TLS 握手的连接包装标准 xtls-rprx-vision 流控。
// 服务端传入 conn = &responseConn{Conn: realityConn}, tlsConn = realityConn；
// 客户端传入 conn = tlsConn, tlsConn = tlsConn。
func NewVisionConn(conn, tlsConn net.Conn, userUUID [16]byte) (*VisionConn, error) {
	raw, input, rawPtr, rawVal, err := extractTLSBuffers(tlsConn)
	if err != nil {
		return nil, err
	}
	return &VisionConn{
		conn:                   conn,
		tlsConn:                tlsConn,
		rawConn:                raw,
		input:                  input,
		rawInputPtr:            rawPtr,
		rawInputVal:            rawVal,
		userUUID:               userUUID,
		numberOfPacketToFilter: 8,
		remainingServerHello:   -1,
		withinPaddingBuffers:   true,
		remainingCommand:       -1,
		remainingContent:       -1,
		remainingPadding:       -1,
		readScratch:            make([]byte, visionMaxBlock),
		isPadding:              true,
		writeUUID:              true,
	}, nil
}

// IsReadDirect / IsWriteDirect 报告对应方向是否已切入裸 TCP 直通（用于测试断言与 splice 优化）。
func (c *VisionConn) IsReadDirect() bool  { return c.readDirect.Load() }
func (c *VisionConn) IsWriteDirect() bool { return c.writeDirect.Load() }
func (c *VisionConn) CanSpliceRead() bool { return c.readDirect.Load() && len(c.pendingRead) == 0 }
func (c *VisionConn) RawConn() net.Conn   { return c.rawConn }

func (c *VisionConn) LocalAddr() net.Addr  { return c.tlsConn.LocalAddr() }
func (c *VisionConn) RemoteAddr() net.Addr { return c.tlsConn.RemoteAddr() }

func (c *VisionConn) SetDeadline(t time.Time) error {
	return c.rawConn.SetDeadline(t)
}
func (c *VisionConn) SetReadDeadline(t time.Time) error {
	return c.rawConn.SetReadDeadline(t)
}
func (c *VisionConn) SetWriteDeadline(t time.Time) error {
	return c.rawConn.SetWriteDeadline(t)
}

func (c *VisionConn) drainTLSBufferedLocked() []byte {
	var out []byte
	if c.input != nil {
		if b, err := io.ReadAll(c.input); err == nil && len(b) > 0 {
			out = append(out, b...)
		}
		*c.input = bytes.Reader{}
		c.input = nil
	}
	if c.rawInputPtr != nil {
		if raw := *c.rawInputPtr; raw != nil && raw.Len() > 0 {
			if b, err := io.ReadAll(raw); err == nil && len(b) > 0 {
				out = append(out, b...)
			}
		}
		c.rawInputPtr = nil
	} else if c.rawInputVal != nil {
		if c.rawInputVal.Len() > 0 {
			if b, err := io.ReadAll(c.rawInputVal); err == nil && len(b) > 0 {
				out = append(out, b...)
			}
		}
		c.rawInputVal = nil
	}
	return out
}

func (c *VisionConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if len(c.pendingRead) > 0 {
			n := copy(p, c.pendingRead)
			if n == len(c.pendingRead) {
				c.pendingRead = nil
			} else {
				c.pendingRead = c.pendingRead[n:]
			}
			return n, nil
		}
		if c.readDirect.Load() {
			return c.rawConn.Read(p)
		}

		buf := c.readScratch
		if len(p) > len(buf) {
			buf = p
		}
		n, err := c.conn.Read(buf)
		if n == 0 {
			return 0, err
		}
		chunk := buf[:n]

		c.stateMu.Lock()
		needFilter := c.numberOfPacketToFilter > 0
		c.stateMu.Unlock()

		if c.withinPaddingBuffers || needFilter {
			unpadded, switchDirect, needMore := c.unpadChunk(chunk)
			if needMore && err == nil {
				continue
			}
			if len(unpadded) > 0 {
				c.filterTLS(unpadded)
			}
			if switchDirect {
				c.readDirect.Store(true)
				c.suppressCloseNotify.Store(true)
				drained := c.drainTLSBufferedLocked()
				if len(drained) > 0 {
					unpadded = append(unpadded, drained...)
				}
			}
			if len(unpadded) > 0 {
				copied := copy(p, unpadded)
				if copied < len(unpadded) {
					c.pendingRead = append([]byte(nil), unpadded[copied:]...)
				}
				return copied, err
			}
			if err != nil {
				return 0, err
			}
			continue
		}

		// 不再解填充且过滤结束，直接透传外层 TLS 明文
		if &chunk[0] == &p[0] {
			return n, err
		}
		copied := copy(p, chunk)
		if copied < n {
			c.pendingRead = append([]byte(nil), chunk[copied:]...)
		}
		return copied, err
	}
}

func (c *VisionConn) unpadChunk(raw []byte) (out []byte, switchDirect bool, needMore bool) {
	b := raw
	if len(c.initPrefixBuf) > 0 {
		b = append(c.initPrefixBuf, raw...)
		c.initPrefixBuf = nil
	}

	if c.remainingCommand == -1 && c.remainingContent == -1 && c.remainingPadding == -1 {
		if len(b) < visionHeaderMax {
			// 若前缀与 UUID 匹配，说明首块被拆包，缓存等待补齐 21 字节再判定
			checkLen := len(b)
			if checkLen > 16 {
				checkLen = 16
			}
			if bytes.Equal(c.userUUID[:checkLen], b[:checkLen]) {
				c.initPrefixBuf = append([]byte(nil), b...)
				return nil, false, true
			}
			// 非 Vision 填充流（如未带 UUID），直接原样透传并停止解填充
			c.withinPaddingBuffers = false
			return append([]byte(nil), b...), false, false
		}
		if bytes.Equal(c.userUUID[:], b[:16]) {
			b = b[16:]
			c.remainingCommand = 5
			c.remainingContent = 0
			c.remainingPadding = 0
		} else {
			c.withinPaddingBuffers = false
			return append([]byte(nil), b...), false, false
		}
	}

	pos := 0
	for pos < len(b) {
		if c.remainingCommand > 0 {
			v := b[pos]
			pos++
			switch c.remainingCommand {
			case 5:
				c.currentCommand = v
			case 4:
				c.remainingContent = int32(v) << 8
			case 3:
				c.remainingContent |= int32(v)
			case 2:
				c.remainingPadding = int32(v) << 8
			case 1:
				c.remainingPadding |= int32(v)
			}
			c.remainingCommand--
		} else if c.remainingContent > 0 {
			take := int(c.remainingContent)
			if rem := len(b) - pos; rem < take {
				take = rem
			}
			out = append(out, b[pos:pos+take]...)
			pos += take
			c.remainingContent -= int32(take)
		} else if c.remainingPadding > 0 {
			skip := int(c.remainingPadding)
			if rem := len(b) - pos; rem < skip {
				skip = rem
			}
			pos += skip
			c.remainingPadding -= int32(skip)
		}

		if c.remainingCommand <= 0 && c.remainingContent <= 0 && c.remainingPadding <= 0 {
			switch c.currentCommand {
			case visionCmdContinue:
				c.remainingCommand = 5
				c.withinPaddingBuffers = true
			case visionCmdEnd:
				c.remainingCommand = -1
				c.remainingContent = -1
				c.remainingPadding = -1
				c.withinPaddingBuffers = false
				if pos < len(b) {
					out = append(out, b[pos:]...)
				}
				return out, false, false
			case visionCmdDirect:
				c.remainingCommand = -1
				c.remainingContent = -1
				c.remainingPadding = -1
				c.withinPaddingBuffers = false
				if pos < len(b) {
					out = append(out, b[pos:]...)
				}
				return out, true, false
			default:
				// 未知命令：保守退出填充状态并透传剩余字节
				c.withinPaddingBuffers = false
				if pos < len(b) {
					out = append(out, b[pos:]...)
				}
				return out, false, false
			}
		}
	}

	if c.remainingCommand > 0 || c.remainingContent > 0 || c.remainingPadding > 0 || c.currentCommand == visionCmdContinue {
		c.withinPaddingBuffers = true
	}
	return out, false, false
}

func (c *VisionConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.writeDirect.Load() {
		return c.rawConn.Write(p)
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeDirect.Load() {
		return c.rawConn.Write(p)
	}

	c.filterTLS(p)

	if !c.isPadding {
		return c.conn.Write(p)
	}

	c.stateMu.Lock()
	isTLS := c.isTLS
	isTLS12orAbove := c.isTLS12orAbove
	enableXTLS := c.enableXTLS
	numFilter := c.numberOfPacketToFilter
	c.stateMu.Unlock()

	isComplete := isCompleteTLSAppData(p)
	chunks := reshapeVisionChunks(p)

	longPadding := isTLS
	switchDirectAfterWrite := false

	var wirePayload bytes.Buffer
	wirePayload.Grow(len(p) + len(chunks)*512)

	for i, chunk := range chunks {
		last := i == len(chunks)-1
		if isTLS && len(chunk) >= 6 && bytes.Equal(tlsApplicationDataStart, chunk[:3]) && isComplete {
			if enableXTLS {
				switchDirectAfterWrite = true
			}
			cmd := visionCmdContinue
			if last {
				cmd = visionCmdEnd
				if enableXTLS {
					cmd = visionCmdDirect
				}
			}
			c.appendPaddedBlock(&wirePayload, chunk, cmd, true)
			c.isPadding = false
			longPadding = false
			continue
		}
		if !isTLS12orAbove && numFilter <= 1 {
			c.isPadding = false
			c.appendPaddedBlock(&wirePayload, chunk, visionCmdEnd, longPadding)
			// 余下未处理块不再填充，直接拼接输出
			for j := i + 1; j < len(chunks); j++ {
				wirePayload.Write(chunks[j])
			}
			break
		}
		cmd := visionCmdContinue
		if last && !c.isPadding {
			cmd = visionCmdEnd
			if enableXTLS {
				cmd = visionCmdDirect
			}
		}
		c.appendPaddedBlock(&wirePayload, chunk, cmd, longPadding)
	}

	if _, err := c.conn.Write(wirePayload.Bytes()); err != nil {
		return 0, err
	}
	if switchDirectAfterWrite {
		c.writeDirect.Store(true)
		c.suppressCloseNotify.Store(true)
	}
	return len(p), nil
}

func (c *VisionConn) appendPaddedBlock(dst *bytes.Buffer, content []byte, cmd byte, longPadding bool) {
	contentLen := len(content)
	var padLen int
	if contentLen < 900 && longPadding {
		padLen = randIntN(500) + 900 - contentLen
	} else {
		padLen = randIntN(256)
	}
	maxPad := visionMaxBlock - visionHeaderMax - contentLen
	if padLen > maxPad {
		padLen = maxPad
	}
	if padLen < 0 {
		padLen = 0
	}

	if c.writeUUID {
		dst.Write(c.userUUID[:])
		c.writeUUID = false
	}
	var hdr [5]byte
	hdr[0] = cmd
	binary.BigEndian.PutUint16(hdr[1:3], uint16(contentLen))
	binary.BigEndian.PutUint16(hdr[3:5], uint16(padLen))
	dst.Write(hdr[:])
	if contentLen > 0 {
		dst.Write(content)
	}
	if padLen > 0 {
		pad := make([]byte, padLen)
		_, _ = rand.Read(pad)
		dst.Write(pad)
	}
}

func (c *VisionConn) filterTLS(buf []byte) {
	if len(buf) == 0 {
		return
	}
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.numberOfPacketToFilter <= 0 {
		return
	}
	c.numberOfPacketToFilter--

	if len(buf) >= 6 {
		if bytes.Equal(tlsServerHandshakeStart, buf[:3]) && buf[5] == 0x02 {
			c.remainingServerHello = (int32(buf[3])<<8 | int32(buf[4])) + 5
			c.isTLS12orAbove = true
			c.isTLS = true
			if len(buf) >= 79 && c.remainingServerHello >= 79 {
				sidLen := int(buf[43])
				if len(buf) >= 43+sidLen+3 {
					c.cipher = uint16(buf[43+sidLen+1])<<8 | uint16(buf[43+sidLen+2])
				}
			}
		} else if bytes.Equal(tlsClientHandshakeStart, buf[:2]) && buf[5] == 0x01 {
			c.isTLS = true
		}
	}

	if c.remainingServerHello > 0 {
		end := int(c.remainingServerHello)
		if end > len(buf) {
			end = len(buf)
		}
		c.remainingServerHello -= int32(len(buf))
		if bytes.Contains(buf[:end], tls13SupportedVersions) {
			if tls13CipherSuites[c.cipher] {
				c.enableXTLS = true
			}
			c.numberOfPacketToFilter = 0
			return
		}
		if c.remainingServerHello <= 0 {
			c.numberOfPacketToFilter = 0
			return
		}
	}
}

// isCompleteTLSAppData 检查 p 是否完全由一个或多个完整的 TLS 1.3 ApplicationData 记录（0x17 0x03 0x03）组成。
func isCompleteTLSAppData(p []byte) bool {
	if len(p) < 5 {
		return false
	}
	i := 0
	for i < len(p) {
		if i+5 > len(p) {
			return false
		}
		if p[i] != 0x17 || p[i+1] != 0x03 || p[i+2] != 0x03 {
			return false
		}
		recLen := int(binary.BigEndian.Uint16(p[i+3 : i+5]))
		i += 5
		if i+recLen > len(p) {
			return false
		}
		i += recLen
	}
	return i == len(p)
}

// reshapeVisionChunks 将单次写入拆分为每块不超过 8192-21 字节的分块，优先在 0x17 0x03 0x03 边界切分。
func reshapeVisionChunks(p []byte) [][]byte {
	const limit = visionMaxBlock - visionHeaderMax
	if len(p) <= limit {
		return [][]byte{p}
	}
	var out [][]byte
	for len(p) > limit {
		window := p[:limit]
		split := bytes.LastIndex(window, tlsApplicationDataStart)
		if split < visionHeaderMax {
			split = limit / 2
		}
		out = append(out, p[:split])
		p = p[split:]
	}
	if len(p) > 0 {
		out = append(out, p)
	}
	return out
}

func randIntN(n int) int {
	if n <= 1 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// CloseWrite 半关闭当前生效层（直通后仅对裸 TCP 执行 FIN，不再向内层 TLS 注入外层 alert）。
func (c *VisionConn) CloseWrite() error {
	if c.writeDirect.Load() || c.suppressCloseNotify.Load() {
		if cw, ok := c.rawConn.(closeWriteConn); ok {
			return cw.CloseWrite()
		}
		return nil
	}
	if cw, ok := c.tlsConn.(closeWriteConn); ok {
		return cw.CloseWrite()
	}
	return nil
}

// Close 在已触发 Vision 直通时直接关闭底层裸 TCP，避免外层 TLS 发送 close_notify 触发客户端 BAD_RECORD_MAC。
func (c *VisionConn) Close() error {
	if c.suppressCloseNotify.Load() || c.writeDirect.Load() || c.readDirect.Load() {
		return c.rawConn.Close()
	}
	return c.tlsConn.Close()
}
