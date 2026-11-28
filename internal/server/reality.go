package server

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/674542449/tunnelx-lite/internal/vless"
)

// NewVLESSServer 构建与主 Server 共享流量统计、活跃连接数、整机带宽限速、
// DNS 缓存、私网拦截及强制 IPv4 出站落地的标准 VLESS + REALITY + Vision 服务端。
func (s *Server) NewVLESSServer() (*vless.Server, error) {
	if s.Config.RealityUUID == "" || s.Config.RealityPrivateKey == "" || s.Config.RealityDest == "" {
		return nil, errors.New("server: reality not configured")
	}
	var upLim, downLim vless.Limiter
	if s.upLimit != nil {
		upLim = s.upLimit
	}
	if s.downLimit != nil {
		downLim = s.downLimit
	}
	return vless.NewServer(vless.ServerConfig{
		UUID:        s.Config.RealityUUID,
		PrivateKey:  s.Config.RealityPrivateKey,
		ShortID:     s.Config.RealityShortID,
		Dest:        s.Config.RealityDest,
		ServerNames: append([]string(nil), s.Config.RealityNames...),
		DialTimeout: time.Duration(s.Config.DialTimeout) * time.Second,
		IdleTimeout: time.Duration(s.Config.IdleTimeout) * time.Second,
		MaxStreams:  s.Config.MaxConnections,
		UpLimit:     upLim,
		DownLimit:   downLim,
		Dialer:      s,
		Active:      &s.Active,
		Uploaded:    &s.Uploaded,
		Downloaded:  &s.Downloaded,
	})
}

func (s *Server) realityConfigured() bool {
	return s.Config.RealityUUID != "" && s.Config.RealityPrivateKey != "" && s.Config.RealityDest != ""
}

// peekConn 在不消费底层流的前提下向后续处理器重放已预读的 TLS ClientHello 字节，
// 同时透传 CloseWrite（满足 reality.Server 的 CloseWriteConn 断言）并支持排空后 Unwrap 到裸 *net.TCPConn。
type peekConn struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
}

func (c *peekConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		if n == len(c.buf) {
			c.buf = nil
		} else {
			c.buf = c.buf[n:]
		}
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	return c.Conn.Read(p)
}

func (c *peekConn) CloseWrite() error {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

// Unwrap 在预读缓冲已完全消费后返回底层裸连接，确保 Linux splice(2) 零拷贝照常生效。
func (c *peekConn) Unwrap() net.Conn {
	c.mu.Lock()
	empty := len(c.buf) == 0
	c.mu.Unlock()
	if empty {
		return c.Conn
	}
	return nil
}

// peekClientHelloSNI 零破坏地预读首条 TLS ClientHello 记录并提取小写 SNI（用于同端口分流）。
// 若非 TLS 握手包，立刻返回空 SNI 与包含已读字节的 peekConn，交由主 HTTP/TLS 处理器处理。
func peekClientHelloSNI(c net.Conn, timeout time.Duration) (string, *peekConn, error) {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	defer c.SetReadDeadline(time.Time{})

	var hdr [5]byte
	n, err := io.ReadFull(c, hdr[:])
	if err != nil {
		if n > 0 {
			return "", &peekConn{Conn: c, buf: append([]byte(nil), hdr[:n]...)}, nil
		}
		return "", nil, err
	}
	// 非 TLS 握手记录（0x16 0x03 ...）或长度异常，直接交主服务器处理
	if hdr[0] != 0x16 || hdr[1] != 0x03 || hdr[2] > 0x04 {
		return "", &peekConn{Conn: c, buf: append([]byte(nil), hdr[:]...)}, nil
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen < 42 || recLen > 16384 {
		return "", &peekConn{Conn: c, buf: append([]byte(nil), hdr[:]...)}, nil
	}
	full := make([]byte, 5+recLen)
	copy(full[:5], hdr[:])
	m, err := io.ReadFull(c, full[5:])
	if err != nil {
		if m > 0 {
			return "", &peekConn{Conn: c, buf: full[:5+m]}, nil
		}
		return "", nil, err
	}
	sni := extractClientHelloSNI(full[5:])
	return sni, &peekConn{Conn: c, buf: full}, nil
}

func extractClientHelloSNI(hs []byte) string {
	if len(hs) < 4 || hs[0] != 0x01 { // HandshakeType ClientHello
		return ""
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if 4+hsLen > len(hs) {
		return ""
	}
	body := hs[4 : 4+hsLen]
	// legacy_version(2) + random(32) + session_id_len(1)
	if len(body) < 35 {
		return ""
	}
	pos := 34
	sidLen := int(body[pos])
	pos += 1 + sidLen
	if pos+2 > len(body) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2 + csLen
	if pos+1 > len(body) {
		return ""
	}
	cmLen := int(body[pos])
	pos += 1 + cmLen
	if pos+2 > len(body) {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+extLen > len(body) {
		return ""
	}
	exts := body[pos : pos+extLen]
	for len(exts) >= 4 {
		et := binary.BigEndian.Uint16(exts[0:2])
		el := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if el > len(exts) {
			return ""
		}
		if et == 0x0000 && el >= 5 { // server_name extension
			listLen := int(binary.BigEndian.Uint16(exts[0:2]))
			if 2+listLen <= el {
				list := exts[2 : 2+listLen]
				for len(list) >= 3 {
					nameType := list[0]
					nameLen := int(binary.BigEndian.Uint16(list[1:3]))
					list = list[3:]
					if nameLen > len(list) {
						return ""
					}
					if nameType == 0x00 { // host_name
						return strings.ToLower(string(list[:nameLen]))
					}
					list = list[nameLen:]
				}
			}
			return ""
		}
		exts = exts[el:]
	}
	return ""
}

// chanListener 将 SNI 分流后属于 txlite 的连接喂给 http.Server.ServeTLS。
type chanListener struct {
	addr   net.Addr
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{
		addr:   addr,
		conns:  make(chan net.Conn, 128),
		closed: make(chan struct{}),
	}
}

func (l *chanListener) Push(c net.Conn) {
	select {
	case l.conns <- c:
	case <-l.closed:
		_ = c.Close()
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.conns:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return l.addr }
