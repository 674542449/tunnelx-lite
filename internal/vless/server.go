package vless

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/reality"
)

// Limiter 与 server.Limiter / pulse.Limiter 同构（共享服务端总带宽限速）。
type Limiter interface {
	Wait(ctx context.Context, n int) error
}

// TargetDialer 由主 server.Server 提供，复用同一套仅 IPv4 落地出站、私网目标防护与 DNS 缓存。
type TargetDialer interface {
	ResolveTarget(ctx context.Context, host, target string) ([]net.IP, int)
	DialTargetTCP(ctx context.Context, ips []net.IP, port string) (net.Conn, error)
	DialTargetUDP(ip net.IP, port int) (*net.UDPConn, error)
}

// ServerConfig 配置内置 VLESS + REALITY + Vision 服务端。
type ServerConfig struct {
	UUID        string
	PrivateKey  string
	ShortID     string
	Dest        string   // 伪装回落目标，如 "itunes.apple.com:443"
	ServerNames []string // 允许的伪装 SNI 列表
	DialTimeout time.Duration
	IdleTimeout time.Duration
	MaxStreams  int
	UpLimit     Limiter
	DownLimit   Limiter
	Dialer      TargetDialer
	Active      *atomic.Int64
	Uploaded    *atomic.Int64
	Downloaded  *atomic.Int64
	// DialDest 可选自定义回落目标拨号器（默认 TCP4/TCP 拨号，单测可注入本地回环服务器）。
	DialDest func(ctx context.Context, network, address string) (net.Conn, error)
}

// Server 处理 SNI 分流后的标准 VLESS + REALITY + Vision 连接。
type Server struct {
	cfg   ServerConfig
	uuid  [16]byte
	rcfg  *reality.Config
	slots chan struct{}

	localActive     atomic.Int64
	localUploaded   atomic.Int64
	localDownloaded atomic.Int64
}

// NewServer 校验并初始化 VLESS + REALITY 服务端。
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Dialer == nil {
		return nil, errors.New("vless: target dialer required")
	}
	uuidBytes, err := ParseUUID(cfg.UUID)
	if err != nil {
		return nil, err
	}
	privKey, err := ParseRealityPrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	shortID, err := ParseShortID(cfg.ShortID)
	if err != nil {
		return nil, err
	}
	if cfg.Dest == "" {
		return nil, errors.New("vless: reality dest required")
	}
	if _, _, err := net.SplitHostPort(cfg.Dest); err != nil {
		cfg.Dest = net.JoinHostPort(cfg.Dest, "443")
	}
	if len(cfg.ServerNames) == 0 {
		host, _, _ := net.SplitHostPort(cfg.Dest)
		cfg.ServerNames = []string{host}
	}
	sniMap := make(map[string]bool, len(cfg.ServerNames))
	for _, s := range cfg.ServerNames {
		if s != "" {
			sniMap[s] = true
		}
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 120 * time.Second
	}
	if cfg.MaxStreams <= 0 {
		cfg.MaxStreams = 2048
	}

	dialDest := cfg.DialDest
	if dialDest == nil {
		d := &net.Dialer{Timeout: 8 * time.Second}
		dialDest = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network == "" || network == "tcp" {
				network = "tcp4"
			}
			return d.DialContext(ctx, network, addr)
		}
	}

	shortIDs := map[[8]byte]bool{shortID: true}
	if cfg.ShortID == "" {
		shortIDs[[8]byte{}] = true
	}

	rcfg := &reality.Config{
		DialContext:            dialDest,
		Type:                   "tcp",
		Dest:                   cfg.Dest,
		ServerNames:            sniMap,
		PrivateKey:             privKey,
		MaxTimeDiff:            2 * time.Minute,
		ShortIds:               shortIDs,
		SessionTicketsDisabled: true,
	}

	s := &Server{
		cfg:   cfg,
		uuid:  uuidBytes,
		rcfg:  rcfg,
		slots: make(chan struct{}, cfg.MaxStreams),
	}
	if s.cfg.Active == nil {
		s.cfg.Active = &s.localActive
	}
	if s.cfg.Uploaded == nil {
		s.cfg.Uploaded = &s.localUploaded
	}
	if s.cfg.Downloaded == nil {
		s.cfg.Downloaded = &s.localDownloaded
	}
	return s, nil
}

// StartDetect 启动 REALITY 官方目标站点握手后记录长度探测（不阻塞服务启动）。
func (s *Server) StartDetect() {
	go reality.DetectPostHandshakeRecordsLens(s.rcfg)
}

// MatchSNI 检查入站 TLS ClientHello SNI 是否属于本 REALITY 服务端。
func (s *Server) MatchSNI(sni string) bool {
	if sni == "" {
		return false
	}
	return s.rcfg.ServerNames[sni]
}

// HandleConn 完成 REALITY 握手（非法探测自动透传至真实目标站），并处理 VLESS TCP / UDP / XUDP。
func (s *Server) HandleConn(ctx context.Context, conn net.Conn) {
	hsCtx, hsCancel := context.WithTimeout(ctx, 15*time.Second)
	rc, err := reality.Server(hsCtx, conn, s.rcfg)
	hsCancel()
	if err != nil {
		// reality.Server 已完成向真实网站的透明回落并关闭连接
		return
	}

	// 读取并校验 VLESS v0 请求头
	_ = rc.SetReadDeadline(time.Now().Add(15 * time.Second))
	req, err := ReadRequest(rc)
	if err != nil {
		_ = rc.Close()
		return
	}
	_ = rc.SetReadDeadline(time.Time{})

	if subtle.ConstantTimeCompare(req.UUID[:], s.uuid[:]) != 1 {
		_ = rc.Close()
		return
	}

	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		_ = rc.Close()
		return
	}
	s.cfg.Active.Add(1)
	defer s.cfg.Active.Add(-1)

	switch req.Command {
	case CommandTCP:
		s.serveTCP(ctx, rc, req)
	case CommandUDP:
		s.serveUDP(ctx, rc, req)
	case CommandMux:
		s.serveMux(ctx, rc, req)
	default:
		_ = rc.Close()
	}
}

func (s *Server) serveTCP(ctx context.Context, rc *reality.Conn, req *Request) {
	target := req.Target()
	if target == "" {
		_ = rc.Close()
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, s.cfg.DialTimeout)
	ips, status := s.cfg.Dialer.ResolveTarget(dialCtx, req.Host, target)
	if status != 0 || len(ips) == 0 {
		cancel()
		_ = rc.Close()
		return
	}
	upstream, err := s.cfg.Dialer.DialTargetTCP(dialCtx, ips, strconv.Itoa(int(req.Port)))
	cancel()
	if err != nil {
		_ = rc.Close()
		return
	}
	defer upstream.Close()

	respConn := &responseConn{Conn: rc}
	var clientStream io.ReadWriteCloser = respConn
	var visionConn *VisionConn
	var closeWriteClient func() error = func() error {
		if cw, ok := net.Conn(rc).(closeWriteConn); ok {
			return cw.CloseWrite()
		}
		return nil
	}

	useVision := req.Flow == FlowVision || req.Flow == FlowVisionUDP443
	if useVision {
		vc, err := NewVisionConn(respConn, rc, req.UUID)
		if err != nil {
			_ = rc.Close()
			return
		}
		visionConn = vc
		clientStream = vc
		closeWriteClient = vc.CloseWrite
	}
	defer clientStream.Close()

	stop := context.AfterFunc(ctx, func() {
		_ = upstream.Close()
		_ = clientStream.Close()
	})
	defer stop()

	upDone := make(chan struct{})
	go func() {
		defer close(upDone)
		buf := make([]byte, 64<<10)
		for {
			// Vision 读侧切入裸 TCP 直通且无限速时，走 Linux splice(2) 零拷贝直通
			if visionConn != nil && s.cfg.UpLimit == nil && visionConn.CanSpliceRead() {
				if rawTCP, ok1 := visionConn.RawConn().(*net.TCPConn); ok1 {
					if upTCP, ok2 := upstream.(*net.TCPConn); ok2 {
						spliceTCP(upTCP, rawTCP, s.cfg.IdleTimeout, s.cfg.Uploaded)
						_ = upTCP.CloseWrite()
						return
					}
				}
			}
			n, rerr := clientStream.Read(buf)
			if n > 0 {
				if s.cfg.UpLimit != nil {
					if err := s.cfg.UpLimit.Wait(ctx, n); err != nil {
						_ = upstream.Close()
						return
					}
				}
				_ = upstream.SetWriteDeadline(time.Now().Add(s.cfg.IdleTimeout))
				if _, werr := upstream.Write(buf[:n]); werr != nil {
					_ = clientStream.Close()
					return
				}
				s.cfg.Uploaded.Add(int64(n))
			}
			if rerr != nil {
				if rerr == io.EOF {
					if tcp, ok := upstream.(*net.TCPConn); ok {
						_ = tcp.CloseWrite()
					}
				} else {
					_ = upstream.Close()
				}
				return
			}
		}
	}()

	downBuf := make([]byte, 64<<10)
	for {
		// Vision 写侧切入裸 TCP 直通且无限速时，走 Linux splice(2) 零拷贝直通
		if visionConn != nil && s.cfg.DownLimit == nil && visionConn.IsWriteDirect() {
			if rawTCP, ok1 := visionConn.RawConn().(*net.TCPConn); ok1 {
				if upTCP, ok2 := upstream.(*net.TCPConn); ok2 {
					spliceTCP(rawTCP, upTCP, s.cfg.IdleTimeout, s.cfg.Downloaded)
					_ = rawTCP.CloseWrite()
					break
				}
			}
		}
		_ = upstream.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
		n, rerr := upstream.Read(downBuf)
		if n > 0 {
			if s.cfg.DownLimit != nil {
				if err := s.cfg.DownLimit.Wait(ctx, n); err != nil {
					break
				}
			}
			if _, werr := clientStream.Write(downBuf[:n]); werr != nil {
				break
			}
			s.cfg.Downloaded.Add(int64(n))
		}
		if rerr != nil {
			if rerr == io.EOF {
				_ = respConn.FlushHeaderIfNeeded()
				_ = closeWriteClient()
			}
			break
		}
	}

	select {
	case <-upDone:
	case <-time.After(3 * time.Second):
		_ = upstream.Close()
	case <-ctx.Done():
	}
}

// spliceTCP 在 Linux 上通过 (*net.TCPConn).ReadFrom 触发内核态 splice(2) 零拷贝直通。
func spliceTCP(dst, src *net.TCPConn, idle time.Duration, counter *atomic.Int64) {
	const chunk = 4 << 20
	var lastDeadline time.Time
	for {
		if idle > 0 {
			now := time.Now()
			if now.Sub(lastDeadline) >= 5*time.Second {
				lastDeadline = now
				dl := now.Add(idle)
				_ = src.SetReadDeadline(dl)
				_ = dst.SetWriteDeadline(dl)
			}
		}
		n, err := dst.ReadFrom(io.LimitReader(src, chunk))
		if n > 0 {
			counter.Add(n)
		}
		if err != nil || n == 0 {
			return
		}
	}
}

func (s *Server) serveUDP(ctx context.Context, rc *reality.Conn, req *Request) {
	defer rc.Close()
	target := req.Target()
	if target == "" {
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, s.cfg.DialTimeout)
	ips, status := s.cfg.Dialer.ResolveTarget(dialCtx, req.Host, target)
	cancel()
	if status != 0 || len(ips) == 0 {
		return
	}
	uc, err := s.cfg.Dialer.DialTargetUDP(ips[0], int(req.Port))
	if err != nil {
		return
	}
	defer uc.Close()

	stop := context.AfterFunc(ctx, func() {
		_ = uc.Close()
		_ = rc.Close()
	})
	defer stop()

	respWritten := false
	var writeMu sync.Mutex
	downDone := make(chan struct{})
	go func() {
		defer close(downDone)
		buf := make([]byte, 65535)
		for {
			_ = uc.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
			n, rerr := uc.Read(buf)
			if rerr != nil {
				return
			}
			if s.cfg.DownLimit != nil {
				if err := s.cfg.DownLimit.Wait(ctx, n); err != nil {
					return
				}
			}
			writeMu.Lock()
			var frame []byte
			if !respWritten {
				respWritten = true
				frame = make([]byte, 4+n)
				frame[0] = Version
				frame[1] = 0
				binary.BigEndian.PutUint16(frame[2:4], uint16(n))
				copy(frame[4:], buf[:n])
			} else {
				frame = make([]byte, 2+n)
				binary.BigEndian.PutUint16(frame[0:2], uint16(n))
				copy(frame[2:], buf[:n])
			}
			_, werr := rc.Write(frame)
			writeMu.Unlock()
			if werr != nil {
				return
			}
			s.cfg.Downloaded.Add(int64(n))
		}
	}()

	var lenBuf [2]byte
	pktBuf := make([]byte, 65535)
	for {
		_ = rc.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
		if _, err := io.ReadFull(rc, lenBuf[:]); err != nil {
			break
		}
		plen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if plen == 0 {
			continue
		}
		if _, err := io.ReadFull(rc, pktBuf[:plen]); err != nil {
			break
		}
		if s.cfg.UpLimit != nil {
			if err := s.cfg.UpLimit.Wait(ctx, plen); err != nil {
				break
			}
		}
		_ = uc.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := uc.Write(pktBuf[:plen]); err != nil {
			break
		}
		s.cfg.Uploaded.Add(int64(plen))
	}
	_ = uc.Close()
	<-downDone
}

// serveMux 实现 VLESS XUDP / Mux (CommandMux = 0x03)，确保启用 xtls-rprx-vision 时
// Shadowrocket / Xray / Sing-box 通过 XUDP 发起的 UDP 流量（如 DNS、QUIC、语音）同样畅通。
func (s *Server) serveMux(ctx context.Context, rc *reality.Conn, req *Request) {
	respConn := &responseConn{Conn: rc}
	var stream io.ReadWriteCloser = respConn
	if req.Flow == FlowVision || req.Flow == FlowVisionUDP443 {
		vc, err := NewVisionConn(respConn, rc, req.UUID)
		if err != nil {
			_ = rc.Close()
			return
		}
		stream = vc
	}
	defer stream.Close()

	const (
		muxStatusNew       byte = 1
		muxStatusKeep      byte = 2
		muxStatusEnd       byte = 3
		muxStatusKeepAlive byte = 4
		muxOptData         byte = 1
		muxNetUDP          byte = 2
	)

	type muxUDP struct {
		conn   *net.UDPConn
		cancel context.CancelFunc
		host   string
		port   uint16
	}

	var writeMu sync.Mutex
	var mapMu sync.Mutex
	sessions := map[uint16]*muxUDP{}
	closeAll := func() {
		mapMu.Lock()
		for id, u := range sessions {
			delete(sessions, id)
			u.cancel()
			_ = u.conn.Close()
		}
		mapMu.Unlock()
	}
	defer closeAll()

	stop := context.AfterFunc(ctx, func() {
		closeAll()
		_ = stream.Close()
	})
	defer stop()

	writeMuxEnd := func(sid uint16) {
		var frame [6]byte
		binary.BigEndian.PutUint16(frame[0:2], 4)
		binary.BigEndian.PutUint16(frame[2:4], sid)
		frame[4] = muxStatusEnd
		frame[5] = 0
		writeMu.Lock()
		_, _ = stream.Write(frame[:])
		writeMu.Unlock()
	}

	var hdr [6]byte // metaLen(2) + sid(2) + status(1) + opt(1)
	for {
		if _, err := io.ReadFull(stream, hdr[:]); err != nil {
			return
		}
		metaLen := int(binary.BigEndian.Uint16(hdr[0:2]))
		sid := binary.BigEndian.Uint16(hdr[2:4])
		status := hdr[4]
		opt := hdr[5]

		var netType byte
		var dstHost string
		var dstPort uint16
		if metaLen > 4 {
			meta := make([]byte, metaLen-4)
			if _, err := io.ReadFull(stream, meta); err != nil {
				return
			}
			if len(meta) >= 4 {
				netType = meta[0]
				if h, p, err := readPortThenAddress(bytes.NewReader(meta[1:])); err == nil {
					dstHost, dstPort = h, p
				}
			}
		}

		var payload []byte
		if opt&muxOptData != 0 {
			var plenBuf [2]byte
			if _, err := io.ReadFull(stream, plenBuf[:]); err != nil {
				return
			}
			plen := int(binary.BigEndian.Uint16(plenBuf[:]))
			if plen > 0 {
				payload = make([]byte, plen)
				if _, err := io.ReadFull(stream, payload); err != nil {
					return
				}
			}
		}

		switch status {
		case muxStatusKeepAlive:
			continue
		case muxStatusEnd:
			mapMu.Lock()
			if u, ok := sessions[sid]; ok {
				delete(sessions, sid)
				u.cancel()
				_ = u.conn.Close()
			}
			mapMu.Unlock()
			continue
		case muxStatusNew:
			if netType != muxNetUDP || dstHost == "" || dstPort == 0 {
				writeMuxEnd(sid)
				continue
			}
			dialCtx, cancel := context.WithTimeout(ctx, s.cfg.DialTimeout)
			ips, st := s.cfg.Dialer.ResolveTarget(dialCtx, dstHost, net.JoinHostPort(dstHost, strconv.Itoa(int(dstPort))))
			cancel()
			if st != 0 || len(ips) == 0 {
				writeMuxEnd(sid)
				continue
			}
			uc, err := s.cfg.Dialer.DialTargetUDP(ips[0], int(dstPort))
			if err != nil {
				writeMuxEnd(sid)
				continue
			}
			uctx, ucancel := context.WithCancel(ctx)
			ent := &muxUDP{conn: uc, cancel: ucancel, host: dstHost, port: dstPort}
			mapMu.Lock()
			if old, ok := sessions[sid]; ok {
				old.cancel()
				_ = old.conn.Close()
			}
			if len(sessions) >= 128 {
				mapMu.Unlock()
				ucancel()
				_ = uc.Close()
				writeMuxEnd(sid)
				continue
			}
			sessions[sid] = ent
			mapMu.Unlock()

			go func(id uint16, u *muxUDP) {
				defer func() {
					mapMu.Lock()
					if cur, ok := sessions[id]; ok && cur == u {
						delete(sessions, id)
					}
					mapMu.Unlock()
					u.cancel()
					_ = u.conn.Close()
				}()
				buf := make([]byte, 65535)
				for {
					_ = u.conn.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
					n, rerr := u.conn.Read(buf)
					if rerr != nil || uctx.Err() != nil {
						return
					}
					if s.cfg.DownLimit != nil {
						if err := s.cfg.DownLimit.Wait(uctx, n); err != nil {
							return
						}
					}
					addrBytes, err := appendPortThenAddress(nil, u.host, u.port)
					if err != nil {
						return
					}
					metaBodyLen := 2 + 1 + 1 + 1 + len(addrBytes)
					frame := make([]byte, 0, 2+metaBodyLen+2+n)
					frame = binary.BigEndian.AppendUint16(frame, uint16(metaBodyLen))
					frame = binary.BigEndian.AppendUint16(frame, id)
					frame = append(frame, muxStatusKeep, muxOptData, muxNetUDP)
					frame = append(frame, addrBytes...)
					frame = binary.BigEndian.AppendUint16(frame, uint16(n))
					frame = append(frame, buf[:n]...)
					writeMu.Lock()
					_, werr := stream.Write(frame)
					writeMu.Unlock()
					if werr != nil {
						return
					}
					s.cfg.Downloaded.Add(int64(n))
				}
			}(sid, ent)
		}

		if len(payload) > 0 {
			mapMu.Lock()
			u := sessions[sid]
			mapMu.Unlock()
			if u != nil {
				if s.cfg.UpLimit != nil {
					if err := s.cfg.UpLimit.Wait(ctx, len(payload)); err != nil {
						return
					}
				}
				_ = u.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, err := u.conn.Write(payload); err == nil {
					s.cfg.Uploaded.Add(int64(len(payload)))
				}
			}
		}
	}
}
