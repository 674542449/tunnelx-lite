package pulse

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Limiter 兼容 server.Limiter 接口（共享服务端带宽上限）。
type Limiter interface {
	Wait(ctx context.Context, n int) error
}

// TargetDialer 由外层 server.Server 提供，确保 TXPulse 与 TCP Vision 共享同一套
// 「仅 IPv4 落地出站 + 禁止私网目标 + DNS 缓存」安全策略。
type TargetDialer interface {
	ResolveTarget(ctx context.Context, host, target string) ([]net.IP, int)
	DialTargetTCP(ctx context.Context, ips []net.IP, port string) (net.Conn, error)
	DialTargetUDP(ip net.IP, port int) (*net.UDPConn, error)
}

// ServerConfig 配置 TXPulse UDP 服务端。
type ServerConfig struct {
	Listen        string // 主 UDP 监听地址，例如 ":34567"
	Network       string // "", "udp4" 或 "udp6"（入口入站协议栈）
	HopStart      int    // 可选原生端口跳跃起始端口（0 表示不开启跳跃）
	HopEnd        int    // 可选原生端口跳跃结束端口
	CertFile      string // 自签 ECDSA P-256 证书路径
	KeyFile       string // 自签 ECDSA P-256 私钥路径
	Token         string // 32-64 字节 base64url 认证密钥
	ObfsKey       string // 16-32 字节 base64url 混淆种子
	DialTimeout   time.Duration
	IdleTimeout   time.Duration
	MaxSessions   int
	MaxStreams    int
	MaxBPS        uint64  // 单连接速率硬上限（字节/秒，0=不限）
	UpLimit       Limiter // 整机共享上行限速器
	DownLimit     Limiter // 整机共享下行限速器
	Dialer        TargetDialer
	Active        *atomic.Int64 // 与主服务端共享的活跃连接数
	Uploaded      *atomic.Int64 // 与主服务端共享的累计上传字节
	Downloaded    *atomic.Int64 // 与主服务端共享的累计下载字节
}

// Server 为 TXPulse 协议 UDP 服务端，支持单端口与原生无 iptables 多端口跳跃。
type Server struct {
	cfg      ServerConfig
	token    []byte
	obfsKey  []byte
	hsCipher *handshakeCipher
	certDER  []byte
	privKey  *ecdsa.PrivateKey
	replay   *replayFilter

	mu       sync.RWMutex
	sessions map[uint64]*Session
	slots    chan struct{}

	// 若未外部传入计数器，使用内置原子计数
	localActive     atomic.Int64
	localUploaded   atomic.Int64
	localDownloaded atomic.Int64
}

// LoadSelfSignedECDSA 读取自签 ECDSA 证书 DER 与私钥。
func LoadSelfSignedECDSA(certFile, keyFile string) ([]byte, *ecdsa.PrivateKey, error) {
	cb, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(cb)
	if block == nil {
		return nil, nil, errors.New("txpulse: invalid certificate PEM")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, nil, err
	}
	kb, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	kblock, _ := pem.Decode(kb)
	if kblock == nil {
		return nil, nil, errors.New("txpulse: invalid private key PEM")
	}
	var priv *ecdsa.PrivateKey
	if pk, err := x509.ParsePKCS8PrivateKey(kblock.Bytes); err == nil {
		ec, ok := pk.(*ecdsa.PrivateKey)
		if !ok {
			return nil, nil, errors.New("txpulse: private key must be ECDSA")
		}
		priv = ec
	} else if ec, err2 := x509.ParseECPrivateKey(kblock.Bytes); err2 == nil {
		priv = ec
	} else {
		return nil, nil, errors.New("txpulse: unsupported private key format")
	}
	return block.Bytes, priv, nil
}

// NewServer 创建并校验 TXPulse 服务端实例。
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Listen == "" {
		return nil, errors.New("txpulse: listen address required")
	}
	if cfg.Dialer == nil {
		return nil, errors.New("txpulse: target dialer required")
	}
	token, obfs, err := DecodeKeyMaterial(cfg.Token, cfg.ObfsKey)
	if err != nil {
		return nil, err
	}
	hs, err := newHandshakeCipher(token, obfs)
	if err != nil {
		return nil, err
	}
	certDER, priv, err := LoadSelfSignedECDSA(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 90 * time.Second
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 512
	}
	if cfg.MaxStreams <= 0 {
		cfg.MaxStreams = 2048
	}
	if cfg.HopStart != 0 || cfg.HopEnd != 0 {
		if cfg.HopStart < 1 || cfg.HopEnd > 65535 || cfg.HopEnd <= cfg.HopStart || cfg.HopEnd-cfg.HopStart+1 > 128 {
			return nil, errors.New("txpulse: invalid port hopping range (must span 2..128 ports)")
		}
	}
	s := &Server{
		cfg:      cfg,
		token:    token,
		obfsKey:  obfs,
		hsCipher: hs,
		certDER:  certDER,
		privKey:  priv,
		replay:   newReplayFilter(),
		sessions: make(map[uint64]*Session, 64),
		slots:    make(chan struct{}, cfg.MaxStreams),
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

func (s *Server) udpNetwork() string {
	switch s.cfg.Network {
	case "udp4", "tcp4", "ipv4":
		return "udp4"
	case "udp6", "tcp6", "ipv6":
		return "udp6"
	default:
		return "udp"
	}
}

func tuneUDPSocket(c *net.UDPConn) {
	_ = c.SetReadBuffer(8 << 20)
	_ = c.SetWriteBuffer(8 << 20)
}

// Serve 启动主 UDP 端口及可选端口跳跃范围监听，阻塞直至 ctx 取消或致命错误。
func (s *Server) Serve(ctx context.Context) error {
	network := s.udpNetwork()
	mainHost, mainPortStr, err := net.SplitHostPort(s.cfg.Listen)
	if err != nil {
		return err
	}
	mainPort, err := strconv.Atoi(mainPortStr)
	if err != nil {
		return err
	}

	ports := []int{mainPort}
	if s.cfg.HopStart > 0 && s.cfg.HopEnd > s.cfg.HopStart {
		for p := s.cfg.HopStart; p <= s.cfg.HopEnd; p++ {
			if p != mainPort {
				ports = append(ports, p)
			}
		}
	}

	conns := make([]*net.UDPConn, 0, len(ports))
	closeAll := func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}
	for i, p := range ports {
		addr, err := net.ResolveUDPAddr(network, net.JoinHostPort(mainHost, strconv.Itoa(p)))
		if err != nil {
			closeAll()
			return err
		}
		c, err := net.ListenUDP(network, addr)
		if err != nil {
			if i == 0 {
				closeAll()
				return fmt.Errorf("txpulse listen %s: %w", addr, err)
			}
			// 跳跃辅助端口偶发占用时跳过，不影响主端口与其余跳跃端口服务
			continue
		}
		tuneUDPSocket(c)
		conns = append(conns, c)
	}
	return s.ServePacketConns(ctx, conns)
}

// ServePacketConns 在已绑定的 UDP Socket 列表上提供服务（也供单测/模拟网络直接调用）。
func (s *Server) ServePacketConns(ctx context.Context, conns []*net.UDPConn) error {
	if len(conns) == 0 {
		return errors.New("txpulse: no UDP listeners")
	}
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for _, conn := range conns {
		wg.Add(1)
		go func(c *net.UDPConn) {
			defer wg.Done()
			s.readLoop(serveCtx, c)
		}(conn)
	}

	<-ctx.Done()
	cancel()
	for _, c := range conns {
		_ = c.Close()
	}
	s.closeAllSessions()
	wg.Wait()
	return nil
}

func (s *Server) closeAllSessions() {
	s.mu.Lock()
	list := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		list = append(list, sess)
	}
	s.sessions = make(map[uint64]*Session)
	s.mu.Unlock()
	for _, sess := range list {
		_ = sess.Close()
	}
}

func (s *Server) readLoop(ctx context.Context, conn *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Temporary() {
				continue
			}
			return
		}
		if n < HeaderSize+TagSize {
			continue // 静默丢弃短包
		}
		pkt := buf[:n]
		hdr, aad, ok := decodeHeader(pkt, s.obfsKey)
		if !ok {
			continue // 伪装前缀不匹配：静默丢弃（0 字节响应）
		}
		switch hdr.Type {
		case PktClientHello:
			// 复制握手包并异步处理，避免 ECDSA 签名短暂阻塞数据转发循环
			cp := make([]byte, n)
			copy(cp, pkt)
			go s.handleClientHello(ctx, cp, hdr, aad, src, conn)
		case PktData:
			s.mu.RLock()
			sess := s.sessions[hdr.SessionID]
			s.mu.RUnlock()
			if sess == nil {
				continue // 未知 SessionID：静默丢弃（抗主动探测）
			}
			// HandlePacket 内部完成 AEAD 解密、认证失败静默丢弃、连接迁移与帧分发
			sess.HandlePacket(pkt, hdr, aad, src, conn)
		default:
			// 非法报文类型：静默丢弃
		}
	}
}

func (s *Server) handleClientHello(ctx context.Context, pkt []byte, hdr PacketHeader, aad [16]byte, src *net.UDPAddr, sock *net.UDPConn) {
	if hdr.Flags != 0 || hdr.SessionID != 0 {
		return
	}
	plain, err := s.hsCipher.open(pkt, hdr, aad)
	if err != nil {
		return // Token / AEAD 校验失败：静默丢弃
	}
	ch, err := decodeClientHello(plain)
	if err != nil {
		return
	}
	if !s.replay.CheckAndAdd(ch.ClientNonce, ch.Timestamp) {
		return // 重放攻击或时间戳超窗：静默丢弃
	}
	cPub, err := ecdh.X25519().NewPublicKey(ch.ClientPub[:])
	if err != nil {
		return
	}
	sPriv, err := generateX25519()
	if err != nil {
		return
	}
	dhSecret, err := sPriv.ECDH(cPub)
	if err != nil {
		return
	}

	s.mu.Lock()
	if len(s.sessions) >= s.cfg.MaxSessions {
		s.mu.Unlock()
		return
	}
	var sid uint64
	for {
		sid = generateSessionID()
		if _, dup := s.sessions[sid]; !dup {
			break
		}
	}
	s.mu.Unlock()

	var sPubArr [32]byte
	copy(sPubArr[:], sPriv.PublicKey().Bytes())
	serverCaps := CapHyBBR | CapUDPFrag
	transcript := computeTranscriptHash(ch.ClientPub[:], ch.ClientNonce[:], sPubArr[:], sid, serverCaps, s.cfg.MaxBPS)
	sk, err := deriveSessionKeys(dhSecret, s.token, transcript)
	if err != nil {
		return
	}
	encCert, err := sealCertAndSig(sk, transcript, s.certDER, s.privKey)
	if err != nil {
		return
	}

	// 计算服务端下行目标速率（客户端请求的弹性 Brutal 上限受服务端 MaxBPS 约束；0 表示自适应 HyBBR）
	downTarget := ch.DesiredDownBPS
	if s.cfg.MaxBPS > 0 && (downTarget == 0 || downTarget > s.cfg.MaxBPS) {
		downTarget = s.cfg.MaxBPS
	}

	udpMapMu := sync.Mutex{}
	udpSockets := make(map[uint32]*serverUDPFlow)

	var sess *Session
	sess = newSession(sessionConfig{
		id:          sid,
		isClient:    false,
		obfsKey:     s.obfsKey,
		keys:        sk,
		targetBPS:   downTarget,
		maxBPS:      s.cfg.MaxBPS,
		idleTimeout: s.cfg.IdleTimeout,
		peerAddr:    src,
		replySock:   sock,
		handlers: SessionHandlers{
			OnStreamOpen: func(st *Stream, target string) {
				s.serveStream(ctx, sess, st, target)
			},
			OnUDPData: func(udpSessID uint32, target string, payload []byte) {
				s.serveUDP(ctx, sess, &udpMapMu, udpSockets, udpSessID, target, payload)
			},
			OnUDPClose: func(udpSessID uint32) {
				udpMapMu.Lock()
				if flow, ok := udpSockets[udpSessID]; ok {
					delete(udpSockets, udpSessID)
					flow.close()
				}
				udpMapMu.Unlock()
			},
			OnClosed: func(id uint64) {
				s.mu.Lock()
				if cur, ok := s.sessions[id]; ok && cur == sess {
					delete(s.sessions, id)
				}
				s.mu.Unlock()
				udpMapMu.Lock()
				for k, flow := range udpSockets {
					delete(udpSockets, k)
					flow.close()
				}
				udpMapMu.Unlock()
			},
		},
	})

	s.mu.Lock()
	if ctx.Err() != nil {
		s.mu.Unlock()
		_ = sess.Close()
		return
	}
	s.sessions[sid] = sess
	s.mu.Unlock()

	shPlain := encodeServerHello(serverHelloPayload{
		ServerPub:      sPubArr,
		SessionID:      sid,
		ServerCaps:     serverCaps,
		ServerMaxBPS:   s.cfg.MaxBPS,
		EncCertPayload: encCert,
	})
	shHdr := PacketHeader{
		Prefix:    makeCamouflagePrefix(),
		Type:      PktServerHello,
		Flags:     FlagServerToClient,
		SessionID: sid,
		PktNum:    hdr.PktNum, // 回显客户端握手序号便于匹配
	}
	shWire := s.hsCipher.seal(s.obfsKey, shHdr, shPlain)
	_, _ = sock.WriteToUDP(shWire, src)
}

func (s *Server) serveStream(ctx context.Context, sess *Session, st *Stream, target string) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		sess.ReplyStreamOpen(st.id, OpenStatusRefused)
		st.failLocal(errStreamReset)
		return
	}
	s.cfg.Active.Add(1)
	defer s.cfg.Active.Add(-1)
	defer st.Close()

	host, port, err := net.SplitHostPort(target)
	p, pe := strconv.Atoi(port)
	if err != nil || pe != nil || p < 1 || p > 65535 || host == "" {
		sess.ReplyStreamOpen(st.id, OpenStatusRefused)
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, s.cfg.DialTimeout)
	ips, httpStatus := s.cfg.Dialer.ResolveTarget(dialCtx, host, target)
	if httpStatus != 0 {
		cancel()
		code := OpenStatusUnreachable
		if httpStatus == 403 {
			code = OpenStatusForbidden
		} else if httpStatus == 504 {
			code = OpenStatusTimeout
		}
		sess.ReplyStreamOpen(st.id, code)
		return
	}
	upstream, err := s.cfg.Dialer.DialTargetTCP(dialCtx, ips, port)
	cancel()
	if err != nil {
		code := OpenStatusRefused
		if errors.Is(err, context.DeadlineExceeded) {
			code = OpenStatusTimeout
		}
		sess.ReplyStreamOpen(st.id, code)
		return
	}
	defer upstream.Close()
	sess.ReplyStreamOpen(st.id, OpenStatusOK)

	stop := context.AfterFunc(ctx, func() {
		_ = upstream.Close()
		_ = st.Close()
	})
	defer stop()

	upDone := make(chan struct{})
	go func() {
		defer close(upDone)
		buf := make([]byte, 64<<10)
		for {
			n, rerr := st.Read(buf)
			if n > 0 {
				if s.cfg.UpLimit != nil {
					if err := s.cfg.UpLimit.Wait(ctx, n); err != nil {
						_ = upstream.Close()
						return
					}
				}
				_ = upstream.SetWriteDeadline(time.Now().Add(s.cfg.IdleTimeout))
				if _, werr := upstream.Write(buf[:n]); werr != nil {
					_ = st.Close()
					return
				}
				s.cfg.Uploaded.Add(int64(n))
			}
			if rerr != nil {
				if tcp, ok := upstream.(*net.TCPConn); ok && rerr == io.EOF {
					_ = tcp.CloseWrite()
				} else {
					_ = upstream.Close()
				}
				return
			}
		}
	}()

	downBuf := make([]byte, 64<<10)
	for {
		_ = upstream.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
		n, rerr := upstream.Read(downBuf)
		if n > 0 {
			if s.cfg.DownLimit != nil {
				if err := s.cfg.DownLimit.Wait(ctx, n); err != nil {
					break
				}
			}
			if _, werr := st.Write(downBuf[:n]); werr != nil {
				break
			}
			s.cfg.Downloaded.Add(int64(n))
		}
		if rerr != nil {
			if rerr == io.EOF {
				_ = st.CloseWrite()
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

type serverUDPFlow struct {
	conn   *net.UDPConn
	cancel context.CancelFunc
	once   sync.Once
}

func (f *serverUDPFlow) close() {
	f.once.Do(func() {
		f.cancel()
		_ = f.conn.Close()
	})
}

func (s *Server) serveUDP(ctx context.Context, sess *Session, mu *sync.Mutex, flows map[uint32]*serverUDPFlow, udpSessID uint32, target string, payload []byte) {
	mu.Lock()
	flow := flows[udpSessID]
	mu.Unlock()

	if flow == nil {
		if target == "" {
			return
		}
		host, portStr, err := net.SplitHostPort(target)
		port, pe := strconv.Atoi(portStr)
		if err != nil || pe != nil || port < 1 || port > 65535 || host == "" {
			return
		}
		rctx, rcancel := context.WithTimeout(ctx, s.cfg.DialTimeout)
		ips, status := s.cfg.Dialer.ResolveTarget(rctx, host, target)
		rcancel()
		if status != 0 || len(ips) == 0 {
			return
		}
		uc, err := s.cfg.Dialer.DialTargetUDP(ips[0], port)
		if err != nil {
			return
		}
		fctx, fcancel := context.WithCancel(ctx)
		nf := &serverUDPFlow{conn: uc, cancel: fcancel}

		mu.Lock()
		if existing, ok := flows[udpSessID]; ok {
			mu.Unlock()
			nf.close()
			flow = existing
		} else {
			if len(flows) >= 256 {
				mu.Unlock()
				nf.close()
				return
			}
			flows[udpSessID] = nf
			mu.Unlock()
			flow = nf
			go func() {
				s.cfg.Active.Add(1)
				defer s.cfg.Active.Add(-1)
				defer func() {
					mu.Lock()
					if flows[udpSessID] == nf {
						delete(flows, udpSessID)
					}
					mu.Unlock()
					nf.close()
				}()
				buf := make([]byte, maxUDPDatagramSize)
				for {
					_ = uc.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
					n, err := uc.Read(buf)
					if err != nil {
						return
					}
					if fctx.Err() != nil || !sess.Alive() {
						return
					}
					if s.cfg.DownLimit != nil {
						if err := s.cfg.DownLimit.Wait(fctx, n); err != nil {
							return
						}
					}
					if err := sess.SendUDPFromServer(udpSessID, buf[:n]); err != nil {
						return
					}
					s.cfg.Downloaded.Add(int64(n))
				}
			}()
		}
	}

	if s.cfg.UpLimit != nil {
		if err := s.cfg.UpLimit.Wait(ctx, len(payload)); err != nil {
			return
		}
	}
	_ = flow.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := flow.conn.Write(payload); err == nil {
		s.cfg.Uploaded.Add(int64(len(payload)))
	}
}
