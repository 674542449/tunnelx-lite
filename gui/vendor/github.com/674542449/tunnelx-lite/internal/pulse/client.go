package pulse

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ClientConfig 配置 TXPulse UDP 客户端连接。
type ClientConfig struct {
	ServerIP       string // 已解析的字面量 IPv4 / IPv6（入口支持双栈）
	Port           int    // 主 UDP 端口
	HopStart       int    // 可选端口跳跃起始端口（0 表示不跳跃）
	HopEnd         int    // 可选端口跳跃结束端口
	Token          string // 认证密钥
	ObfsKey        string // 混淆种子
	CertPin        string // 服务端自签证书 SPKI SHA-256 指纹（必填，零 insecure=1）
	DesiredDownBPS uint64 // 0=自适应 HyBBR；>0=弹性 Brutal 目标下行速率（字节/秒）
	DesiredUpBPS   uint64 // 0=自适应 HyBBR；>0=弹性 Brutal 目标上行速率（字节/秒）
	ConnectTimeout time.Duration
	IdleTimeout    time.Duration
	// Control 可选底层 Socket 控制回调（例如 Windows TUN 绑定物理网卡防回环）。
	Control func(network, address string, c syscall.RawConn) error
}

// Client 管理到单个 TXPulse 服务端的持久多路复用 UDP 会话、端口跳跃与断线自动重建。
type Client struct {
	cfg      ClientConfig
	token    []byte
	obfsKey  []byte
	hsCipher *handshakeCipher

	mu        sync.Mutex
	closed    bool
	dialing   chan struct{}
	sess      *Session
	conn      *net.UDPConn
	targetMu  sync.RWMutex
	target    *net.UDPAddr
	hopCancel context.CancelFunc
	dials     atomic.Int64
}

// NewClient 校验配置并创建 TXPulse 客户端控制器。
func NewClient(cfg ClientConfig) (*Client, error) {
	if net.ParseIP(cfg.ServerIP) == nil {
		return nil, errors.New("txpulse: server_ip must be a literal IP")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, errors.New("txpulse: invalid port")
	}
	if cfg.CertPin == "" {
		return nil, errors.New("txpulse: self-signed cert_pin is required")
	}
	token, obfs, err := DecodeKeyMaterial(cfg.Token, cfg.ObfsKey)
	if err != nil {
		return nil, err
	}
	hs, err := newHandshakeCipher(token, obfs)
	if err != nil {
		return nil, err
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 90 * time.Second
	}
	if cfg.HopStart != 0 || cfg.HopEnd != 0 {
		if cfg.HopStart < 1 || cfg.HopEnd > 65535 || cfg.HopEnd <= cfg.HopStart {
			return nil, errors.New("txpulse: invalid port hopping range")
		}
	}
	return &Client{
		cfg:      cfg,
		token:    token,
		obfsKey:  obfs,
		hsCipher: hs,
	}, nil
}

// DialCount 返回累计建立会话次数。
func (c *Client) DialCount() int64 { return c.dials.Load() }

// CCStats 返回当前活跃会话的拥塞控制统计（无会话返回零值）。
func (c *Client) CCStats() CCStats {
	c.mu.Lock()
	sess := c.sess
	c.mu.Unlock()
	if sess == nil {
		return CCStats{}
	}
	return sess.CCStats()
}

// EnsureSession 确保存在可用会话；若不存在或已断开则发起 1-RTT 握手建立。
func (c *Client) EnsureSession(ctx context.Context) (*Session, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, net.ErrClosed
		}
		if c.sess != nil && c.sess.Alive() {
			s := c.sess
			c.mu.Unlock()
			return s, nil
		}
		if c.dialing != nil {
			wait := c.dialing
			c.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		wait := make(chan struct{})
		c.dialing = wait
		c.mu.Unlock()

		sess, conn, target, err := c.handshake(ctx)

		c.mu.Lock()
		c.dialing = nil
		if err != nil || c.closed {
			close(wait)
			c.mu.Unlock()
			if sess != nil {
				_ = sess.Close()
			}
			if conn != nil {
				_ = conn.Close()
			}
			if c.closed {
				return nil, net.ErrClosed
			}
			return nil, err
		}
		if c.hopCancel != nil {
			c.hopCancel()
			c.hopCancel = nil
		}
		c.sess = sess
		c.conn = conn
		c.targetMu.Lock()
		c.target = target
		c.targetMu.Unlock()
		if c.cfg.HopStart > 0 && c.cfg.HopEnd > c.cfg.HopStart {
			hctx, hcancel := context.WithCancel(context.Background())
			c.hopCancel = hcancel
			go c.hopLoop(hctx, sess)
		}
		close(wait)
		c.mu.Unlock()
		c.dials.Add(1)
		return sess, nil
	}
}

// OpenStream 打开代理 TCP 流；waitAck=true 等待服务端确认。
func (c *Client) OpenStream(ctx context.Context, target string, waitAck bool) (*Stream, error) {
	sess, err := c.EnsureSession(ctx)
	if err != nil {
		return nil, err
	}
	return sess.OpenStream(ctx, target, waitAck)
}

// OpenUDP 打开原生不可靠 UDP 转发流。
func (c *Client) OpenUDP(ctx context.Context, target string) (*UDPStream, error) {
	sess, err := c.EnsureSession(ctx)
	if err != nil {
		return nil, err
	}
	return sess.OpenUDP(target)
}

// Probe 执行一次完整的 1-RTT 加密认证握手（校验自签证书指纹 + Token）并返回往返耗时。
func (c *Client) Probe(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	sess, conn, _, err := c.handshake(ctx)
	if err != nil {
		return 0, err
	}
	rtt := time.Since(start)
	_ = sess.Close()
	_ = conn.Close()
	if rtt < time.Millisecond {
		rtt = time.Millisecond
	}
	return rtt, nil
}

// Close 关闭当前客户端会话与底层 UDP Socket。
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	sess := c.sess
	conn := c.conn
	hcancel := c.hopCancel
	c.sess = nil
	c.conn = nil
	c.hopCancel = nil
	c.mu.Unlock()

	if hcancel != nil {
		hcancel()
	}
	if sess != nil {
		_ = sess.Close()
	}
	if conn != nil {
		_ = conn.Close()
	}
	return nil
}

func (c *Client) dialUDPSocket(ctx context.Context, targetAddr string) (*net.UDPConn, *net.UDPAddr, error) {
	ip := net.ParseIP(c.cfg.ServerIP)
	network := "udp4"
	if ip != nil && ip.To4() == nil {
		network = "udp6"
	}
	raddr, err := net.ResolveUDPAddr(network, targetAddr)
	if err != nil {
		return nil, nil, err
	}
	// 使用未绑定远端的 ListenUDP（配合 WriteToUDP），从而天然支持端口跳跃时无缝切换目的端口！
	lc := net.ListenConfig{}
	if c.cfg.Control != nil {
		ctrl := c.cfg.Control
		lc.Control = func(netw, _ string, raw syscall.RawConn) error {
			return ctrl(netw, targetAddr, raw)
		}
	}
	laddr := "0.0.0.0:0"
	if network == "udp6" {
		laddr = "[::]:0"
	}
	pc, err := lc.ListenPacket(ctx, network, laddr)
	if err != nil {
		return nil, nil, err
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, nil, errors.New("txpulse: expected *net.UDPConn")
	}
	tuneUDPSocket(uc)
	return uc, raddr, nil
}

func (c *Client) handshake(parent context.Context) (*Session, *net.UDPConn, *net.UDPAddr, error) {
	timeout := c.cfg.ConnectTimeout
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	initPort := c.cfg.Port
	if c.cfg.HopStart > 0 && c.cfg.HopEnd > c.cfg.HopStart {
		// 即使开启端口跳跃，首跳优先使用主端口（也可随机落在区间内，主端口最稳妥）
		initPort = c.cfg.Port
	}
	targetStr := net.JoinHostPort(c.cfg.ServerIP, strconv.Itoa(initPort))
	uc, raddr, err := c.dialUDPSocket(ctx, targetStr)
	if err != nil {
		return nil, nil, nil, err
	}

	cPriv, err := generateX25519()
	if err != nil {
		_ = uc.Close()
		return nil, nil, nil, err
	}
	var cPubArr [32]byte
	copy(cPubArr[:], cPriv.PublicKey().Bytes())

	type hsAttempt struct {
		seq   uint32
		nonce [16]byte
	}
	attempts := make([]hsAttempt, 0, 6)
	buildHello := func() (hsAttempt, []byte) {
		var cNonce [16]byte
		_, _ = rand.Read(cNonce[:])
		var seqBytes [4]byte
		_, _ = rand.Read(seqBytes[:])
		seq := binary.BigEndian.Uint32(seqBytes[:])
		chPlain := encodeClientHello(clientHelloPayload{
			Version:        ProtocolVersion,
			ClientPub:      cPubArr,
			ClientNonce:    cNonce,
			Timestamp:      time.Now().Unix(),
			Caps:           CapHyBBR | CapUDPFrag,
			DesiredDownBPS: c.cfg.DesiredDownBPS,
			DesiredUpBPS:   c.cfg.DesiredUpBPS,
		})
		chHdr := PacketHeader{
			Prefix:    makeCamouflagePrefix(),
			Type:      PktClientHello,
			Flags:     0,
			SessionID: 0,
			PktNum:    seq,
		}
		att := hsAttempt{seq: seq, nonce: cNonce}
		attempts = append(attempts, att)
		return att, c.hsCipher.seal(c.obfsKey, chHdr, chPlain)
	}

	// 1-RTT 握手 + 指数退避重试（250ms, 450ms, 800ms, 1500ms）应对 UDP 首包丢包
	backoffs := []time.Duration{250 * time.Millisecond, 450 * time.Millisecond, 800 * time.Millisecond, 1500 * time.Millisecond, 2500 * time.Millisecond}
	buf := make([]byte, 2048)

	var sh serverHelloPayload
	var sk *sessionKeys
	var lastErr error

	stopClose := context.AfterFunc(ctx, func() {
		_ = uc.SetReadDeadline(time.Now())
	})
	defer stopClose()

	attempt := 0
	_, chWire := buildHello()
	for {
		if ctx.Err() != nil {
			_ = uc.Close()
			if lastErr != nil {
				return nil, nil, nil, lastErr
			}
			return nil, nil, nil, ctx.Err()
		}
		if _, err := uc.WriteToUDP(chWire, raddr); err != nil {
			_ = uc.Close()
			return nil, nil, nil, fmt.Errorf("txpulse: send ClientHello: %w", err)
		}
		wait := backoffs[min(attempt, len(backoffs)-1)]
		if dl, ok := ctx.Deadline(); ok {
			if rem := time.Until(dl); rem < wait {
				wait = rem
			}
		}
		if wait <= 0 {
			_ = uc.Close()
			return nil, nil, nil, context.DeadlineExceeded
		}
		_ = uc.SetReadDeadline(time.Now().Add(wait))
		n, _, rerr := uc.ReadFromUDP(buf)
		if rerr != nil {
			var ne net.Error
			if errors.As(rerr, &ne) && ne.Timeout() && ctx.Err() == nil {
				attempt++
				_, chWire = buildHello()
				continue
			}
			_ = uc.Close()
			return nil, nil, nil, rerr
		}

		hdr, aad, ok := decodeHeader(buf[:n], c.obfsKey)
		if !ok || hdr.Type != PktServerHello || hdr.Flags != FlagServerToClient {
			continue
		}
		var matchedNonce [16]byte
		matched := false
		for _, att := range attempts {
			if att.seq == hdr.PktNum {
				matchedNonce = att.nonce
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		shPlain, err := c.hsCipher.open(buf[:n], hdr, aad)
		if err != nil {
			continue
		}
		parsed, err := decodeServerHello(shPlain)
		if err != nil {
			lastErr = err
			continue
		}
		sPub, err := ecdh.X25519().NewPublicKey(parsed.ServerPub[:])
		if err != nil {
			lastErr = err
			continue
		}
		dhSecret, err := cPriv.ECDH(sPub)
		if err != nil {
			lastErr = err
			continue
		}
		transcript := computeTranscriptHash(cPubArr[:], matchedNonce[:], parsed.ServerPub[:], parsed.SessionID, parsed.ServerCaps, parsed.ServerMaxBPS)
		keys, err := deriveSessionKeys(dhSecret, c.token, transcript)
		if err != nil {
			_ = uc.Close()
			return nil, nil, nil, err
		}
		// 严格校验证书指纹（CertPin）、有效期与 ECDSA 签名 —— 自签证书零 MITM！
		if err := verifyCertAndSig(keys, transcript, parsed.EncCertPayload, c.cfg.CertPin, time.Now()); err != nil {
			_ = uc.Close()
			return nil, nil, nil, err
		}
		sh = parsed
		sk = keys
		break
	}
	_ = uc.SetReadDeadline(time.Time{})

	c.targetMu.Lock()
	c.target = raddr
	c.targetMu.Unlock()

	sendFn := func(pkt []byte) error {
		c.targetMu.RLock()
		dst := c.target
		c.targetMu.RUnlock()
		if dst == nil {
			dst = raddr
		}
		_, err := uc.WriteToUDP(pkt, dst)
		return err
	}

	var sess *Session
	sess = newSession(sessionConfig{
		id:          sh.SessionID,
		isClient:    true,
		obfsKey:     c.obfsKey,
		keys:        sk,
		targetBPS:   c.cfg.DesiredUpBPS,
		maxBPS:      sh.ServerMaxBPS,
		idleTimeout: c.cfg.IdleTimeout,
		rawSend:     sendFn,
		handlers: SessionHandlers{
			OnClosed: func(uint64) {
				_ = uc.Close()
				c.mu.Lock()
				if c.sess == sess {
					c.sess = nil
					c.conn = nil
					if c.hopCancel != nil {
						c.hopCancel()
						c.hopCancel = nil
					}
				}
				c.mu.Unlock()
			},
		},
	})

	// 启动客户端 UDP 接收循环（仅当该 socket 仍为当前活跃连接时退出才关闭会话，支持零中断连接迁移）
	go func() {
		defer func() {
			c.mu.Lock()
			stillCur := c.conn == uc
			c.mu.Unlock()
			if stillCur {
				_ = sess.Close()
			}
		}()
		rbuf := make([]byte, 2048)
		for {
			n, _, err := uc.ReadFromUDP(rbuf)
			if err != nil {
				return
			}
			if n < HeaderSize+TagSize {
				continue
			}
			hdr, aad, ok := decodeHeader(rbuf[:n], c.obfsKey)
			if !ok || hdr.Type != PktData || hdr.SessionID != sh.SessionID {
				continue
			}
			sess.HandlePacket(rbuf[:n], hdr, aad, nil, nil)
		}
	}()

	return sess, uc, raddr, nil
}

// hopLoop 在启用端口跳跃时，每隔 25..45 秒随机平滑切换服务端目标 UDP 端口，
// 利用同一 SessionID 无缝迁移，避免运营商针对单一 UDP 五元组的长时间限速。
func (c *Client) hopLoop(ctx context.Context, sess *Session) {
	span := c.cfg.HopEnd - c.cfg.HopStart + 1
	if span < 2 {
		return
	}
	for {
		var r [2]byte
		_, _ = rand.Read(r[:])
		interval := time.Duration(25+int(r[0])%21) * time.Second
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-sess.doneCh:
			timer.Stop()
			return
		case <-timer.C:
		}
		nextPort := c.cfg.HopStart + int(binary.BigEndian.Uint16(r[:]))%span
		c.targetMu.Lock()
		if c.target != nil {
			next := *c.target
			next.Port = nextPort
			c.target = &next
		}
		c.targetMu.Unlock()
		// 立即发送一个加密 PING 让服务端将回复 socket 切换到新端口
		sess.Ping()
	}
}

// MigrateSocket 供客户端在网络切换（或测试验证连接迁移）时切换本地源 UDP 端口而不断开现有流！
func (c *Client) MigrateSocket(ctx context.Context) error {
	c.mu.Lock()
	sess := c.sess
	oldConn := c.conn
	c.mu.Unlock()
	if sess == nil || !sess.Alive() {
		return errSessionClosed
	}
	c.targetMu.RLock()
	curTarget := c.target
	c.targetMu.RUnlock()
	if curTarget == nil {
		return errSessionClosed
	}

	newConn, _, err := c.dialUDPSocket(ctx, curTarget.String())
	if err != nil {
		return err
	}

	// 先检查会话是否仍然存活并原子更新活跃连接句柄，避免会话已关闭时泄漏新 socket
	c.mu.Lock()
	if c.closed || c.sess != sess || !sess.Alive() {
		c.mu.Unlock()
		_ = newConn.Close()
		return errSessionClosed
	}
	c.conn = newConn
	c.mu.Unlock()

	sess.SetRawSend(func(pkt []byte) error {
		c.targetMu.RLock()
		dst := c.target
		c.targetMu.RUnlock()
		if dst == nil {
			dst = curTarget
		}
		_, err := newConn.WriteToUDP(pkt, dst)
		return err
	})

	go func() {
		defer func() {
			c.mu.Lock()
			stillCur := c.conn == newConn
			c.mu.Unlock()
			if stillCur {
				_ = sess.Close()
			}
		}()
		rbuf := make([]byte, 2048)
		for {
			n, _, err := newConn.ReadFromUDP(rbuf)
			if err != nil {
				return
			}
			if n < HeaderSize+TagSize {
				continue
			}
			hdr, aad, ok := decodeHeader(rbuf[:n], c.obfsKey)
			if !ok || hdr.Type != PktData || hdr.SessionID != sess.id {
				continue
			}
			sess.HandlePacket(rbuf[:n], hdr, aad, nil, nil)
		}
	}()

	sess.Ping()
	if oldConn != nil {
		time.AfterFunc(300*time.Millisecond, func() { _ = oldConn.Close() })
	}
	return nil
}

// SwitchTargetPort 供端口跳跃逻辑或测试立即将目标切换到指定端口。
func (c *Client) SwitchTargetPort(port int) {
	c.targetMu.Lock()
	if c.target != nil {
		next := *c.target
		next.Port = port
		c.target = &next
	}
	c.targetMu.Unlock()
	c.mu.Lock()
	sess := c.sess
	c.mu.Unlock()
	if sess != nil {
		sess.Ping()
	}
}
