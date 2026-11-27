// Package pulse 实现 TXPulse —— 借鉴 Hysteria 2 优缺点全新重写的自研 UDP 隧道协议。
//
// 核心特性：
//   - 自签 ECDSA P-256 证书 + 公钥指纹固定（CertPin / SPKI SHA-256）+ X25519 前向保密，免域名且杜绝 insecure=1 中间人风险；
//   - 彻底脱离 QUIC / HTTP/3 特征，首包经密钥派生 AEAD 加密 + 防重放窗口，未授权探测静默丢弃（0 字节响应）；
//   - 结构化低熵伪装前缀 + 每包独立掩码混淆头 + 动态长度填充，缓解高熵识别与长度统计特征；
//   - 单连接独立多流复用（按流 SACK / 快速重传 / 流控，无 TCP-over-TCP 队头阻塞）+ 原生不可靠 UDP 分片直传；
//   - 自适应 HyBBR + 可选弹性 Brutal 混合拥塞控制，免填带宽自动区分随机丢包与真实拥塞；
//   - 支持连接迁移（Wi-Fi <-> 5G 无缝切换）与原生无 iptables 端口跳跃（Port Hopping）。
package pulse

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/674542449/tunnelx-lite/internal/config"
)

const (
	// ProtocolVersion 为 TXPulse 协议版本号。
	ProtocolVersion uint16 = 1

	// MaxPacketSize 取 1232 字节（1280 最小 IPv6 MTU - 40 IPv6 - 8 UDP），
	// 确保在 IPv4 / IPv6 / PPPoE / 4G / 5G 路径上永不发生 IP 层分片。
	MaxPacketSize = 1232

	// HeaderSize 为外层 4 字节伪装前缀 + 12 字节掩码路由头。
	HeaderSize = 16
	// TagSize 为 AES-128-GCM 认证标签长度。
	TagSize = 16
	// HandshakeSaltSize 为握手包额外 8 字节随机数（与 4 字节前缀组成 96-bit Nonce 熵）。
	HandshakeSaltSize = 8

	// MaxDataPayload 为单个 Data 报文内可承载的最大明文帧负载字节数。
	MaxDataPayload = MaxPacketSize - HeaderSize - TagSize // 1200

	// 报文类型
	PktClientHello byte = 0x01
	PktServerHello byte = 0x02
	PktData        byte = 0x03

	// 方向标志（meta[1] bit0）
	FlagServerToClient byte = 0x01

	// 能力位
	CapHyBBR   uint32 = 1 << 0
	CapUDPFrag uint32 = 1 << 1

	// 时间戳允许偏差（±120 秒），兼顾移动设备时钟漂移与防重放。
	maxClockSkew = 120
	replayTTL    = 240 * time.Second
	maxReplayCap = 16384
)

// PacketHeader 为解掩码后的 16 字节报文头。
type PacketHeader struct {
	Prefix    [4]byte
	Type      byte
	Flags     byte
	SessionID uint64 // 48-bit 非零随机 ID（ClientHello 时为 0）
	PktNum    uint32
}

// GenerateObfsKey 生成 16 字节 URL-safe Base64 混淆种子（22 字符）。
func GenerateObfsKey() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ValidObfsKey 校验混淆种子格式（解码后 16..32 字节）。
func ValidObfsKey(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) >= 16 && len(b) <= 32
}

// DecodeKeyMaterial 解码并校验 token 与 obfsKey 的原始字节。
func DecodeKeyMaterial(token, obfs string) ([]byte, []byte, error) {
	tb, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(tb) < 32 || len(tb) > 64 {
		return nil, nil, errors.New("txpulse: invalid token")
	}
	ob, err := base64.RawURLEncoding.DecodeString(obfs)
	if err != nil || len(ob) < 16 || len(ob) > 32 {
		return nil, nil, errors.New("txpulse: invalid obfs key")
	}
	return tb, ob, nil
}

// headerMask 基于 obfsKey 与每包 4 字节前缀生成 12 字节一次性路由头掩码。
func headerMask(obfsKey []byte, prefix [4]byte) [12]byte {
	h := sha256.New()
	h.Write([]byte("txpulse-v1-hdr-mask"))
	h.Write(obfsKey)
	h.Write(prefix[:])
	var sum [32]byte
	h.Sum(sum[:0])
	var out [12]byte
	copy(out[:], sum[:12])
	return out
}

// makeCamouflagePrefix 生成结构化低熵 4 字节前缀：
// 首字节落在 0x80..0x8F（模拟常规 RTP/媒体报文前缀，彻底避开 QUIC Long/Short Header 位模式），
// 后 3 字节为每包随机盐，使每包掩码彼此独立且无法跨跳关联。
func makeCamouflagePrefix() [4]byte {
	var p [4]byte
	_, _ = rand.Read(p[:])
	p[0] = 0x80 | (p[0] & 0x0F)
	return p
}

// encodeHeader 将 PacketHeader 编码并掩码写入 dst[:16]，同时返回未掩码 AAD 副本（16 字节）。
func encodeHeader(dst []byte, obfsKey []byte, hdr PacketHeader) [16]byte {
	var aad [16]byte
	copy(aad[0:4], hdr.Prefix[:])
	aad[4] = hdr.Type
	aad[5] = hdr.Flags
	// 48-bit SessionID 大端写入 aad[6:12]
	aad[6] = byte(hdr.SessionID >> 40)
	aad[7] = byte(hdr.SessionID >> 32)
	aad[8] = byte(hdr.SessionID >> 24)
	aad[9] = byte(hdr.SessionID >> 16)
	aad[10] = byte(hdr.SessionID >> 8)
	aad[11] = byte(hdr.SessionID)
	binary.BigEndian.PutUint32(aad[12:16], hdr.PktNum)

	mask := headerMask(obfsKey, hdr.Prefix)
	copy(dst[0:4], hdr.Prefix[:])
	for i := 0; i < 12; i++ {
		dst[4+i] = aad[4+i] ^ mask[i]
	}
	return aad
}

// decodeHeader 校验伪装前缀并对 12 字节路由头解掩码，返回 PacketHeader 与 16 字节明文 AAD。
func decodeHeader(pkt []byte, obfsKey []byte) (PacketHeader, [16]byte, bool) {
	if len(pkt) < HeaderSize+TagSize {
		return PacketHeader{}, [16]byte{}, false
	}
	// 快速拒绝不符合结构化伪装前缀的随机噪声/扫描包
	if pkt[0]&0xF0 != 0x80 {
		return PacketHeader{}, [16]byte{}, false
	}
	var hdr PacketHeader
	copy(hdr.Prefix[:], pkt[0:4])
	mask := headerMask(obfsKey, hdr.Prefix)

	var aad [16]byte
	copy(aad[0:4], pkt[0:4])
	for i := 0; i < 12; i++ {
		aad[4+i] = pkt[4+i] ^ mask[i]
	}
	hdr.Type = aad[4]
	hdr.Flags = aad[5]
	hdr.SessionID = uint64(aad[6])<<40 | uint64(aad[7])<<32 | uint64(aad[8])<<24 |
		uint64(aad[9])<<16 | uint64(aad[10])<<8 | uint64(aad[11])
	hdr.PktNum = binary.BigEndian.Uint32(aad[12:16])
	return hdr, aad, true
}

// handshakeCipher 持有基于 (token, obfsKey) 派生的预共享握手 AEAD。
type handshakeCipher struct {
	aead cipher.AEAD
	iv   [12]byte
}

func newHandshakeCipher(token, obfsKey []byte) (*handshakeCipher, error) {
	key, err := hkdf.Key(sha256.New, token, obfsKey, "txpulse-v1-hs-key", 16)
	if err != nil {
		return nil, err
	}
	ivBytes, err := hkdf.Key(sha256.New, token, obfsKey, "txpulse-v1-hs-iv", 12)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	var hc handshakeCipher
	hc.aead = aead
	copy(hc.iv[:], ivBytes)
	return &hc, nil
}

func (hc *handshakeCipher) seal(obfsKey []byte, hdr PacketHeader, plaintext []byte) []byte {
	var salt [HandshakeSaltSize]byte
	_, _ = rand.Read(salt[:])

	out := make([]byte, HeaderSize+HandshakeSaltSize+len(plaintext)+TagSize)
	aadHdr := encodeHeader(out[:HeaderSize], obfsKey, hdr)
	copy(out[HeaderSize:HeaderSize+HandshakeSaltSize], salt[:])

	var aad [HeaderSize + HandshakeSaltSize]byte
	copy(aad[:HeaderSize], aadHdr[:])
	copy(aad[HeaderSize:], salt[:])

	var nonce [12]byte
	for i := 0; i < 4; i++ {
		nonce[i] = hc.iv[i] ^ hdr.Prefix[i]
	}
	for i := 0; i < 8; i++ {
		nonce[4+i] = hc.iv[4+i] ^ salt[i]
	}
	hc.aead.Seal(out[HeaderSize+HandshakeSaltSize:HeaderSize+HandshakeSaltSize], nonce[:], plaintext, aad[:])
	return out
}

func (hc *handshakeCipher) open(pkt []byte, hdr PacketHeader, aadHdr [16]byte) ([]byte, error) {
	if len(pkt) < HeaderSize+HandshakeSaltSize+TagSize {
		return nil, errors.New("txpulse: handshake packet too short")
	}
	salt := pkt[HeaderSize : HeaderSize+HandshakeSaltSize]
	var aad [HeaderSize + HandshakeSaltSize]byte
	copy(aad[:HeaderSize], aadHdr[:])
	copy(aad[HeaderSize:], salt)

	var nonce [12]byte
	for i := 0; i < 4; i++ {
		nonce[i] = hc.iv[i] ^ hdr.Prefix[i]
	}
	for i := 0; i < 8; i++ {
		nonce[4+i] = hc.iv[4+i] ^ salt[i]
	}
	return hc.aead.Open(nil, nonce[:], pkt[HeaderSize+HandshakeSaltSize:], aad[:])
}

// dataCipher 持有单向 AES-128-GCM 会话数据密钥与 IV。
type dataCipher struct {
	aead cipher.AEAD
	iv   [12]byte
}

func newDataCipher(key, iv []byte) (*dataCipher, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	dc := &dataCipher{aead: aead}
	copy(dc.iv[:], iv)
	return dc, nil
}

func (dc *dataCipher) nonce(pktNum uint32) [12]byte {
	n := dc.iv
	n[8] ^= byte(pktNum >> 24)
	n[9] ^= byte(pktNum >> 16)
	n[10] ^= byte(pktNum >> 8)
	n[11] ^= byte(pktNum)
	return n
}

func (dc *dataCipher) sealTo(dst []byte, obfsKey []byte, hdr PacketHeader, plaintext []byte) []byte {
	need := HeaderSize + len(plaintext) + TagSize
	if cap(dst) < need {
		dst = make([]byte, need)
	} else {
		dst = dst[:need]
	}
	aad := encodeHeader(dst[:HeaderSize], obfsKey, hdr)
	n := dc.nonce(hdr.PktNum)
	dc.aead.Seal(dst[HeaderSize:HeaderSize], n[:], plaintext, aad[:])
	return dst
}

func (dc *dataCipher) openTo(dst, pkt []byte, hdr PacketHeader, aad [16]byte) ([]byte, error) {
	if len(pkt) < HeaderSize+TagSize {
		return nil, errors.New("txpulse: data packet too short")
	}
	n := dc.nonce(hdr.PktNum)
	return dc.aead.Open(dst[:0], n[:], pkt[HeaderSize:], aad[:])
}

// sessionKeys 为一次 X25519 + token 握手派生的双向流量密钥及证书加密密钥。
type sessionKeys struct {
	c2s     *dataCipher
	s2c     *dataCipher
	hsReply cipher.AEAD
	hsIV    [12]byte
}

func computeTranscriptHash(cPub, cNonce, sPub []byte, sessionID uint64, serverCaps uint32, serverMaxBPS uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte("txpulse-v1-transcript"))
	h.Write(cPub)
	h.Write(cNonce)
	h.Write(sPub)
	var tail [18]byte
	tail[0] = byte(sessionID >> 40)
	tail[1] = byte(sessionID >> 32)
	tail[2] = byte(sessionID >> 24)
	tail[3] = byte(sessionID >> 16)
	tail[4] = byte(sessionID >> 8)
	tail[5] = byte(sessionID)
	binary.BigEndian.PutUint32(tail[6:10], serverCaps)
	binary.BigEndian.PutUint64(tail[10:18], serverMaxBPS)
	h.Write(tail[:])
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}

func deriveSessionKeys(dhSecret, token []byte, transcript [32]byte) (*sessionKeys, error) {
	ikm := make([]byte, 0, len(dhSecret)+len(token))
	ikm = append(ikm, dhSecret...)
	ikm = append(ikm, token...)
	// 16(c2sKey)+12(c2sIV)+16(s2cKey)+12(s2cIV)+16(hsReplyKey)+12(hsReplyIV) = 84 bytes
	mat, err := hkdf.Key(sha256.New, ikm, transcript[:], "txpulse-v1-session-keys", 84)
	if err != nil {
		return nil, err
	}
	c2s, err := newDataCipher(mat[0:16], mat[16:28])
	if err != nil {
		return nil, err
	}
	s2c, err := newDataCipher(mat[28:44], mat[44:56])
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(mat[56:72])
	if err != nil {
		return nil, err
	}
	hsReply, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	sk := &sessionKeys{c2s: c2s, s2c: s2c, hsReply: hsReply}
	copy(sk.hsIV[:], mat[72:84])
	return sk, nil
}

// clientHelloPayload 描述客户端握手内层明文。
type clientHelloPayload struct {
	Version        uint16
	ClientPub      [32]byte
	ClientNonce    [16]byte
	Timestamp      int64
	Caps           uint32
	DesiredDownBPS uint64
	DesiredUpBPS   uint64
}

func encodeClientHello(p clientHelloPayload) []byte {
	// 随机填充 32..224 字节，打破固定首包长度特征（避免 QUIC 1200B 首包指纹）。
	var r [1]byte
	_, _ = rand.Read(r[:])
	padLen := 32 + int(r[0])%193

	buf := make([]byte, 2+32+16+8+4+8+8+2+padLen)
	binary.BigEndian.PutUint16(buf[0:2], p.Version)
	copy(buf[2:34], p.ClientPub[:])
	copy(buf[34:50], p.ClientNonce[:])
	binary.BigEndian.PutUint64(buf[50:58], uint64(p.Timestamp))
	binary.BigEndian.PutUint32(buf[58:62], p.Caps)
	binary.BigEndian.PutUint64(buf[62:70], p.DesiredDownBPS)
	binary.BigEndian.PutUint64(buf[70:78], p.DesiredUpBPS)
	binary.BigEndian.PutUint16(buf[78:80], uint16(padLen))
	_, _ = rand.Read(buf[80:])
	return buf
}

func decodeClientHello(b []byte) (clientHelloPayload, error) {
	if len(b) < 80 {
		return clientHelloPayload{}, errors.New("txpulse: short ClientHello")
	}
	var p clientHelloPayload
	p.Version = binary.BigEndian.Uint16(b[0:2])
	if p.Version != ProtocolVersion {
		return p, errors.New("txpulse: unsupported protocol version")
	}
	copy(p.ClientPub[:], b[2:34])
	copy(p.ClientNonce[:], b[34:50])
	p.Timestamp = int64(binary.BigEndian.Uint64(b[50:58]))
	p.Caps = binary.BigEndian.Uint32(b[58:62])
	p.DesiredDownBPS = binary.BigEndian.Uint64(b[62:70])
	p.DesiredUpBPS = binary.BigEndian.Uint64(b[70:78])
	padLen := int(binary.BigEndian.Uint16(b[78:80]))
	if 80+padLen != len(b) {
		return p, errors.New("txpulse: invalid ClientHello padding")
	}
	return p, nil
}

// serverHelloPayload 描述服务端握手内层明文。
// 证书 DER 与 ECDSA 签名被前向保密 DH 密钥（hsReply）再次加密，被动嗅探者永不可见自签证书内容。
type serverHelloPayload struct {
	ServerPub      [32]byte
	SessionID      uint64
	ServerCaps     uint32
	ServerMaxBPS   uint64
	EncCertPayload []byte
}

func encodeServerHello(p serverHelloPayload) []byte {
	buf := make([]byte, 32+6+4+8+2+len(p.EncCertPayload))
	copy(buf[0:32], p.ServerPub[:])
	buf[32] = byte(p.SessionID >> 40)
	buf[33] = byte(p.SessionID >> 32)
	buf[34] = byte(p.SessionID >> 24)
	buf[35] = byte(p.SessionID >> 16)
	buf[36] = byte(p.SessionID >> 8)
	buf[37] = byte(p.SessionID)
	binary.BigEndian.PutUint32(buf[38:42], p.ServerCaps)
	binary.BigEndian.PutUint64(buf[42:50], p.ServerMaxBPS)
	binary.BigEndian.PutUint16(buf[50:52], uint16(len(p.EncCertPayload)))
	copy(buf[52:], p.EncCertPayload)
	return buf
}

func decodeServerHello(b []byte) (serverHelloPayload, error) {
	if len(b) < 52 {
		return serverHelloPayload{}, errors.New("txpulse: short ServerHello")
	}
	var p serverHelloPayload
	copy(p.ServerPub[:], b[0:32])
	p.SessionID = uint64(b[32])<<40 | uint64(b[33])<<32 | uint64(b[34])<<24 |
		uint64(b[35])<<16 | uint64(b[36])<<8 | uint64(b[37])
	p.ServerCaps = binary.BigEndian.Uint32(b[38:42])
	p.ServerMaxBPS = binary.BigEndian.Uint64(b[42:50])
	encLen := int(binary.BigEndian.Uint16(b[50:52]))
	if 52+encLen != len(b) || p.SessionID == 0 {
		return p, errors.New("txpulse: invalid ServerHello")
	}
	p.EncCertPayload = b[52:]
	return p, nil
}

// sealCertAndSig 使用自签证书 ECDSA 私钥签名 transcript，并将 certDER + sig + 随机填充加密。
func sealCertAndSig(sk *sessionKeys, transcript [32]byte, certDER []byte, priv *ecdsa.PrivateKey) ([]byte, error) {
	sig, err := ecdsa.SignASN1(rand.Reader, priv, transcript[:])
	if err != nil {
		return nil, err
	}
	var r [1]byte
	_, _ = rand.Read(r[:])
	// 保持总 ServerHello 远低于 1232B MTU，同时随机化长度。
	padLen := 24 + int(r[0])%73
	plain := make([]byte, 2+len(certDER)+2+len(sig)+2+padLen)
	off := 0
	binary.BigEndian.PutUint16(plain[off:off+2], uint16(len(certDER)))
	off += 2
	copy(plain[off:off+len(certDER)], certDER)
	off += len(certDER)
	binary.BigEndian.PutUint16(plain[off:off+2], uint16(len(sig)))
	off += 2
	copy(plain[off:off+len(sig)], sig)
	off += len(sig)
	binary.BigEndian.PutUint16(plain[off:off+2], uint16(padLen))
	off += 2
	_, _ = rand.Read(plain[off:])

	return sk.hsReply.Seal(nil, sk.hsIV[:], plain, transcript[:]), nil
}

// verifyCertAndSig 解密并严格校验服务端自签证书：
//  1. SPKI SHA-256 公钥指纹必须与 pinned cert_pin 完全一致（零 MITM，无需域名或系统 CA）；
//  2. 证书处于有效期内；
//  3. ECDSA 签名与本次 X25519 握手 transcript 完全匹配。
func verifyCertAndSig(sk *sessionKeys, transcript [32]byte, enc []byte, expectedPin string, now time.Time) error {
	plain, err := sk.hsReply.Open(nil, sk.hsIV[:], enc, transcript[:])
	if err != nil {
		return errors.New("txpulse: certificate block decryption failed")
	}
	if len(plain) < 6 {
		return errors.New("txpulse: malformed certificate block")
	}
	off := 0
	certLen := int(binary.BigEndian.Uint16(plain[off : off+2]))
	off += 2
	if off+certLen+4 > len(plain) {
		return errors.New("txpulse: truncated certificate DER")
	}
	certDER := plain[off : off+certLen]
	off += certLen
	sigLen := int(binary.BigEndian.Uint16(plain[off : off+2]))
	off += 2
	if off+sigLen+2 > len(plain) {
		return errors.New("txpulse: truncated certificate signature")
	}
	sig := plain[off : off+sigLen]
	off += sigLen
	padLen := int(binary.BigEndian.Uint16(plain[off : off+2]))
	off += 2
	if off+padLen != len(plain) {
		return errors.New("txpulse: invalid certificate block padding")
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return errors.New("txpulse: invalid server certificate")
	}
	gotPin := config.CertPin(cert)
	if subtle.ConstantTimeCompare([]byte(gotPin), []byte(expectedPin)) != 1 {
		return errors.New("txpulse: server self-signed certificate pin mismatch")
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return errors.New("txpulse: server self-signed certificate expired or not yet valid")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("txpulse: server certificate key is not ECDSA")
	}
	if !ecdsa.VerifyASN1(pub, transcript[:], sig) {
		return errors.New("txpulse: server handshake signature verification failed")
	}
	return nil
}

// generateX25519 生成临时 X25519 密钥对用于单次会话前向保密。
func generateX25519() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// generateSessionID 生成非零 48-bit 随机 SessionID。
func generateSessionID() uint64 {
	var b [6]byte
	for {
		_, _ = rand.Read(b[:])
		id := uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 |
			uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])
		if id != 0 {
			return id
		}
	}
}

// replayFilter 防止主动探测器重放合法 ClientHello 握手包。
type replayFilter struct {
	mu      sync.Mutex
	seen    map[[16]byte]time.Time
	lastGC  time.Time
	nowFunc func() time.Time
}

func newReplayFilter() *replayFilter {
	return &replayFilter{
		seen:    make(map[[16]byte]time.Time, 256),
		nowFunc: time.Now,
	}
}

func (f *replayFilter) CheckAndAdd(nonce [16]byte, ts int64) bool {
	now := f.nowFunc()
	diff := now.Unix() - ts
	if diff < -maxClockSkew || diff > maxClockSkew {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if now.Sub(f.lastGC) > 30*time.Second || len(f.seen) >= maxReplayCap {
		cutoff := now.Add(-replayTTL)
		for k, t := range f.seen {
			if t.Before(cutoff) {
				delete(f.seen, k)
			}
		}
		f.lastGC = now
		if len(f.seen) >= maxReplayCap {
			// 极端 DoS 场景下淘汰最旧一批，防止内存无界增长
			clear(f.seen)
		}
	}
	if _, dup := f.seen[nonce]; dup {
		return false
	}
	f.seen[nonce] = now
	return true
}
