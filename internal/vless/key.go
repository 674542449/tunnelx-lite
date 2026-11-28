// Package vless 实现标准 VLESS + REALITY + xtls-rprx-vision 服务端，
// 供 iOS 小火箭（Shadowrocket）、Stash、Loon、Sing-box、V2RayN 等标准客户端直接扫码接入，
// 并与 txlite 主服务端共用 TCP 端口（按 TLS SNI 自动分流）、仅 IPv4 落地出站与流量统计。
package vless

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// DefaultRealitySNI 默认选用全球 CDN 覆盖广、支持 TLS 1.3 + H2 且相对不泛滥的苹果官方域名；
// 用户随时可在面板中替换为与自己 VPS 同地区的冷门 TLS 1.3 网站。
const DefaultRealitySNI = "itunes.apple.com"

// GenerateUUID 生成符合 RFC 4122 v4 的标准小写 UUID。
func GenerateUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ParseUUID 解析标准连字符或 32 位十六进制 UUID 字符串。
func ParseUUID(s string) ([16]byte, error) {
	var out [16]byte
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if len(clean) != 32 {
		return out, errors.New("无效的 VLESS UUID")
	}
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) != 16 {
		return out, errors.New("无效的 VLESS UUID")
	}
	copy(out[:], b)
	return out, nil
}

// GenerateRealityKeyPair 生成 X25519 REALITY 密钥对（RawURL Base64，与 Xray / 小火箭 pbk 完全一致）。
func GenerateRealityKeyPair() (privB64, pubB64 string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(priv.Bytes()),
		base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
		nil
}

// ParseRealityPrivateKey 解析 RawURL/Std Base64 编码的 32 字节 X25519 私钥。
func ParseRealityPrivateKey(privB64 string) (*ecdh.PrivateKey, error) {
	raw, err := decodeB64Flexible(privB64)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("无效的 REALITY X25519 私钥")
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

// RealityPublicKey 从 REALITY 私钥推导客户端分享链接所需的 pbk 公钥（RawURL Base64）。
func RealityPublicKey(privB64 string) (string, error) {
	priv, err := ParseRealityPrivateKey(privB64)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func decodeB64Flexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// GenerateShortID 生成 8 字节（16 位小写十六进制）REALITY ShortID。
func GenerateShortID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// ParseShortID 将 2..16 位偶数长度十六进制字符串解析为 8 字节 ShortID（右补零，与 Xray 规范一致）。
func ParseShortID(s string) ([8]byte, error) {
	var out [8]byte
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return out, nil
	}
	if len(s) > 16 || len(s)%2 != 0 {
		return out, errors.New("REALITY ShortID 需为 2–16 位偶数十六进制字符")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, errors.New("REALITY ShortID 包含非法十六进制字符")
	}
	copy(out[:], b)
	return out, nil
}

// NormalizeSNI 规范化并校验 REALITY 伪装目标域名（不含端口、协议头与路径）。
func NormalizeSNI(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 || !strings.Contains(s, ".") || strings.ContainsAny(s, " /\\:@?#*\t\r\n") {
		return "", errors.New("REALITY 伪装域名格式无效，请填写纯域名（例如 itunes.apple.com）")
	}
	if net.ParseIP(s) != nil {
		return "", errors.New("REALITY 伪装目标必须为支持 TLS 1.3 的域名，不能填写 IP")
	}
	return s, nil
}

// ShareURL 生成标准 VLESS + REALITY + xtls-rprx-vision 分享链接（小火箭 / Sing-box / Stash / V2RayN 通用）。
func ShareURL(uuid, host string, port int, sni, pbk, sid, name string) string {
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("flow", FlowVision)
	q.Set("security", "reality")
	q.Set("sni", sni)
	q.Set("fp", "chrome")
	q.Set("pbk", pbk)
	if sid != "" {
		q.Set("sid", sid)
	}
	q.Set("type", "tcp")
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(uuid),
		Host:     net.JoinHostPort(host, strconv.Itoa(port)),
		RawQuery: q.Encode(),
		Fragment: name,
	}
	return u.String()
}
