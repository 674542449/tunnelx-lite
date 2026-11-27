// Package share encodes a server as a single pasteable link:
//
//	txlite://TOKEN@HOST:PORT?sni=INNER&ech=ECHCONFIG&pin=FINGERPRINT#NAME
//	txpulse://TOKEN@HOST:PORT?obfs=OBFSKEY&pin=FINGERPRINT[&hop=START-END]#NAME
//
// HOST is an IPv4 address, a bracketed IPv6 address or a domain.
// pin is config.CertPin (SPKI SHA-256) of the server's self-signed certificate.
package share

import (
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/674542449/tunnelx-lite/internal/config"
)

const (
	Scheme      = "txlite"
	PulseScheme = "txpulse"
)

type Link struct {
	Protocol   string `json:"protocol,omitempty"` // "" / "txlite" 或 "txpulse"
	Name       string `json:"name"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Token      string `json:"token"`
	ServerName string `json:"server_name,omitempty"`
	ECHConfig  string `json:"ech_config,omitempty"` // standard base64, as in config.Client
	CertPin    string `json:"cert_pin"`
	ObfsKey    string `json:"obfs_key,omitempty"` // TXPulse 混淆种子（base64url）
	HopStart   int    `json:"hop_start,omitempty"`
	HopEnd     int    `json:"hop_end,omitempty"`
}

// IsPulse 报告该链接是否为自研类 Hy2 UDP 协议（TXPulse）。
func (l Link) IsPulse() bool { return strings.EqualFold(l.Protocol, PulseScheme) }

// HasSupportedScheme 检查字段是否以受支持的分享链接协议头开头。
func HasSupportedScheme(field string) bool {
	low := strings.ToLower(strings.TrimSpace(field))
	return strings.HasPrefix(low, Scheme+"://") || strings.HasPrefix(low, PulseScheme+"://")
}

func (l Link) String() string {
	q := url.Values{}
	scheme := Scheme
	if l.IsPulse() {
		scheme = PulseScheme
		q.Set("obfs", l.ObfsKey)
		q.Set("pin", l.CertPin)
		if l.HopStart > 0 && l.HopEnd > l.HopStart {
			q.Set("hop", strconv.Itoa(l.HopStart)+"-"+strconv.Itoa(l.HopEnd))
		}
	} else {
		ech, _ := base64.StdEncoding.DecodeString(l.ECHConfig)
		q.Set("sni", l.ServerName)
		q.Set("ech", base64.RawURLEncoding.EncodeToString(ech))
		q.Set("pin", l.CertPin)
	}
	u := url.URL{Scheme: scheme, User: url.User(l.Token), Host: net.JoinHostPort(l.Host, strconv.Itoa(l.Port)), RawQuery: q.Encode(), Fragment: l.Name}
	return u.String()
}

func Parse(raw string) (Link, error) {
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil || u.User == nil || u.Opaque != "" {
		return Link{}, errors.New("不是有效的 txlite:// 或 txpulse:// 分享链接")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != Scheme && scheme != PulseScheme {
		return Link{}, errors.New("不是有效的 txlite:// 或 txpulse:// 分享链接")
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 {
		return Link{}, errors.New("分享链接的端口无效")
	}
	q := u.Query()
	l := Link{
		Name:    u.Fragment,
		Host:    u.Hostname(),
		Port:    port,
		Token:   u.User.Username(),
		CertPin: q.Get("pin"),
	}
	if l.Host == "" || strings.ContainsAny(l.Host, ` /\@`) {
		return Link{}, errors.New("分享链接的服务器地址无效")
	}
	if !config.TokenValid(l.Token) {
		return Link{}, errors.New("分享链接的密钥无效")
	}
	if pin, e := base64.RawURLEncoding.DecodeString(l.CertPin); e != nil || len(pin) != 32 {
		return Link{}, errors.New("分享链接的自签证书指纹无效")
	}
	if scheme == PulseScheme {
		l.Protocol = PulseScheme
		l.ObfsKey = q.Get("obfs")
		ob, err := base64.RawURLEncoding.DecodeString(l.ObfsKey)
		if err != nil || len(ob) < 16 || len(ob) > 32 {
			return Link{}, errors.New("TXPulse 分享链接缺少有效的混淆种子（obfs）")
		}
		if hop := strings.TrimSpace(q.Get("hop")); hop != "" {
			a, b, ok := strings.Cut(hop, "-")
			sPort, e1 := strconv.Atoi(a)
			ePort, e2 := strconv.Atoi(b)
			if !ok || e1 != nil || e2 != nil || sPort < 1 || ePort > 65535 || ePort <= sPort {
				return Link{}, errors.New("TXPulse 分享链接的端口跳跃范围无效")
			}
			l.HopStart, l.HopEnd = sPort, ePort
		}
	} else {
		ech, e := base64.RawURLEncoding.DecodeString(strings.TrimRight(q.Get("ech"), "="))
		if e != nil || len(ech) < 8 {
			return Link{}, errors.New("分享链接缺少有效的 ECH 配置")
		}
		l.ServerName = q.Get("sni")
		l.ECHConfig = base64.StdEncoding.EncodeToString(ech)
		if l.ServerName == "" || strings.ContainsAny(l.ServerName, ` /\:@`) {
			return Link{}, errors.New("分享链接的 sni 无效")
		}
	}
	if l.Name == "" {
		l.Name = l.Host
	}
	// Cut by characters: a byte cut can split a Chinese name mid-character.
	if r := []rune(l.Name); len(r) > 64 {
		l.Name = string(r[:64])
	}
	return l, nil
}

// Client builds the kernel client configuration; ip must be a literal address
// (callers resolve domain hosts first).
func (l Link) Client(ip string) config.Client {
	if l.IsPulse() {
		return config.Client{
			Protocol:       PulseScheme,
			ServerIP:       ip,
			Port:           l.Port,
			Token:          l.Token,
			Transport:      "pulse",
			CertPin:        l.CertPin,
			ObfsKey:        l.ObfsKey,
			HopStart:       l.HopStart,
			HopEnd:         l.HopEnd,
			ConnectTimeout: 10,
			MaxConnections: 1024,
		}
	}
	// Default to dedicated TLS 1.3 TCP tunnels ("tcp") so every flow gets its
	// own congestion window with zero H2 HoL blocking; keep 6 H2 carriers ready
	// for UDP (connect-udp) and legacy-server fallback.
	return config.Client{ServerName: l.ServerName, ServerIP: ip, Port: l.Port, Token: l.Token, Transport: "tcp", Privacy: "strict", ECHConfig: l.ECHConfig, CertPin: l.CertPin, ConnectTimeout: 15, MaxConnections: 1024, H2Connections: 6, H2RetryNew: true}
}
