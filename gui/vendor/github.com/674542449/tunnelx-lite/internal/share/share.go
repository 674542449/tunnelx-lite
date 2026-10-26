// Package share encodes a server as a single pasteable link:
//
//	txlite://TOKEN@HOST:PORT?sni=INNER&ech=ECHCONFIG&pin=FINGERPRINT#NAME
//
// HOST is an IPv4 address, a bracketed IPv6 address or a domain. ech is the
// ECHConfigList in unpadded base64url; pin is config.CertPin of the server.
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

const Scheme = "txlite"

type Link struct {
	Name       string `json:"name"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Token      string `json:"token"`
	ServerName string `json:"server_name"`
	ECHConfig  string `json:"ech_config"` // standard base64, as in config.Client
	CertPin    string `json:"cert_pin"`
}

func (l Link) String() string {
	ech, _ := base64.StdEncoding.DecodeString(l.ECHConfig)
	q := url.Values{}
	q.Set("sni", l.ServerName)
	q.Set("ech", base64.RawURLEncoding.EncodeToString(ech))
	q.Set("pin", l.CertPin)
	u := url.URL{Scheme: Scheme, User: url.User(l.Token), Host: net.JoinHostPort(l.Host, strconv.Itoa(l.Port)), RawQuery: q.Encode(), Fragment: l.Name}
	return u.String()
}

func Parse(raw string) (Link, error) {
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil || u.Scheme != Scheme || u.User == nil || u.Opaque != "" {
		return Link{}, errors.New("不是有效的 txlite:// 分享链接")
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 {
		return Link{}, errors.New("分享链接的端口无效")
	}
	q := u.Query()
	ech, e := base64.RawURLEncoding.DecodeString(strings.TrimRight(q.Get("ech"), "="))
	if e != nil || len(ech) < 8 {
		return Link{}, errors.New("分享链接缺少有效的 ECH 配置")
	}
	l := Link{Name: u.Fragment, Host: u.Hostname(), Port: port, Token: u.User.Username(), ServerName: q.Get("sni"), ECHConfig: base64.StdEncoding.EncodeToString(ech), CertPin: q.Get("pin")}
	if l.Host == "" || strings.ContainsAny(l.Host, ` /\@`) {
		return Link{}, errors.New("分享链接的服务器地址无效")
	}
	if !config.TokenValid(l.Token) {
		return Link{}, errors.New("分享链接的密钥无效")
	}
	if l.ServerName == "" || strings.ContainsAny(l.ServerName, ` /\:@`) {
		return Link{}, errors.New("分享链接的 sni 无效")
	}
	if pin, e := base64.RawURLEncoding.DecodeString(l.CertPin); e != nil || len(pin) != 32 {
		return Link{}, errors.New("分享链接的证书指纹无效")
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
	// The server may spend up to 10s dialing a slow target, so wait longer than
	// that for CONNECT; the system proxy carries every app, so allow 1024 flows.
	return config.Client{ServerName: l.ServerName, ServerIP: ip, Port: l.Port, Token: l.Token, Transport: "h2", Privacy: "strict", ECHConfig: l.ECHConfig, CertPin: l.CertPin, ConnectTimeout: 15, MaxConnections: 1024}
}
