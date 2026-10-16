// Package lite is the standalone server: one proxy, one owner, one panel.
package lite

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/674542449/tunnelx-lite/internal/config"
)

const Version = "v0.2.2"

type Config struct {
	Name           string   `json:"name"`
	Port           int      `json:"port"`
	PanelPort      int      `json:"panel_port"`
	PanelPath      string   `json:"panel_path"`
	PanelHash      string   `json:"panel_password_hash"`
	Token          string   `json:"token"`
	InnerName      string   `json:"inner_name"`
	PublicName     string   `json:"public_name"`
	Hosts          []string `json:"hosts,omitempty"`
	Inbound        string   `json:"inbound,omitempty"` // "", "ipv4" or "ipv6"
	OutboundIP     string   `json:"outbound_ip,omitempty"`
	BandwidthLimit int64    `json:"bandwidth_limit_bytes,omitempty"`
	NoQUIC         bool     `json:"no_quic,omitempty"` // QUIC on the UDP port is on unless switched off
}

// Dir holds config.json, the certificate, the ECH key and traffic counters.
type Dir string

func (d Dir) path(name string) string { return filepath.Join(string(d), name) }
func (d Dir) Config() string          { return d.path("config.json") }
func (d Dir) Cert() string            { return d.path("cert.pem") }
func (d Dir) Key() string             { return d.path("key.pem") }
func (d Dir) ECH() string             { return d.path("ech.json") }
func (d Dir) Traffic() string         { return d.path("traffic.json") }

func (c *Config) Validate() error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" || len(c.Name) > 48 || strings.ContainsAny(c.Name, "#\r\n") {
		return errors.New("名称需要 1 到 48 个字符，且不能包含 #")
	}
	if c.Port < 1 || c.Port > 65535 || c.PanelPort < 1 || c.PanelPort > 65535 || c.Port == c.PanelPort {
		return errors.New("代理端口和面板端口需在 1–65535 之间且互不相同")
	}
	if len(c.PanelPath) < 8 || strings.ContainsAny(c.PanelPath, "/?#% ") {
		return errors.New("面板路径无效")
	}
	if !config.TokenValid(c.Token) {
		return errors.New("密钥无效")
	}
	if len(c.Hosts) > 4 {
		return errors.New("自定义分享地址最多 4 个")
	}
	for i, h := range c.Hosts {
		h = strings.Trim(strings.TrimSpace(h), "[]")
		if h == "" || len(h) > 253 || strings.ContainsAny(h, " /\\@?#") {
			return errors.New("自定义分享地址无效：" + h)
		}
		c.Hosts[i] = h
	}
	switch c.Inbound {
	case "", "ipv4", "ipv6":
	default:
		return errors.New("入站方式无效")
	}
	switch c.OutboundIP {
	case "", "prefer_ipv4", "prefer_ipv6", "ipv4", "ipv6":
	default:
		return errors.New("出站方式无效")
	}
	if c.BandwidthLimit != 0 && (c.BandwidthLimit < 1024 || c.BandwidthLimit > 1<<30) {
		return errors.New("限速需为 0（不限）或 0.01–8589 Mbps")
	}
	return nil
}

func Load(d Dir) (Config, error) {
	var c Config
	if e := config.Read(d.Config(), &c); e != nil {
		return c, e
	}
	return c, c.Validate()
}

func Save(d Dir, c Config) error {
	if e := c.Validate(); e != nil {
		return e
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return writeFile(d.Config(), append(b, '\n'))
}

// Server builds the kernel server configuration from the owner settings.
func (c Config) Server(d Dir) config.Server {
	return config.Server{Listen: ":" + strconv.Itoa(c.Port), CertFile: d.Cert(), KeyFile: d.Key(), ECHKeyFile: d.ECH(), InnerName: c.InnerName, InnerCertFile: d.Cert(), InnerKeyFile: d.Key(), Tokens: []string{c.Token}, Network: map[string]string{"ipv4": "tcp4", "ipv6": "tcp6"}[c.Inbound], OutboundIP: c.OutboundIP, BandwidthLimit: c.BandwidthLimit, MaxConnections: 1024, QUIC: !c.NoQUIC}
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func NewToken() string { return randomToken(32) }

const passwordRounds = 200000

func HashPassword(p string) (string, error) {
	if len(p) < 8 || len(p) > 128 {
		return "", errors.New("面板密码需要 8 到 128 个字符")
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	key, e := pbkdf2.Key(sha256.New, p, salt, passwordRounds, 32)
	if e != nil {
		return "", e
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", passwordRounds, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func CheckPassword(hash, p string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	rounds, e := strconv.Atoi(parts[1])
	salt, e1 := base64.RawStdEncoding.DecodeString(parts[2])
	want, e2 := base64.RawStdEncoding.DecodeString(parts[3])
	if e != nil || e1 != nil || e2 != nil || rounds < 1000 || rounds > 10_000_000 {
		return false
	}
	got, e := pbkdf2.Key(sha256.New, p, salt, rounds, len(want))
	return e == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// writeFile replaces a file atomically. When root edits the state directory
// (CLI menu), the file keeps the directory owner so the service can read it.
func writeFile(path string, data []byte) error {
	tmp, e := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if e != nil {
		return e
	}
	defer os.Remove(tmp.Name())
	if _, e = tmp.Write(data); e == nil {
		e = tmp.Sync()
	}
	if c := tmp.Close(); e == nil {
		e = c
	}
	if e != nil {
		return e
	}
	if e = os.Chmod(tmp.Name(), 0600); e != nil {
		return e
	}
	matchOwner(tmp.Name(), filepath.Dir(path))
	return os.Rename(tmp.Name(), path)
}
