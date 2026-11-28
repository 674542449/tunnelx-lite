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
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/674542449/tunnelx-lite/internal/config"
	"github.com/674542449/tunnelx-lite/internal/pulse"
	"github.com/674542449/tunnelx-lite/internal/vless"
)

const Version = "v0.7.0"

type Config struct {
	Name              string   `json:"name"`
	Port              int      `json:"port"`
	PulsePort         int      `json:"pulse_port,omitempty"`
	PulseObfs         string   `json:"pulse_obfs,omitempty"`
	PulseHopStart     int      `json:"pulse_hop_start,omitempty"`
	PulseHopEnd       int      `json:"pulse_hop_end,omitempty"`
	RealityEnabled    *bool    `json:"reality_enabled,omitempty"`
	RealityUUID       string   `json:"reality_uuid,omitempty"`
	RealityPrivateKey string   `json:"reality_private_key,omitempty"`
	RealityShortID    string   `json:"reality_short_id,omitempty"`
	RealitySNI        string   `json:"reality_sni,omitempty"`
	PanelPort         int      `json:"panel_port"`
	PanelPath      string   `json:"panel_path"`
	PanelHash      string   `json:"panel_password_hash"`
	Token          string   `json:"token"`
	InnerName      string   `json:"inner_name"`
	PublicName     string   `json:"public_name"`
	Hosts          []string `json:"hosts,omitempty"`
	Inbound        string   `json:"inbound,omitempty"` // "", "ipv4" or "ipv6"
	OutboundIP     string   `json:"outbound_ip,omitempty"`
	BandwidthLimit int64    `json:"bandwidth_limit_bytes,omitempty"`
	// NoQUIC is kept only so config.json files from older releases still decode cleanly.
	NoQUIC bool `json:"no_quic,omitempty"`
}

// Dir holds config.json, certificates, the ECH key and traffic counters.
type Dir string

func (d Dir) path(name string) string { return filepath.Join(string(d), name) }
func (d Dir) Config() string          { return d.path("config.json") }
func (d Dir) Cert() string            { return d.path("cert.pem") }
func (d Dir) Key() string             { return d.path("key.pem") }
func (d Dir) PulseCert() string       { return d.path("pulse-cert.pem") }
func (d Dir) PulseKey() string        { return d.path("pulse-key.pem") }
func (d Dir) ECH() string             { return d.path("ech.json") }
func (d Dir) Traffic() string         { return d.path("traffic.json") }

func (c *Config) Validate() error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" || utf8.RuneCountInString(c.Name) > 48 || strings.ContainsAny(c.Name, "#\r\n") {
		return errors.New("名称需要 1 到 48 个字符，且不能包含 #")
	}
	if c.Port < 1 || c.Port > 65535 || c.PanelPort < 1 || c.PanelPort > 65535 || c.Port == c.PanelPort {
		return errors.New("代理端口和面板端口需在 1–65535 之间且互不相同")
	}
	if c.PulsePort != 0 && (c.PulsePort < 1 || c.PulsePort > 65535) {
		return errors.New("TXPulse UDP 端口需在 1–65535 之间")
	}
	if c.PulseObfs != "" && !pulse.ValidObfsKey(c.PulseObfs) {
		return errors.New("TXPulse 混淆种子无效")
	}
	if c.PulseHopStart != 0 || c.PulseHopEnd != 0 {
		if c.PulseHopStart < 1 || c.PulseHopEnd > 65535 || c.PulseHopEnd <= c.PulseHopStart || c.PulseHopEnd-c.PulseHopStart+1 > 128 {
			return errors.New("TXPulse 端口跳跃范围无效（需为 2–128 个连续有效端口）")
		}
	}
	if c.RealityUUID != "" {
		if _, err := vless.ParseUUID(c.RealityUUID); err != nil {
			return err
		}
	}
	if c.RealityPrivateKey != "" {
		if _, err := vless.ParseRealityPrivateKey(c.RealityPrivateKey); err != nil {
			return err
		}
	}
	if c.RealityShortID != "" {
		if _, err := vless.ParseShortID(c.RealityShortID); err != nil {
			return err
		}
	}
	if c.RealitySNI != "" {
		norm, err := vless.NormalizeSNI(c.RealitySNI)
		if err != nil {
			return err
		}
		c.RealitySNI = norm
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
	// Outbound landing is strictly IPv4-only so dual-stack / IPv6-inbound nodes
	// always exit cleanly on a single IPv4 address without IPv6 leak or dual-IP issues.
	switch c.OutboundIP {
	case "", "ipv4":
		c.OutboundIP = "ipv4"
	default:
		return errors.New("出站落地仅支持 IPv4")
	}
	if c.BandwidthLimit != 0 && (c.BandwidthLimit < 1024 || c.BandwidthLimit > 1<<30) {
		return errors.New("限速需为 0（不限）或 0.01–8589 Mbps")
	}
	return nil
}

// ParseHopRange 解析类似 "20000-20031" 的端口跳跃区间；空字符串返回 0, 0, nil。
func ParseHopRange(raw string) (int, int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, 0, nil
	}
	a, b, ok := strings.Cut(raw, "-")
	if !ok {
		return 0, 0, errors.New("端口跳跃格式需为 起始端口-结束端口，例如 20000-20031")
	}
	s, e1 := strconv.Atoi(strings.TrimSpace(a))
	e, e2 := strconv.Atoi(strings.TrimSpace(b))
	if e1 != nil || e2 != nil || s < 1 || e > 65535 || e <= s || e-s+1 > 128 {
		return 0, 0, errors.New("端口跳跃范围需为 2–128 个有效端口（1–65535）")
	}
	return s, e, nil
}

func (c Config) HopRangeString() string {
	if c.PulseHopStart > 0 && c.PulseHopEnd > c.PulseHopStart {
		return strconv.Itoa(c.PulseHopStart) + "-" + strconv.Itoa(c.PulseHopEnd)
	}
	return ""
}

func Load(d Dir) (Config, error) {
	var c Config
	if e := config.Read(d.Config(), &c); e != nil {
		return c, e
	}
	// Migrate legacy outbound_ip values cleanly to IPv4-only egress on upgrade.
	c.OutboundIP = "ipv4"
	return c, c.Validate()
}

func Save(d Dir, c Config) error {
	c.NoQUIC = false
	c.OutboundIP = "ipv4"
	if e := c.Validate(); e != nil {
		return e
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return writeFile(d.Config(), append(b, '\n'))
}

func boolPtr(v bool) *bool { return &v }

// IsRealityEnabled 报告 iOS 小火箭兼容（VLESS + REALITY + Vision）是否启用且配置完整。
func (c Config) IsRealityEnabled() bool {
	if c.RealityEnabled != nil && !*c.RealityEnabled {
		return false
	}
	return c.RealityUUID != "" && c.RealityPrivateKey != "" && c.RealitySNI != ""
}

// Server builds the kernel server configuration from the owner settings.
func (c Config) Server(d Dir) config.Server {
	pulseListen := ""
	if c.PulsePort > 0 {
		pulseListen = ":" + strconv.Itoa(c.PulsePort)
	}
	srv := config.Server{
		Listen:         ":" + strconv.Itoa(c.Port),
		CertFile:       d.Cert(),
		KeyFile:        d.Key(),
		ECHKeyFile:     d.ECH(),
		InnerName:      c.InnerName,
		InnerCertFile:  d.Cert(),
		InnerKeyFile:   d.Key(),
		PulseListen:    pulseListen,
		PulseCertFile:  d.PulseCert(),
		PulseKeyFile:   d.PulseKey(),
		PulseObfs:      c.PulseObfs,
		PulseHopStart:  c.PulseHopStart,
		PulseHopEnd:    c.PulseHopEnd,
		Tokens:         []string{c.Token},
		Network:        map[string]string{"ipv4": "tcp4", "ipv6": "tcp6"}[c.Inbound],
		OutboundIP:     "ipv4",
		BandwidthLimit: c.BandwidthLimit,
		MaxConnections: 2048,
		DNSCacheTTL:    300,
	}
	if c.IsRealityEnabled() {
		srv.RealityUUID = c.RealityUUID
		srv.RealityPrivateKey = c.RealityPrivateKey
		srv.RealityShortID = c.RealityShortID
		srv.RealityDest = net.JoinHostPort(c.RealitySNI, "443")
		srv.RealityNames = []string{c.RealitySNI}
	}
	return srv
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
