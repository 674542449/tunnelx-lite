package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const Version = "1"

type Client struct {
	ServerName     string `json:"server_name"`
	ServerIP       string `json:"server_ip"`
	Port           int    `json:"port"`
	Token          string `json:"token"`
	Transport      string `json:"transport"`
	Privacy        string `json:"privacy"`
	ECHConfig      string `json:"ech_config,omitempty"`
	CAFile         string `json:"ca_file,omitempty"`
	CertPin        string `json:"cert_pin,omitempty"`
	SOCKSListen    string `json:"socks_listen"`
	HTTPListen     string `json:"http_listen"`
	WebListen      string `json:"web_listen"`
	MaxConnections int    `json:"max_connections"`
	ConnectTimeout int    `json:"connect_timeout_seconds"`
	H2Connections  int    `json:"h2_connections,omitempty"`
	H2ReadIdle     int    `json:"h2_read_idle_seconds,omitempty"`
	H2PingTimeout  int    `json:"h2_ping_timeout_seconds,omitempty"`
	H2MaxAge       int    `json:"h2_max_age_seconds,omitempty"`
	H2RetryNew     bool   `json:"h2_retry_new_connection,omitempty"`
	DeviceID       string `json:"device_id,omitempty"`
}
type Server struct {
	ManagedOnly           bool                `json:"managed_only,omitempty"`
	Listen                string              `json:"listen"`
	CertFile              string              `json:"cert_file"`
	KeyFile               string              `json:"key_file"`
	ECHKeyFile            string              `json:"ech_key_file,omitempty"`
	InnerName             string              `json:"inner_name,omitempty"`
	InnerCertFile         string              `json:"inner_cert_file,omitempty"`
	InnerKeyFile          string              `json:"inner_key_file,omitempty"`
	Tokens                []string            `json:"tokens"`
	PublicDir             string              `json:"public_dir,omitempty"`
	AllowedPrivateTargets []string            `json:"allowed_private_targets,omitempty"`
	PreferredTargetIPs    map[string][]string `json:"preferred_target_ips,omitempty"`
	MaxConnections        int                 `json:"max_connections"`
	DialTimeout           int                 `json:"dial_timeout_seconds"`
	IdleTimeout           int                 `json:"idle_timeout_seconds"`
	MaxLifetime           int                 `json:"max_lifetime_seconds,omitempty"`
	BandwidthLimit        int64               `json:"bandwidth_limit_bytes,omitempty"`
	DNSCacheTTL           int                 `json:"dns_cache_ttl_seconds,omitempty"`
	AccessLog             string              `json:"access_log,omitempty"`
	OutboundIP            string              `json:"outbound_ip,omitempty"`
	Network               string              `json:"network,omitempty"` // "", "tcp4" or "tcp6": inbound address family
	QUIC                  bool                `json:"quic,omitempty"`    // also serve QUIC on the UDP port of the same number
}
type ECHKey struct {
	Config     []byte `json:"config"`
	PrivateKey []byte `json:"private_key"`
}

func Read(path string, dst any) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if e = d.Decode(dst); e != nil {
		return fmt.Errorf("configuration: %w", e)
	}
	if e = d.Decode(new(any)); e != io.EOF {
		return errors.New("configuration must contain one JSON object")
	}
	return nil
}
func Resolve(base, name string) string {
	if name == "" || filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(filepath.Dir(base), name)
}
func TokenValid(t string) bool {
	b, e := base64.RawURLEncoding.DecodeString(t)
	return e == nil && len(b) >= 32 && len(b) <= 64
}
func (c *Client) Validate() error {
	if c.DeviceID != "" {
		b, e := hex.DecodeString(c.DeviceID)
		if e != nil || len(b) != 16 {
			return errors.New("device_id must be 16-byte hex")
		}
	}
	if c.ServerName == "" || strings.ContainsAny(c.ServerName, " /\\:@") {
		return errors.New("server_name must be a DNS name")
	}
	if net.ParseIP(c.ServerIP) == nil {
		return errors.New("server_ip must be a literal bootstrap IP; no local DNS lookup")
	}
	if c.Port < 1 || c.Port > 65535 || !TokenValid(c.Token) {
		return errors.New("invalid server port or token")
	}
	if c.Transport == "" {
		c.Transport = "h2"
	}
	// "h2" is HTTP/2 over TCP only; "quic" is QUIC over UDP only; "auto"
	// prefers QUIC and falls back to HTTP/2 while UDP does not get through.
	if c.Transport != "h2" && c.Transport != "quic" && c.Transport != "auto" {
		return errors.New("transport must be h2, quic or auto")
	}
	if c.Privacy == "" {
		c.Privacy = "normal"
	}
	if c.Privacy != "normal" && c.Privacy != "strict" {
		return errors.New("privacy must be normal or strict")
	}
	if c.Privacy == "strict" && c.ECHConfig == "" {
		return errors.New("strict privacy requires an ECH configuration")
	}
	if c.SOCKSListen == "" {
		c.SOCKSListen = "127.0.0.1:1080"
	}
	if c.HTTPListen == "" {
		c.HTTPListen = "127.0.0.1:8088"
	}
	if c.WebListen == "" {
		c.WebListen = "127.0.0.1:9080"
	}
	seen := map[string]bool{}
	for _, a := range []string{c.SOCKSListen, c.HTTPListen, c.WebListen} {
		h, _, e := net.SplitHostPort(a)
		if e != nil || net.ParseIP(h) == nil || !net.ParseIP(h).IsLoopback() {
			return errors.New("local listeners must use literal loopback addresses")
		}
		if seen[a] {
			return errors.New("local listeners must have different ports")
		}
		seen[a] = true
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = 128
	}
	if c.MaxConnections < 1 || c.MaxConnections > 1024 {
		return errors.New("max_connections must be 1..1024")
	}
	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = 5
	}
	if c.ConnectTimeout < 1 || c.ConnectTimeout > 60 {
		return errors.New("connect timeout must be 1..60 seconds")
	}
	if c.H2Connections == 0 {
		c.H2Connections = 1
	}
	if c.H2ReadIdle == 0 {
		c.H2ReadIdle = 25
	}
	if c.H2PingTimeout == 0 {
		c.H2PingTimeout = 5
	}
	if c.H2Connections < 1 || c.H2Connections > 8 || c.H2ReadIdle < 1 || c.H2ReadIdle > 120 || c.H2PingTimeout < 1 || c.H2PingTimeout > 30 || (c.H2MaxAge != 0 && (c.H2MaxAge < 10 || c.H2MaxAge > 3600)) {
		return errors.New("invalid H2 pool, health timeout or maximum age")
	}
	return nil
}
func (s *Server) Validate() error {
	if s.Listen == "" {
		s.Listen = ":8443"
	}
	if _, _, e := net.SplitHostPort(s.Listen); e != nil {
		return e
	}
	if s.CertFile == "" || s.KeyFile == "" || !s.ManagedOnly && len(s.Tokens) == 0 || len(s.Tokens) > 32 || s.ManagedOnly && len(s.Tokens) > 0 {
		return errors.New("server requires certificate, key and 1..32 tokens")
	}
	for _, t := range s.Tokens {
		if !TokenValid(t) {
			return errors.New("invalid server token")
		}
	}
	if s.MaxConnections == 0 {
		s.MaxConnections = 256
	}
	if s.MaxConnections < 1 || s.MaxConnections > 4096 {
		return errors.New("invalid max_connections")
	}
	if s.DialTimeout == 0 {
		s.DialTimeout = 10
	}
	if s.IdleTimeout == 0 {
		s.IdleTimeout = 120
	}
	if s.DialTimeout < 1 || s.DialTimeout > 60 || s.IdleTimeout < 10 || s.IdleTimeout > 3600 {
		return errors.New("invalid server timeout")
	}
	if s.MaxLifetime != 0 && (s.MaxLifetime < 60 || s.MaxLifetime > 86400) {
		return errors.New("max_lifetime_seconds must be 0 or 60..86400")
	}
	if s.BandwidthLimit != 0 && (s.BandwidthLimit < 1024 || s.BandwidthLimit > 1<<30) {
		return errors.New("bandwidth_limit_bytes must be 0 or 1024..1073741824")
	}
	if s.Network != "" && s.Network != "tcp4" && s.Network != "tcp6" {
		return errors.New("network must be empty, tcp4 or tcp6")
	}
	switch s.OutboundIP {
	case "", "prefer_ipv4", "prefer_ipv6", "ipv4", "ipv6":
	default:
		return errors.New("outbound_ip must be empty, prefer_ipv4, prefer_ipv6, ipv4 or ipv6")
	}
	if s.DNSCacheTTL != 0 && (s.DNSCacheTTL < 10 || s.DNSCacheTTL > 3600) {
		return errors.New("dns_cache_ttl_seconds must be 0 or 10..3600")
	}
	if len(s.PreferredTargetIPs) > 128 {
		return errors.New("too many preferred target domains")
	}
	for host, ips := range s.PreferredTargetIPs {
		if host == "" || len(host) > 253 || host != strings.ToLower(strings.TrimSuffix(host, ".")) || strings.ContainsAny(host, " /\\:@*\t\r\n") || net.ParseIP(host) != nil || len(ips) < 1 || len(ips) > 8 {
			return errors.New("preferred_target_ips requires canonical exact domain names and 1..8 public IPs")
		}
		for _, address := range ips {
			ip := net.ParseIP(address)
			if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				return errors.New("preferred_target_ips must contain public IP literals")
			}
		}
	}
	return nil
}
func (c Client) TLS() (*tls.Config, error) {
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if c.CAFile != "" {
		b, e := os.ReadFile(c.CAFile)
		if e != nil {
			return nil, e
		}
		if !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("invalid CA PEM")
		}
	}
	t := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: c.ServerName, RootCAs: roots, CurvePreferences: []tls.CurveID{tls.X25519}, ClientSessionCache: tls.NewLRUClientSessionCache(64)}
	if c.CertPin != "" {
		// A pinned self-signed server: trust exactly this public key, nothing from the system store.
		pin := c.CertPin
		check := func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || CertPin(cs.PeerCertificates[0]) != pin {
				return errors.New("server certificate does not match the pinned fingerprint")
			}
			now := time.Now()
			if leaf := cs.PeerCertificates[0]; now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
				return errors.New("pinned server certificate is not currently valid")
			}
			return nil
		}
		t.InsecureSkipVerify = true
		t.VerifyConnection = check
		t.EncryptedClientHelloRejectionVerify = check
	}
	if c.Privacy == "strict" {
		b, e := base64.StdEncoding.DecodeString(c.ECHConfig)
		if e != nil {
			return nil, errors.New("invalid ECH base64")
		}
		t.EncryptedClientHelloConfigList = b
	}
	return t, nil
}
func (s Server) TLS() (*tls.Config, error) {
	cert, e := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
	if e != nil {
		return nil, e
	}
	t := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, CurvePreferences: []tls.CurveID{tls.X25519}}
	// Certificate files are refreshed by the deployment timer; reload on each handshake.
	t.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		certFile, keyFile := s.CertFile, s.KeyFile
		if s.InnerName != "" && hello.ServerName == s.InnerName {
			certFile, keyFile = s.InnerCertFile, s.InnerKeyFile
		}
		c, e := tls.LoadX509KeyPair(certFile, keyFile)
		return &c, e
	}
	if s.ECHKeyFile != "" {
		var key ECHKey
		if e := Read(s.ECHKeyFile, &key); e != nil {
			return nil, e
		}
		t.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{{Config: key.Config, PrivateKey: key.PrivateKey, SendAsRetry: true}}
	}
	return t, nil
}

type Auth struct{ hashes [][32]byte }

func NewAuth(tokens []string) *Auth {
	a := &Auth{}
	for _, t := range tokens {
		a.hashes = append(a.hashes, sha256.Sum256([]byte("Bearer "+t)))
	}
	return a
}
func (a *Auth) Valid(headers []string) bool {
	v := ""
	if len(headers) == 1 && len(headers[0]) <= 128 {
		v = headers[0]
	}
	h := sha256.Sum256([]byte(v))
	ok := 0
	for _, s := range a.hashes {
		ok |= subtle.ConstantTimeCompare(h[:], s[:])
	}
	return ok == 1
}

// CertPin is the share-link fingerprint: unpadded base64url SHA-256 of the public key.
func CertPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func (c Client) Timeout() time.Duration { return time.Duration(c.ConnectTimeout) * time.Second }
