package lite

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"time"

	"github.com/674542449/tunnelx-lite/internal/config"
	"github.com/674542449/tunnelx-lite/internal/pki"
	"github.com/674542449/tunnelx-lite/internal/pulse"
	"github.com/674542449/tunnelx-lite/internal/vless"
)

func pickUDPPort(avoid ...int) int {
	banned := func(p int) bool {
		for _, a := range avoid {
			if p == a {
				return true
			}
		}
		return false
	}
	for i := 0; i < 60; i++ {
		c, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
		if err != nil {
			break
		}
		p := c.LocalAddr().(*net.UDPAddr).Port
		_ = c.Close()
		if p >= 10000 && p <= 60000 && !banned(p) {
			return p
		}
	}
	p := 25000 + int(time.Now().UnixNano()%25000)
	for banned(p) {
		p++
	}
	return p
}

// Init creates a complete server identity (TCP Vision + TXPulse UDP with self-signed certs).
// It refuses to overwrite an existing one, because that would invalidate every share link in use.
func Init(d Dir, name string, port, panelPort int) (Config, string, error) {
	return InitFull(d, name, port, 0, panelPort, 0, 0)
}

// InitFull initializes a server with explicit TCP port, TXPulse UDP port, panel port and optional hop range.
func InitFull(d Dir, name string, port, pulsePort, panelPort, hopStart, hopEnd int) (Config, string, error) {
	if _, e := os.Stat(d.Config()); e == nil {
		return Config{}, "", errors.New("已存在配置，拒绝覆盖：" + d.Config())
	}
	if e := os.MkdirAll(string(d), 0700); e != nil {
		return Config{}, "", e
	}
	if pulsePort == 0 {
		pulsePort = pickUDPPort(port, panelPort)
	}
	realityPriv, _, e := vless.GenerateRealityKeyPair()
	if e != nil {
		return Config{}, "", e
	}
	id := hex.EncodeToString([]byte(randomToken(6)))[:12]
	c := Config{
		Name:              name,
		Port:              port,
		PulsePort:         pulsePort,
		PulseObfs:         pulse.GenerateObfsKey(),
		PulseHopStart:     hopStart,
		PulseHopEnd:       hopEnd,
		RealityEnabled:    boolPtr(true),
		RealityUUID:       vless.GenerateUUID(),
		RealityPrivateKey: realityPriv,
		RealityShortID:    vless.GenerateShortID(),
		RealitySNI:        vless.DefaultRealitySNI,
		PanelPort:         panelPort,
		PanelPath:         randomToken(9),
		Token:             NewToken(),
		InnerName:         "edge-" + id + ".txlite.invalid",
		PublicName:        "gw-" + id + ".txlite.invalid",
		OutboundIP:        "ipv4",
	}
	password := randomToken(12)
	hash, e := HashPassword(password)
	if e != nil {
		return c, "", e
	}
	c.PanelHash = hash
	if e = c.Validate(); e != nil {
		return c, "", e
	}
	// TCP Vision / Panel 自签证书
	cert, key, e := pki.SelfSigned([]string{c.InnerName, c.PublicName}, 20)
	if e != nil {
		return c, "", e
	}
	// TXPulse 独立 20 年自签 ECDSA P-256 证书（免域名，客户端强制 CertPin 公钥固定，零 MITM）
	pulseCert, pulseKey, e := pki.SelfSigned([]string{"pulse-" + id + ".local"}, 20)
	if e != nil {
		return c, "", e
	}
	ech, _, e := pki.ECH(c.PublicName)
	if e != nil {
		return c, "", e
	}
	echJSON, _ := json.Marshal(ech)
	for path, data := range map[string][]byte{
		d.Cert():      cert,
		d.Key():       key,
		d.PulseCert(): pulseCert,
		d.PulseKey():  pulseKey,
		d.ECH():       echJSON,
	} {
		if e = writeFile(path, data); e != nil {
			return c, "", e
		}
	}
	return c, password, Save(d, c)
}

// EnsurePulseIdentity 为从旧版升级的节点自动补齐 TXPulse 独立自签证书、混淆种子与 UDP 端口。
func EnsurePulseIdentity(d Dir, c *Config) (bool, error) {
	changed := false
	if c.PulsePort == 0 {
		// 旧节点升级时复用原代理端口号的 UDP（与 TCP 不冲突，方便沿用现有安全组）
		c.PulsePort = c.Port
		changed = true
	}
	if c.PulseObfs == "" {
		c.PulseObfs = pulse.GenerateObfsKey()
		changed = true
	}
	_, errC := os.Stat(d.PulseCert())
	_, errK := os.Stat(d.PulseKey())
	if errC != nil || errK != nil {
		id := hex.EncodeToString([]byte(randomToken(6)))[:12]
		pulseCert, pulseKey, err := pki.SelfSigned([]string{"pulse-" + id + ".local"}, 20)
		if err != nil {
			return false, err
		}
		if err := writeFile(d.PulseCert(), pulseCert); err != nil {
			return false, err
		}
		if err := writeFile(d.PulseKey(), pulseKey); err != nil {
			return false, err
		}
	}
	if changed {
		if err := Save(d, *c); err != nil {
			return false, err
		}
	}
	return changed, nil
}

// EnsureRealityIdentity 为从旧版升级的节点自动补齐 VLESS + REALITY 密钥与 UUID（复用现有 TCP 端口，免开新端口）。
func EnsureRealityIdentity(d Dir, c *Config) (bool, error) {
	changed := false
	if c.RealityEnabled == nil {
		c.RealityEnabled = boolPtr(true)
		changed = true
	}
	if c.RealityUUID == "" {
		c.RealityUUID = vless.GenerateUUID()
		changed = true
	}
	if c.RealityPrivateKey == "" {
		priv, _, err := vless.GenerateRealityKeyPair()
		if err != nil {
			return false, err
		}
		c.RealityPrivateKey = priv
		changed = true
	}
	if c.RealityShortID == "" {
		c.RealityShortID = vless.GenerateShortID()
		changed = true
	}
	if c.RealitySNI == "" {
		c.RealitySNI = vless.DefaultRealitySNI
		changed = true
	}
	if changed {
		if err := Save(d, *c); err != nil {
			return false, err
		}
	}
	return changed, nil
}

// Identity is what every share link of this server carries besides the host.
type Identity struct {
	ECHConfig    string // standard base64 ECHConfigList
	CertPin      string
	PulseCertPin string
}

func readCertPin(path string) (string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return "", errors.New("证书文件无效")
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return "", e
	}
	return config.CertPin(cert), nil
}

func LoadIdentity(d Dir) (Identity, error) {
	certPin, e := readCertPin(d.Cert())
	if e != nil {
		return Identity{}, e
	}
	var key config.ECHKey
	if e = config.Read(d.ECH(), &key); e != nil {
		return Identity{}, e
	}
	list := binary.BigEndian.AppendUint16(nil, uint16(len(key.Config)))
	list = append(list, key.Config...)

	pulsePin, _ := readCertPin(d.PulseCert())
	return Identity{
		ECHConfig:    base64.StdEncoding.EncodeToString(list),
		CertPin:      certPin,
		PulseCertPin: pulsePin,
	}, nil
}
