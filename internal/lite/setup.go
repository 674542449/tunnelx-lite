package lite

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"

	"github.com/674542449/tunnelx-lite/internal/config"
	"github.com/674542449/tunnelx-lite/internal/pki"
)

// Init creates a complete server identity. It refuses to overwrite an
// existing one, because that would invalidate every share link in use.
func Init(d Dir, name string, port, panelPort int) (Config, string, error) {
	if _, e := os.Stat(d.Config()); e == nil {
		return Config{}, "", errors.New("已存在配置，拒绝覆盖：" + d.Config())
	}
	if e := os.MkdirAll(string(d), 0700); e != nil {
		return Config{}, "", e
	}
	id := hex.EncodeToString([]byte(randomToken(6)))[:12]
	c := Config{Name: name, Port: port, PanelPort: panelPort, PanelPath: randomToken(9), Token: NewToken(), InnerName: "edge-" + id + ".txlite.invalid", PublicName: "gw-" + id + ".txlite.invalid"}
	password := randomToken(12)
	hash, e := HashPassword(password)
	if e != nil {
		return c, "", e
	}
	c.PanelHash = hash
	if e = c.Validate(); e != nil {
		return c, "", e
	}
	cert, key, e := pki.SelfSigned([]string{c.InnerName, c.PublicName}, 20)
	if e != nil {
		return c, "", e
	}
	ech, _, e := pki.ECH(c.PublicName)
	if e != nil {
		return c, "", e
	}
	echJSON, _ := json.Marshal(ech)
	for path, data := range map[string][]byte{d.Cert(): cert, d.Key(): key, d.ECH(): echJSON} {
		if e = writeFile(path, data); e != nil {
			return c, "", e
		}
	}
	return c, password, Save(d, c)
}

// Identity is what every share link of this server carries besides the host.
type Identity struct {
	ECHConfig string // standard base64 ECHConfigList
	CertPin   string
}

func LoadIdentity(d Dir) (Identity, error) {
	b, e := os.ReadFile(d.Cert())
	if e != nil {
		return Identity{}, e
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return Identity{}, errors.New("证书文件无效")
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return Identity{}, e
	}
	var key config.ECHKey
	if e = config.Read(d.ECH(), &key); e != nil {
		return Identity{}, e
	}
	list := binary.BigEndian.AppendUint16(nil, uint16(len(key.Config)))
	list = append(list, key.Config...)
	return Identity{ECHConfig: base64.StdEncoding.EncodeToString(list), CertPin: config.CertPin(cert)}, nil
}
