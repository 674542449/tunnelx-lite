package mobile

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/674542449/tunnelx-lite/internal/config"
	"github.com/674542449/tunnelx-lite/internal/pki"
	"github.com/674542449/tunnelx-lite/internal/pulse"
	"github.com/674542449/tunnelx-lite/internal/share"
)

func makeTestLink(t *testing.T, name string) string {
	t.Helper()
	certPEM, _, err := pki.SelfSigned([]string{"edge.txlite.invalid", "gw.txlite.invalid"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ech, _, err := pki.ECH("gw.txlite.invalid")
	if err != nil {
		t.Fatal(err)
	}
	list := binary.BigEndian.AppendUint16(nil, uint16(len(ech.Config)))
	list = append(list, ech.Config...)
	tok := make([]byte, 32)
	rand.Read(tok)
	l := share.Link{
		Name:       name,
		Host:       "203.0.113.10",
		Port:       443,
		Token:      hex.EncodeToString(tok),
		ServerName: "edge.txlite.invalid",
		ECHConfig:  base64.StdEncoding.EncodeToString(list),
		CertPin:    config.CertPin(cert),
	}
	return l.String()
}

func mustCall(t *testing.T, svc *Service, action string, req any) map[string]any {
	t.Helper()
	var payload []byte
	if req != nil {
		payload, _ = json.Marshal(req)
	}
	raw := svc.Call(action, payload)
	var resp struct {
		OK    bool            `json:"ok"`
		Data  json.RawMessage `json:"data"`
		Error string          `json:"error"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("%s invalid json %q: %v", action, string(raw), err)
	}
	if !resp.OK {
		t.Fatalf("%s failed: %s", action, resp.Error)
	}
	var out map[string]any
	_ = json.Unmarshal(resp.Data, &out)
	return out
}

func TestMobileCoreRPCFlow(t *testing.T) {
	var svc Service
	if err := svc.Init(t.TempDir(), "127.0.0.1:0", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	// Import link with emoji name (verifying full UTF-8 fidelity).
	link := makeTestLink(t, "🇭🇰 香港测试节点")
	imp := mustCall(t, &svc, "import", map[string]string{"text": link})
	if int(imp["added"].(float64)) != 1 {
		t.Fatalf("expected added=1, got %v", imp)
	}

	rawServers := svc.Call("servers", nil)
	var srvResp struct {
		OK   bool `json:"ok"`
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rawServers, &srvResp); err != nil || !srvResp.OK || len(srvResp.Data) != 1 {
		t.Fatalf("servers failed: %s", string(rawServers))
	}
	id := srvResp.Data[0].ID
	if srvResp.Data[0].Name != "🇭🇰 香港测试节点" {
		t.Fatalf("emoji name corrupted: %q", srvResp.Data[0].Name)
	}

	mustCall(t, &svc, "rename", map[string]string{"id": id, "name": "🇯🇵 东京高速"})
	mustCall(t, &svc, "save_mode", map[string]string{"mode": "global", "direct_domains": "corp.example.com"})
	mustCall(t, &svc, "save_direct_presets", map[string]any{"presets": []string{"netease", "tencent"}})
	mustCall(t, &svc, "save_dns", map[string]any{"enabled": true, "domestic": "https://223.5.5.5/dns-query", "remote": "1.1.1.1:53"})
	mustCall(t, &svc, "save_transport", map[string]string{"transport": "tcp"})

	st := mustCall(t, &svc, "status", nil)
	if st["transport_preference"] != "tcp" {
		t.Fatalf("unexpected transport_preference: %v", st["transport_preference"])
	}
	if presets, ok := st["direct_presets"].([]any); !ok || len(presets) != 2 {
		t.Fatalf("unexpected direct_presets: %v", st["direct_presets"])
	}

	sh := mustCall(t, &svc, "share_link", map[string]string{"id": id})
	if sh["link"] == "" {
		t.Fatal("empty share link")
	}

	// Import TXPulse link alongside existing server (same host/port allowed with distinct protocol).
	certPEM, _, err := pki.SelfSigned([]string{"pulse-mobile.local"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(certPEM)
	pCert, _ := x509.ParseCertificate(blk.Bytes)
	tok := make([]byte, 32)
	_, _ = rand.Read(tok)
	pLink := share.Link{
		Protocol: share.PulseScheme,
		Name:     "🚀 新加坡 TXPulse",
		Host:     "203.0.113.10",
		Port:     28443,
		Token:    base64.RawURLEncoding.EncodeToString(tok),
		CertPin:  config.CertPin(pCert),
		ObfsKey:  pulse.GenerateObfsKey(),
		HopStart: 29000,
		HopEnd:   29031,
	}
	impP := mustCall(t, &svc, "import", map[string]string{"text": pLink.String()})
	if int(impP["added"].(float64)) != 1 {
		t.Fatalf("expected txpulse added=1, got %v", impP)
	}
	rawServers2 := svc.Call("servers", nil)
	var srvResp2 struct {
		OK   bool `json:"ok"`
		Data []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Protocol string `json:"protocol"`
			Hop      string `json:"hop"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rawServers2, &srvResp2); err != nil || !srvResp2.OK || len(srvResp2.Data) != 2 {
		t.Fatalf("servers after txpulse import failed: %s", string(rawServers2))
	}
	if srvResp2.Data[1].Protocol != "txpulse" || srvResp2.Data[1].Hop != "29000-29031" {
		t.Fatalf("unexpected txpulse server view: %+v", srvResp2.Data[1])
	}

	mustCall(t, &svc, "remove", map[string]string{"id": id})
}
