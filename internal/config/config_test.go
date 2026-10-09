package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestRejectUnsafeClientConfiguration(t *testing.T) {
	base := Client{ServerName: "proxy.test", ServerIP: "127.0.0.1", Port: 8443, Token: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}
	for _, mutate := range []func(*Client){
		func(c *Client) { c.Privacy = "strict" },
		func(c *Client) { c.ServerIP = "bootstrap.example" },
		func(c *Client) { c.HTTPListen = "0.0.0.0:8088" },
		func(c *Client) { c.Token = "short" },
		func(c *Client) { c.H2Connections = 9 },
		func(c *Client) { c.H2PingTimeout = -1 },
		func(c *Client) { c.H2ReadIdle = 121 },
		func(c *Client) { c.H2MaxAge = 1 },
		func(c *Client) { c.Transport = "h3" },
		func(c *Client) { c.Transport = "auto" },
	} {
		c := base
		mutate(&c)
		if c.Validate() == nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
	for _, input := range []string{`{"unexpected":1}`, `{} {}`} {
		p := filepath.Join(t.TempDir(), "client.json")
		os.WriteFile(p, []byte(input), 0600)
		if Read(p, new(Client)) == nil {
			t.Fatal("ambiguous configuration accepted")
		}
	}
}

func TestRejectUnsafeTargetPreferences(t *testing.T) {
	base := Server{CertFile: "cert.pem", KeyFile: "key.pem", Tokens: []string{base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}}
	for _, rule := range []map[string][]string{
		{"download.test": {"127.0.0.1"}},
		{"download.test": {"10.0.0.1"}},
		{"download.test": {"not-an-ip"}},
		{"*.test": {"1.1.1.1"}},
		{"Download.Test": {"1.1.1.1"}},
	} {
		c := base
		c.PreferredTargetIPs = rule
		if c.Validate() == nil {
			t.Fatal("unsafe or ambiguous preference accepted")
		}
	}
}
