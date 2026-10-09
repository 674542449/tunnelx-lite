package lite

import "testing"

func TestInboundFamilyShapesListenerAndLinks(t *testing.T) {
	c := Config{Name: "n", Port: 443, PanelPort: 8443, PanelPath: "abcdefghij", Token: NewToken(), InnerName: "a.invalid"}
	id := Identity{ECHConfig: "AAAA", CertPin: "pin"}
	for inbound, want := range map[string]struct {
		network string
		labels  string
	}{
		"":     {"", "IPv4,IPv6,"},
		"ipv4": {"tcp4", "IPv4,"},
		"ipv6": {"tcp6", "IPv6,"},
	} {
		c.Inbound = inbound
		if e := c.Validate(); e != nil {
			t.Fatal(inbound, e)
		}
		if got := c.Server(Dir(t.TempDir())).Network; got != want.network {
			t.Errorf("%q: listener network %q, want %q", inbound, got, want.network)
		}
		labels := ""
		for _, l := range Links(c, id, "203.0.113.5", "2001:db8::5") {
			labels += l.Label + ","
		}
		if labels != want.labels {
			t.Errorf("%q: links %q, want %q", inbound, labels, want.labels)
		}
	}
	c.Inbound = "both"
	if c.Validate() == nil {
		t.Fatal("unknown inbound accepted")
	}
}
