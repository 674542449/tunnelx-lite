package server

import (
	"net"
	"testing"
)

func TestOutboundOrder(t *testing.T) {
	ips := []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("1.1.1.1"), net.ParseIP("2001:db8::2"), net.ParseIP("8.8.8.8")}
	str := func(v []net.IP) (s string) {
		for _, ip := range v {
			s += ip.String() + " "
		}
		return
	}
	for policy, want := range map[string]string{
		"":            "2001:db8::1 1.1.1.1 2001:db8::2 8.8.8.8 ",
		"prefer_ipv4": "1.1.1.1 8.8.8.8 2001:db8::1 2001:db8::2 ",
		"prefer_ipv6": "2001:db8::1 2001:db8::2 1.1.1.1 8.8.8.8 ",
		"ipv4":        "1.1.1.1 8.8.8.8 ",
		"ipv6":        "2001:db8::1 2001:db8::2 ",
	} {
		if got := str(outboundOrder(append([]net.IP(nil), ips...), policy)); got != want {
			t.Errorf("%q: got %q want %q", policy, got, want)
		}
	}
	if len(outboundOrder([]net.IP{net.ParseIP("1.1.1.1")}, "ipv6")) != 0 {
		t.Fatal("ipv6-only kept an IPv4 target")
	}
}
