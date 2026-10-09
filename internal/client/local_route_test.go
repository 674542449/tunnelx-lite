package client

import (
	"context"
	"testing"
)

func TestGlobalModeSendsLocalTargetsDirect(t *testing.T) {
	p := &Proxy{}
	for target, direct := range map[string]bool{"192.168.1.1:80": true, "10.0.0.5:445": true, "172.20.1.1:22": true, "127.0.0.1:631": true, "localhost:8080": true, "169.254.1.1:80": true, "[fe80::1]:80": true, "8.8.8.8:443": false, "example.com:443": false, "[2001:db8::1]:443": false} {
		if got := p.route(context.Background(), target).Direct; got != direct {
			t.Errorf("%s: direct=%v, want %v", target, got, direct)
		}
	}
}
