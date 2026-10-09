package server

import (
	"context"
	"github.com/674542449/tunnelx-lite/internal/config"
	"net"
	"testing"
)

func TestPreferredTargetIPsRemainDNSBoundAndFiltered(t *testing.T) {
	s := &Server{Config: config.Server{PreferredTargetIPs: map[string][]string{"download.test": {"1.1.1.1", "9.9.9.9"}}}}
	s.Resolver = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("127.0.0.1"), net.ParseIP("1.1.1.1")}, nil
	}
	addresses, status := s.resolve(context.Background(), "Download.Test.", "Download.Test.:443")
	if status != 0 || len(addresses) != 2 || addresses[0].String() != "1.1.1.1" || addresses[1].String() != "8.8.8.8" {
		t.Fatal("preference failed to retain only current public DNS answers", addresses, status)
	}
	addresses, status = s.resolve(context.Background(), "other.test", "other.test:443")
	if status != 0 || addresses[0].String() != "8.8.8.8" {
		t.Fatal("preference changed an unrelated domain", addresses, status)
	}
	s.Resolver = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}
	addresses, status = s.resolve(context.Background(), "download.test", "download.test:443")
	if status != 0 || len(addresses) != 1 || addresses[0].String() != "8.8.8.8" {
		t.Fatal("missing preferred IP must use current DNS answer", addresses, status)
	}
	s.Resolver = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	if _, status = s.resolve(context.Background(), "download.test", "download.test:443"); status != 403 {
		t.Fatal("preference bypassed private-target denial", status)
	}
}
