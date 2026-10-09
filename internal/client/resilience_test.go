package client

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/674542449/tunnelx-lite/internal/config"
	"golang.org/x/net/dns/dnsmessage"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestDNSAdaptiveFailoverAndRecovery(t *testing.T) {
	p := &Proxy{dnsSlots: make(chan struct{}, 32)}
	var calls []int
	working := 2
	resolver := func(ctx context.Context, index int, q []byte) ([]byte, error) {
		calls = append(calls, index)
		if index != working {
			return nil, errors.New("simulated resolver outage")
		}
		h, question, _ := dnsQuestion(q)
		return dnsAnswer(h, question, dnsmessage.RCodeSuccess), nil
	}
	query := testDNSQuery(t, dnsmessage.TypeA)
	var result dnsmessage.Message
	if result.Unpack(p.exchangeDNSWith(context.Background(), query, resolver)) != nil || result.RCode != 0 || !reflect.DeepEqual(calls, []int{0, 1, 2}) {
		t.Fatal(result, calls)
	}
	calls = nil
	p.exchangeDNSWith(context.Background(), query, resolver)
	if !reflect.DeepEqual(calls, []int{2}) {
		t.Fatal("failed resolvers were retried before last good one", calls)
	}
	working = 0
	calls = nil
	p.exchangeDNSWith(context.Background(), query, resolver)
	if !reflect.DeepEqual(calls, []int{2, 3, 0}) || p.DNSRoute() != "tcp_cloudflare" {
		t.Fatal("resolver recovery failed", calls)
	}
	working = -1
	result.Unpack(p.exchangeDNSWith(context.Background(), query, resolver))
	if result.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal(result)
	}
}
func TestDNSRejectsMismatchedResponses(t *testing.T) {
	p := &Proxy{dnsSlots: make(chan struct{}, 32)}
	query := testDNSQuery(t, dnsmessage.TypeA)
	reply := p.exchangeDNSWith(context.Background(), query, func(ctx context.Context, index int, q []byte) ([]byte, error) {
		h, question, _ := dnsQuestion(q)
		h.ID++
		return dnsAnswer(h, question, 0), nil
	})
	var result dnsmessage.Message
	result.Unpack(reply)
	if result.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("wrong request response accepted")
	}
}
func TestIPv6RuntimeFailureAndStableRecovery(t *testing.T) {
	p := &Proxy{dnsSlots: make(chan struct{}, 32)}
	p.TUNIPv6.Store(true)
	if !p.ObserveIPv6(false) || p.TUNIPv6.Load() {
		t.Fatal("failed IPv6 stayed enabled")
	}
	calls := 0
	resolve := func(ctx context.Context, index int, q []byte) ([]byte, error) {
		calls++
		h, question, _ := dnsQuestion(q)
		return dnsAnswer(h, question, 0), nil
	}
	p.exchangeDNSWith(context.Background(), testDNSQuery(t, dnsmessage.TypeAAAA), resolve)
	if calls != 0 {
		t.Fatal("unusable AAAA query was sent upstream")
	}
	if p.ObserveIPv6(true) || p.TUNIPv6.Load() {
		t.Fatal("one successful probe prematurely enabled IPv6")
	}
	p.ObserveIPv6(false)
	p.ObserveIPv6(true)
	if !p.ObserveIPv6(true) || !p.TUNIPv6.Load() {
		t.Fatal("stable recovery not applied")
	}
	p.exchangeDNSWith(context.Background(), testDNSQuery(t, dnsmessage.TypeAAAA), resolve)
	if calls != 1 {
		t.Fatal("AAAA resolution not restored")
	}
}

// Explicit opt-in: private fixture supplied by the deployment acceptance runner.
func TestLiveNetworkHealthAndDoH(t *testing.T) {
	path := os.Getenv("TUNNELX_LIVE_CLIENT_CONFIG")
	if path == "" {
		t.Skip("requires isolated beta fixture")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("private fixture unavailable")
	}
	var cfg config.Client
	if json.Unmarshal(data, &cfg) != nil {
		t.Fatal("invalid fixture")
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatal("fixture initialization failed")
	}
	p := NewProxy(m)
	defer p.Close()
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		reply, err := p.queryDoH(ctx, i, healthQuery())
		cancel()
		var msg dnsmessage.Message
		if err != nil || msg.Unpack(reply) != nil || msg.RCode != 0 || len(msg.Answers) == 0 {
			t.Fatalf("DoH provider %d failed", i)
		}
	}
	p.dnsPreferred.Store(2)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if kind := p.CheckDNS(ctx); kind != "" {
		t.Fatal(kind)
	}
	if kind := p.CheckEgress(ctx); kind != "" {
		t.Fatal(kind)
	}
}
