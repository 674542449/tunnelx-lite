package client

import (
	"context"
	"encoding/binary"
	"github.com/674542449/tunnelx-lite/internal/config"
	"github.com/674542449/tunnelx-lite/internal/routing"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testDNSQuery(t *testing.T, kind dnsmessage.Type) []byte {
	t.Helper()
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("www.google.com."), Type: kind, Class: dnsmessage.ClassINET}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 4123, RecursionDesired: true})
	b.StartQuestions()
	b.Question(q)
	v, e := b.Finish()
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestTUNDNSUsesH2TCPAndFiltersUnreachableIPv6(t *testing.T) {
	var requests atomic.Int32
	cfg := poolServer(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "CONNECT" || r.Host != "1.1.1.1:53" {
			t.Errorf("unexpected DNS tunnel %s %s", r.Method, r.Host)
		}
		w.Header().Set("Tunnelx-Version", config.Version)
		w.WriteHeader(200)
		http.NewResponseController(w).Flush()
		length := make([]byte, 2)
		if _, e := io.ReadFull(r.Body, length); e != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(length))
		if _, e := io.ReadFull(r.Body, q); e != nil {
			return
		}
		h, question, e := dnsQuestion(q)
		if e != nil {
			t.Error(e)
			return
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
		b.StartQuestions()
		b.Question(question)
		b.StartAnswers()
		b.AResource(dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{142, 250, 1, 1}})
		answer, _ := b.Finish()
		w.Write(binary.BigEndian.AppendUint16(nil, uint16(len(answer))))
		w.Write(answer)
		http.NewResponseController(w).Flush()
		<-r.Context().Done()
	})
	m, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	p := NewProxy(m)
	p.TUN = true
	defer p.Close()
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeAAAA, 65, 64} {
		response := p.exchangeDNS(context.Background(), testDNSQuery(t, typ))
		var msg dnsmessage.Message
		if e = msg.Unpack(response); e != nil || msg.ID != 4123 || !msg.Response || msg.RCode != 0 || len(msg.Answers) != 0 {
			t.Fatal(msg, e)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("filtered questions reached upstream")
	}
	for _, udp := range []bool{true, false} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		q := testDNSQuery(t, dnsmessage.TypeA)
		var response []byte
		if udp {
			stream, e := p.openUDP(ctx, "223.5.5.5:53")
			if e != nil {
				t.Fatal(e)
			}
			if e = stream.Send(q); e != nil {
				t.Fatal(e)
			}
			response, e = stream.Receive(ctx)
			stream.Close()
			if e != nil {
				t.Fatal(e)
			}
		} else {
			stream, e := p.openTCP(ctx, "8.8.8.8:53")
			if e != nil {
				t.Fatal(e)
			}
			stream.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
			length := make([]byte, 2)
			if _, e = io.ReadFull(stream, length); e != nil {
				t.Fatal(e)
			}
			response = make([]byte, binary.BigEndian.Uint16(length))
			_, e = io.ReadFull(stream, response)
			stream.Close()
			if e != nil {
				t.Fatal(e)
			}
		}
		cancel()
		var msg dnsmessage.Message
		if e = msg.Unpack(response); e != nil || len(msg.Answers) != 1 || msg.ID != 4123 {
			t.Fatal(msg, e)
		}
	}
	if requests.Load() != 2 {
		t.Fatal("DNS exchange did not use H2 TCP", requests.Load())
	}
	before := time.Now()
	if _, e = p.openTCP(context.Background(), "[2404:6800:400b:c015::bc]:443"); e != errTUNIPv6Unavailable || time.Since(before) > 100*time.Millisecond {
		t.Fatal("IPv6 did not fail immediately", e)
	}
	if _, e = p.openUDP(context.Background(), "[2404:6800:400b:c015::bc]:443"); e != errTUNIPv6Unavailable {
		t.Fatal(e)
	}
}
func TestDNSMalformedAndCancellation(t *testing.T) {
	for _, packet := range [][]byte{nil, {1, 2, 3}, make([]byte, 12)} {
		if _, _, e := dnsQuestion(packet); e == nil {
			t.Fatal("malformed accepted")
		}
	}
	cfg := poolServer(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	m, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	p := NewProxy(m)
	defer p.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	answer := p.exchangeDNS(ctx, testDNSQuery(t, dnsmessage.TypeA))
	var msg dnsmessage.Message
	if e = msg.Unpack(answer); e != nil || msg.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal(msg, e)
	}
}

func TestTUNIPv6CapabilityRequiresBothEgressChecks(t *testing.T) {
	for _, working := range []bool{true, false} {
		t.Run(map[bool]string{true: "working", false: "unavailable"}[working], func(t *testing.T) {
			cfg := poolServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Tunnelx-Version", config.Version)
				if !working && r.Host == "[2001:4860:4860::8888]:443" {
					w.WriteHeader(502)
					return
				}
				w.WriteHeader(200)
				http.NewResponseController(w).Flush()
				<-r.Context().Done()
			})
			m, e := New(cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer m.Close()
			if m.ProbeTUNIPv6(context.Background()) != working {
				t.Fatal("incorrect capability")
			}
		})
	}
}

func makeQuery(t *testing.T, id uint16, name string, kind dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: kind, Class: dnsmessage.ClassINET})
	v, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func makeAReply(id uint16, name string, ip [4]byte) []byte {
	q := dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: true, RecursionDesired: true, RecursionAvailable: true})
	b.StartQuestions()
	b.Question(q)
	b.StartAnswers()
	b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: ip})
	v, _ := b.Finish()
	return v
}

func TestTUNDNSCaseInsensitiveAndSplitHorizonAndCache(t *testing.T) {
	var remoteCalls, directCalls atomic.Int32
	cfg := poolServer(t, func(w http.ResponseWriter, r *http.Request) {
		remoteCalls.Add(1)
		w.Header().Set("Tunnelx-Version", config.Version)
		w.WriteHeader(200)
		http.NewResponseController(w).Flush()
		length := make([]byte, 2)
		if _, e := io.ReadFull(r.Body, length); e != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(length))
		if _, e := io.ReadFull(r.Body, q); e != nil {
			return
		}
		h, _, _ := dnsQuestion(q)
		// Deliberately reply with lowercase name to verify case-insensitive question match.
		answer := makeAReply(h.ID, "www.google.com.", [4]byte{142, 250, 1, 2})
		w.Write(binary.BigEndian.AppendUint16(nil, uint16(len(answer))))
		w.Write(answer)
		http.NewResponseController(w).Flush()
		<-r.Context().Done()
	})
	m, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	p := NewProxy(m)
	p.TUN = true
	p.EnableDNSCache()
	defer p.Close()

	rules, err := routing.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	rt, err := routing.New(rules, "")
	if err != nil {
		t.Fatal(err)
	}
	p.SetRouter(rt)
	p.directDNSQuery = func(_ context.Context, _ string, query []byte) ([]byte, error) {
		directCalls.Add(1)
		h, q, err := dnsQuestion(query)
		if err != nil {
			return nil, err
		}
		return makeAReply(h.ID, q.Name.String(), [4]byte{110, 242, 68, 66}), nil
	}

	// Mixed-case foreign domain goes remote and is accepted despite lowercase reply.
	ans1 := p.exchangeDNS(context.Background(), makeQuery(t, 1001, "WwW.GoOgLe.CoM.", dnsmessage.TypeA))
	var msg dnsmessage.Message
	if err := msg.Unpack(ans1); err != nil || msg.RCode != dnsmessage.RCodeSuccess || msg.ID != 1001 || len(msg.Answers) != 1 {
		t.Fatalf("case-insensitive reply failed: %+v %v", msg, err)
	}
	// Second query with a different transaction ID hits DNS cache.
	ans2 := p.exchangeDNS(context.Background(), makeQuery(t, 2002, "www.google.com.", dnsmessage.TypeA))
	if err := msg.Unpack(ans2); err != nil || msg.ID != 2002 || remoteCalls.Load() != 1 {
		t.Fatalf("cache miss: id=%d remoteCalls=%d", msg.ID, remoteCalls.Load())
	}
	if rev := p.lookupReverseDNS(netip.MustParseAddr("142.250.1.2")); rev != "www.google.com" {
		t.Fatalf("reverse DNS mismatch: %q", rev)
	}

	// Domestic CN domain uses direct domestic DNS in Bypass CN mode.
	cnAns := p.exchangeDNS(context.Background(), makeQuery(t, 3003, "www.baidu.com.", dnsmessage.TypeA))
	if err := msg.Unpack(cnAns); err != nil || msg.RCode != dnsmessage.RCodeSuccess || directCalls.Load() != 1 || remoteCalls.Load() != 1 {
		t.Fatalf("domestic split-horizon failed: direct=%d remote=%d err=%v", directCalls.Load(), remoteCalls.Load(), err)
	}
	if rev := p.lookupReverseDNS(netip.MustParseAddr("110.242.68.66")); rev != "www.baidu.com" {
		t.Fatalf("CN reverse DNS mismatch: %q", rev)
	}
}

func TestSniffTLSSNIAndHTTPHost(t *testing.T) {
	// Construct a minimal valid TLS ClientHello with SNI "www.example.org".
	host := "www.example.org"
	sniEntry := append([]byte{0x00, byte(len(host) >> 8), byte(len(host))}, []byte(host)...)
	sniList := append([]byte{byte(len(sniEntry) >> 8), byte(len(sniEntry))}, sniEntry...)
	ext := append([]byte{0x00, 0x00, byte(len(sniList) >> 8), byte(len(sniList))}, sniList...)
	extBlock := append([]byte{byte(len(ext) >> 8), byte(len(ext))}, ext...)
	body := append([]byte{0x03, 0x03}, make([]byte, 32)...) // version + random
	body = append(body, 0x00)                               // session ID len
	body = append(body, 0x00, 0x02, 0x13, 0x01)             // cipher suites
	body = append(body, 0x01, 0x00)                         // compression
	body = append(body, extBlock...)
	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)

	if got := sniffDomain(rec); got != "www.example.org" {
		t.Fatalf("TLS SNI got %q, want www.example.org", got)
	}
	if got := sniffDomain([]byte("GET / HTTP/1.1\r\nHost: API.GitHub.COM:80\r\n\r\n")); got != "api.github.com" {
		t.Fatalf("HTTP Host got %q, want api.github.com", got)
	}
	if got := sniffDomain([]byte("GET / HTTP/1.1\r\nHost: 1.2.3.4:80\r\n\r\n")); got != "" {
		t.Fatalf("literal IP host should not sniff: %q", got)
	}
	if got := sniffDomain([]byte{0x16, 0x03, 0x01, 0x00, 0x02}); got != "" {
		t.Fatalf("truncated TLS should return empty: %q", got)
	}
}

func TestDNSOverrideParsingAndUnknownDomainAntiPollution(t *testing.T) {
	got, err := ParseDNSUpstreams([]string{"https://223.5.5.5/dns-query", "https://dns.alidns.com", "119.29.29.29", "223.5.5.5:53"})
	if err != nil || len(got) != 4 || got[1] != "https://dns.alidns.com/dns-query" || got[2] != "119.29.29.29:53" {
		t.Fatalf("ParseDNSUpstreams unexpected: %v %v", got, err)
	}
	for _, bad := range []string{"http://223.5.5.5/dns-query", "udp://223.5.5.5", "not-an-ip", "223.5.5.5:99999"} {
		if _, err := ParseDNSUpstreams([]string{bad}); err == nil {
			t.Fatalf("accepted invalid DNS upstream %q", bad)
		}
	}

	var remoteCalls, domesticCalls atomic.Int32
	cfg := poolServer(t, func(w http.ResponseWriter, r *http.Request) {
		remoteCalls.Add(1)
		w.Header().Set("Tunnelx-Version", config.Version)
		w.WriteHeader(200)
		http.NewResponseController(w).Flush()
		length := make([]byte, 2)
		if _, e := io.ReadFull(r.Body, length); e != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(length))
		if _, e := io.ReadFull(r.Body, q); e != nil {
			return
		}
		h, question, _ := dnsQuestion(q)
		var ip [4]byte
		if question.Name.String() == "unknown-cn-site-9x2a.com." {
			ip = [4]byte{223, 5, 5, 5} // CN IP
		} else {
			ip = [4]byte{1, 1, 1, 1} // Foreign IP
		}
		answer := makeAReply(h.ID, question.Name.String(), ip)
		w.Write(binary.BigEndian.AppendUint16(nil, uint16(len(answer))))
		w.Write(answer)
		http.NewResponseController(w).Flush()
		<-r.Context().Done()
	})
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxy(m)
	p.TUN = true
	p.SetDNSConfig(DNSConfig{Enabled: true, Domestic: []string{"https://223.5.5.5/dns-query"}})
	defer p.Close()

	rules, _ := routing.Builtin()
	rt, _ := routing.New(rules, "")
	p.SetRouter(rt)
	p.directDNSQuery = func(_ context.Context, upstream string, query []byte) ([]byte, error) {
		domesticCalls.Add(1)
		if upstream != "https://223.5.5.5/dns-query" {
			t.Errorf("expected AliDNS DoH upstream, got %q", upstream)
		}
		h, q, _ := dnsQuestion(query)
		// Domestic CDN IP (also in geoip:cn)
		return makeAReply(h.ID, q.Name.String(), [4]byte{119, 29, 29, 29}), nil
	}

	// 1. Unknown foreign site: must resolve via remote tunnel ONLY (zero mainland pollution risk).
	ansForeign := p.exchangeDNS(context.Background(), makeQuery(t, 4001, "unknown-foreign-site-9x2a.com.", dnsmessage.TypeA))
	if ips := extractAnswerIPs(ansForeign); len(ips) != 1 || ips[0].String() != "1.1.1.1" || domesticCalls.Load() != 0 || remoteCalls.Load() != 1 {
		t.Fatalf("unknown foreign domain leaked to domestic DNS: ips=%v domestic=%d remote=%d", ips, domesticCalls.Load(), remoteCalls.Load())
	}

	// 2. Unknown CN site: remote tunnel confirms geoip:cn, then upgrades via AliDNS DoH for domestic CDN IP.
	ansCN := p.exchangeDNS(context.Background(), makeQuery(t, 4002, "unknown-cn-site-9x2a.com.", dnsmessage.TypeA))
	if ips := extractAnswerIPs(ansCN); len(ips) != 1 || ips[0].String() != "119.29.29.29" || domesticCalls.Load() != 1 || remoteCalls.Load() != 2 {
		t.Fatalf("unknown CN domain did not upgrade via AliDNS DoH: ips=%v domestic=%d remote=%d", ips, domesticCalls.Load(), remoteCalls.Load())
	}
}

func TestTUNDNSSingleflightCoalescing(t *testing.T) {
	var remoteCalls atomic.Int32
	gate := make(chan struct{})
	cfg := poolServer(t, func(w http.ResponseWriter, r *http.Request) {
		remoteCalls.Add(1)
		w.Header().Set("Tunnelx-Version", config.Version)
		w.WriteHeader(200)
		http.NewResponseController(w).Flush()
		length := make([]byte, 2)
		if _, e := io.ReadFull(r.Body, length); e != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(length))
		if _, e := io.ReadFull(r.Body, q); e != nil {
			return
		}
		<-gate
		h, question, _ := dnsQuestion(q)
		answer := makeAReply(h.ID, question.Name.String(), [4]byte{93, 184, 216, 34})
		w.Write(binary.BigEndian.AppendUint16(nil, uint16(len(answer))))
		w.Write(answer)
		http.NewResponseController(w).Flush()
		<-r.Context().Done()
	})
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxy(m)
	p.TUN = true
	p.EnableDNSCache()
	defer p.Close()

	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		id := uint16(5000 + i)
		go func(txid uint16) {
			defer wg.Done()
			ans := p.exchangeDNS(context.Background(), makeQuery(t, txid, "video.cdn-burst-test.com.", dnsmessage.TypeA))
			var msg dnsmessage.Message
			if err := msg.Unpack(ans); err != nil {
				errs <- err
				return
			}
			if msg.ID != txid || msg.RCode != dnsmessage.RCodeSuccess || len(msg.Answers) != 1 {
				t.Errorf("unexpected coalesced reply for id=%d: %+v", txid, msg)
			}
		}(id)
	}
	time.Sleep(40 * time.Millisecond)
	close(gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if calls := remoteCalls.Load(); calls != 1 {
		t.Fatalf("expected 1 coalesced upstream DNS call, got %d", calls)
	}
}
