package client

import (
	"context"
	"encoding/binary"
	"github.com/674542449/tunnelx-lite/internal/config"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net/http"
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
