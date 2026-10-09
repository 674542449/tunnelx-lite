package client

import (
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"time"
)

// A virtual IPv6 adapter does not prove that the remote node has IPv6 egress.
// A conservative result also avoids returning unusable AAAA/HTTPS IP hints.
func (m *Mux) ProbeTUNIPv6(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	results := make(chan bool, 2)
	for _, target := range []string{"[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443"} {
		go func(target string) {
			t, e := m.OpenTCP(ctx, target)
			if e == nil {
				t.Close()
			}
			results <- e == nil
		}(target)
	}
	valid := true
	for i := 0; i < 2; i++ {
		if !<-results {
			valid = false
		}
	}
	return valid
}

func dnsQuestion(packet []byte) (dnsmessage.Header, dnsmessage.Question, error) {
	var parser dnsmessage.Parser
	h, e := parser.Start(packet)
	if e != nil || h.Response || h.OpCode != 0 {
		return h, dnsmessage.Question{}, errors.New("invalid DNS query")
	}
	q, e := parser.Question()
	if e != nil {
		return h, q, e
	}
	if _, e = parser.Question(); e != dnsmessage.ErrSectionDone {
		return h, q, errors.New("DNS requires one question")
	}
	return h, q, nil
}
func dnsAnswer(h dnsmessage.Header, q dnsmessage.Question, code dnsmessage.RCode) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true, RCode: code})
	b.StartQuestions()
	b.Question(q)
	packet, _ := b.Finish()
	return packet
}
func (p *Proxy) exchangeDNS(ctx context.Context, query []byte) []byte {
	return p.exchangeDNSWith(ctx, query, p.queryResolver)
}
func (p *Proxy) queryResolver(ctx context.Context, index int, query []byte) ([]byte, error) {
	if index < 2 {
		return p.queryDNS(ctx, []string{"1.1.1.1:53", "8.8.8.8:53"}[index], query)
	}
	return p.queryDoH(ctx, index-2, query)
}
func (p *Proxy) exchangeDNSWith(ctx context.Context, query []byte, resolve func(context.Context, int, []byte) ([]byte, error)) []byte {
	h, q, e := dnsQuestion(query)
	if e != nil {
		return nil
	}
	if !p.TUNIPv6.Load() && (q.Type == dnsmessage.TypeAAAA || q.Type == dnsmessage.Type(64) || q.Type == dnsmessage.Type(65)) {
		return dnsAnswer(h, q, dnsmessage.RCodeSuccess)
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	select {
	case p.dnsSlots <- struct{}{}:
		defer func() { <-p.dnsSlots }()
	case <-ctx.Done():
		return dnsAnswer(h, q, dnsmessage.RCodeServerFailure)
	}
	first := int(p.dnsPreferred.Load()) % 4
	for i := 0; i < 4; i++ {
		index := (first + i) % 4
		attempt, stop := context.WithTimeout(ctx, 2*time.Second)
		answer, err := resolve(attempt, index, query)
		stop()
		if err != nil {
			continue
		}
		var parser dnsmessage.Parser
		header, err := parser.Start(answer)
		if err != nil || !header.Response || header.ID != h.ID {
			continue
		}
		question, err := parser.Question()
		if err != nil || question != q {
			continue
		}
		if header.RCode == dnsmessage.RCodeServerFailure || header.RCode == dnsmessage.RCodeRefused {
			continue
		}
		p.dnsPreferred.Store(uint32(index))
		return answer
	}
	flowFrom(ctx).event("tun_dns_failed", map[string]any{"query_type": uint16(q.Type), "transport": "h2_tcp"})
	return dnsAnswer(h, q, dnsmessage.RCodeServerFailure)
}
func (p *Proxy) queryDNS(ctx context.Context, target string, query []byte) ([]byte, error) {
	if len(query) > 65535 {
		return nil, errors.New("DNS packet too large")
	}
	stream, e := p.Mux.OpenTCP(ctx, target)
	if e != nil {
		return nil, e
	}
	defer stream.Close()
	// Cancellation does not interrupt reads on an established H2 stream; without
	// this a silent resolver blocks health checks and therefore Disconnect.
	stop := context.AfterFunc(ctx, func() { stream.Close() })
	defer stop()
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	frame = append(frame, query...)
	if _, e = stream.Write(frame); e != nil {
		return nil, e
	}
	length := make([]byte, 2)
	if _, e = io.ReadFull(stream, length); e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint16(length))
	if n < 12 {
		return nil, errors.New("short DNS reply")
	}
	response := make([]byte, n)
	_, e = io.ReadFull(stream, response)
	return response, e
}
func (p *Proxy) dnsTCP(ctx context.Context) *Tunnel {
	a, b := net.Pipe()
	live, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(live, func() { a.Close(); b.Close() })
	go func() {
		defer cancel()
		defer b.Close()
		length := make([]byte, 2)
		for {
			b.SetDeadline(time.Now().Add(30 * time.Second))
			if _, e := io.ReadFull(b, length); e != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(length))
			if n < 12 {
				return
			}
			query := make([]byte, n)
			if _, e := io.ReadFull(b, query); e != nil {
				return
			}
			answer := p.exchangeDNS(live, query)
			if len(answer) == 0 {
				return
			}
			frame := binary.BigEndian.AppendUint16(nil, uint16(len(answer)))
			frame = append(frame, answer...)
			if _, e := b.Write(frame); e != nil {
				return
			}
		}
	}()
	stream := &Tunnel{Reader: a, Writer: a, close: func() error { stop(); cancel(); b.Close(); return a.Close() }, closeWrite: func() error { return nil }, setDeadline: a.SetDeadline, transport: "h2_dns"}
	flowFrom(ctx).openedOn(stream)
	return stream
}

type dnsPackets struct {
	ctx       context.Context
	cancel    context.CancelFunc
	proxy     *Proxy
	responses chan []byte
	pending   chan struct{}
}

func (p *Proxy) dnsUDP(ctx context.Context) *dnsPackets {
	live, cancel := context.WithCancel(ctx)
	flowFrom(ctx).openedOn(&Tunnel{transport: "h2_dns"})
	return &dnsPackets{live, cancel, p, make(chan []byte, 16), make(chan struct{}, 16)}
}
func (d *dnsPackets) Send(packet []byte) error {
	if e := d.ctx.Err(); e != nil {
		return e
	}
	if _, _, e := dnsQuestion(packet); e != nil {
		return e
	}
	select {
	case d.pending <- struct{}{}:
	default:
		return errors.New("DNS query queue full")
	}
	query := append([]byte{}, packet...)
	go func() {
		defer func() { <-d.pending }()
		answer := d.proxy.exchangeDNS(d.ctx, query)
		if len(answer) > 0 {
			select {
			case d.responses <- answer:
			case <-d.ctx.Done():
			}
		}
	}()
	return nil
}
func (d *dnsPackets) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-d.responses:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.ctx.Done():
		return nil, d.ctx.Err()
	}
}
func (d *dnsPackets) Close() error { d.cancel(); return nil }
