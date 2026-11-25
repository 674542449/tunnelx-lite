package client

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type dnsCacheKey struct {
	name   string
	qtype  dnsmessage.Type
	qclass dnsmessage.Class
}

type dnsCacheEntry struct {
	packet  []byte
	expires time.Time
}

type dnsFlight struct {
	done   chan struct{}
	answer []byte
}

type revDNSEntry struct {
	domain  string
	expires time.Time
}

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

// sameQuestion compares DNS questions case-insensitively on the domain name
// because RFC 1035 names are case-insensitive and resolvers may normalize case.
func sameQuestion(a, b dnsmessage.Question) bool {
	return a.Type == b.Type && a.Class == b.Class && strings.EqualFold(a.Name.String(), b.Name.String())
}

func dnsAnswer(h dnsmessage.Header, q dnsmessage.Question, code dnsmessage.RCode) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true, RCode: code})
	b.StartQuestions()
	b.Question(q)
	packet, _ := b.Finish()
	return packet
}

// FlushDNSCache drops cached TUN DNS answers and reverse-DNS IP->domain
// mappings (e.g. after switching routing mode or direct-domain exceptions).
func (p *Proxy) FlushDNSCache() {
	p.dnsCacheMu.Lock()
	clear(p.dnsCache)
	p.dnsCacheMu.Unlock()
	p.revDNSMu.Lock()
	clear(p.revDNS)
	p.revDNSMu.Unlock()
}

func (p *Proxy) lookupDNSCache(h dnsmessage.Header, q dnsmessage.Question) []byte {
	if !p.dnsCacheEnabled.Load() {
		return nil
	}
	key := dnsCacheKey{name: strings.ToLower(q.Name.String()), qtype: q.Type, qclass: q.Class}
	p.dnsCacheMu.Lock()
	entry, ok := p.dnsCache[key]
	p.dnsCacheMu.Unlock()
	if !ok || time.Now().After(entry.expires) || len(entry.packet) < 2 {
		return nil
	}
	out := append([]byte(nil), entry.packet...)
	binary.BigEndian.PutUint16(out[:2], h.ID)
	return out
}

func (p *Proxy) storeDNSCache(q dnsmessage.Question, answer []byte) {
	if !p.dnsCacheEnabled.Load() || len(answer) < 12 {
		return
	}
	ttl := extractMinTTL(answer)
	if ttl <= 0 {
		return
	}
	key := dnsCacheKey{name: strings.ToLower(q.Name.String()), qtype: q.Type, qclass: q.Class}
	p.dnsCacheMu.Lock()
	if p.dnsCache == nil {
		p.dnsCache = make(map[dnsCacheKey]dnsCacheEntry)
	}
	if len(p.dnsCache) >= 4096 {
		now := time.Now()
		for k, v := range p.dnsCache {
			if now.After(v.expires) {
				delete(p.dnsCache, k)
			}
		}
		if len(p.dnsCache) >= 4096 {
			clear(p.dnsCache)
		}
	}
	p.dnsCache[key] = dnsCacheEntry{packet: append([]byte(nil), answer...), expires: time.Now().Add(ttl)}
	p.dnsCacheMu.Unlock()
}

func extractMinTTL(answer []byte) time.Duration {
	var msg dnsmessage.Message
	if msg.Unpack(answer) != nil {
		return 0
	}
	if msg.RCode != dnsmessage.RCodeSuccess && msg.RCode != dnsmessage.RCodeNameError {
		return 0
	}
	if len(msg.Answers) == 0 {
		return 15 * time.Second
	}
	minTTL := uint32(300)
	for _, a := range msg.Answers {
		if a.Header.TTL < minTTL {
			minTTL = a.Header.TTL
		}
	}
	if minTTL < 15 {
		minTTL = 15
	}
	return time.Duration(minTTL) * time.Second
}

// recordDNSAnswers remembers IP -> domain mappings from DNS responses so TUN
// connections arriving as literal IPs can still be routed by domain rules.
func (p *Proxy) recordDNSAnswers(qname string, answer []byte) {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(qname)), ".")
	if domain == "" {
		return
	}
	var msg dnsmessage.Message
	if msg.Unpack(answer) != nil || msg.RCode != dnsmessage.RCodeSuccess {
		return
	}
	var ips []netip.Addr
	for _, a := range msg.Answers {
		switch body := a.Body.(type) {
		case *dnsmessage.AResource:
			ips = append(ips, netip.AddrFrom4(body.A))
		case *dnsmessage.AAAAResource:
			ips = append(ips, netip.AddrFrom16(body.AAAA).Unmap())
		}
	}
	if len(ips) == 0 {
		return
	}
	exp := time.Now().Add(5 * time.Minute)
	p.revDNSMu.Lock()
	if p.revDNS == nil {
		p.revDNS = make(map[netip.Addr]revDNSEntry)
	}
	if len(p.revDNS) >= 4096 {
		now := time.Now()
		for k, v := range p.revDNS {
			if now.After(v.expires) {
				delete(p.revDNS, k)
			}
		}
		if len(p.revDNS) >= 4096 {
			clear(p.revDNS)
		}
	}
	for _, ip := range ips {
		p.revDNS[ip] = revDNSEntry{domain: domain, expires: exp}
	}
	p.revDNSMu.Unlock()
}

func (p *Proxy) lookupReverseDNS(ip netip.Addr) string {
	ip = ip.Unmap()
	p.revDNSMu.Lock()
	entry, ok := p.revDNS[ip]
	p.revDNSMu.Unlock()
	if !ok || time.Now().After(entry.expires) {
		return ""
	}
	return entry.domain
}

func (p *Proxy) exchangeDNS(ctx context.Context, query []byte) []byte {
	h, q, e := dnsQuestion(query)
	if e != nil {
		return nil
	}
	if !p.TUNIPv6.Load() && (q.Type == dnsmessage.TypeAAAA || q.Type == dnsmessage.Type(64) || q.Type == dnsmessage.Type(65)) {
		return dnsAnswer(h, q, dnsmessage.RCodeSuccess)
	}
	if cached := p.lookupDNSCache(h, q); cached != nil {
		return cached
	}
	// Coalesce burst duplicate queries from browsers/video players into a single
	// upstream lookup when DNS caching is active.
	if p.dnsCacheEnabled.Load() {
		key := dnsCacheKey{name: strings.ToLower(q.Name.String()), qtype: q.Type, qclass: q.Class}
		p.dnsInflightMu.Lock()
		if p.dnsInflight == nil {
			p.dnsInflight = make(map[dnsCacheKey]*dnsFlight)
		}
		if f, exists := p.dnsInflight[key]; exists {
			p.dnsInflightMu.Unlock()
			select {
			case <-f.done:
				if len(f.answer) >= 2 {
					out := append([]byte(nil), f.answer...)
					binary.BigEndian.PutUint16(out[:2], h.ID)
					return out
				}
				return dnsAnswer(h, q, dnsmessage.RCodeServerFailure)
			case <-ctx.Done():
				return dnsAnswer(h, q, dnsmessage.RCodeServerFailure)
			}
		}
		f := &dnsFlight{done: make(chan struct{})}
		p.dnsInflight[key] = f
		p.dnsInflightMu.Unlock()
		ans := p.resolveDNSLive(ctx, h, q, query)
		f.answer = ans
		close(f.done)
		p.dnsInflightMu.Lock()
		delete(p.dnsInflight, key)
		p.dnsInflightMu.Unlock()
		return ans
	}
	return p.resolveDNSLive(ctx, h, q, query)
}

func (p *Proxy) resolveDNSLive(ctx context.Context, h dnsmessage.Header, q dnsmessage.Question, query []byte) []byte {
	qname := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")
	if r := p.getRouter(); r != nil {
		if r.IsLocalOrPrivateDomain(qname) {
			if ans := p.queryDirectDNS(ctx, h, q, query, true); len(ans) > 0 {
				p.recordDNSAnswers(qname, ans)
				p.storeDNSCache(q, ans)
				return ans
			}
		} else if r.IsDomesticDomain(qname) {
			if ans := p.queryDirectDNS(ctx, h, q, query, false); len(ans) > 0 {
				p.recordDNSAnswers(qname, ans)
				p.storeDNSCache(q, ans)
				return ans
			}
		} else if !r.Global && !r.IsProxyDomain(qname) {
			// Unknown domain in Bypass CN mode: resolve via encrypted remote tunnel DNS
			// first so uncategorized foreign domains can never be poisoned by mainland DNS.
			// If every returned IP is in geoip:cn, optionally upgrade via domestic encrypted
			// DoH (AliDNS) for optimal domestic CDN IPs while keeping the GeoIP guard.
			remoteAns := p.exchangeDNSWith(ctx, query, p.queryResolver)
			if len(remoteAns) > 0 && p.getDNSConfig().Enabled && p.allAnswersAreCN(remoteAns) {
				if domAns := p.queryDomesticUpstreams(ctx, h, q, query); len(domAns) > 0 && p.allAnswersAreCN(domAns) {
					p.recordDNSAnswers(qname, domAns)
					p.storeDNSCache(q, domAns)
					return domAns
				}
			}
			if len(remoteAns) > 0 {
				p.recordDNSAnswers(qname, remoteAns)
				p.storeDNSCache(q, remoteAns)
			}
			return remoteAns
		}
	}
	answer := p.exchangeDNSWith(ctx, query, p.queryResolver)
	if len(answer) > 0 {
		p.recordDNSAnswers(qname, answer)
		p.storeDNSCache(q, answer)
	}
	return answer
}

// exchangeDNSRemote always resolves through the remote tunnel without consulting
// the cache or domestic resolvers (used by health checks).
func (p *Proxy) exchangeDNSRemote(ctx context.Context, query []byte) []byte {
	return p.exchangeDNSWith(ctx, query, p.queryResolver)
}

func (p *Proxy) queryDirectDNS(ctx context.Context, h dnsmessage.Header, q dnsmessage.Question, query []byte, localOnly bool) []byte {
	uplink := p.getUplink()
	// When running in TUN mode without a known physical uplink interface, avoid
	// direct dials that would loop back into the TUN adapter.
	if p.TUN && uplink.ifV4 == 0 && uplink.ifV6 == 0 && p.directDNSQuery == nil {
		return nil
	}
	if localOnly {
		// LAN/private/exception domains try physical uplink DNS first so routers
		// and corporate intranet names resolve accurately.
		if ans := p.tryPlainDNSList(ctx, h, q, query, uplink.dnsServers); len(ans) > 0 {
			return ans
		}
		if isStrictlyLocalDNSName(q.Name.String()) {
			return nil
		}
		return p.queryDomesticUpstreams(ctx, h, q, query)
	}
	// Domestic CN domains: prefer encrypted domestic DoH (default AliDNS + DNSPod)
	// when DNS override is enabled, then fall back to plain UDP/53 + uplink DNS.
	if p.getDNSConfig().Enabled {
		if ans := p.queryDomesticUpstreams(ctx, h, q, query); len(ans) > 0 {
			return ans
		}
	}
	fallback := append([]string(nil), uplink.dnsServers...)
	fallback = append(fallback, "223.5.5.5", "119.29.29.29")
	return p.tryPlainDNSList(ctx, h, q, query, fallback)
}

func (p *Proxy) queryDomesticUpstreams(ctx context.Context, h dnsmessage.Header, q dnsmessage.Question, query []byte) []byte {
	uplink := p.getUplink()
	if p.TUN && uplink.ifV4 == 0 && uplink.ifV6 == 0 && p.directDNSQuery == nil {
		return nil
	}
	for _, up := range p.domesticUpstreams() {
		attempt, stop := context.WithTimeout(ctx, 2500*time.Millisecond)
		var ans []byte
		var err error
		if p.directDNSQuery != nil {
			ans, err = p.directDNSQuery(attempt, up, query)
		} else if strings.HasPrefix(strings.ToLower(up), "https://") {
			ans, err = p.queryDirectDoH(attempt, up, query)
		} else {
			ans, err = p.dialDirectUDPQuery(attempt, up, query)
		}
		stop()
		if err != nil {
			continue
		}
		if validDNSReply(ans, h, q) {
			return ans
		}
	}
	return nil
}

func (p *Proxy) tryPlainDNSList(ctx context.Context, h dnsmessage.Header, q dnsmessage.Question, query []byte, servers []string) []byte {
	seen := map[string]bool{}
	for _, s := range servers {
		if s == "" {
			continue
		}
		target := s
		if _, _, err := net.SplitHostPort(s); err != nil {
			target = net.JoinHostPort(s, "53")
		}
		if seen[target] {
			continue
		}
		seen[target] = true
		attempt, stop := context.WithTimeout(ctx, 2*time.Second)
		var ans []byte
		var err error
		if p.directDNSQuery != nil {
			ans, err = p.directDNSQuery(attempt, target, query)
		} else {
			ans, err = p.dialDirectUDPQuery(attempt, target, query)
		}
		stop()
		if err != nil {
			continue
		}
		if validDNSReply(ans, h, q) {
			return ans
		}
	}
	return nil
}

func validDNSReply(ans []byte, h dnsmessage.Header, q dnsmessage.Question) bool {
	var parser dnsmessage.Parser
	header, err := parser.Start(ans)
	if err != nil || !header.Response || header.ID != h.ID {
		return false
	}
	question, err := parser.Question()
	if err != nil || !sameQuestion(question, q) {
		return false
	}
	return header.RCode != dnsmessage.RCodeServerFailure && header.RCode != dnsmessage.RCodeRefused
}

func isStrictlyLocalDNSName(name string) bool {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	return n == "localhost" || strings.HasSuffix(n, ".localhost") || strings.HasSuffix(n, ".local") || strings.HasSuffix(n, ".lan") || strings.HasSuffix(n, ".home.arpa") || strings.HasSuffix(n, ".internal") || strings.HasSuffix(n, ".localdomain")
}

func (p *Proxy) dialDirectUDPQuery(ctx context.Context, target string, query []byte) ([]byte, error) {
	c, err := p.directDialer(2*time.Second).DialContext(ctx, "udp", target)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	} else {
		c.SetDeadline(time.Now().Add(2 * time.Second))
	}
	if _, err = c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (p *Proxy) queryResolver(ctx context.Context, index int, query []byte) ([]byte, error) {
	upstreams := p.remoteUpstreams()
	if len(upstreams) == 0 {
		return nil, errors.New("no remote DNS upstreams")
	}
	up := upstreams[index%len(upstreams)]
	return p.queryRemoteUpstream(ctx, up, query)
}

func (p *Proxy) exchangeDNSWith(ctx context.Context, query []byte, resolve func(context.Context, int, []byte) ([]byte, error)) []byte {
	h, q, e := dnsQuestion(query)
	if e != nil {
		return nil
	}
	if !p.TUNIPv6.Load() && (q.Type == dnsmessage.TypeAAAA || q.Type == dnsmessage.Type(64) || q.Type == dnsmessage.Type(65)) {
		return dnsAnswer(h, q, dnsmessage.RCodeSuccess)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	select {
	case p.dnsSlots <- struct{}{}:
		defer func() { <-p.dnsSlots }()
	case <-ctx.Done():
		return dnsAnswer(h, q, dnsmessage.RCodeServerFailure)
	}
	total := len(p.remoteUpstreams())
	if total == 0 {
		total = 4
	}
	first := int(p.dnsPreferred.Load()) % total
	for i := 0; i < total; i++ {
		index := (first + i) % total
		attempt, stop := context.WithTimeout(ctx, 3*time.Second)
		answer, err := resolve(attempt, index, query)
		stop()
		if err != nil {
			continue
		}
		if !validDNSReply(answer, h, q) {
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
