package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// These HTTPS requests are carried inside the authenticated H2 tunnel. Fixed
// bootstrap IPs avoid depending on the DNS service being diagnosed.
type streamConn struct{ *Tunnel }

func (c streamConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c streamConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c streamConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c streamConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

func (p *Proxy) tunnelHTTPS(ctx context.Context, ip, host, path string, body []byte) ([]byte, error) {
	stream, err := p.Mux.OpenTCP(ctx, net.JoinHostPort(ip, "443"))
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { stream.Close() })
	defer stop()
	conn := tls.Client(streamConn{stream}, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if err = conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	method := "GET"
	if body != nil {
		method = "POST"
	}
	request, err := http.NewRequestWithContext(ctx, method, "https://"+host+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Close = true
	if body != nil {
		request.Header.Set("Content-Type", "application/dns-message")
		request.Header.Set("Accept", "application/dns-message")
	}
	if err = request.Write(conn); err != nil {
		return nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("HTTPS probe status")
	}
	if body != nil && !strings.EqualFold(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]), "application/dns-message") {
		return nil, errors.New("invalid DoH media type")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if len(data) >= 65536 {
		return nil, errors.New("HTTPS probe response too large")
	}
	return data, err
}
func (p *Proxy) queryDoH(ctx context.Context, index int, query []byte) ([]byte, error) {
	if index == 0 {
		return p.tunnelHTTPS(ctx, "1.1.1.1", "cloudflare-dns.com", "/dns-query", query)
	}
	return p.tunnelHTTPS(ctx, "8.8.8.8", "dns.google", "/dns-query", query)
}
func healthQuery() []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 19471, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("www.google.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	return q
}
func (p *Proxy) CheckDNS(ctx context.Context) string {
	var response dnsmessage.Message
	if response.Unpack(p.exchangeDNS(ctx, healthQuery())) != nil || response.RCode != dnsmessage.RCodeSuccess {
		return "dns_resolution"
	}
	for _, r := range response.Answers {
		if r.Header.Type == dnsmessage.TypeA {
			return ""
		}
	}
	return "dns_no_address"
}
func (p *Proxy) CheckEgress(ctx context.Context) string {
	// Test TLS and HTTP independently of the DNS path. Either provider suffices.
	for _, target := range [][3]string{{"1.1.1.1", "one.one.one.one", "/cdn-cgi/trace"}, {"8.8.8.8", "dns.google", "/"}} {
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		body, err := p.tunnelHTTPS(attempt, target[0], target[1], target[2], nil)
		cancel()
		if err == nil && len(body) > 0 {
			return ""
		}
	}
	return "egress_https"
}
func (p *Proxy) DNSRoute() string {
	return []string{"tcp_cloudflare", "tcp_google", "doh_cloudflare", "doh_google"}[int(p.dnsPreferred.Load())%4]
}

// Failure disables IPv6 immediately; recovery needs two consecutive probes to
// avoid oscillating DNS answers during an unstable uplink.
func (p *Proxy) ObserveIPv6(available bool) bool {
	successes := int32(0)
	if available {
		successes = p.ipv6Successes.Add(1)
	} else {
		p.ipv6Successes.Store(0)
	}
	next := available && (p.TUNIPv6.Load() || successes >= 2)
	return p.TUNIPv6.Swap(next) != next
}
