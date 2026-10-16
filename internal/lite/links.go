package lite

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/674542449/tunnelx-lite/internal/share"
)

type ShareLink struct {
	Label string `json:"label"`
	Host  string `json:"host"`
	URL   string `json:"url"`
}

// Links lists one link per custom host, or per detected public IPv4/IPv6.
func Links(c Config, id Identity, v4, v6 string) []ShareLink {
	type entry struct{ label, host string }
	var hosts []entry
	if len(c.Hosts) > 0 {
		for _, h := range c.Hosts {
			hosts = append(hosts, entry{"自定义 · " + h, h})
		}
	} else {
		if v4 != "" && c.Inbound != "ipv6" {
			hosts = append(hosts, entry{"IPv4", v4})
		}
		if v6 != "" && c.Inbound != "ipv4" {
			hosts = append(hosts, entry{"IPv6", v6})
		}
	}
	out := []ShareLink{}
	for _, h := range hosts {
		name := c.Name
		if len(hosts) > 1 && len(c.Hosts) == 0 {
			name += " " + h.label
		}
		l := share.Link{Name: name, Host: h.host, Port: c.Port, Token: c.Token, ServerName: c.InnerName, ECHConfig: id.ECHConfig, CertPin: id.CertPin}
		out = append(out, ShareLink{Label: h.label, Host: h.host, URL: l.String()})
	}
	return out
}

var ipCache struct {
	sync.Mutex
	v4, v6  string
	checked time.Time
}

// PublicIPs asks external echo services over each address family, because
// cloud servers usually only see a private address on their interfaces.
// Results are cached for 10 minutes, failed lookups for 2, so the panel
// stays responsive on servers whose IPv6 route is broken.
func PublicIPs(ctx context.Context) (v4, v6 string) {
	ipCache.Lock()
	defer ipCache.Unlock()
	ttl := 10 * time.Minute
	if ipCache.v4 == "" && ipCache.v6 == "" {
		ttl = 2 * time.Minute
	}
	if !ipCache.checked.IsZero() && time.Since(ipCache.checked) < ttl {
		return ipCache.v4, ipCache.v6
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		v4 = lookupIP(ctx, "tcp4", []string{"https://api.ipify.org", "https://ipv4.icanhazip.com"})
	}()
	go func() {
		defer wg.Done()
		v6 = lookupIP(ctx, "tcp6", []string{"https://api6.ipify.org", "https://ipv6.icanhazip.com"})
	}()
	wg.Wait()
	if v4 == "" && v6 == "" {
		v4, v6 = interfaceIPs()
	}
	ipCache.v4, ipCache.v6, ipCache.checked = v4, v6, time.Now()
	return v4, v6
}

// lookupIP asks all echo services at once and takes the first valid answer.
func lookupIP(ctx context.Context, network string, urls []string) string {
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	c := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}}}
	defer c.CloseIdleConnections()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	found := make(chan string, len(urls))
	for _, u := range urls {
		go func() {
			req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
			res, e := c.Do(req)
			if e != nil {
				found <- ""
				return
			}
			b, _ := io.ReadAll(io.LimitReader(res.Body, 64))
			res.Body.Close()
			ip := net.ParseIP(strings.TrimSpace(string(b)))
			if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || (network == "tcp4") != (ip.To4() != nil) {
				found <- ""
				return
			}
			found <- ip.String()
		}()
	}
	for range urls {
		if ip := <-found; ip != "" {
			return ip
		}
	}
	return ""
}

func interfaceIPs() (v4, v6 string) {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || !n.IP.IsGlobalUnicast() || n.IP.IsPrivate() {
			continue
		}
		if n.IP.To4() != nil && v4 == "" {
			v4 = n.IP.String()
		} else if n.IP.To4() == nil && v6 == "" {
			v6 = n.IP.String()
		}
	}
	return
}
