package lite

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestIPv6OnlyNeedsPublicIPv6(t *testing.T) {
	_, _, cl, base, password := panelFixture(t)
	call(t, cl, "POST", base+"api/login", map[string]string{"password": password}, 200)
	detectIPs = func(context.Context) (string, string) { return "203.0.113.5", "" }
	settings := map[string]any{"name": "n", "port": 18443, "inbound": "", "outbound_ip": "ipv6", "bandwidth_mbps": 0, "hosts": []string{}}
	call(t, cl, "POST", base+"api/settings", settings, 400)
	settings["outbound_ip"], settings["inbound"] = "", "ipv6"
	call(t, cl, "POST", base+"api/settings", settings, 400)
	detectIPs = func(context.Context) (string, string) { return "203.0.113.5", "2001:db8::5" }
	settings["outbound_ip"] = "ipv6"
	call(t, cl, "POST", base+"api/settings", settings, 200)
}

// A busy proxy port must not take the panel down with it.
func TestPanelSurvivesProxyPortFailure(t *testing.T) {
	busy, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	free, _ := net.Listen("tcp", ":0")
	panelPort := free.Addr().(*net.TCPAddr).Port
	free.Close()
	d := Dir(t.TempDir())
	if _, _, err = Init(d, "n", busy.Addr().(*net.TCPAddr).Port, panelPort); err != nil {
		t.Fatal(err)
	}
	r, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for r.ProxyError() == "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(r.ProxyError(), "启动失败") {
		t.Fatal("proxy failure not reported", r.ProxyError())
	}
	select {
	case e := <-done:
		t.Fatal("runtime exited with the proxy port busy", e)
	case <-time.After(300 * time.Millisecond):
	}
	if c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(panelPort)), time.Second); e != nil {
		t.Fatal("panel not listening", e)
	} else {
		c.Close()
	}
	cancel()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
