package app

import (
	"context"
	"testing"

	"github.com/674542449/tunnelx-lite/internal/routing"
)

func TestExtractIPFromBodyAndCustomTarget(t *testing.T) {
	cases := []struct {
		body   string
		wantV4 string
	}{
		{"203.0.113.42\n", "203.0.113.42"},
		{"fl=29f1\nh=www.cloudflare.com\nip=198.51.100.77\nts=123\n", "198.51.100.77"},
		{"IP\t: 114.114.114.114\n地址\t: 中国 江苏 南京\n", "114.114.114.114"},
		{"127.0.0.1\n192.168.1.1\n8.8.8.8", "8.8.8.8"},
		{"<html>no ip here</html>", ""},
	}
	for _, tc := range cases {
		if got := extractIPFromBody(tc.body, true, false); got != tc.wantV4 {
			t.Errorf("extractIPFromBody(%q) = %q, want %q", tc.body, got, tc.wantV4)
		}
	}

	if d, u, err := parseCustomCheckTarget("cip.cc"); err != nil || d != "cip.cc" || u != "https://cip.cc/" {
		t.Fatalf("parseCustomCheckTarget(cip.cc) = %q %q %v", d, u, err)
	}
	if d, u, err := parseCustomCheckTarget("https://www.Google.com/generate_204"); err != nil || d != "www.google.com" || u != "https://www.Google.com/generate_204" {
		t.Fatalf("parseCustomCheckTarget(url) = %q %q %v", d, u, err)
	}
	if _, _, err := parseCustomCheckTarget("ftp://example.com"); err == nil {
		t.Fatal("expected ftp URL to be rejected")
	}
}

func TestClassifyRouteAcrossModesAndExceptions(t *testing.T) {
	rules, err := routing.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	bypass, err := buildRouter(routing.Bypass, rules, "custom-direct.example.org", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	global, err := buildRouter(routing.Global, rules, "custom-direct.example.org", nil, false)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	// Bypass CN: domestic sites & domestic IP checkers go direct; overseas go proxy.
	for _, dom := range []string{"www.baidu.com", "www.bilibili.com", "myip.ipip.net", "4.ipw.cn", "custom-direct.example.org"} {
		route, _ := classifyRoute(ctx, dom, nil, bypass)
		if route != "direct" {
			t.Errorf("bypass_cn: %s route = %q, want direct", dom, route)
		}
	}
	for _, dom := range []string{"www.google.com", "www.youtube.com", "github.com", "api.ipify.org", "api-ipv4.ip.sb"} {
		route, _ := classifyRoute(ctx, dom, nil, bypass)
		if route != "proxy" {
			t.Errorf("bypass_cn: %s route = %q, want proxy", dom, route)
		}
	}

	// Global: domestic sites & domestic IP checkers go proxy; only explicit exceptions stay direct.
	for _, dom := range []string{"www.baidu.com", "myip.ipip.net", "4.ipw.cn", "www.google.com", "api.ipify.org"} {
		route, _ := classifyRoute(ctx, dom, nil, global)
		if route != "proxy" {
			t.Errorf("global: %s route = %q, want proxy", dom, route)
		}
	}
	if route, _ := classifyRoute(ctx, "custom-direct.example.org", nil, global); route != "direct" {
		t.Errorf("global exception route = %q, want direct", route)
	}
}

func TestFillExitKind(t *testing.T) {
	exit := ExitIPInfo{DirectIP: "114.114.114.114", ProxyIP: "203.0.113.9"}

	item := SiteCheckItem{Route: "proxy"}
	fillExitKind(&item, exit)
	if item.ExitIP != "203.0.113.9" || item.ExitKind != "proxy" {
		t.Fatalf("expected inferred proxy exit, got %+v", item)
	}

	// Verified echo response showing local IP despite proxy route must flag "direct".
	leak := SiteCheckItem{Route: "proxy", ExitIP: "114.114.114.114", VerifiedIP: true}
	fillExitKind(&leak, exit)
	if leak.ExitKind != "direct" {
		t.Fatalf("expected leak exit_kind=direct, got %+v", leak)
	}
}
