package routing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltinEnterpriseCoverage(t *testing.T) {
	r, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"qq.com", "weixin.qq.com", "wechat.com", "qpic.cn", "gtimg.com", "tencent.com", "aliyun.com", "alibaba.com", "taobao.com", "tmall.com", "alipay.com", "alicdn.com", "baidu.com", "bdstatic.com", "jd.com", "360buyimg.com", "bilibili.com", "hdslb.com", "163.com", "126.com", "netease.com", "douyin.com", "bytedance.com", "byteimg.com", "xiaomi.com", "mi.com", "huawei.com", "huaweicloud.com", "meituan.com", "dianping.com", "pinduoduo.com", "pddpic.com", "icbc.com.cn", "ccb.com", "boc.cn", "cmbchina.com", "unionpay.com"} {
		t.Run(domain, func(t *testing.T) {
			if !r.MatchDomain(domain) {
				t.Errorf("enterprise domain missing: %s", domain)
			}
		})
	}
	for _, ip := range []string{"223.5.5.5", "119.29.29.29", "180.76.76.76", "2400:3200::1"} {
		if !r.MatchIP(netip.MustParseAddr(ip)) {
			t.Errorf("CN IP missed: %s", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if r.MatchIP(netip.MustParseAddr(ip)) {
			t.Errorf("foreign IP matched: %s", ip)
		}
	}
}
func TestDomainBoundariesAndExceptions(t *testing.T) {
	r, err := Parse([]byte("qq.com\nfull:exact.example\nregexp:^node[0-9]+\\.test$"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"qq.com", "A.QQ.COM.", "exact.example", "node123.test"} {
		if !r.MatchDomain(d) {
			t.Fatal(d)
		}
	}
	for _, d := range []string{"fakeqq.com", "qq.com.attacker.example", "sub.exact.example", "notnode123.test", "https://qq.com"} {
		if r.MatchDomain(d) {
			t.Fatal(d)
		}
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "https://qq.com/a", "qq.com:443", "*"} {
		if _, _, e := ParseExceptions(bad); e == nil {
			t.Fatal("accepted", bad)
		}
	}
	extra, normalized, err := ParseExceptions("*.example.cn,192.168.1.7/24\n1.2.3.4")
	if err != nil || len(normalized) != 3 || !extra.MatchDomain("a.example.cn") || !extra.MatchIP(netip.MustParseAddr("192.168.1.8")) {
		t.Fatal(normalized, err)
	}
}
func TestRoutingUsesAllAddressesAndDoesNotResolveKnownRules(t *testing.T) {
	rules, e := Builtin()
	if e != nil {
		t.Fatal(e)
	}
	r, e := New(rules, "private.example")
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	r.Lookup = func(context.Context, string) ([]netip.Addr, error) { calls++; return nil, errors.New("DNS offline") }
	for _, host := range []string{"qq.com:443", "private.example:443", "127.0.0.1:80", "[::1]:80", "223.5.5.5:53"} {
		if !r.Decide(context.Background(), host).Direct {
			t.Fatal(host)
		}
	}
	if r.Decide(context.Background(), "google.com:443").Direct || calls != 0 {
		t.Fatal("known rule invoked DNS")
	}
	for _, tc := range []struct {
		ips  []string
		want bool
	}{{[]string{"223.5.5.5", "119.29.29.29"}, true}, {[]string{"223.5.5.5", "1.1.1.1"}, false}, {[]string{"127.0.0.1"}, false}, {nil, false}} {
		r, _ = New(rules, "")
		r.Lookup = func(context.Context, string) ([]netip.Addr, error) {
			var a []netip.Addr
			for _, ip := range tc.ips {
				a = append(a, netip.MustParseAddr(ip))
			}
			return a, nil
		}
		d := r.Decide(context.Background(), "unknown-snapshot-domain.example:443")
		if d.Direct != tc.want {
			t.Fatal(tc, d)
		}
	}
}
func TestSnapshotIntegrityAndFallback(t *testing.T) {
	s := Snapshot{Files: map[string]string{}}
	b, _ := data.ReadFile("data/manifest.json")
	if e := json.Unmarshal(b, &s.Sources); e != nil {
		t.Fatal(e)
	}
	for _, src := range s.Sources {
		b, _ = data.ReadFile("data/" + src.File)
		s.Files[src.File] = string(b)
	}
	r, e := s.Parse()
	if e != nil || r.proxy == nil {
		t.Fatal(e)
	}
	s.Files["proxy-list.txt"] += "\nnew-proxy.example"
	if _, e = s.Parse(); e == nil {
		t.Fatal("tamper accepted")
	}
	sum := sha256.Sum256([]byte(s.Files["proxy-list.txt"]))
	for i := range s.Sources {
		if s.Sources[i].File == "proxy-list.txt" {
			s.Sources[i].SHA256 = hex.EncodeToString(sum[:])
		}
	}
	r, e = s.Parse()
	if e != nil || !r.proxy.MatchDomain("new-proxy.example") {
		t.Fatal("proxy rules not refreshed", e)
	}
	s.Sources[0] = s.Sources[1]
	if _, e = s.Parse(); e == nil {
		t.Fatal("duplicate manifest accepted")
	}
	file := filepath.Join(t.TempDir(), "rules.json")
	os.WriteFile(file, []byte(`{"files":{}}`), 0600)
	r, info, e := Load(file)
	if e != nil || !r.MatchDomain("qq.com") || !strings.Contains(info["warning"].(string), "内置") {
		t.Fatal(info, e)
	}
}
