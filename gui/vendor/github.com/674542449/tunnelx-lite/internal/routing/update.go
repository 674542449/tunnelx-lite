package routing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"time"
)

type Source struct {
	Source string `json:"source"`
	SHA256 string `json:"sha256"`
	File   string `json:"file"`
}
type Snapshot struct {
	UpdatedAt int64             `json:"updated_at"`
	Files     map[string]string `json:"files"`
	Sources   []Source          `json:"sources"`
}

func (s Snapshot) Parse() (*Rules, error) {
	required := map[string]bool{"direct-list.txt": true, "proxy-list.txt": true, "china.txt": true, "china6.txt": true}
	for _, src := range s.Sources {
		if !required[src.File] {
			return nil, errors.New("规则文件重复或未知")
		}
		delete(required, src.File)
		b, ok := s.Files[src.File]
		sum := sha256.Sum256([]byte(b))
		if !ok || hex.EncodeToString(sum[:]) != src.SHA256 {
			return nil, errors.New("规则快照校验失败")
		}
	}
	if len(s.Sources) != 4 {
		return nil, errors.New("规则快照不完整")
	}
	r, e := Parse([]byte(s.Files["direct-list.txt"]), []byte(s.Files["china.txt"]+"\n"+s.Files["china6.txt"]))
	if e != nil {
		return nil, e
	}
	r.proxy, e = Parse([]byte(s.Files["proxy-list.txt"]), nil)
	if e != nil {
		return nil, e
	}
	if len(r.suffix) < 1000 || len(r.prefixes) < 1000 || len(r.proxy.suffix) < 100 {
		return nil, errors.New("规则数量异常，保留原有规则")
	}
	return r, nil
}
func Load(path string) (*Rules, map[string]any, error) {
	r, e := Builtin()
	if e != nil {
		return nil, nil, e
	}
	info := map[string]any{"source": "builtin", "domains": len(r.suffix) + len(r.exact), "ip_prefixes": len(r.prefixes), "sources": Metadata()}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return r, info, nil
	}
	if err != nil {
		info["warning"] = "规则快照未能读取，使用内置规则"
		return r, info, nil
	}
	var s Snapshot
	if len(b) > 24<<20 || json.Unmarshal(b, &s) != nil {
		info["warning"] = "规则快照无效，使用内置规则"
		return r, info, nil
	}
	updated, err := s.Parse()
	if err != nil {
		info["warning"] = err.Error() + "，使用内置规则"
		return r, info, nil
	}
	return updated, map[string]any{"source": "updated", "updated_at": s.UpdatedAt, "domains": len(updated.suffix) + len(updated.exact), "ip_prefixes": len(updated.prefixes), "sources": s.Sources}, nil
}
func Download(ctx context.Context, h *http.Client) (Snapshot, error) {
	s := Snapshot{UpdatedAt: time.Now().Unix(), Files: map[string]string{}}
	get := func(url string, limit int64) ([]byte, error) {
		req, e := http.NewRequestWithContext(ctx, "GET", url, nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("User-Agent", "tunnelX-routing")
		res, e := h.Do(req)
		if e != nil {
			return nil, e
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return nil, errors.New("GitHub 规则源暂时不可用")
		}
		b, e := io.ReadAll(io.LimitReader(res.Body, limit+1))
		if e == nil && int64(len(b)) > limit {
			e = errors.New("规则文件超过大小限制")
		}
		return b, e
	}
	for _, src := range []struct {
		repo, branch string
		files        []string
	}{{"Loyalsoldier/v2ray-rules-dat", "release", []string{"direct-list.txt", "proxy-list.txt"}}, {"gaoyifan/china-operator-ip", "ip-lists", []string{"china.txt", "china6.txt"}}} {
		b, e := get("https://api.github.com/repos/"+src.repo+"/commits/"+src.branch, 2<<20)
		if e != nil {
			return s, e
		}
		var c struct {
			SHA string `json:"sha"`
		}
		if json.Unmarshal(b, &c) != nil || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(c.SHA) {
			return s, errors.New("规则版本无效")
		}
		for _, name := range src.files {
			url := "https://raw.githubusercontent.com/" + src.repo + "/" + c.SHA + "/" + name
			b, e = get(url, 8<<20)
			if e != nil {
				return s, e
			}
			sum := sha256.Sum256(b)
			s.Files[name] = string(b)
			s.Sources = append(s.Sources, Source{url, hex.EncodeToString(sum[:]), name})
		}
	}
	_, e := s.Parse()
	return s, e
}
