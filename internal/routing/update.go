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
	required := map[string]bool{}
	for _, name := range ruleFiles {
		required[name] = true
	}
	files := map[string][]byte{}
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
		files[src.File] = []byte(b)
	}
	if len(required) != 0 {
		return nil, errors.New("规则快照不完整")
	}
	return assemble(files)
}

// legacy reports a snapshot saved by an earlier release with other rule sources.
func (s Snapshot) legacy() bool {
	for _, src := range s.Sources {
		if src.File == "direct-list.txt" || src.File == "china.txt" {
			return true
		}
	}
	return false
}

func Load(path string) (*Rules, map[string]any, error) {
	r, e := Builtin()
	if e != nil {
		return nil, nil, e
	}
	domains, prefixes := r.Counts()
	info := map[string]any{"source": "builtin", "domains": domains, "ip_prefixes": prefixes, "sources": Metadata()}
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
	if s.legacy() {
		return r, info, nil
	}
	updated, err := s.Parse()
	if err != nil {
		info["warning"] = err.Error() + "，使用内置规则"
		return r, info, nil
	}
	domains, prefixes = updated.Counts()
	return updated, map[string]any{"source": "updated", "updated_at": s.UpdatedAt, "domains": domains, "ip_prefixes": prefixes, "sources": s.Sources}, nil
}
func Download(ctx context.Context, h *http.Client) (Snapshot, error) {
	s := Snapshot{UpdatedAt: time.Now().Unix(), Files: map[string]string{}}
	get := func(url string, limit int64) ([]byte, error) {
		req, e := http.NewRequestWithContext(ctx, "GET", url, nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("User-Agent", "txlite-routing")
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
	b, e := get("https://api.github.com/repos/MetaCubeX/meta-rules-dat/commits/meta", 2<<20)
	if e != nil {
		return s, e
	}
	var c struct {
		SHA string `json:"sha"`
	}
	if json.Unmarshal(b, &c) != nil || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(c.SHA) {
		return s, errors.New("规则版本无效")
	}
	paths := map[string]string{"geosite-cn.list": "geosite/cn.list", "geosite-geolocation-not-cn.list": "geosite/geolocation-!cn.list", "geosite-private.list": "geosite/private.list", "geoip-cn.list": "geoip/cn.list", "geoip-private.list": "geoip/private.list"}
	for _, name := range ruleFiles {
		url := "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/" + c.SHA + "/geo/" + paths[name]
		b, e = get(url, 8<<20)
		if e != nil {
			return s, e
		}
		sum := sha256.Sum256(b)
		s.Files[name] = string(b)
		s.Sources = append(s.Sources, Source{url, hex.EncodeToString(sum[:]), name})
	}
	_, e = s.Parse()
	return s, e
}
