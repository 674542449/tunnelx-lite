package app

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/674542449/tunnelx-lite/internal/fsutil"
	"github.com/674542449/tunnelx-lite/internal/share"
)

// Server is one imported share link. Tokens stay inside the DPAPI-protected file.
type Server struct {
	ID      string     `json:"id"`
	Link    share.Link `json:"link"`
	AddedAt int64      `json:"added_at"`
}

// ServerView is what the UI sees: everything except the secret token.
type ServerView struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Family string `json:"family"`
}

const serversFile = "servers.dpapi"

func (e *Engine) loadServers() error {
	b, err := os.ReadFile(e.statePath(serversFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	plain, err := unprotect(b)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, &e.servers)
}

func (e *Engine) saveServersLocked(list []Server) error {
	b, _ := json.Marshal(list)
	b, err := protect(b)
	if err != nil {
		return err
	}
	if err = fsutil.WriteFile(e.statePath(serversFile), b); err != nil {
		return err
	}
	e.servers = list
	return nil
}

func (e *Engine) findLocked(id string) *Server {
	for i := range e.servers {
		if e.servers[i].ID == id {
			return &e.servers[i]
		}
	}
	return nil
}

func view(s Server) ServerView {
	family := "域名"
	if strings.Contains(s.Link.Host, ":") {
		family = "IPv6"
	} else if strings.Count(s.Link.Host, ".") == 3 && strings.Trim(s.Link.Host, "0123456789.") == "" {
		family = "IPv4"
	}
	return ServerView{ID: s.ID, Name: s.Link.Name, Host: s.Link.Host, Port: s.Link.Port, Family: family}
}

func (e *Engine) Servers() []ServerView {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]ServerView, 0, len(e.servers))
	for _, s := range e.servers {
		out = append(out, view(s))
	}
	return out
}

// Import accepts one or more links separated by whitespace. A link for a
// server already in the list (same host, port and key) updates its name.
func (e *Engine) Import(text string) (added int, updated int, err error) {
	var links []share.Link
	for _, field := range strings.Fields(text) {
		if !strings.HasPrefix(strings.ToLower(field), share.Scheme+"://") {
			continue
		}
		l, perr := share.Parse(field)
		if perr != nil {
			return 0, 0, perr
		}
		links = append(links, l)
	}
	if len(links) == 0 {
		return 0, 0, errors.New("没有找到 txlite:// 分享链接，请从服务器面板复制完整链接后再粘贴")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	list := append([]Server(nil), e.servers...)
	for _, l := range links {
		found := false
		for i := range list {
			if list[i].Link.Host == l.Host && list[i].Link.Port == l.Port && list[i].Link.Token == l.Token {
				list[i].Link = l
				found = true
				updated++
				break
			}
		}
		if !found {
			if len(list) >= 200 {
				return 0, 0, errors.New("最多保存 200 个服务器")
			}
			id := make([]byte, 16)
			rand.Read(id)
			list = append(list, Server{ID: hex.EncodeToString(id), Link: l, AddedAt: time.Now().Unix()})
			added++
		}
	}
	if err = e.saveServersLocked(list); err != nil {
		return 0, 0, err
	}
	if e.preferences.SelectedID == "" || e.findLocked(e.preferences.SelectedID) == nil {
		p := e.preferences
		p.SelectedID = list[len(list)-1].ID
		_ = e.savePreferencesLocked(p)
	}
	return added, updated, nil
}

func (e *Engine) Rename(id, name string) error {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 64 {
		return errors.New("名称需要 1 到 64 个字符")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	list := append([]Server(nil), e.servers...)
	for i := range list {
		if list[i].ID == id {
			list[i].Link.Name = name
			return e.saveServersLocked(list)
		}
	}
	return errors.New("服务器不存在")
}

func (e *Engine) Remove(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.nodeID == id && (e.mux != nil || e.connecting) {
		return errors.New("请先断开这个服务器再删除")
	}
	list := make([]Server, 0, len(e.servers))
	for _, s := range e.servers {
		if s.ID != id {
			list = append(list, s)
		}
	}
	if len(list) == len(e.servers) {
		return errors.New("服务器不存在")
	}
	if err := e.saveServersLocked(list); err != nil {
		return err
	}
	if e.preferences.SelectedID == id {
		p := e.preferences
		p.SelectedID = ""
		if len(list) > 0 {
			p.SelectedID = list[0].ID
		}
		_ = e.savePreferencesLocked(p)
	}
	return nil
}

// ShareLink returns the original link so it can be copied to another device.
func (e *Engine) ShareLink(id string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s := e.findLocked(id); s != nil {
		return s.Link.String(), nil
	}
	return "", errors.New("服务器不存在")
}
