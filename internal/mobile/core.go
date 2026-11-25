// Package mobile wraps internal/app.Engine with a single JSON RPC dispatcher
// shared by the Android JNI library and desktop/unit tests.
package mobile

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/674542449/tunnelx-lite/internal/app"
)

type Service struct {
	mu     sync.RWMutex
	engine *app.Engine
}

var defaultSvc Service

// Init initializes the global mobile Engine singleton using dataDir and local
// loopback SOCKS5/HTTP proxy addresses. Safe to call multiple times (idempotent).
func Init(dataDir, socksAddr, httpAddr string) error {
	return defaultSvc.Init(dataDir, socksAddr, httpAddr)
}

// Call executes a JSON-encoded command against the global Engine singleton.
func Call(action string, payload []byte) []byte {
	return defaultSvc.Call(action, payload)
}

func (s *Service) Init(dataDir, socksAddr, httpAddr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine != nil {
		return nil
	}
	if dataDir == "" {
		return errors.New("data_dir 不能为空")
	}
	if socksAddr == "" {
		socksAddr = "127.0.0.1:10808"
	}
	if httpAddr == "" {
		httpAddr = "127.0.0.1:10809"
	}
	eng, err := app.New(dataDir, app.Settings{
		SOCKS: socksAddr,
		HTTP:  httpAddr,
		Web:   "127.0.0.1:0",
	})
	if err != nil {
		return err
	}
	s.engine = eng
	return nil
}

func (s *Service) Close() error {
	s.mu.Lock()
	eng := s.engine
	s.engine = nil
	s.mu.Unlock()
	if eng != nil {
		return eng.Close()
	}
	return nil
}

func (s *Service) getEngine() (*app.Engine, error) {
	s.mu.RLock()
	eng := s.engine
	s.mu.RUnlock()
	if eng == nil {
		return nil, errors.New("内核尚未初始化")
	}
	return eng, nil
}

type rpcResponse struct {
	OK    bool   `json:"ok"`
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

func okJSON(data any) []byte {
	b, _ := json.Marshal(rpcResponse{OK: true, Data: data})
	return b
}

func errJSON(err error) []byte {
	msg := "操作失败"
	if err != nil {
		msg = err.Error()
	}
	b, _ := json.Marshal(rpcResponse{OK: false, Error: msg})
	return b
}

func decodePayload(raw []byte, dst any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, dst)
}

// Call routes an action + UTF-8 JSON payload to Engine and always returns a
// valid UTF-8 JSON rpcResponse.
func (s *Service) Call(action string, payload []byte) []byte {
	eng, err := s.getEngine()
	if err != nil {
		return errJSON(err)
	}
	switch action {
	case "status":
		return okJSON(eng.Status())

	case "servers":
		return okJSON(eng.Servers())

	case "import":
		var req struct {
			Text string `json:"text"`
		}
		if err := decodePayload(payload, &req); err != nil {
			return errJSON(err)
		}
		added, updated, err := eng.Import(req.Text)
		if err != nil {
			return errJSON(err)
		}
		return okJSON(map[string]int{"added": added, "updated": updated})

	case "rename":
		var req struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := decodePayload(payload, &req); err != nil {
			return errJSON(err)
		}
		if err := eng.Rename(req.ID, req.Name); err != nil {
			return errJSON(err)
		}
		return okJSON(true)

	case "remove":
		var req struct {
			ID string `json:"id"`
		}
		if err := decodePayload(payload, &req); err != nil {
			return errJSON(err)
		}
		if err := eng.Remove(req.ID); err != nil {
			return errJSON(err)
		}
		return okJSON(true)

	case "share_link":
		var req struct {
			ID string `json:"id"`
		}
		if err := decodePayload(payload, &req); err != nil {
			return errJSON(err)
		}
		link, err := eng.ShareLink(req.ID)
		if err != nil {
			return errJSON(err)
		}
		return okJSON(map[string]string{"link": link})

	case "select":
		var req struct {
			ID string `json:"id"`
		}
		if err := decodePayload(payload, &req); err != nil {
			return errJSON(err)
		}
		if err := eng.SavePreferences(req.ID); err != nil {
			return errJSON(err)
		}
		return okJSON(true)

	case "connect":
		var req struct {
			ID         string   `json:"id"`
			DNSServers []string `json:"dns_servers"`
		}
		if err := decodePayload(payload, &req); err != nil {
			return errJSON(err)
		}
		if err := eng.ConnectExternalTUN(req.ID, req.DNSServers); err != nil {
			return errJSON(err)
		}
		return okJSON(true)

	case "disconnect":
		if err := eng.Disconnect(); err != nil {
			return errJSON(err)
		}
		return okJSON(true)

	case "cancel":
		_ = eng.CancelConnect()
		return okJSON(true)

	case "update_dns":
		var req struct {
			DNSServers []string `json:"dns_servers"`
		}
		if err := decodePayload(payload, &req); err != nil {
			return errJSON(err)
		}
		eng.UpdateExternalDNS(req.DNSServers)
		return okJSON(true)

	case "probe":
		var req struct {
			ID string `json:"id"`
		}
		if err := decodePayload(payload, &req); err != nil {
			return errJSON(err)
		}
		ms, err := eng.Probe(req.ID)
		if err != nil {
			return errJSON(err)
		}
		return okJSON(map[string]int64{"ms": ms})

	case "probe_all":
		return okJSON(eng.ProbeAll())

	case "save_mode":
		var req struct {
			Mode          string `json:"mode"`
			DirectDomains string `json:"direct_domains"`
		}
		if err := decodePayload(payload, &req); err != nil {
			return errJSON(err)
		}
		if err := eng.SaveProxyMode(req.Mode, req.DirectDomains); err != nil {
			return errJSON(err)
		}
		return okJSON(true)

	case "save_dns":
		var req struct {
			Enabled  bool   `json:"enabled"`
			Domestic string `json:"domestic"`
			Remote   string `json:"remote"`
		}
		if err := decodePayload(payload, &req); err != nil {
			return errJSON(err)
		}
		if err := eng.SaveDNS(req.Enabled, req.Domestic, req.Remote); err != nil {
			return errJSON(err)
		}
		return okJSON(true)

	case "save_transport":
		var req struct {
			Transport string `json:"transport"`
		}
		if err := decodePayload(payload, &req); err != nil {
			return errJSON(err)
		}
		if err := eng.SaveTransport(req.Transport); err != nil {
			return errJSON(err)
		}
		return okJSON(true)

	case "update_rules":
		if err := eng.UpdateRoutingRules(); err != nil {
			return errJSON(err)
		}
		return okJSON(true)

	case "check_sites":
		return okJSON(eng.CheckSites())

	case "check_domain":
		var req struct {
			Domain string `json:"domain"`
		}
		if err := decodePayload(payload, &req); err != nil {
			return errJSON(err)
		}
		item, err := eng.CheckDomain(req.Domain)
		if err != nil {
			return errJSON(err)
		}
		return okJSON(item)

	default:
		return errJSON(errors.New("未知操作：" + action))
	}
}
