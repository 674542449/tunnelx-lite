package client

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"github.com/674542449/tunnelx-lite/internal/systemproxy"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

//go:embed ui.html
var uiHTML string

type UI struct {
	Mux      *Mux
	Proxy    *systemproxy.Manager
	HTTP     *http.Server
	Shutdown func()
	csrf     string
	host     string
}

func (u *UI) Start() error {
	u.csrf = rand.Text()
	u.host = u.Mux.Config.WebListen
	ln, e := net.Listen("tcp", u.host)
	if e != nil {
		return e
	}
	u.HTTP = &http.Server{Handler: u, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	go u.HTTP.Serve(ln)
	return nil
}
func (u *UI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host != u.host {
		http.Error(w, "Forbidden", 403)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+u.csrf+"'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
	if r.URL.Path == "/" && r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, strings.ReplaceAll(uiHTML, "__NONCE__", u.csrf))
		return
	}
	if r.URL.Path == "/api/status" && r.Method == "GET" {
		s := &u.Mux.Stats
		json.NewEncoder(w).Encode(map[string]any{"server": u.Mux.Config.ServerIP, "name": u.Mux.Config.ServerName, "mode": u.Mux.Mode(), "tcp_carrier": u.Mux.LastTCP.Load(), "privacy": u.Mux.Config.Privacy, "ech": u.Mux.LastECH.Load(), "system_proxy": u.Proxy.Enabled(), "socks": u.Mux.Config.SOCKSListen, "http": u.Mux.Config.HTTPListen, "active": s.Active.Load(), "uploaded": s.Uploaded.Load(), "downloaded": s.Downloaded.Load(), "udp_dropped": s.UDPDropped.Load(), "h2_streams": s.H2Streams.Load(), "logging": u.Mux.LoggingStatus(), "client_version": "v0.4.0", "h2_retries": s.H2Retries.Load()})
		return
	}
	if r.Method != "POST" || r.Header.Get("Origin") != "http://"+u.host || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(u.csrf)) != 1 {
		http.Error(w, "Forbidden", 403)
		return
	}
	var e error
	switch r.URL.Path {
	case "/api/proxy/enable":
		e = u.Proxy.Enable()
	case "/api/proxy/restore":
		e = u.Proxy.Restore()
	case "/api/probe":
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		var res *http.Response
		res, e = u.Mux.PublicGET(ctx)
		if e == nil {
			io.Copy(io.Discard, io.LimitReader(res.Body, 8192))
			res.Body.Close()
			if res.StatusCode != 200 {
				http.Error(w, "Public service check failed", 502)
				return
			}
		}
	case "/api/exit":
		if e = u.Proxy.Restore(); e == nil {
			time.AfterFunc(300*time.Millisecond, u.Shutdown)
		}
	default:
		http.NotFound(w, r)
		return
	}
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}
