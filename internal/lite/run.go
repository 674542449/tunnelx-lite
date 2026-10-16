package lite

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/674542449/tunnelx-lite/internal/config"
	"github.com/674542449/tunnelx-lite/internal/server"
)

type traffic struct {
	Uploaded   int64 `json:"uploaded"`
	Downloaded int64 `json:"downloaded"`
}

// Runtime owns the running proxy and serves the owner panel.
type Runtime struct {
	Dir     Dir
	Restart func() // replaced in tests; systemd restarts the process
	mu      sync.Mutex
	cfg     Config
	id      Identity
	srv     *server.Server
	started time.Time
	base    traffic // persisted totals minus what srv has counted in this run
	logs    *ring
	auth    sessions
	// proxyErr is set when the proxy listener could not start; the panel keeps
	// running so the owner can pick another port or inbound family.
	proxyErr atomic.Value
	quicErr  atomic.Value
}

func Open(d Dir) (*Runtime, error) {
	c, e := Load(d)
	if e != nil {
		return nil, e
	}
	id, e := LoadIdentity(d)
	if e != nil {
		return nil, e
	}
	srv, e := server.New(c.Server(d))
	if e != nil {
		return nil, e
	}
	r := &Runtime{Dir: d, cfg: c, id: id, srv: srv, started: time.Now(), logs: newRing(300), auth: newSessions()}
	r.Restart = func() { r.persist(); os.Exit(0) }
	var t traffic
	if config.Read(d.Traffic(), &t) == nil {
		r.base = t
	}
	return r, nil
}

// ProxyError is empty while the proxy listener is serving.
func (r *Runtime) ProxyError() string { s, _ := r.proxyErr.Load().(string); return s }

// QUICError is empty while QUIC is serving or switched off. TCP keeps working
// either way and clients in auto mode fall back to it.
func (r *Runtime) QUICError() string { s, _ := r.quicErr.Load().(string); return s }

func (r *Runtime) Totals() traffic {
	r.mu.Lock()
	defer r.mu.Unlock()
	return traffic{r.base.Uploaded + r.srv.Uploaded.Load(), r.base.Downloaded + r.srv.Downloaded.Load()}
}

func (r *Runtime) persist() {
	b, _ := json.Marshal(r.Totals())
	if e := writeFile(r.Dir.Traffic(), b); e != nil {
		log.Print("流量统计保存失败：", e)
	}
}

func (r *Runtime) resetTraffic() {
	r.mu.Lock()
	r.base = traffic{-r.srv.Uploaded.Load(), -r.srv.Downloaded.Load()}
	r.mu.Unlock()
	r.persist()
}

// Run serves the proxy and the panel until ctx ends or either listener fails.
func (r *Runtime) Run(ctx context.Context) error {
	log.SetOutput(io.MultiWriter(os.Stderr, r.logs))
	cert, e := tls.LoadX509KeyPair(r.Dir.Cert(), r.Dir.Key())
	if e != nil {
		return e
	}
	panel := &http.Server{Addr: ":" + strconv.Itoa(r.cfg.PanelPort), Handler: r, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}, ErrorLog: log.New(io.Discard, "", 0)}
	proxyErrs, errs := make(chan error, 1), make(chan error, 1)
	go func() { proxyErrs <- r.srv.Serve(ctx) }()
	if r.srv.Config.QUIC {
		go func() {
			if e := r.srv.ServeQUIC(ctx); e != nil && ctx.Err() == nil {
				msg := fmt.Sprintf("QUIC（UDP %d）启动失败：%v。客户端会自动改用 TCP", r.cfg.Port, e)
				r.quicErr.Store(msg)
				log.Print(msg)
			}
		}()
	}
	go func() { errs <- panel.ListenAndServeTLS("", "") }()
	quic := "关闭"
	if r.srv.Config.QUIC {
		quic = "UDP " + strconv.Itoa(r.cfg.Port)
	}
	log.Printf("txlite %s 已启动：代理端口 %d，QUIC %s，面板端口 %d", Version, r.cfg.Port, quic, r.cfg.PanelPort)
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			panel.Close()
			r.persist()
			return nil
		case e = <-proxyErrs:
			if ctx.Err() != nil {
				continue
			}
			if e == nil {
				e = errors.New("listener stopped")
			}
			msg := fmt.Sprintf("代理端口 %d 启动失败：%v。面板仍可使用，请在设置里更换端口或入站方式", r.cfg.Port, e)
			r.proxyErr.Store(msg)
			log.Print(msg)
		case e = <-errs:
			panel.Close()
			r.persist()
			if e == nil || errors.Is(e, http.ErrServerClosed) {
				e = errors.New("listener stopped")
			}
			return e
		case <-tick.C:
			r.persist()
		}
	}
}

// ring keeps the most recent log lines for the panel.
type ring struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func newRing(n int) *ring { return &ring{max: n} }

func (g *ring) Write(p []byte) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		g.lines = append(g.lines, line)
	}
	if len(g.lines) > g.max {
		g.lines = append([]string(nil), g.lines[len(g.lines)-g.max:]...)
	}
	return len(p), nil
}

func (g *ring) Lines() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.lines...)
}
