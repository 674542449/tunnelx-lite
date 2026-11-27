package client

import (
	"context"
	"errors"
	"time"

	"github.com/674542449/tunnelx-lite/internal/pulse"
)

// PacketTransport 是代理 UDP 转发流的通用接口（兼容 HTTP/2 Capsule 与 TXPulse 原生分片 UDP）。
type PacketTransport interface {
	Send([]byte) error
	Receive(context.Context) ([]byte, error)
	Close() error
}

// IsPulse 报告当前 Mux 是否运行在自研类 Hy2 UDP 协议（TXPulse）上。
func (m *Mux) IsPulse() bool {
	return m.Config.Transport == "pulse" || m.Config.Protocol == "txpulse"
}

func (m *Mux) pulseClient() (*pulse.Client, error) {
	m.pulseMu.Lock()
	defer m.pulseMu.Unlock()
	if m.closed {
		return nil, errors.New("client closed")
	}
	if m.pulse != nil {
		return m.pulse, nil
	}
	pc, err := pulse.NewClient(pulse.ClientConfig{
		ServerIP:       m.Config.ServerIP,
		Port:           m.Config.Port,
		HopStart:       m.Config.HopStart,
		HopEnd:         m.Config.HopEnd,
		Token:          m.Config.Token,
		ObfsKey:        m.Config.ObfsKey,
		CertPin:        m.Config.CertPin,
		DesiredDownBPS: m.Config.PulseDownBPS,
		DesiredUpBPS:   m.Config.PulseUpBPS,
		ConnectTimeout: m.Config.Timeout(),
		Control:        uplinkControl(m.uplinkIfV4, m.uplinkIfV6),
	})
	if err != nil {
		return nil, err
	}
	m.pulse = pc
	return pc, nil
}

// EnsurePulseSession 建立并验证 TXPulse 加密会话（1-RTT X25519 + 自签证书指纹校验）。
func (m *Mux) EnsurePulseSession(ctx context.Context) error {
	pc, err := m.pulseClient()
	if err != nil {
		return err
	}
	_, err = pc.EnsureSession(ctx)
	if err == nil {
		m.Stats.PulseDials.Store(pc.DialCount())
	}
	return err
}

// ProbePulse 执行一次独立的 1-RTT 认证探活（校验自签证书指纹 + Token），不影响已有长连接。
func (m *Mux) ProbePulse(ctx context.Context) (time.Duration, error) {
	pc, err := pulse.NewClient(pulse.ClientConfig{
		ServerIP:       m.Config.ServerIP,
		Port:           m.Config.Port,
		Token:          m.Config.Token,
		ObfsKey:        m.Config.ObfsKey,
		CertPin:        m.Config.CertPin,
		ConnectTimeout: m.Config.Timeout(),
		Control:        uplinkControl(m.uplinkIfV4, m.uplinkIfV6),
	})
	if err != nil {
		return 0, err
	}
	defer pc.Close()
	return pc.Probe(ctx)
}

// PulseStats 返回当前 TXPulse 会话的拥塞控制指标（RTT / 丢包率 / HyBBR 速率）。
func (m *Mux) PulseStats() pulse.CCStats {
	m.pulseMu.Lock()
	pc := m.pulse
	m.pulseMu.Unlock()
	if pc == nil {
		return pulse.CCStats{}
	}
	return pc.CCStats()
}

// MigratePulse 在移动网络 Wi-Fi <-> 5G 切换时主动重建底层 UDP Socket 并保持所有活跃流不断线。
func (m *Mux) MigratePulse(ctx context.Context) error {
	m.pulseMu.Lock()
	pc := m.pulse
	m.pulseMu.Unlock()
	if pc == nil {
		return nil
	}
	return pc.MigrateSocket(ctx)
}

func (m *Mux) openPulseTCP(ctx context.Context, target string, waitAck bool) (*Tunnel, error) {
	pc, err := m.pulseClient()
	if err != nil {
		return nil, err
	}
	st, err := pc.OpenStream(ctx, target, waitAck)
	if err != nil {
		var oe *pulse.OpenStreamError
		if errors.As(err, &oe) {
			status := 502
			switch oe.Status {
			case pulse.OpenStatusForbidden:
				status = 403
			case pulse.OpenStatusTimeout:
				status = 504
			}
			return nil, &RequestError{Status: status, Known: true}
		}
		return nil, err
	}
	m.Stats.PulseStreams.Add(1)
	m.Stats.PulseDials.Store(pc.DialCount())
	t := &Tunnel{
		Reader:      st,
		Writer:      st,
		closeWrite:  st.CloseWrite,
		close:       st.Close,
		setDeadline: st.SetDeadline,
		transport:   "txpulse",
		carrierID:   "pulse",
	}
	flowFrom(ctx).openedOn(t)
	return t, nil
}

func (m *Mux) openPulseUDP(ctx context.Context, target string) (PacketTransport, error) {
	pc, err := m.pulseClient()
	if err != nil {
		return nil, err
	}
	u, err := pc.OpenUDP(ctx, target)
	if err != nil {
		return nil, err
	}
	m.Stats.PulseDials.Store(pc.DialCount())
	flowFrom(ctx).openedOn(&Tunnel{transport: "txpulse", carrierID: "pulse"})
	return u, nil
}

func (m *Mux) closePulse() {
	m.pulseMu.Lock()
	pc := m.pulse
	m.pulse = nil
	m.pulseMu.Unlock()
	if pc != nil {
		_ = pc.Close()
	}
}
