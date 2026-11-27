package pulse

import (
	"math"
	"time"
)

// congestionController 实现 TXPulse 的自适应混合拥塞控制：
//   - 默认模式（targetBPS == 0）：自适应 HyBBR
//     结合 BBR 的 minRTT + 瓶颈交付率采样与 Hy2 的抗随机丢包补偿：
//       * 当 RTT 接近 minRTT（排队延迟极低）且存在丢包时 -> 判定为跨境随机丢包，不降速并施加有上限的丢包补偿；
//       * 当 RTT 显著高于 minRTT（队列膨胀）时 -> 判定为真实链路拥塞/ISP 限速，温和回落排空队列，避免 Bufferbloat 与封杀；
//       * 周期性 ProbeBW（1.25x）自动探测可用带宽，用户完全无需手填宽带速度。
//   - 弹性 Brutal 模式（targetBPS > 0）：
//     以用户/服务端设定的目标速率为基准做平滑 Pacing + 抗丢包补偿，
//     同时自带拥塞泄压阀（连续严重 RTT 膨胀或极端丢包时温和退让，克服原版 Brutal 盲目打死链路的缺点）。
type congestionController struct {
	targetBPS uint64 // 0 = 自适应 HyBBR；>0 = 弹性 Brutal 上限（字节/秒）
	maxBPS    uint64 // 硬性上限（0 表示不设额外天花板）

	// RTT 估计（RFC 6298 + 窗口化 minRTT）
	hasRTT       bool
	srtt         time.Duration
	rttvar       time.Duration
	minRTT       time.Duration
	minRTTStamp  time.Time
	latestRTT    time.Duration

	// 带宽采样（类似 BBR 的滑动窗口最大交付速率）
	bwSamples    [8]bwSample
	bwIdx        int
	btlBW        float64 // 字节/秒
	inStartup    bool
	startupFull  int
	lastMaxBW    float64
	cycleIdx     int
	cycleStamp   time.Time

	// 滑动交付率窗口（发端 ACK 统计）
	winStart     time.Time
	winAckBytes  uint64
	peerRecvBPS  uint64

	// 滑动丢包率统计（最近窗口内已确认 vs 丢失）
	lossAcked    float64
	lossLost     float64
	lossRate     float64

	// 弹性 Brutal 泄压因子（0.35..1.0）
	brutalScale  float64
	pressureAt   time.Time

	// 发送窗口与平滑令牌桶 Pacer
	pacingRate   float64 // 字节/秒
	cwnd         int64
	tokens       float64
	lastRefill   time.Time
}

type bwSample struct {
	at   time.Time
	rate float64
}

var probeBWGains = [8]float64{1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}

const (
	initialPacingBPS = 8 * 1024 * 1024  // 8 MB/s（64 Mbps）温和起步，Startup 迅速爬升
	minPacingBPS     = 256 * 1024       // 256 KB/s 下限，防止彻底饿死
	maxAutoPacingBPS = 250 * 1024 * 1024 // 2 Gbps 自动模式安全上限
	minCwndBytes     = 48 * 1024
	maxCwndBytes     = 32 * 1024 * 1024
	initialCwndBytes = 128 * 1024
)

func newCongestionController(targetBPS, maxBPS uint64) *congestionController {
	now := time.Now()
	initRate := float64(initialPacingBPS)
	if targetBPS > 0 {
		initRate = float64(targetBPS)
	}
	if maxBPS > 0 && initRate > float64(maxBPS) {
		initRate = float64(maxBPS)
	}
	return &congestionController{
		targetBPS:   targetBPS,
		maxBPS:      maxBPS,
		inStartup:   targetBPS == 0,
		btlBW:       initRate,
		brutalScale: 1.0,
		pacingRate:  initRate,
		cwnd:        initialCwndBytes,
		tokens:      64 * 1024,
		lastRefill:  now,
		winStart:    now,
		cycleStamp:  now,
		minRTTStamp: now,
	}
}

func (c *congestionController) SetTargetBPS(targetBPS, maxBPS uint64) {
	c.targetBPS = targetBPS
	c.maxBPS = maxBPS
	if targetBPS > 0 {
		c.inStartup = false
	}
	c.recompute(time.Now())
}

// OnRTT 更新 RTT 统计（忽略因重传或过长 ackDelay 导致的畸变值）。
func (c *congestionController) OnRTT(sample, ackDelay time.Duration, now time.Time) {
	if sample <= 0 {
		return
	}
	if ackDelay > 0 && ackDelay < sample/2 {
		sample -= ackDelay
	}
	if sample < 200*time.Microsecond {
		sample = 200 * time.Microsecond
	}
	c.latestRTT = sample
	if !c.hasRTT {
		c.hasRTT = true
		c.srtt = sample
		c.rttvar = sample / 2
		c.minRTT = sample
		c.minRTTStamp = now
		return
	}
	diff := c.srtt - sample
	if diff < 0 {
		diff = -diff
	}
	c.rttvar = (3*c.rttvar + diff) / 4
	c.srtt = (7*c.srtt + sample) / 8

	// minRTT 采用 10 秒滑动窗口，既能捕捉真实传播延迟也能适应路由切换。
	if sample <= c.minRTT || now.Sub(c.minRTTStamp) > 10*time.Second {
		c.minRTT = sample
		c.minRTTStamp = now
	}
}

// OnAck 在收到 ACK 确认 ackedBytes / ackedPkts 与对端汇报接收速率时调用。
func (c *congestionController) OnAck(ackedBytes uint64, ackedPkts int, peerRecvBPS uint64, now time.Time) {
	if ackedPkts > 0 {
		c.lossAcked = c.lossAcked*0.92 + float64(ackedPkts)
		c.lossLost = c.lossLost * 0.92
		c.updateLossRate()
	}
	if peerRecvBPS > 0 {
		c.peerRecvBPS = peerRecvBPS
	}
	c.winAckBytes += ackedBytes
	elapsed := now.Sub(c.winStart)
	minWin := c.rttOrDefault()
	if minWin < 40*time.Millisecond {
		minWin = 40 * time.Millisecond
	}
	if minWin > 250*time.Millisecond {
		minWin = 250 * time.Millisecond
	}
	if elapsed >= minWin && c.winAckBytes > 0 {
		localRate := float64(c.winAckBytes) / elapsed.Seconds()
		sampleRate := localRate
		if c.peerRecvBPS > 0 && float64(c.peerRecvBPS) > sampleRate*0.8 {
			// 结合对端实测交付率，避免批量 ACK 造成瞬时虚高。
			sampleRate = math.Min(localRate*1.2, float64(c.peerRecvBPS)*1.05)
		}
		c.recordBW(sampleRate, now)
		c.winStart = now
		c.winAckBytes = 0
	}
	c.recompute(now)
}

// OnLoss 在检测到丢包时更新丢包率，但不会像 CUBIC 那样盲目将 cwnd 砍半。
func (c *congestionController) OnLoss(lostPkts int, now time.Time) {
	if lostPkts <= 0 {
		return
	}
	c.lossLost = c.lossLost*0.92 + float64(lostPkts)
	c.lossAcked = c.lossAcked * 0.92
	c.updateLossRate()
	c.recompute(now)
}

func (c *congestionController) updateLossRate() {
	tot := c.lossAcked + c.lossLost
	if tot < 4 {
		c.lossRate = 0
		return
	}
	c.lossRate = c.lossLost / tot
	if c.lossRate < 0 {
		c.lossRate = 0
	} else if c.lossRate > 0.85 {
		c.lossRate = 0.85
	}
}

func (c *congestionController) recordBW(rate float64, now time.Time) {
	c.bwSamples[c.bwIdx] = bwSample{at: now, rate: rate}
	c.bwIdx = (c.bwIdx + 1) % len(c.bwSamples)

	var maxRate float64
	cutoff := now.Add(-10 * time.Second)
	for _, s := range c.bwSamples {
		if !s.at.IsZero() && s.at.After(cutoff) && s.rate > maxRate {
			maxRate = s.rate
		}
	}
	if maxRate > 0 {
		c.btlBW = maxRate
	}
	if c.inStartup {
		if c.btlBW >= c.lastMaxBW*1.20 {
			c.lastMaxBW = c.btlBW
			c.startupFull = 0
		} else {
			c.startupFull++
			if c.startupFull >= 3 {
				c.inStartup = false
			}
		}
	}
}

func (c *congestionController) recompute(now time.Time) {
	rtt := c.rttOrDefault()
	minRTT := c.minRTT
	if minRTT <= 0 {
		minRTT = rtt
	}
	queueRatio := float64(rtt) / float64(max(minRTT, time.Millisecond))

	var rate float64
	if c.targetBPS > 0 {
		// 弹性 Brutal 模式：抗随机丢包 + 拥塞泄压阀
		if queueRatio > 2.2 || c.lossRate > 0.45 {
			if c.pressureAt.IsZero() {
				c.pressureAt = now
			} else if now.Sub(c.pressureAt) > 1500*time.Millisecond {
				c.brutalScale = math.Max(0.35, c.brutalScale*0.85)
				c.pressureAt = now
			}
		} else {
			c.pressureAt = time.Time{}
			if c.brutalScale < 1.0 {
				c.brutalScale = math.Min(1.0, c.brutalScale+0.05)
			}
		}
		effLoss := math.Min(c.lossRate, 0.40)
		comp := 1.0 / (1.0 - effLoss)
		if queueRatio > 1.75 {
			comp = 1.0
		}
		rate = float64(c.targetBPS) * c.brutalScale * comp
		capRate := float64(c.targetBPS) * 1.65
		if rate > capRate {
			rate = capRate
		}
	} else {
		// 自适应 HyBBR 模式（零配置）
		base := c.btlBW
		if base < float64(minPacingBPS) {
			base = float64(initialPacingBPS)
		}
		var gain float64
		if c.inStartup {
			gain = 2.0
		} else {
			cyclePeriod := rtt
			if cyclePeriod < 30*time.Millisecond {
				cyclePeriod = 30 * time.Millisecond
			}
			if now.Sub(c.cycleStamp) >= cyclePeriod {
				c.cycleIdx = (c.cycleIdx + 1) % len(probeBWGains)
				c.cycleStamp = now
			}
			gain = probeBWGains[c.cycleIdx]
		}

		// 关键改进：基于排队延迟区分「随机丢包」与「真实拥塞」
		if c.lossRate > 0.005 && queueRatio < 1.35 {
			// 随机丢包（队列未膨胀）：应用上限 1.54x 的抗丢包补偿，保持跨境吞吐
			effLoss := math.Min(c.lossRate, 0.35)
			comp := 1.0 / (1.0 - effLoss)
			rate = base * math.Max(gain, 1.0) * comp
		} else if queueRatio >= 1.55 {
			// 队列明显膨胀（真实拥塞 / ISP 限速）：温和排空队列，防止爆延迟
			rate = base * 0.85
		} else {
			rate = base * gain
		}
		if rate > float64(maxAutoPacingBPS) {
			rate = float64(maxAutoPacingBPS)
		}
	}

	if c.maxBPS > 0 && rate > float64(c.maxBPS) {
		rate = float64(c.maxBPS)
	}
	if rate < float64(minPacingBPS) {
		rate = float64(minPacingBPS)
	}
	c.pacingRate = rate

	// BDP * 2.5，留足抗抖动与丢包重传的在途流水线空间
	bdp := rate * minRTT.Seconds()
	cwndGain := 2.5
	if c.inStartup {
		cwndGain = 3.0
	} else if queueRatio >= 1.65 {
		cwndGain = 1.6
	}
	cwnd := int64(bdp * cwndGain)
	if cwnd < minCwndBytes {
		cwnd = minCwndBytes
	}
	if cwnd > maxCwndBytes {
		cwnd = maxCwndBytes
	}
	c.cwnd = cwnd
}

func (c *congestionController) rttOrDefault() time.Duration {
	if c.hasRTT && c.srtt > 0 {
		return c.srtt
	}
	return 80 * time.Millisecond
}

// PTO 计算 RFC 9002 风格的探测超时时间，用于无新 ACK 时的尾部丢包恢复。
func (c *congestionController) PTO(backoffCount int) time.Duration {
	var pto time.Duration
	if !c.hasRTT {
		pto = 250 * time.Millisecond
	} else {
		varTerm := 4 * c.rttvar
		if varTerm < 10*time.Millisecond {
			varTerm = 10 * time.Millisecond
		}
		pto = c.srtt + varTerm + 10*time.Millisecond
	}
	if pto < 35*time.Millisecond {
		pto = 35 * time.Millisecond
	}
	if backoffCount > 0 {
		shift := backoffCount
		if shift > 5 {
			shift = 5
		}
		pto <<= shift
	}
	if pto > 5*time.Second {
		pto = 5 * time.Second
	}
	return pto
}

// LossTimeThreshold 返回 RACK 时间丢包判定阈值：max(srtt, latestRTT) * 9 / 8。
func (c *congestionController) LossTimeThreshold() time.Duration {
	r := c.srtt
	if c.latestRTT > r {
		r = c.latestRTT
	}
	if r <= 0 {
		r = 80 * time.Millisecond
	}
	t := r + r/8
	if t < 5*time.Millisecond {
		t = 5 * time.Millisecond
	}
	return t
}

// CanSend 检查是否允许发送下一个数据包；若受令牌桶限制，返回建议等待时长。
func (c *congestionController) CanSend(inFlight int64, pktBytes int, now time.Time) (bool, time.Duration) {
	// 允许至少 1 个在途包以防止零窗口死锁
	if inFlight > 0 && inFlight >= c.cwnd {
		return false, 0
	}
	dt := now.Sub(c.lastRefill).Seconds()
	if dt > 0 {
		c.tokens += dt * c.pacingRate
		c.lastRefill = now
		// 突发上限适配 Windows/Android 定时器粒度（最多累积 25ms 或 64KB 令牌）
		maxBurst := math.Max(32*1024, math.Min(256*1024, c.pacingRate*0.025))
		if c.tokens > maxBurst {
			c.tokens = maxBurst
		}
	}
	need := float64(pktBytes)
	if c.tokens >= need {
		return true, 0
	}
	waitSec := (need - c.tokens) / c.pacingRate
	wait := time.Duration(waitSec * float64(time.Second))
	if wait < 500*time.Microsecond {
		wait = 500 * time.Microsecond
	}
	if wait > 20*time.Millisecond {
		wait = 20 * time.Millisecond
	}
	return false, wait
}

func (c *congestionController) OnPacketSent(pktBytes int) {
	c.tokens -= float64(pktBytes)
	if c.tokens < -64*1024 {
		c.tokens = -64 * 1024
	}
}

// StatsSnapshot 返回当前拥塞控制器的观测指标。
type CCStats struct {
	SRTTMs      int64   `json:"srtt_ms"`
	MinRTTMs    int64   `json:"min_rtt_ms"`
	LossRate    float64 `json:"loss_rate"`
	PacingMbps  float64 `json:"pacing_mbps"`
	CwndBytes   int64   `json:"cwnd_bytes"`
}

func (c *congestionController) Snapshot() CCStats {
	return CCStats{
		SRTTMs:     c.srtt.Milliseconds(),
		MinRTTMs:   c.minRTT.Milliseconds(),
		LossRate:   math.Round(c.lossRate*10000) / 10000,
		PacingMbps: math.Round((c.pacingRate*8/1e6)*10) / 10,
		CwndBytes:  c.cwnd,
	}
}

// recvRateTracker 统计接收端最近时间窗口的真实交付吞吐率，随 ACK 反馈给发端。
type recvRateTracker struct {
	winStart time.Time
	winBytes uint64
	rateBPS  uint64
}

func (t *recvRateTracker) Record(n int, now time.Time) uint64 {
	if t.winStart.IsZero() {
		t.winStart = now
	}
	t.winBytes += uint64(n)
	if dt := now.Sub(t.winStart); dt >= 100*time.Millisecond {
		t.rateBPS = uint64(float64(t.winBytes) / dt.Seconds())
		t.winStart = now
		t.winBytes = 0
	}
	return t.rateBPS
}
