package pulse

import (
	"context"
	"errors"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	initialStreamWindow = 4 << 20  // 单流 4 MiB 接收窗口（覆盖高 BDP 跨境链路）
	initialConnWindow   = 16 << 20 // 会话级 16 MiB 接收窗口
	streamSendBufCap    = 2 << 20  // 单流 2 MiB 发送缓冲
	maxStreamChunk      = 1150     // 单帧最大 STREAM_DATA 载荷
	maxUDPFragPayload   = 1100     // 单片最大 UDP 载荷
	maxUDPDatagramSize  = 65527
	maxPendingUDPFrags  = 256
	udpFragTTL          = 3 * time.Second
	maxPktNumBeforeRekey = 0x7FFFFFF0 // ~21 亿包安全上限，防 Nonce 溢出
)

var (
	errSessionClosed = errors.New("txpulse: session closed")
	errStreamReset   = errors.New("txpulse: stream reset")
)

// OpenStreamError 表示服务端明确拒绝打开目标 TCP 流（如禁止访问私网地址、目标连接被拒等）。
type OpenStreamError struct {
	Status byte
}

func (e *OpenStreamError) Error() string {
	switch e.Status {
	case OpenStatusForbidden:
		return "txpulse: target forbidden"
	case OpenStatusTimeout:
		return "txpulse: target dial timeout"
	case OpenStatusUnreachable:
		return "txpulse: target unreachable"
	default:
		return "txpulse: target connection refused"
	}
}

// sentPacket 记录一个在途数据包的元数据与可重传帧。
type sentPacket struct {
	pktNum       uint32
	sentAt       time.Time
	wireBytes    int
	ackEliciting bool
	inFlight     bool
	frames       []Frame // 仅保留 IsReliable() == true 的帧，UDP 数据报不重传
}

// ackTracker 维护接收端已收到的报文编号区间（降序 SACK 块）。
type ackTracker struct {
	ranges         []AckRange
	largest        uint32
	largestTime    time.Time
	hasAny         bool
	elicitSinceAck int
	ackNeeded      bool
	ackImmediate   bool
	firstPendingAt time.Time
}

func (a *ackTracker) OnRecv(pktNum uint32, elicit bool, now time.Time) {
	if !a.hasAny {
		a.hasAny = true
		a.largest = pktNum
		a.largestTime = now
		a.ranges = []AckRange{{Start: pktNum, End: pktNum}}
	} else {
		gap := pktNum != a.largest+1
		if pktNum > a.largest {
			a.largest = pktNum
			a.largestTime = now
		}
		a.insertRange(pktNum)
		if gap && elicit {
			// 检测到乱序或空洞，立即回复 SACK 触发快速重传
			a.ackImmediate = true
		}
	}
	if elicit {
		if !a.ackNeeded {
			a.ackNeeded = true
			a.firstPendingAt = now
		}
		a.elicitSinceAck++
		if a.elicitSinceAck >= 2 {
			a.ackImmediate = true
		}
	}
}

func (a *ackTracker) insertRange(pn uint32) {
	// ranges 按降序排列：ranges[0].End >= ranges[0].Start > ranges[1].End ...
	for i := 0; i < len(a.ranges); i++ {
		r := &a.ranges[i]
		if pn >= r.Start && pn <= r.End {
			return
		}
		if pn == r.End+1 {
			r.End = pn
			if i > 0 && a.ranges[i-1].Start == r.End+1 {
				a.ranges[i-1].Start = r.Start
				a.ranges = append(a.ranges[:i], a.ranges[i+1:]...)
			}
			return
		}
		if pn+1 == r.Start {
			r.Start = pn
			if i+1 < len(a.ranges) && a.ranges[i+1].End+1 == r.Start {
				r.Start = a.ranges[i+1].Start
				a.ranges = append(a.ranges[:i+1], a.ranges[i+2:]...)
			}
			return
		}
		if pn > r.End {
			a.ranges = append(a.ranges, AckRange{})
			copy(a.ranges[i+1:], a.ranges[i:])
			a.ranges[i] = AckRange{Start: pn, End: pn}
			if len(a.ranges) > 32 {
				a.ranges = a.ranges[:32]
			}
			return
		}
	}
	if len(a.ranges) < 32 {
		a.ranges = append(a.ranges, AckRange{Start: pn, End: pn})
	}
}

func (a *ackTracker) BuildFrame(recvRateBPS uint64, now time.Time) (Frame, bool) {
	if !a.hasAny || !a.ackNeeded {
		return Frame{}, false
	}
	delayUs := uint32(0)
	if !a.largestTime.IsZero() && now.After(a.largestTime) {
		us := now.Sub(a.largestTime).Microseconds()
		if us > 0 && us < 10_000_000 {
			delayUs = uint32(us)
		}
	}
	cp := make([]AckRange, len(a.ranges))
	copy(cp, a.ranges)
	a.ackNeeded = false
	a.ackImmediate = false
	a.elicitSinceAck = 0
	return Frame{
		Type:         FrameAck,
		LargestAcked: a.largest,
		AckDelayUs:   delayUs,
		RecvRateBPS:  recvRateBPS,
		AckRanges:    cp,
	}, true
}

func ackCovers(ranges []AckRange, pn uint32) bool {
	for _, r := range ranges {
		if pn >= r.Start && pn <= r.End {
			return true
		}
		if pn > r.End {
			return false
		}
	}
	return false
}

// udpFragKey 与 udpFragEntry 用于不可靠 UDP 大包分片重组。
type udpFragKey struct {
	sessionID uint32
	pktID     uint16
}

type udpFragEntry struct {
	created time.Time
	total   byte
	got     byte
	target  string
	parts   [][]byte
}

// Stream 表示 TXPulse 会话内的一条可靠有序全双工字节流（对应一条代理 TCP 连接）。
type Stream struct {
	id      uint32
	sess    *Session
	target  string
	isCli   bool

	// 打开确认状态（客户端等待 OpenStream 握手确认时使用）
	openAckCh   chan byte
	openAckOnce sync.Once
	openErr     atomic.Pointer[error]

	// 读侧状态（仅由 rmu 保护）
	rmu           sync.Mutex
	recvReady     []byte
	recvChunks    map[uint64][]byte // 乱序到达的片段 offset -> data
	recvNextOff   uint64
	recvFinOff    uint64
	recvHasFin    bool
	recvEOF       bool
	recvConsumed  uint64
	recvWinSent   uint64
	recvErr       error
	readDeadline  time.Time
	readWake      chan struct{}

	// 写侧状态（仅由 wmu 保护）
	wmu           sync.Mutex
	sendBuf       []byte
	sendNextOff   uint64 // 下一个待分片发送的流偏移
	sendMaxOff    uint64 // 对端通告的流级接收窗口上限
	sendNeedOpen  bool   // 尚未排队发送 STREAM_OPEN
	sendFinQueued bool   // 上层已调用 CloseWrite
	sendFinSent   bool   // FIN 帧已发出
	sendClosed    bool
	sendErr       error
	writeDeadline time.Time
	writeWake     chan struct{}

	// 流是否已完全结束（用于会话清理）
	closedOnce sync.Once
	done       atomic.Bool
}

func newStream(sess *Session, id uint32, target string, isCli bool, needOpen bool) *Stream {
	return &Stream{
		id:           id,
		sess:         sess,
		target:       target,
		isCli:        isCli,
		openAckCh:    make(chan byte, 1),
		recvChunks:   make(map[uint64][]byte),
		recvWinSent:  initialStreamWindow,
		readWake:     make(chan struct{}, 1),
		sendMaxOff:   initialStreamWindow,
		sendNeedOpen: needOpen,
		writeWake:    make(chan struct{}, 1),
	}
}

func wakeChan(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (st *Stream) signalOpenAck(status byte) {
	if status != OpenStatusOK {
		err := error(&OpenStreamError{Status: status})
		st.openErr.Store(&err)
		st.failLocal(err)
	}
	st.openAckOnce.Do(func() {
		st.openAckCh <- status
		close(st.openAckCh)
	})
}

func (st *Stream) waitOpenAck(ctx context.Context) error {
	select {
	case status, ok := <-st.openAckCh:
		if !ok {
			if ep := st.openErr.Load(); ep != nil {
				return *ep
			}
			return nil
		}
		if status != OpenStatusOK {
			return &OpenStreamError{Status: status}
		}
		return nil
	case <-ctx.Done():
		_ = st.Close()
		return ctx.Err()
	case <-st.sess.doneCh:
		return errSessionClosed
	}
}

func (st *Stream) deliverData(offset uint64, data []byte, fin bool) {
	var newWin uint64
	var sendReset bool
	st.rmu.Lock()
	if st.recvErr != nil || st.recvEOF {
		st.rmu.Unlock()
		return
	}
	end := offset + uint64(len(data))
	if end > st.recvWinSent+65536 {
		// 对端严重超窗，重置流保护内存
		st.recvErr = errStreamReset
		sendReset = true
		st.rmu.Unlock()
		wakeChan(st.readWake)
		if sendReset {
			st.sess.queueControlFrame(Frame{Type: FrameStreamReset, StreamID: st.id, ErrCode: 2})
		}
		return
	}
	if fin {
		st.recvHasFin = true
		st.recvFinOff = end
	}
	if len(data) > 0 {
		if end <= st.recvNextOff {
			// 完全重复的旧包，忽略
		} else {
			if offset < st.recvNextOff {
				trim := st.recvNextOff - offset
				data = data[trim:]
				offset = st.recvNextOff
			}
			if offset == st.recvNextOff {
				st.recvReady = append(st.recvReady, data...)
				st.recvNextOff += uint64(len(data))
				st.drainContiguousLocked()
			} else {
				// 乱序片段暂存，避免覆盖更长的已有片段
				if old, ok := st.recvChunks[offset]; !ok || len(data) > len(old) {
					st.recvChunks[offset] = data
				}
			}
		}
	}
	if st.recvHasFin && st.recvNextOff >= st.recvFinOff {
		st.recvEOF = true
		clear(st.recvChunks)
	}
	_ = newWin
	st.rmu.Unlock()
	wakeChan(st.readWake)
	st.checkGC()
}

func (st *Stream) drainContiguousLocked() {
	for len(st.recvChunks) > 0 {
		if chunk, ok := st.recvChunks[st.recvNextOff]; ok {
			delete(st.recvChunks, st.recvNextOff)
			st.recvReady = append(st.recvReady, chunk...)
			st.recvNextOff += uint64(len(chunk))
			continue
		}
		// 检查是否存在起点小于 recvNextOff 但尾部超出 recvNextOff 的重叠乱序片
		progressed := false
		for off, chunk := range st.recvChunks {
			if off < st.recvNextOff {
				delete(st.recvChunks, off)
				end := off + uint64(len(chunk))
				if end > st.recvNextOff {
					st.recvReady = append(st.recvReady, chunk[st.recvNextOff-off:]...)
					st.recvNextOff = end
					progressed = true
					break
				}
			}
		}
		if !progressed {
			break
		}
	}
}

func (st *Stream) onWindowUpdate(maxOff uint64) {
	st.wmu.Lock()
	if maxOff > st.sendMaxOff {
		st.sendMaxOff = maxOff
	}
	st.wmu.Unlock()
	wakeChan(st.writeWake)
	st.sess.kickSend()
}

func (st *Stream) failLocal(err error) {
	if err == nil {
		err = errStreamReset
	}
	st.rmu.Lock()
	if st.recvErr == nil {
		st.recvErr = err
	}
	clear(st.recvChunks)
	st.rmu.Unlock()
	wakeChan(st.readWake)

	st.wmu.Lock()
	if st.sendErr == nil {
		st.sendErr = err
	}
	st.sendBuf = nil
	st.sendClosed = true
	st.wmu.Unlock()
	wakeChan(st.writeWake)

	st.openAckOnce.Do(func() {
		st.openErr.CompareAndSwap(nil, &err)
		close(st.openAckCh)
	})
	st.done.Store(true)
}

func (st *Stream) checkGC() {
	st.rmu.Lock()
	rDone := (st.recvEOF && len(st.recvReady) == 0) || st.recvErr != nil
	st.rmu.Unlock()
	st.wmu.Lock()
	wDone := st.sendFinSent || st.sendClosed || st.sendErr != nil
	st.wmu.Unlock()
	if rDone && wDone {
		st.done.Store(true)
		st.sess.gcStream(st.id)
	}
}

// Read 从可靠有序流中读取数据。
func (st *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		var winUpdate uint64
		st.rmu.Lock()
		if len(st.recvReady) > 0 {
			n := copy(p, st.recvReady)
			if n == len(st.recvReady) {
				st.recvReady = st.recvReady[:0]
			} else {
				copy(st.recvReady, st.recvReady[n:])
				st.recvReady = st.recvReady[:len(st.recvReady)-n]
			}
			st.recvConsumed += uint64(n)
			if st.recvConsumed+initialStreamWindow-st.recvWinSent >= initialStreamWindow/2 {
				st.recvWinSent = st.recvConsumed + initialStreamWindow
				winUpdate = st.recvWinSent
			}
			st.rmu.Unlock()
			if winUpdate > 0 {
				st.sess.queueControlFrame(Frame{Type: FrameStreamWindow, StreamID: st.id, MaxData: winUpdate})
			}
			st.sess.onAppConsumed(uint64(n))
			st.checkGC()
			return n, nil
		}
		if st.recvErr != nil {
			err := st.recvErr
			st.rmu.Unlock()
			return 0, err
		}
		if st.recvEOF {
			st.rmu.Unlock()
			st.checkGC()
			return 0, io.EOF
		}
		dl := st.readDeadline
		st.rmu.Unlock()

		var timer *time.Timer
		var timerCh <-chan time.Time
		if !dl.IsZero() {
			rem := time.Until(dl)
			if rem <= 0 {
				return 0, osTimeoutError{}
			}
			timer = time.NewTimer(rem)
			timerCh = timer.C
		}
		select {
		case <-st.readWake:
		case <-st.sess.doneCh:
			if timer != nil {
				timer.Stop()
			}
			return 0, errSessionClosed
		case <-timerCh:
			return 0, osTimeoutError{}
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

// Write 将字节写入流发送缓冲，受单流缓冲上限与对端接收窗口反压控制。
func (st *Stream) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		st.wmu.Lock()
		if st.sendErr != nil {
			err := st.sendErr
			st.wmu.Unlock()
			return written, err
		}
		if st.sendClosed || st.sendFinQueued {
			st.wmu.Unlock()
			return written, net.ErrClosed
		}
		space := streamSendBufCap - len(st.sendBuf)
		if space > 0 {
			n := len(p)
			if n > space {
				n = space
			}
			st.sendBuf = append(st.sendBuf, p[:n]...)
			p = p[n:]
			written += n
			st.wmu.Unlock()
			st.sess.kickSend()
			continue
		}
		dl := st.writeDeadline
		st.wmu.Unlock()

		var timer *time.Timer
		var timerCh <-chan time.Time
		if !dl.IsZero() {
			rem := time.Until(dl)
			if rem <= 0 {
				return written, osTimeoutError{}
			}
			timer = time.NewTimer(rem)
			timerCh = timer.C
		}
		select {
		case <-st.writeWake:
		case <-st.sess.doneCh:
			if timer != nil {
				timer.Stop()
			}
			return written, errSessionClosed
		case <-timerCh:
			return written, osTimeoutError{}
		}
		if timer != nil {
			timer.Stop()
		}
	}
	return written, nil
}

// CloseWrite 半关闭写方向（发送 FIN），读方向继续接收对端剩余数据。
func (st *Stream) CloseWrite() error {
	st.wmu.Lock()
	if !st.sendFinQueued && !st.sendClosed {
		st.sendFinQueued = true
	}
	st.wmu.Unlock()
	st.sess.kickSend()
	return nil
}

// Close 关闭本端流句柄：
//   - 若已调用 CloseWrite（优雅半关闭），保留待发缓冲让 sendLoop 刷完剩余数据与 FIN，不发 RESET；
//   - 若未调用 CloseWrite（异常中断/主动取消），立即清空未发缓冲并发送 STREAM_RESET。
func (st *Stream) Close() error {
	st.closedOnce.Do(func() {
		st.wmu.Lock()
		gracefulWrite := st.sendFinQueued
		if !gracefulWrite {
			if st.sendErr == nil {
				st.sendErr = net.ErrClosed
			}
			st.sendBuf = nil
			st.sendClosed = true
		}
		st.wmu.Unlock()
		wakeChan(st.writeWake)

		st.rmu.Lock()
		if st.recvErr == nil && !st.recvEOF {
			st.recvErr = net.ErrClosed
		}
		clear(st.recvChunks)
		st.rmu.Unlock()
		wakeChan(st.readWake)

		if !gracefulWrite {
			st.done.Store(true)
			st.sess.queueControlFrame(Frame{Type: FrameStreamReset, StreamID: st.id, ErrCode: 0})
			st.sess.gcStream(st.id)
		} else {
			st.checkGC()
		}
	})
	return nil
}

func (st *Stream) SetDeadline(t time.Time) error {
	st.rmu.Lock()
	st.readDeadline = t
	st.rmu.Unlock()
	st.wmu.Lock()
	st.writeDeadline = t
	st.wmu.Unlock()
	wakeChan(st.readWake)
	wakeChan(st.writeWake)
	return nil
}

func (st *Stream) SetReadDeadline(t time.Time) error {
	st.rmu.Lock()
	st.readDeadline = t
	st.rmu.Unlock()
	wakeChan(st.readWake)
	return nil
}

func (st *Stream) SetWriteDeadline(t time.Time) error {
	st.wmu.Lock()
	st.writeDeadline = t
	st.wmu.Unlock()
	wakeChan(st.writeWake)
	return nil
}

// popSendFrame 由 Session.sendLoop 调用，从流中提取下一帧（OPEN / DATA / FIN）。
// connAvail 为当前会话级窗口剩余额度；返回 ok=false 表示此刻无可发送帧或受窗口限制。
func (st *Stream) popSendFrame(maxPayload int, connAvail uint64) (f Frame, payloadBytes uint64, ok bool) {
	st.wmu.Lock()
	defer st.wmu.Unlock()
	if st.sendErr != nil || st.sendClosed {
		return Frame{}, 0, false
	}
	if st.sendNeedOpen {
		st.sendNeedOpen = false
		return Frame{Type: FrameStreamOpen, StreamID: st.id, Target: st.target}, 0, true
	}
	if len(st.sendBuf) > 0 {
		winAvail := uint64(0)
		if st.sendMaxOff > st.sendNextOff {
			winAvail = st.sendMaxOff - st.sendNextOff
		}
		avail := winAvail
		if connAvail < avail {
			avail = connAvail
		}
		if avail == 0 {
			return Frame{}, 0, false
		}
		chunkLen := len(st.sendBuf)
		if chunkLen > maxPayload {
			chunkLen = maxPayload
		}
		if uint64(chunkLen) > avail {
			chunkLen = int(avail)
		}
		if chunkLen <= 0 {
			return Frame{}, 0, false
		}
		data := make([]byte, chunkLen)
		copy(data, st.sendBuf[:chunkLen])
		if chunkLen == len(st.sendBuf) {
			st.sendBuf = st.sendBuf[:0]
		} else {
			copy(st.sendBuf, st.sendBuf[chunkLen:])
			st.sendBuf = st.sendBuf[:len(st.sendBuf)-chunkLen]
		}
		off := st.sendNextOff
		st.sendNextOff += uint64(chunkLen)
		var flags byte
		finishedWrite := false
		if st.sendFinQueued && len(st.sendBuf) == 0 && !st.sendFinSent {
			flags = StreamFlagFIN
			st.sendFinSent = true
			finishedWrite = true
		}
		wakeChan(st.writeWake)
		if finishedWrite {
			go st.checkGC()
		}
		return Frame{
			Type:     FrameStreamData,
			StreamID: st.id,
			Offset:   off,
			Flags:    flags,
			Data:     data,
		}, uint64(chunkLen), true
	}
	if st.sendFinQueued && !st.sendFinSent {
		st.sendFinSent = true
		go st.checkGC()
		return Frame{
			Type:     FrameStreamData,
			StreamID: st.id,
			Offset:   st.sendNextOff,
			Flags:    StreamFlagFIN,
		}, 0, true
	}
	return Frame{}, 0, false
}

// UDPStream 表示客户端侧一条基于 TXPulse 原生不可靠分片通道的 UDP 流（实现 PacketTransport）。
type UDPStream struct {
	id       uint32
	target   string
	sess     *Session
	recvCh   chan []byte
	closed   atomic.Bool
	sentAddr atomic.Bool
	doneCh   chan struct{}
	once     sync.Once
}

func (u *UDPStream) Send(b []byte) error {
	if u.closed.Load() {
		return net.ErrClosed
	}
	if len(b) > maxUDPDatagramSize {
		return errors.New("txpulse: UDP payload too large")
	}
	return u.sess.sendUDPDatagram(u.id, u.target, true, b)
}

func (u *UDPStream) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-u.recvCh:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-u.doneCh:
		return nil, io.EOF
	case <-u.sess.doneCh:
		return nil, errSessionClosed
	}
}

func (u *UDPStream) Close() error {
	u.once.Do(func() {
		u.closed.Store(true)
		close(u.doneCh)
		u.sess.closeClientUDP(u.id)
	})
	return nil
}

// osTimeoutError 实现 net.Error Timeout() 接口。
type osTimeoutError struct{}

func (osTimeoutError) Error() string   { return "txpulse: i/o timeout" }
func (osTimeoutError) Timeout() bool   { return true }
func (osTimeoutError) Temporary() bool { return true }

// SessionHandlers 定义服务端/客户端对新流与原生 UDP 数据报的回调。
type SessionHandlers struct {
	OnStreamOpen func(st *Stream, target string)
	OnUDPData    func(udpSessID uint32, target string, payload []byte)
	OnUDPClose   func(udpSessID uint32)
	OnClosed     func(sessionID uint64)
}

// Session 管理一条 TXPulse 加密 UDP 会话的全部多路复用流、SACK 恢复、流控、拥塞控制与连接迁移。
type Session struct {
	id        uint64
	isClient  bool
	obfsKey   []byte
	txCipher  *dataCipher
	rxCipher  *dataCipher
	handlers  SessionHandlers

	// 底层发包函数（支持服务端多端口回复与客户端端口跳跃原子切换）
	rawSendMu sync.RWMutex
	rawSend   func(pkt []byte) error
	peerAddr  *net.UDPAddr
	replySock *net.UDPConn

	// 会话核心状态
	mu               sync.Mutex
	closed           bool
	nextPktNum       uint32
	highestRecvPkt   uint32
	sentPkts         map[uint32]*sentPacket
	inFlightBytes    int64
	ctrlQueue        []Frame // 紧急控制帧（OPEN_ACK / WINDOW / RESET / CLOSE / UDP_CLOSE）
	retxQueue        []Frame // 丢包重传队列（不消耗新流控窗口）
	udpQueue         []Frame // 不可靠 UDP 数据报队列（有界防积压）
	ack              ackTracker
	recvTracker      recvRateTracker
	cc               *congestionController
	ptoBackoff       int
	lastRecvAt       time.Time
	lastSentAt       time.Time
	idleTimeout      time.Duration

	// 连接级流控
	connSendBytes    uint64
	connSendMax      uint64
	connRecvConsumed uint64
	connRecvWinSent  uint64

	// 流管理
	nextStreamID  uint32
	streams       map[uint32]*Stream
	streamOrder   []uint32 // 公平轮询游标
	streamRR      int
	openedStreams map[uint32]byte // 防止重复 STREAM_OPEN 触发重复拨号

	// UDP 流与分片重组
	nextUDPSessID atomic.Uint32
	nextUDPPktID  atomic.Uint32
	clientUDPs    map[uint32]*UDPStream
	udpTargets    map[uint32]string // 记住每个 udpSessID 的最近目标地址
	udpFrags      map[udpFragKey]*udpFragEntry

	// 外部统计回调
	onWireTX func(n int)
	onWireRX func(n int)

	sendWake chan struct{}
	doneCh   chan struct{}
	closeOnce sync.Once
}

type sessionConfig struct {
	id          uint64
	isClient    bool
	obfsKey     []byte
	keys        *sessionKeys
	targetBPS   uint64
	maxBPS      uint64
	idleTimeout time.Duration
	rawSend     func(pkt []byte) error
	peerAddr    *net.UDPAddr
	replySock   *net.UDPConn
	handlers    SessionHandlers
	onWireTX    func(n int)
	onWireRX    func(n int)
}

func newSession(cfg sessionConfig) *Session {
	tx, rx := cfg.keys.s2c, cfg.keys.c2s
	nextSID := uint32(2)
	if cfg.isClient {
		tx, rx = cfg.keys.c2s, cfg.keys.s2c
		nextSID = 1
	}
	idle := cfg.idleTimeout
	if idle <= 0 {
		idle = 90 * time.Second
	}
	now := time.Now()
	s := &Session{
		id:              cfg.id,
		isClient:        cfg.isClient,
		obfsKey:         append([]byte(nil), cfg.obfsKey...),
		txCipher:        tx,
		rxCipher:        rx,
		handlers:        cfg.handlers,
		rawSend:         cfg.rawSend,
		peerAddr:        cfg.peerAddr,
		replySock:       cfg.replySock,
		sentPkts:        make(map[uint32]*sentPacket, 64),
		cc:              newCongestionController(cfg.targetBPS, cfg.maxBPS),
		lastRecvAt:      now,
		lastSentAt:      now,
		idleTimeout:     idle,
		connSendMax:     initialConnWindow,
		connRecvWinSent: initialConnWindow,
		nextStreamID:    nextSID,
		streams:         make(map[uint32]*Stream, 32),
		openedStreams:   make(map[uint32]byte, 64),
		clientUDPs:      make(map[uint32]*UDPStream, 16),
		udpTargets:      make(map[uint32]string, 16),
		udpFrags:        make(map[udpFragKey]*udpFragEntry, 16),
		onWireTX:        cfg.onWireTX,
		onWireRX:        cfg.onWireRX,
		sendWake:        make(chan struct{}, 1),
		doneCh:          make(chan struct{}),
	}
	go s.sendLoop()
	return s
}

func (s *Session) kickSend() {
	select {
	case s.sendWake <- struct{}{}:
	default:
	}
}

// CCStats 返回当前会话拥塞控制指标（RTT / 丢包率 / Pacing 速率）。
func (s *Session) CCStats() CCStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cc.Snapshot()
}

// Alive 报告会话是否仍活跃。
func (s *Session) Alive() bool {
	select {
	case <-s.doneCh:
		return false
	default:
		return true
	}
}

// UpdatePeer 在服务端收到经过 AEAD 验证的新来源地址或新跳跃端口时原子迁移回包路径。
func (s *Session) UpdatePeer(addr *net.UDPAddr, sock *net.UDPConn) {
	s.rawSendMu.Lock()
	s.peerAddr = addr
	s.replySock = sock
	s.rawSendMu.Unlock()
}

// SetRawSend 供客户端在端口跳跃或网络切换时原子替换发包通道。
func (s *Session) SetRawSend(fn func([]byte) error) {
	s.rawSendMu.Lock()
	s.rawSend = fn
	s.rawSendMu.Unlock()
}

func (s *Session) writeWirePacket(pkt []byte) error {
	s.rawSendMu.RLock()
	fn := s.rawSend
	addr := s.peerAddr
	sock := s.replySock
	s.rawSendMu.RUnlock()
	var err error
	if fn != nil {
		err = fn(pkt)
	} else if sock != nil && addr != nil {
		_, err = sock.WriteToUDP(pkt, addr)
	} else {
		return net.ErrClosed
	}
	if err == nil && s.onWireTX != nil {
		s.onWireTX(len(pkt))
	}
	return err
}

// OpenStream 打开一条新可靠流；waitAck=true 时等待服务端确认目标已拨通。
func (s *Session) OpenStream(ctx context.Context, target string, waitAck bool) (*Stream, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errSessionClosed
	}
	sid := s.nextStreamID
	s.nextStreamID += 2
	st := newStream(s, sid, target, true, true)
	s.streams[sid] = st
	s.streamOrder = append(s.streamOrder, sid)
	s.mu.Unlock()
	s.kickSend()

	if waitAck {
		if err := st.waitOpenAck(ctx); err != nil {
			return nil, err
		}
	}
	return st, nil
}

// OpenUDP 打开一条客户端原生不可靠 UDP 转发流。
func (s *Session) OpenUDP(target string) (*UDPStream, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errSessionClosed
	}
	uid := s.nextUDPSessID.Add(1)
	u := &UDPStream{
		id:     uid,
		target: target,
		sess:   s,
		recvCh: make(chan []byte, 128),
		doneCh: make(chan struct{}),
	}
	s.clientUDPs[uid] = u
	s.mu.Unlock()
	return u, nil
}

func (s *Session) closeClientUDP(uid uint32) {
	s.mu.Lock()
	delete(s.clientUDPs, uid)
	if !s.closed {
		s.ctrlQueue = append(s.ctrlQueue, Frame{Type: FrameUDPClose, UDPSessionID: uid})
	}
	s.mu.Unlock()
	s.kickSend()
}

// SendUDPFromServer 由服务端调用，将目标返回的 UDP 数据报分片不可靠地回传给客户端。
func (s *Session) SendUDPFromServer(udpSessID uint32, payload []byte) error {
	return s.sendUDPDatagram(udpSessID, "", false, payload)
}

func (s *Session) sendUDPDatagram(udpSessID uint32, target string, includeAddr bool, payload []byte) error {
	if len(payload) > maxUDPDatagramSize {
		return errors.New("txpulse: UDP payload too large")
	}
	pktID := uint16(s.nextUDPPktID.Add(1))
	maxFrag := maxUDPFragPayload
	if includeAddr && len(target)+8 < 260 {
		maxFrag -= len(target) + 8
	}
	if maxFrag < 512 {
		maxFrag = 512
	}
	total := 1
	if len(payload) > maxFrag {
		total = (len(payload) + maxFrag - 1) / maxFrag
	}
	if total > 255 {
		return errors.New("txpulse: UDP packet requires too many fragments")
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errSessionClosed
	}
	// 有界队列：UDP 突发过载时丢弃旧包，避免拖垮 TCP 或撑爆内存
	if len(s.udpQueue)+total > 512 {
		s.mu.Unlock()
		return nil
	}
	for i := 0; i < total; i++ {
		start := i * maxFrag
		end := start + maxFrag
		if end > len(payload) {
			end = len(payload)
		}
		chunk := make([]byte, end-start)
		copy(chunk, payload[start:end])
		f := Frame{
			Type:         FrameUDPDatagram,
			UDPSessionID: udpSessID,
			UDPPktID:     pktID,
			UDPFragIdx:   byte(i),
			UDPFragTotal: byte(total),
			Data:         chunk,
		}
		if includeAddr && i == 0 {
			f.UDPHasAddr = true
			f.Target = target
		}
		s.udpQueue = append(s.udpQueue, f)
	}
	s.mu.Unlock()
	s.kickSend()
	return nil
}

// Ping 发送保活探测帧（也用于端口跳跃后立即通知服务端更新回复 socket）。
func (s *Session) Ping() {
	s.mu.Lock()
	if !s.closed {
		s.ctrlQueue = append(s.ctrlQueue, Frame{Type: FramePing})
	}
	s.mu.Unlock()
	s.kickSend()
}

func (s *Session) queueControlFrame(f Frame) {
	s.mu.Lock()
	if !s.closed {
		s.ctrlQueue = append(s.ctrlQueue, f)
	}
	s.mu.Unlock()
	s.kickSend()
}

func (s *Session) onAppConsumed(n uint64) {
	var connWin uint64
	s.mu.Lock()
	s.connRecvConsumed += n
	if s.connRecvConsumed+initialConnWindow-s.connRecvWinSent >= initialConnWindow/2 {
		s.connRecvWinSent = s.connRecvConsumed + initialConnWindow
		connWin = s.connRecvWinSent
	}
	s.mu.Unlock()
	if connWin > 0 {
		s.queueControlFrame(Frame{Type: FrameConnWindow, MaxData: connWin})
	}
}

func (s *Session) gcStream(id uint32) {
	s.mu.Lock()
	if st, ok := s.streams[id]; ok && st.done.Load() {
		delete(s.streams, id)
	}
	s.mu.Unlock()
}

// Close 优雅关闭会话及所有下属流。
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		streams := make([]*Stream, 0, len(s.streams))
		for _, st := range s.streams {
			streams = append(streams, st)
		}
		s.streams = nil
		udps := make([]*UDPStream, 0, len(s.clientUDPs))
		for _, u := range s.clientUDPs {
			udps = append(udps, u)
		}
		s.clientUDPs = nil
		s.mu.Unlock()

		// 尽力发一个加密 CLOSE 包，失败无妨
		_ = s.sendClosePacket()
		close(s.doneCh)

		for _, st := range streams {
			st.failLocal(errSessionClosed)
		}
		for _, u := range udps {
			u.closed.Store(true)
			u.once.Do(func() { close(u.doneCh) })
		}
		if s.handlers.OnClosed != nil {
			s.handlers.OnClosed(s.id)
		}
	})
	return nil
}

func (s *Session) sendClosePacket() error {
	s.mu.Lock()
	s.nextPktNum++
	pn := s.nextPktNum
	s.mu.Unlock()
	plain, err := appendFrame(make([]byte, 0, 64), Frame{Type: FrameClose, ErrCode: 0})
	if err != nil {
		return err
	}
	plain = appendAdaptivePadding(plain)
	var flags byte
	if !s.isClient {
		flags = FlagServerToClient
	}
	hdr := PacketHeader{
		Prefix:    makeCamouflagePrefix(),
		Type:      PktData,
		Flags:     flags,
		SessionID: s.id,
		PktNum:    pn,
	}
	wirePkt := s.txCipher.sealTo(nil, s.obfsKey, hdr, plain)
	return s.writeWirePacket(wirePkt)
}

// HandlePacket 解密并处理一个到达本会话的 Data 报文；认证失败返回 false（服务端静默丢弃）。
func (s *Session) HandlePacket(pkt []byte, hdr PacketHeader, aad [16]byte, srcAddr *net.UDPAddr, recvSock *net.UDPConn) bool {
	// 方向位防反射校验
	wantFlag := byte(0)
	if s.isClient {
		wantFlag = FlagServerToClient
	}
	if hdr.Flags != wantFlag {
		return false
	}

	plain, err := s.rxCipher.openTo(nil, pkt, hdr, aad)
	if err != nil {
		return false
	}
	if s.onWireRX != nil {
		s.onWireRX(len(pkt))
	}
	frames, err := parseFrames(plain)
	if err != nil {
		return false
	}

	now := time.Now()
	elicit := false
	immediateAck := false
	for _, f := range frames {
		if f.Type != FrameAck && f.Type != FramePadding {
			elicit = true
		}
		if f.Type == FramePing || f.Type == FrameStreamOpen || f.Type == FrameStreamOpenAck || f.Type == FrameStreamReset {
			immediateAck = true
		}
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return true
	}
	s.lastRecvAt = now
	s.recvTracker.Record(len(pkt), now)
	// 仅在收到比历史更高编号的合法 AEAD 报文时迁移对端地址（防旧乱序包把地址迁回去）
	if !s.isClient && srcAddr != nil && hdr.PktNum > s.highestRecvPkt {
		s.highestRecvPkt = hdr.PktNum
		s.UpdatePeer(srcAddr, recvSock)
	} else if hdr.PktNum > s.highestRecvPkt {
		s.highestRecvPkt = hdr.PktNum
	}
	s.ack.OnRecv(hdr.PktNum, elicit, now)
	if immediateAck {
		s.ack.ackImmediate = true
	}
	s.mu.Unlock()

	for _, f := range frames {
		s.dispatchFrame(f, now)
	}
	s.kickSend()
	return true
}

func (s *Session) dispatchFrame(f Frame, now time.Time) {
	switch f.Type {
	case FramePing:
		// ACK 即是对 PING 的加密回应

	case FrameAck:
		s.onAckFrame(f, now)

	case FrameStreamOpen:
		if s.isClient {
			return
		}
		var newSt *Stream
		var dupStatus byte
		isDup := false
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		if status, existed := s.openedStreams[f.StreamID]; existed {
			isDup = true
			dupStatus = status
		} else {
			if len(s.openedStreams) > 8192 {
				// 裁剪已结束的历史 ID，保留活跃流 ID
				for id := range s.openedStreams {
					if _, active := s.streams[id]; !active {
						delete(s.openedStreams, id)
					}
				}
			}
			s.openedStreams[f.StreamID] = 0xFF // 正在拨号中
			if existing, ok := s.streams[f.StreamID]; ok {
				// 此前因 UDP 乱序/首包丢失，STREAM_DATA 先于 STREAM_OPEN 到达并预建了缓冲流
				existing.target = f.Target
				newSt = existing
			} else {
				newSt = newStream(s, f.StreamID, f.Target, false, false)
				s.streams[f.StreamID] = newSt
				s.streamOrder = append(s.streamOrder, f.StreamID)
			}
		}
		s.mu.Unlock()

		if isDup {
			if dupStatus != 0xFF {
				s.queueControlFrame(Frame{Type: FrameStreamOpenAck, StreamID: f.StreamID, Status: dupStatus})
			}
			return
		}
		if len(f.Data) > 0 {
			newSt.deliverData(0, f.Data, false)
		}
		if s.handlers.OnStreamOpen != nil {
			go s.handlers.OnStreamOpen(newSt, f.Target)
		} else {
			s.ReplyStreamOpen(f.StreamID, OpenStatusRefused)
			newSt.failLocal(errStreamReset)
		}

	case FrameStreamOpenAck:
		s.mu.Lock()
		st := s.streams[f.StreamID]
		s.mu.Unlock()
		if st != nil {
			st.signalOpenAck(f.Status)
		}

	case FrameStreamData:
		s.mu.Lock()
		st := s.streams[f.StreamID]
		if st == nil && !s.isClient && !s.closed && f.StreamID%2 == 1 {
			if _, opened := s.openedStreams[f.StreamID]; !opened && len(s.streams) < 4096 {
				// 乱序/首包丢失场景：STREAM_DATA 先于 STREAM_OPEN 到达，预建流保留数据，待 STREAM_OPEN 到达后直接消费
				st = newStream(s, f.StreamID, "", false, false)
				s.streams[f.StreamID] = st
				s.streamOrder = append(s.streamOrder, f.StreamID)
			}
		}
		s.mu.Unlock()
		if st != nil {
			st.deliverData(f.Offset, f.Data, f.Flags&StreamFlagFIN != 0)
		}

	case FrameStreamWindow:
		s.mu.Lock()
		st := s.streams[f.StreamID]
		s.mu.Unlock()
		if st != nil {
			st.onWindowUpdate(f.MaxData)
		}

	case FrameConnWindow:
		s.mu.Lock()
		if f.MaxData > s.connSendMax {
			s.connSendMax = f.MaxData
		}
		s.mu.Unlock()

	case FrameStreamReset:
		s.mu.Lock()
		st := s.streams[f.StreamID]
		delete(s.streams, f.StreamID)
		s.mu.Unlock()
		if st != nil {
			st.failLocal(errStreamReset)
		}

	case FrameUDPDatagram:
		s.onUDPDatagram(f, now)

	case FrameUDPClose:
		s.mu.Lock()
		delete(s.udpTargets, f.UDPSessionID)
		s.mu.Unlock()
		if s.handlers.OnUDPClose != nil {
			s.handlers.OnUDPClose(f.UDPSessionID)
		}

	case FrameClose:
		go s.Close()
	}
}

// ReplyStreamOpen 由服务端拨号协程调用，向客户端发送流打开状态回执。
func (s *Session) ReplyStreamOpen(streamID uint32, status byte) {
	s.mu.Lock()
	if s.openedStreams != nil {
		s.openedStreams[streamID] = status
	}
	if !s.closed {
		s.ctrlQueue = append(s.ctrlQueue, Frame{Type: FrameStreamOpenAck, StreamID: streamID, Status: status})
	}
	s.mu.Unlock()
	s.kickSend()
}

func (s *Session) onUDPDatagram(f Frame, now time.Time) {
	if f.UDPFragTotal == 0 {
		return
	}
	var payload []byte
	var target string

	if f.UDPFragTotal == 1 {
		payload = f.Data
		target = f.Target
		if f.UDPHasAddr && target != "" {
			s.mu.Lock()
			s.udpTargets[f.UDPSessionID] = target
			s.mu.Unlock()
		} else {
			s.mu.Lock()
			target = s.udpTargets[f.UDPSessionID]
			s.mu.Unlock()
		}
	} else {
		if f.UDPFragIdx >= f.UDPFragTotal {
			return
		}
		key := udpFragKey{sessionID: f.UDPSessionID, pktID: f.UDPPktID}
		s.mu.Lock()
		if len(s.udpFrags) >= maxPendingUDPFrags {
			cutoff := now.Add(-udpFragTTL)
			for k, ent := range s.udpFrags {
				if ent.created.Before(cutoff) {
					delete(s.udpFrags, k)
				}
			}
			if len(s.udpFrags) >= maxPendingUDPFrags {
				s.mu.Unlock()
				return
			}
		}
		ent := s.udpFrags[key]
		if ent == nil || ent.total != f.UDPFragTotal {
			ent = &udpFragEntry{
				created: now,
				total:   f.UDPFragTotal,
				parts:   make([][]byte, f.UDPFragTotal),
			}
			s.udpFrags[key] = ent
		}
		if f.UDPHasAddr && f.Target != "" {
			ent.target = f.Target
			s.udpTargets[f.UDPSessionID] = f.Target
		}
		if ent.parts[f.UDPFragIdx] == nil {
			ent.parts[f.UDPFragIdx] = f.Data
			ent.got++
		}
		if ent.got < ent.total {
			s.mu.Unlock()
			return
		}
		delete(s.udpFrags, key)
		target = ent.target
		if target == "" {
			target = s.udpTargets[f.UDPSessionID]
		}
		totalLen := 0
		for _, part := range ent.parts {
			totalLen += len(part)
		}
		if totalLen > maxUDPDatagramSize {
			s.mu.Unlock()
			return
		}
		payload = make([]byte, 0, totalLen)
		for _, part := range ent.parts {
			payload = append(payload, part...)
		}
		s.mu.Unlock()
	}

	if s.isClient {
		s.mu.Lock()
		u := s.clientUDPs[f.UDPSessionID]
		s.mu.Unlock()
		if u != nil && !u.closed.Load() {
			select {
			case u.recvCh <- payload:
			default:
			}
		}
		return
	}
	if s.handlers.OnUDPData != nil {
		s.handlers.OnUDPData(f.UDPSessionID, target, payload)
	}
}

func (s *Session) onAckFrame(f Frame, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	var ackedBytes uint64
	ackedPkts := 0

	// 1) 更新 RTT（仅基于最新确认的 LargestAcked，消除重传歧义）
	if sp, ok := s.sentPkts[f.LargestAcked]; ok {
		sample := now.Sub(sp.sentAt)
		ackDelay := time.Duration(f.AckDelayUs) * time.Microsecond
		s.cc.OnRTT(sample, ackDelay, now)
	}

	// 2) 清理所有被 SACK 区间确认的在途包
	for pn, sp := range s.sentPkts {
		if pn == f.LargestAcked || ackCovers(f.AckRanges, pn) {
			if sp.inFlight {
				s.inFlightBytes -= int64(sp.wireBytes)
				if s.inFlightBytes < 0 {
					s.inFlightBytes = 0
				}
			}
			ackedBytes += uint64(sp.wireBytes)
			ackedPkts++
			delete(s.sentPkts, pn)
		}
	}
	if ackedPkts > 0 {
		s.ptoBackoff = 0
		s.cc.OnAck(ackedBytes, ackedPkts, f.RecvRateBPS, now)
	}

	// 3) RFC 9002 快速重传 + RACK 时间阈值丢包检测
	// 包序号阈值为 5（兼顾移动/多路径轻度乱序，避免虚假重传），时间阈值为 max(srtt, latestRTT)*9/8。
	lossTime := s.cc.LossTimeThreshold()
	var lostList []*sentPacket
	for pn, sp := range s.sentPkts {
		if pn >= f.LargestAcked {
			continue
		}
		if f.LargestAcked-pn >= 5 || now.Sub(sp.sentAt) >= lossTime {
			lostList = append(lostList, sp)
		}
	}
	if len(lostList) > 0 {
		// 按原始包号升序重传，提升接收端按序重组效率
		sort.Slice(lostList, func(i, j int) bool { return lostList[i].pktNum < lostList[j].pktNum })
		for _, sp := range lostList {
			if sp.inFlight {
				s.inFlightBytes -= int64(sp.wireBytes)
				if s.inFlightBytes < 0 {
					s.inFlightBytes = 0
				}
			}
			delete(s.sentPkts, sp.pktNum)
			s.retxQueue = append(s.retxQueue, sp.frames...)
		}
		s.cc.OnLoss(len(lostList), now)
	}
}

func (s *Session) sendLoop() {
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
	plainBuf := make([]byte, 0, MaxDataPayload)
	wireBuf := make([]byte, 0, MaxPacketSize)

	for {
		now := time.Now()
		nextWait := s.stepSend(now, &plainBuf, &wireBuf)
		if nextWait == 0 {
			continue
		}
		if nextWait < 0 {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(nextWait)

		select {
		case <-s.sendWake:
		case <-timer.C:
		case <-s.doneCh:
			return
		}
	}
}

// stepSend 执行一次发送调度；返回 0 表示立即可继续发下一包，-1 表示会话已关闭，>0 为下次唤醒等待时间。
func (s *Session) stepSend(now time.Time, plainBuf, wireBuf *[]byte) time.Duration {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return -1
	}

	// 空闲超时检查
	if now.Sub(s.lastRecvAt) > s.idleTimeout {
		s.mu.Unlock()
		go s.Close()
		return -1
	}

	// 客户端定期发送保活 PING，维持 NAT 路由 UDP 映射
	if s.isClient && now.Sub(s.lastSentAt) >= 15*time.Second && len(s.sentPkts) == 0 {
		s.ctrlQueue = append(s.ctrlQueue, Frame{Type: FramePing})
	}

	// 清理过期不完整 UDP 分片
	if len(s.udpFrags) > 0 && now.Sub(s.lastSentAt) > time.Second {
		cutoff := now.Add(-udpFragTTL)
		for k, ent := range s.udpFrags {
			if ent.created.Before(cutoff) {
				delete(s.udpFrags, k)
			}
		}
	}

	// 1) 检查 PTO 尾部丢包超时
	pto := s.cc.PTO(s.ptoBackoff)
	var oldestSent time.Time
	var oldestPkts []*sentPacket
	for _, sp := range s.sentPkts {
		if oldestSent.IsZero() || sp.sentAt.Before(oldestSent) {
			oldestSent = sp.sentAt
		}
		if now.Sub(sp.sentAt) >= pto {
			oldestPkts = append(oldestPkts, sp)
		}
	}
	if len(oldestPkts) > 0 {
		sort.Slice(oldestPkts, func(i, j int) bool { return oldestPkts[i].pktNum < oldestPkts[j].pktNum })
		s.ptoBackoff++
		limit := len(oldestPkts)
		if limit > 4 {
			limit = 4
		}
		lostCount := 0
		for i := 0; i < limit; i++ {
			sp := oldestPkts[i]
			if sp.inFlight {
				s.inFlightBytes -= int64(sp.wireBytes)
				if s.inFlightBytes < 0 {
					s.inFlightBytes = 0
				}
			}
			delete(s.sentPkts, sp.pktNum)
			if len(sp.frames) > 0 {
				s.retxQueue = append(s.retxQueue, sp.frames...)
			}
			lostCount++
		}
		if lostCount > 0 {
			s.cc.OnLoss(lostCount, now)
		}
	}

	// 2) 判断是否需要立即发送 ACK
	ackReady := s.ack.ackNeeded && (s.ack.ackImmediate || now.Sub(s.ack.firstPendingAt) >= 8*time.Millisecond)

	// 3) 检查拥塞窗口与 Pacer 是否允许发送数据/重传/UDP 帧
	canData, paceWait := s.cc.CanSend(s.inFlightBytes, MaxPacketSize, now)

	// 收集本包待打包帧
	plain := (*plainBuf)[:0]
	var reliableFrames []Frame
	ackEliciting := false
	hasDataWork := false

	// 优先把 ACK 搭便车塞进数据包（无数据时单独发纯 ACK）
	if s.ack.ackNeeded && (ackReady || canData) {
		if ackFrame, ok := s.ack.BuildFrame(s.recvTracker.rateBPS, now); ok {
			if next, err := appendFrame(plain, ackFrame); err == nil && len(next) <= MaxDataPayload {
				plain = next
			}
		}
	}

	// 控制帧优先发送（不完全受 cwnd 卡死，确保 WINDOW / OPEN_ACK / RESET / PING 及时送达）
	for len(s.ctrlQueue) > 0 {
		f := s.ctrlQueue[0]
		next, err := appendFrame(plain, f)
		if err != nil {
			s.ctrlQueue = s.ctrlQueue[1:]
			continue
		}
		if len(next) > MaxDataPayload {
			break
		}
		plain = next
		s.ctrlQueue = s.ctrlQueue[1:]
		ackEliciting = true
		if f.IsReliable() {
			reliableFrames = append(reliableFrames, f)
		}
		hasDataWork = true
	}

	if canData {
		// 优先重传丢失的可靠帧
		for len(s.retxQueue) > 0 {
			f := s.retxQueue[0]
			next, err := appendFrame(plain, f)
			if err != nil {
				s.retxQueue = s.retxQueue[1:]
				continue
			}
			if len(next) > MaxDataPayload {
				break
			}
			plain = next
			s.retxQueue = s.retxQueue[1:]
			ackEliciting = true
			if f.IsReliable() {
				reliableFrames = append(reliableFrames, f)
			}
			hasDataWork = true
		}

		// 原生不可靠 UDP 数据报
		for len(s.udpQueue) > 0 {
			f := s.udpQueue[0]
			next, err := appendFrame(plain, f)
			if err != nil {
				s.udpQueue = s.udpQueue[1:]
				continue
			}
			if len(next) > MaxDataPayload {
				break
			}
			plain = next
			s.udpQueue = s.udpQueue[1:]
			ackEliciting = true
			hasDataWork = true
		}

		// 公平轮询各活跃流的新数据（防止单条大流饿死网页/DNS 短流）
		if len(s.streams) > 0 {
			s.compactStreamOrderLocked()
			nStreams := len(s.streamOrder)
			tried := 0
			for tried < nStreams && MaxDataPayload-len(plain) >= 32 {
				idx := (s.streamRR + tried) % nStreams
				sid := s.streamOrder[idx]
				st := s.streams[sid]
				tried++
				if st == nil {
					continue
				}
				connAvail := uint64(0)
				if s.connSendMax > s.connSendBytes {
					connAvail = s.connSendMax - s.connSendBytes
				}
				availPayload := MaxDataPayload - len(plain) - 24
				if availPayload > maxStreamChunk {
					availPayload = maxStreamChunk
				}
				if availPayload < 16 {
					break
				}
				f, nBytes, ok := st.popSendFrame(availPayload, connAvail)
				if !ok {
					continue
				}
				next, err := appendFrame(plain, f)
				if err != nil || len(next) > MaxDataPayload {
					// 回退放回重传队列（极端边界保护）
					s.retxQueue = append(s.retxQueue, f)
					break
				}
				plain = next
				s.connSendBytes += nBytes
				ackEliciting = true
				if f.IsReliable() {
					reliableFrames = append(reliableFrames, f)
				}
				hasDataWork = true
				s.streamRR = (idx + 1) % nStreams
				// 允许同一条流在刚打开时把 OPEN 和首批 DATA 打包进同一个 UDP 报文（0-RTT 首包融合）
				if f.Type == FrameStreamOpen && MaxDataPayload-len(plain) >= 48 {
					avail2 := MaxDataPayload - len(plain) - 24
					if avail2 > maxStreamChunk {
						avail2 = maxStreamChunk
					}
					cAvail := uint64(0)
					if s.connSendMax > s.connSendBytes {
						cAvail = s.connSendMax - s.connSendBytes
					}
					if f2, nb2, ok2 := st.popSendFrame(avail2, cAvail); ok2 {
						if next2, err2 := appendFrame(plain, f2); err2 == nil && len(next2) <= MaxDataPayload {
							plain = next2
							s.connSendBytes += nb2
							if f2.IsReliable() {
								reliableFrames = append(reliableFrames, f2)
							}
						} else {
							s.retxQueue = append(s.retxQueue, f2)
						}
					}
				}
				if MaxDataPayload-len(plain) < 128 {
					break
				}
			}
		}
	}

	if len(plain) == 0 {
		// 没有任何帧需要立刻发出，计算下一次唤醒时间
		wait := 500 * time.Millisecond
		if s.ack.ackNeeded {
			rem := 8*time.Millisecond - now.Sub(s.ack.firstPendingAt)
			if rem < time.Millisecond {
				rem = time.Millisecond
			}
			if rem < wait {
				wait = rem
			}
		}
		if paceWait > 0 && paceWait < wait {
			wait = paceWait
		}
		if !oldestSent.IsZero() {
			rem := pto - now.Sub(oldestSent)
			if rem < 5*time.Millisecond {
				rem = 5 * time.Millisecond
			}
			if rem < wait {
				wait = rem
			}
		}
		s.mu.Unlock()
		return wait
	}

	// 追加自适应抗 DPI 长度填充
	plain = appendAdaptivePadding(plain)
	*plainBuf = plain

	if s.nextPktNum >= maxPktNumBeforeRekey {
		s.mu.Unlock()
		go s.Close()
		return -1
	}
	s.nextPktNum++
	pn := s.nextPktNum
	var flags byte
	if !s.isClient {
		flags = FlagServerToClient
	}
	hdr := PacketHeader{
		Prefix:    makeCamouflagePrefix(),
		Type:      PktData,
		Flags:     flags,
		SessionID: s.id,
		PktNum:    pn,
	}
	pkt := s.txCipher.sealTo(*wireBuf, s.obfsKey, hdr, plain)
	*wireBuf = pkt
	wireLen := len(pkt)

	s.lastSentAt = now
	if ackEliciting {
		sp := &sentPacket{
			pktNum:       pn,
			sentAt:       now,
			wireBytes:    wireLen,
			ackEliciting: true,
			inFlight:     len(reliableFrames) > 0,
			frames:       reliableFrames,
		}
		s.sentPkts[pn] = sp
		if sp.inFlight {
			s.inFlightBytes += int64(wireLen)
		}
		s.cc.OnPacketSent(wireLen)
	}
	// 复制发送缓冲区，解锁后再做 UDP 系统调用，防止阻塞接收与上层写入
	toSend := make([]byte, wireLen)
	copy(toSend, pkt)
	s.mu.Unlock()

	_ = s.writeWirePacket(toSend)
	if hasDataWork {
		return 0 // 立即检查是否还有更多待发数据可满速流水线输出
	}
	return 2 * time.Millisecond
}

func (s *Session) compactStreamOrderLocked() {
	if len(s.streamOrder) <= len(s.streams)*2+8 {
		return
	}
	kept := s.streamOrder[:0]
	for _, id := range s.streamOrder {
		if _, ok := s.streams[id]; ok {
			kept = append(kept, id)
		}
	}
	s.streamOrder = kept
	if s.streamRR >= len(s.streamOrder) {
		s.streamRR = 0
	}
}
