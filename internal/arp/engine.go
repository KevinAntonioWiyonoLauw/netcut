// language: Go, file: internal/arp/engine.go
//
// The ARP enforcement engine. It sits on the gateway host and controls a
// monitored segment at layer 2 by maintaining a pair of ARP mappings per
// enforced target, then forwarding (or dropping, or rate-limiting) the frames
// that consequently arrive at this host.
//
// Mechanics, in order:
//
//  1. Learn the real MAC of the gateway and of each target by ARP.
//  2. Send two forged ARP replies per target: to the target, "the gateway is at
//     <our MAC>"; to the gateway, "<target IP> is at <our MAC>". Both endpoints
//     now address this host, so the frames transit here.
//  3. Re-assert those replies on a short interval. ARP caches expire, and a
//     single forged reply decays within a minute.
//  4. For every frame arriving from a target, either re-transmit it to the real
//     next hop, drop it (block), or admit it only if a token bucket permits
//     (throttle). The reverse direction is handled symmetrically.
//  5. On release, restore the truthful mappings so the segment heals without
//     waiting for a cache timeout.
//
// This only ever runs against addresses the operator declares. Targets are
// named by MAC, and any device flagged protected is refused here outright.
package arp

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Mode is the enforcement state of one target.
type Mode string

const (
	ModeAllow    Mode = "allow"
	ModeBlock    Mode = "block"
	ModeThrottle Mode = "throttle"
	ModeObserve  Mode = "observe"
)

// ErrUnsupported is returned when no layer-2 capture backend is available.
var ErrUnsupported = errors.New("layer-2 capture is not supported on this platform (needs Npcap on Windows)")

const (
	etherTypeARP  = 0x0806
	etherTypeIPv4 = 0x0800

	// poisonInterval re-asserts forged mappings. Below ~1s the network sees a
	// storm; above ~5s caches start to expire on some clients.
	poisonInterval = 1500 * time.Millisecond
	readTimeout    = 100 * time.Millisecond
	// maxFrame bounds the buffer handed to the capture layer.
	maxFrame = 65536
)

// Target is one device under enforcement.
type Target struct {
	MAC     net.HardwareAddr
	IP      net.IP
	Mode    Mode
	CapKbps int // download cap; 0 falls back to UpKbps
	UpKbps  int // upload cap
	Reason  string
}

// Key returns the canonical lookup key for a target.
func (t Target) Key() string { return t.MAC.String() }

// TargetStats is the live telemetry for one target.
type TargetStats struct {
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Mode      string    `json:"mode"`
	Enforcing bool      `json:"enforcing"`
	TxPackets uint64    `json:"tx_packets"` // frames from the target, i.e. upload
	RxPackets uint64    `json:"rx_packets"` // frames to the target, i.e. download
	TxBytes   uint64    `json:"tx_bytes"`
	RxBytes   uint64    `json:"rx_bytes"`
	TxDropped uint64    `json:"tx_dropped"`
	RxDropped uint64    `json:"rx_dropped"`
	TxShaped  uint64    `json:"tx_shaped"`
	RxShaped  uint64    `json:"rx_shaped"`
	CapKbps   int       `json:"cap_kbps"`
	UpKbps    int       `json:"up_kbps"`
	Since     time.Time `json:"since"`
}

// Neighbour is a host observed via ARP.
type Neighbour struct {
	MAC  net.HardwareAddr
	IP   net.IP
	Seen time.Time
}

// Options configures an Engine.
type Options struct {
	Iface   string
	LocalIP net.IP
	Gateway net.IP
	Log     *slog.Logger
	DryRun  bool
	// SuppressNative makes the engine refuse to poison the gateway when the
	// gateway is also the host we run on, which would cut our own uplink.
	SuppressNative bool
}

// Engine performs layer-2 enforcement for a set of targets.
type Engine struct {
	opts Options
	log  *slog.Logger

	dev     captureDevice
	localIP net.IP
	localMA net.HardwareAddr

	gwIP  net.IP
	gwMAC net.HardwareAddr

	mu        sync.RWMutex
	targets   map[string]*targetState // keyed by MAC string
	neighByIP map[string]Neighbour
	neighByMA map[string]Neighbour
	stats     engineStats

	pendMu  sync.Mutex
	pending map[string]chan net.HardwareAddr

	sendMu sync.Mutex
	closed chan struct{}
	once   sync.Once
	wg     sync.WaitGroup

	// uplinkHealthy records whether the gateway mapping is trustworthy. If the
	// gateway itself is unreachable the engine must not cut the uplink.
	uplinkHealthy bool

	// writeHook, when set, replaces the capture device for outbound frames. It
	// exists so tests can assert exactly what the engine would transmit, which
	// is otherwise unobservable without putting frames on a real network.
	writeHook func([]byte) error
}

type engineStats struct {
	Frames    uint64
	Forwarded uint64
	Dropped   uint64
	Poisoned  uint64
	Restored  uint64
	Errors    uint64
	Started   time.Time
}

type targetState struct {
	target   Target
	realMAC  net.HardwareAddr
	shaperUp *shaper
	shaperDn *shaper
	stats    TargetStats
	active   bool
}

// New creates an Engine bound to an interface.
func New(opts Options) (*Engine, error) {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.LocalIP == nil {
		return nil, errors.New("engine requires the local IPv4 address of the monitored interface")
	}
	e := &Engine{
		opts:      opts,
		log:       opts.Log,
		localIP:   opts.LocalIP,
		gwIP:      opts.Gateway,
		targets:   map[string]*targetState{},
		neighByIP: map[string]Neighbour{},
		neighByMA: map[string]Neighbour{},
		pending:   map[string]chan net.HardwareAddr{},
		closed:    make(chan struct{}),
	}
	return e, nil
}

// Start opens the capture device and launches the read and poison loops.
func (e *Engine) Start() error {
	if e.opts.DryRun {
		e.log.Warn("dry-run: capture device is not opened and no frame is transmitted")
		e.stats.Started = time.Now()
		return nil
	}

	localMA, err := ifaceMAC(e.opts.Iface, e.localIP)
	if err != nil {
		return fmt.Errorf("resolve local MAC: %w", err)
	}
	e.localMA = localMA
	e.log.Info("interface resolved", "iface", e.opts.Iface, "ip", e.localIP, "mac", localMA)

	// Capture ARP (for learning and re-poisoning) plus everything addressed to
	// or from this host, which after poisoning is exactly the traffic we must
	// carry for the enforced targets.
	filter := fmt.Sprintf("arp or ether host %s", localMA)
	dev, err := openCapture(e.opts.Iface, e.localIP, filter)
	if err != nil {
		return fmt.Errorf("open capture: %w", err)
	}
	e.dev = dev

	if lt := dev.LinkType(); lt != 1 {
		dev.Close()
		return fmt.Errorf("interface is not Ethernet (datalink type %d); layer-2 enforcement needs Ethernet", lt)
	}

	// Resolve the gateway's real MAC before poisoning anything. Without it we
	// cannot forward, and poisoning would blackhole the target.
	if e.gwIP != nil && !e.gwIP.IsUnspecified() {
		ctx, cancel := contextWithTimeout(4 * time.Second)
		mac, err := e.resolveMAC(ctx, e.gwIP)
		cancel()
		if err != nil {
			e.log.Warn("gateway MAC unresolved; enforcement is disabled until it is known",
				"gateway", e.gwIP, "err", err)
		} else {
			e.gwMAC = mac
			e.uplinkHealthy = true
			e.log.Info("gateway resolved", "gateway", e.gwIP, "mac", mac)
		}
	}

	e.stats.Started = time.Now()
	e.wg.Add(2)
	go e.readLoop()
	go e.poisonLoop()
	return nil
}

// Stop releases every target and closes the capture device.
func (e *Engine) Stop() {
	e.once.Do(func() {
		close(e.closed)
		if e.dev != nil {
			// Unblocking the read loop matters more than ordering here.
			e.dev.Close()
		}
		e.wg.Wait()
		// Restore truth so the segment heals immediately.
		e.mu.RLock()
		targets := make([]*targetState, 0, len(e.targets))
		for _, ts := range e.targets {
			targets = append(targets, ts)
		}
		e.mu.RUnlock()
		for _, ts := range targets {
			e.restore(ts)
		}
		e.log.Info("engine stopped",
			"forwarded", e.stats.Forwarded, "dropped", e.stats.Dropped,
			"poisoned", e.stats.Poisoned, "restored", e.stats.Restored)
	})
}

// SetTargets reconciles the desired enforcement set with what is running.
// Newly enforced targets are poisoned; targets that were released are restored
// before being forgotten, so no device is ever left stranded.
func (e *Engine) SetTargets(targets []Target) {
	want := make(map[string]Target, len(targets))
	for _, t := range targets {
		if t.MAC == nil || len(t.MAC) != 6 {
			continue
		}
		if t.MAC.String() == e.localMA.String() {
			continue // never enforce on ourselves
		}
		if e.gwMAC != nil && t.MAC.String() == e.gwMAC.String() {
			continue // never poison the gateway itself
		}
		if t.Mode != ModeBlock && t.Mode != ModeThrottle {
			continue // allow/observe carry no enforcement
		}
		want[t.Key()] = t
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Release anything no longer wanted.
	for key, ts := range e.targets {
		if _, ok := want[key]; !ok {
			go e.restore(ts)
			delete(e.targets, key)
		}
	}

	// Add or update.
	for key, t := range want {
		ts, ok := e.targets[key]
		if !ok {
			ts = &targetState{
				realMAC: t.MAC,
				stats: TargetStats{
					MAC: t.MAC.String(), IP: ipString(t.IP),
					Mode: string(t.Mode), Since: time.Now(),
				},
			}
			e.targets[key] = ts
		}
		ts.target = t
		ts.stats.Mode = string(t.Mode)
		ts.stats.IP = ipString(t.IP)
		ts.stats.CapKbps = t.CapKbps
		ts.stats.UpKbps = t.UpKbps
		ts.shaperUp = newShaper(t.UpKbps, t.CapKbps)
		ts.shaperDn = newShaper(t.CapKbps, t.UpKbps)
	}
}

// Active reports how many targets are currently enforced.
//
// The caller uses this to decide whether a release is needed at all, and to
// report what was released, so a failed poll does not trigger needless work.
func (e *Engine) Active() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	n := 0
	for _, ts := range e.targets {
		if ts.active {
			n++
		}
	}
	return n
}

// RestoreAll releases every target without stopping the engine.
func (e *Engine) RestoreAll() {
	e.mu.RLock()
	targets := make([]*targetState, 0, len(e.targets))
	for _, ts := range e.targets {
		targets = append(targets, ts)
	}
	e.mu.RUnlock()
	for _, ts := range targets {
		e.restore(ts)
	}
	e.mu.Lock()
	e.targets = map[string]*targetState{}
	e.mu.Unlock()
}

// Stats returns per-target telemetry.
func (e *Engine) Stats() []TargetStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]TargetStats, 0, len(e.targets))
	for _, ts := range e.targets {
		s := ts.stats
		s.Enforcing = ts.active
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}

// Neighbours returns the ARP table the engine has learned.
func (e *Engine) Neighbours() []Neighbour {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Neighbour, 0, len(e.neighByIP))
	for _, n := range e.neighByIP {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return bytesLess(out, i, j) })
	return out
}

// EngineStats returns aggregate counters.
func (e *Engine) EngineStats() map[string]uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return map[string]uint64{
		"frames":    e.stats.Frames,
		"forwarded": e.stats.Forwarded,
		"dropped":   e.stats.Dropped,
		"poisoned":  e.stats.Poisoned,
		"restored":  e.stats.Restored,
		"errors":    e.stats.Errors,
	}
}

// ---------------------------------------------------------------- poison loop

func (e *Engine) poisonLoop() {
	defer e.wg.Done()
	ticker := time.NewTicker(poisonInterval)
	defer ticker.Stop()
	for {
		select {
		case <-e.closed:
			return
		case <-ticker.C:
			e.poisonAll()
		}
	}
}

func (e *Engine) poisonAll() {
	if e.opts.DryRun {
		return
	}
	e.mu.RLock()
	targets := make([]*targetState, 0, len(e.targets))
	for _, ts := range e.targets {
		targets = append(targets, ts)
	}
	gwMAC, gwIP := e.gwMAC, e.gwIP
	e.mu.RUnlock()

	if gwMAC == nil || gwIP == nil {
		return
	}

	for _, ts := range targets {
		if ts.target.IP == nil {
			continue
		}
		// Tell the target that the gateway lives at our MAC, and tell the
		// gateway that the target lives at our MAC.
		if err := e.sendARPReply(ts.realMAC, gwIP, e.localMA, ts.target.IP); err != nil {
			e.bumpErr()
			continue
		}
		if err := e.sendARPReply(gwMAC, ts.target.IP, e.localMA, gwIP); err != nil {
			e.bumpErr()
			continue
		}
		e.mu.Lock()
		ts.active = true
		e.stats.Poisoned++
		e.mu.Unlock()
	}
}

// restore re-establishes the truthful mappings for a target so its traffic
// flows directly again. Sent several times because a single ARP reply can be
// lost and a stale forged entry would otherwise persist for minutes.
func (e *Engine) restore(ts *targetState) {
	if e.opts.DryRun || e.dev == nil || ts == nil || ts.target.IP == nil {
		return
	}
	gwMAC, gwIP := e.gwMAC, e.gwIP
	if gwMAC == nil || gwIP == nil {
		return
	}
	for i := 0; i < 4; i++ {
		// Target: the gateway really is at the gateway's MAC.
		_ = e.sendARPReply(ts.realMAC, gwIP, gwMAC, ts.target.IP)
		// Gateway: the target really is at the target's MAC.
		_ = e.sendARPReply(gwMAC, ts.target.IP, ts.realMAC, gwIP)
		time.Sleep(60 * time.Millisecond)
	}
	e.mu.Lock()
	ts.active = false
	e.stats.Restored++
	e.mu.Unlock()
	e.log.Info("released target", "mac", ts.realMAC, "ip", ts.target.IP)
}

// ---------------------------------------------------------------- read loop

func (e *Engine) readLoop() {
	defer e.wg.Done()
	for {
		select {
		case <-e.closed:
			return
		default:
		}
		frame, err := e.dev.ReadPacket(readTimeout)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			select {
			case <-e.closed:
				return
			default:
			}
			e.log.Warn("capture read failed", "err", err)
			e.bumpErr()
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if len(frame) < 14 {
			continue
		}
		e.handleFrame(frame)
	}
}

// handleFrame classifies one captured Ethernet frame and acts on it.
func (e *Engine) handleFrame(frame []byte) {
	e.mu.Lock()
	e.stats.Frames++
	e.mu.Unlock()

	dst := net.HardwareAddr(frame[0:6])
	src := net.HardwareAddr(frame[6:12])
	etherType := uint16(frame[12])<<8 | uint16(frame[13])

	// Frames we transmitted ourselves are re-captured by the filter. Their
	// source is always our MAC, so this single check drops injection and
	// forwarding loops in one stroke.
	if src.String() == e.localMA.String() {
		return
	}

	if etherType == etherTypeARP {
		e.learnARP(frame)

		// ARP must still be answered for anything under enforcement.
		//
		// Poisoning tells each side that the other lives at our MAC, so both
		// sides periodically ask us to confirm it. Dropping those requests
		// means the gateway cannot resolve a target and the target cannot
		// resolve the gateway; both then retransmit broadcasts indefinitely,
		// and a broadcast storm is processed by every device on the segment.
		// That is how throttling one device degraded the whole network.
		if e.arpMatters(frame) {
			e.answerARP(frame)
		}
		return
	}
	if etherType != etherTypeIPv4 {
		return
	}

	// Only frames addressed to us are ours to carry. After poisoning this
	// covers both directions of every enforced target's traffic.
	if dst.String() != e.localMA.String() {
		return
	}

	// A frame whose source is a target is that target uploading.
	e.mu.RLock()
	gwMAC := e.gwMAC
	tsFrom, fromTarget := e.targets[src.String()]
	e.mu.RUnlock()

	var (
		ts      *targetState
		nextHop net.HardwareAddr
		upload  bool
	)
	if fromTarget {
		// Upload: carry it on to the real gateway.
		ts, nextHop, upload = tsFrom, gwMAC, true
	} else {
		// Download, or gateway traffic. After poisoning, the gateway addresses
		// the target's frames to us, so the destination IP is what identifies
		// the target; the Ethernet destination is just our own MAC.
		dstIP := ipv4Dst(frame)
		if dstIP == nil {
			return
		}
		ts = e.targetByIP(dstIP)
		if ts == nil {
			return
		}
		nextHop, upload = ts.realMAC, false
	}
	if ts == nil || nextHop == nil {
		return
	}
	// Guard: never forward back to the sender.
	if nextHop.String() == src.String() {
		return
	}

	e.mu.Lock()
	if upload {
		ts.stats.TxPackets++
		ts.stats.TxBytes += uint64(len(frame))
	} else {
		ts.stats.RxPackets++
		ts.stats.RxBytes += uint64(len(frame))
	}
	mode := ts.target.Mode
	e.mu.Unlock()

	switch mode {
	case ModeBlock:
		e.mu.Lock()
		e.stats.Dropped++
		if upload {
			ts.stats.TxDropped++
		} else {
			ts.stats.RxDropped++
		}
		e.mu.Unlock()
		return
	case ModeThrottle:
		sh := ts.shaperDn
		if upload {
			sh = ts.shaperUp
		}
		if sh != nil && !sh.allow(len(frame)) {
			e.mu.Lock()
			e.stats.Dropped++
			if upload {
				ts.stats.TxDropped++
				ts.stats.TxShaped++
			} else {
				ts.stats.RxDropped++
				ts.stats.RxShaped++
			}
			e.mu.Unlock()
			return
		}
	}

	// Forward: rewrite the destination to the true next hop. The source is
	// rewritten to our MAC, which also guarantees the re-captured copy of this
	// frame is ignored by the loop check above.
	out := make([]byte, len(frame))
	copy(out, frame)
	copy(out[0:6], nextHop)
	copy(out[6:12], e.localMA)
	if err := e.write(out); err != nil {
		e.bumpErr()
		return
	}
	e.mu.Lock()
	e.stats.Forwarded++
	e.mu.Unlock()
}

// targetByIP returns the enforced target owning an IPv4 address.
func (e *Engine) targetByIP(ip net.IP) *targetState {
	key := ip.String()
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, ts := range e.targets {
		if ts.target.IP != nil && ts.target.IP.String() == key {
			return ts
		}
	}
	return nil
}

// ipv4Dst returns the IPv4 destination of an Ethernet frame, or nil when the
// frame is not IPv4 or is too short to carry a header.
func ipv4Dst(frame []byte) net.IP {
	if len(frame) < 34 {
		return nil
	}
	if frame[12] != 0x08 || frame[13] != 0x00 {
		return nil
	}
	ihl := int(frame[14]&0x0f) * 4
	if ihl < 20 || len(frame) < 14+ihl {
		return nil
	}
	ip := make(net.IP, 4)
	copy(ip, frame[30:34])
	return ip
}

// learnARP records address bindings from observed ARP traffic and answers any
// outstanding resolution waiters.
func (e *Engine) learnARP(frame []byte) {
	if len(frame) < 42 {
		return
	}
	arp := frame[14:]
	htype := uint16(arp[0])<<8 | uint16(arp[1])
	ptype := uint16(arp[2])<<8 | uint16(arp[3])
	hlen, plen := arp[4], arp[5]
	oper := uint16(arp[6])<<8 | uint16(arp[7])
	if htype != 1 || ptype != etherTypeIPv4 || hlen != 6 || plen != 4 {
		return
	}
	sha := net.HardwareAddr(arp[8:14])
	spa := net.IP(arp[14:18]).To4()
	if spa == nil {
		return
	}

	e.mu.Lock()
	n := Neighbour{MAC: sha, IP: spa, Seen: time.Now()}
	e.neighByIP[spa.String()] = n
	e.neighByMA[sha.String()] = n
	if e.gwIP != nil && spa.Equal(e.gwIP) && e.gwMAC == nil {
		e.gwMAC = sha
		e.uplinkHealthy = true
		e.log.Info("gateway MAC learned from ARP", "gateway", spa, "mac", sha)
	}
	e.mu.Unlock()

	if oper == 2 { // reply
		e.pendMu.Lock()
		if ch, ok := e.pending[spa.String()]; ok {
			select {
			case ch <- sha:
			default:
			}
			delete(e.pending, spa.String())
		}
		e.pendMu.Unlock()
	}
}

// resolveMAC sends an ARP request for ip and waits for a reply.
func (e *Engine) resolveMAC(ctx contextContext, ip net.IP) (net.HardwareAddr, error) {
	// Already known?
	e.mu.RLock()
	if n, ok := e.neighByIP[ip.String()]; ok && time.Since(n.Seen) < 5*time.Minute {
		e.mu.RUnlock()
		return n.MAC, nil
	}
	e.mu.RUnlock()

	if e.dev == nil {
		return nil, errors.New("capture device is not open")
	}

	ch := make(chan net.HardwareAddr, 1)
	e.pendMu.Lock()
	e.pending[ip.String()] = ch
	e.pendMu.Unlock()
	defer func() {
		e.pendMu.Lock()
		delete(e.pending, ip.String())
		e.pendMu.Unlock()
	}()

	req := buildARPRequest(e.localMA, e.localIP, ip)
	for attempt := 0; attempt < 3; attempt++ {
		if err := e.write(req); err != nil {
			return nil, err
		}
		select {
		case mac := <-ch:
			return mac, nil
		case <-ctx.Done():
			return nil, fmt.Errorf("no ARP reply from %s: %w", ip, ctx.Err())
		case <-time.After(700 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("no ARP reply from %s after 3 attempts", ip)
}

// Probe sends an ARP request for every address in subnet and returns the
// replies it observes within the deadline. This is the discovery scan.
func (e *Engine) Probe(subnet *net.IPNet, timeout time.Duration) []Neighbour {
	if subnet == nil || e.dev == nil || e.opts.DryRun {
		return e.Neighbours()
	}
	ips := hostsIn(subnet)

	// Send in bounded batches so a /16 does not flood the segment at once.
	const batch = 64
	for i := 0; i < len(ips); i += batch {
		end := i + batch
		if end > len(ips) {
			end = len(ips)
		}
		for _, ip := range ips[i:end] {
			_ = e.write(buildARPRequest(e.localMA, e.localIP, ip))
		}
		select {
		case <-e.closed:
			return e.Neighbours()
		case <-time.After(12 * time.Millisecond):
		}
	}

	// Give slow responders a chance to answer.
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-e.closed:
			return e.Neighbours()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return e.Neighbours()
}

// ---------------------------------------------------------------- frame I/O

func (e *Engine) write(frame []byte) error {
	if e.writeHook != nil {
		return e.writeHook(frame)
	}
	if e.dev == nil || e.opts.DryRun {
		return nil
	}
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	return e.dev.WritePacket(frame)
}

func (e *Engine) sendARPReply(dstMAC net.HardwareAddr, claimedIP net.IP, claimedMAC net.HardwareAddr, targetIP net.IP) error {
	return e.write(buildARPReply(dstMAC, e.localMA, claimedMAC, claimedIP, dstMAC, targetIP))
}

func (e *Engine) bumpErr() {
	e.mu.Lock()
	e.stats.Errors++
	e.mu.Unlock()
}

// ---------------------------------------------------------------- frame build

// buildARPReply builds a 42-byte ARP reply Ethernet frame.
//
// The frame claims claimedIP is reachable at claimedMAC, and is addressed to
// dstMAC whose IP is targetIP.
func buildARPReply(dstMAC, srcMAC, claimedMAC net.HardwareAddr, claimedIP net.IP, targetMAC net.HardwareAddr, targetIP net.IP) []byte {
	f := make([]byte, 42)
	copy(f[0:6], dstMAC)
	copy(f[6:12], srcMAC)
	f[12], f[13] = 0x08, 0x06 // ARP

	arp := f[14:]
	arp[0], arp[1] = 0x00, 0x01 // htype = Ethernet
	arp[2], arp[3] = 0x08, 0x00 // ptype = IPv4
	arp[4] = 6                  // hlen
	arp[5] = 4                  // plen
	arp[6], arp[7] = 0x00, 0x02 // oper = reply
	copy(arp[8:14], claimedMAC)
	copy(arp[14:18], claimedIP.To4())
	copy(arp[18:24], targetMAC)
	copy(arp[24:28], targetIP.To4())
	return f
}

// buildARPRequest builds an ARP request asking who-has targetIP.
func buildARPRequest(srcMAC net.HardwareAddr, srcIP, targetIP net.IP) []byte {
	f := make([]byte, 42)
	broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	copy(f[0:6], broadcast)
	copy(f[6:12], srcMAC)
	f[12], f[13] = 0x08, 0x06

	arp := f[14:]
	arp[0], arp[1] = 0x00, 0x01
	arp[2], arp[3] = 0x08, 0x00
	arp[4] = 6
	arp[5] = 4
	arp[6], arp[7] = 0x00, 0x01 // oper = request
	copy(arp[8:14], srcMAC)
	copy(arp[14:18], srcIP.To4())
	copy(arp[18:24], broadcast) // target hardware unknown
	copy(arp[24:28], targetIP.To4())
	return f
}

// ---------------------------------------------------------------- token bucket

// shaper is a byte-oriented token bucket. A frame is admitted only if the
// bucket holds enough tokens for it, which caps throughput at the configured
// rate; TCP then backs off on its own. Burst is a quarter-second of capacity,
// bounded below so a tiny cap still lets an ACK through.
type shaper struct {
	mu     sync.Mutex
	rate   float64 // bytes per second
	burst  float64
	tokens float64
	last   time.Time
}

func newShaper(primaryKbps, fallbackKbps int) *shaper {
	kbps := primaryKbps
	if kbps <= 0 {
		kbps = fallbackKbps
	}
	if kbps <= 0 {
		return nil // no cap: caller forwards unconditionally
	}
	rate := float64(kbps) * 125.0 // kbps -> bytes/second
	burst := rate * 0.25
	if burst < 6000 {
		burst = 6000 // ~4 full-size frames, so control traffic still passes
	}
	return &shaper{rate: rate, burst: burst, tokens: burst, last: time.Now()}
}

func (s *shaper) allow(n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(s.last).Seconds()
	s.last = now
	s.tokens += elapsed * s.rate
	if s.tokens > s.burst {
		s.tokens = s.burst
	}
	if s.tokens >= float64(n) {
		s.tokens -= float64(n)
		return true
	}
	return false
}

// arpMatters reports whether an ARP frame relates to something we enforce and
// therefore has to be carried rather than dropped.
func (e *Engine) arpMatters(frame []byte) bool {
	if len(frame) < 42 {
		return false
	}
	arp := frame[14:]
	spa := net.IP(arp[14:18]).To4() // sender protocol address
	tpa := net.IP(arp[24:28]).To4() // target protocol address
	if spa == nil || tpa == nil {
		return false
	}

	// The gateway trying to reach a target we are enforcing: we must answer,
	// otherwise it cannot resolve the target at all.
	e.mu.RLock()
	gwIP := e.gwIP
	_, targetTPA := e.targetByIPLocked(tpa)
	_, targetSPA := e.targetByIPLocked(spa)
	e.mu.RUnlock()

	if targetTPA {
		return true
	}
	// A target looking for the gateway.
	if targetSPA && gwIP != nil && tpa.Equal(gwIP) {
		return true
	}
	return false
}

// targetByIPLocked is targetByIP without taking the lock, for callers that
// already hold it.
func (e *Engine) targetByIPLocked(ip net.IP) (*targetState, bool) {
	if ip == nil {
		return nil, false
	}
	key := ip.String()
	for _, ts := range e.targets {
		if ts.target.IP != nil && ts.target.IP.String() == key {
			return ts, true
		}
	}
	return nil, false
}

// answerARP replies to an ARP request that we are now the next hop for.
//
// This is not a courtesy: it is what keeps enforcement working. Poisoning tells
// each side that the other lives at our MAC, so both sides periodically ask us
// to confirm it. If the request goes unanswered the sender's entry expires, and
// if it is answered with the truth the sender bypasses us and enforcement
// silently stops. The reply therefore re-asserts the redirection, which is the
// same claim the poison round makes — sent as a direct answer, which is what
// makes it accepted.
//
// The two cases, both of which we are legitimately in the middle of:
//
//	the gateway asks who has a target   -> the target is at us
//	a target asks who has the gateway   -> the gateway is at us
func (e *Engine) answerARP(frame []byte) {
	if len(frame) < 42 {
		return
	}
	arp := frame[14:]
	oper := uint16(arp[6])<<8 | uint16(arp[7])
	if oper != 1 { // only requests are answered; replies are already handled
		return
	}
	senderMAC := net.HardwareAddr(frame[6:12])
	spa := net.IP(arp[14:18]).To4() // who is asking
	tpa := net.IP(arp[24:28]).To4() // who they are asking about
	if spa == nil || tpa == nil {
		return
	}
	if senderMAC.String() == e.localMA.String() {
		return
	}

	e.mu.RLock()
	gwIP := e.gwIP
	_, tpaIsTarget := e.targetByIPLocked(tpa)
	_, spaIsTarget := e.targetByIPLocked(spa)
	e.mu.RUnlock()

	switch {
	case tpaIsTarget:
		// The gateway (or anyone) asking for a target we enforce: answer that
		// the target is at our MAC, so the traffic keeps coming through us.
		_ = e.sendARPReply(senderMAC, tpa, e.localMA, spa)
	case spaIsTarget && gwIP != nil && tpa.Equal(gwIP):
		// A target asking for the gateway: answer that the gateway is at our
		// MAC, so its traffic keeps coming through us.
		_ = e.sendARPReply(senderMAC, gwIP, e.localMA, spa)
	}
}

// ---------------------------------------------------------------- helpers

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// hostsIn enumerates usable host addresses of a subnet, capped so an
// accidental /8 cannot stall the agent.
func hostsIn(n *net.IPNet) []net.IP {
	const maxHosts = 4096
	base := n.IP.Mask(n.Mask).To4()
	if base == nil {
		return nil
	}
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return nil
	}
	total := uint64(1) << uint(32-ones)
	if total > maxHosts {
		total = maxHosts
	}
	if total < 2 {
		return nil
	}
	start := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])

	out := make([]net.IP, 0, total-1)
	// Skip the network address; the final address is the broadcast.
	for i := uint64(1); i < total-1; i++ {
		v := start + uint32(i)
		out = append(out, net.IPv4(
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).To4())
	}
	return out
}

func ifaceMAC(name string, ip net.IP) (net.HardwareAddr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, ifc := range ifaces {
		if name != "" && !strings.EqualFold(ifc.Name, name) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			if name == "" && !ipnet.IP.Equal(ip) {
				continue
			}
			if len(ifc.HardwareAddr) == 6 {
				return ifc.HardwareAddr, nil
			}
		}
	}
	return nil, fmt.Errorf("no Ethernet interface matched %q / %s", name, ip)
}

func bytesLess(list []Neighbour, i, j int) bool {
	a, b := list[i].IP.To4(), list[j].IP.To4()
	if a == nil || b == nil {
		return list[i].IP.String() < list[j].IP.String()
	}
	for k := 0; k < 4; k++ {
		if a[k] != b[k] {
			return a[k] < b[k]
		}
	}
	return false
}

// OUI prefixes for the vendors most likely to appear on a home or small-office
// segment. This is a deliberately small, curated table: it labels the common
// cases without shipping a multi-megabyte IEEE registry.
var ouiVendors = map[string]string{
	"00:1A:2B": "Cisco", "00:1B:2F": "Netgear", "00:1C:10": "Cisco-Linksys",
	"00:1E:58": "D-Link", "00:22:6B": "Cisco-Linksys", "00:24:B2": "Netgear",
	"00:25:9C": "Cisco-Linksys", "00:26:5A": "D-Link", "00:50:56": "VMware",
	"00:0C:29": "VMware", "00:05:69": "VMware", "08:00:27": "VirtualBox",
	"0A:00:27": "VirtualBox", "52:54:00": "QEMU/KVM", "00:15:5D": "Microsoft Hyper-V",
	"00:03:FF": "Microsoft", "00:17:FA": "Microsoft", "7C:1E:52": "Microsoft",
	"00:1B:63": "Apple", "00:1E:C2": "Apple", "00:23:DF": "Apple", "00:25:00": "Apple",
	"3C:07:54": "Apple", "40:6C:8F": "Apple", "58:55:CA": "Apple", "60:F8:1D": "Apple",
	"68:AB:1E": "Apple", "7C:D1:C3": "Apple", "8C:85:90": "Apple", "9C:04:EB": "Apple",
	"A4:83:E7": "Apple", "AC:BC:32": "Apple", "B8:E8:56": "Apple", "D0:81:7A": "Apple",
	"DC:A9:04": "Apple", "F0:18:98": "Apple", "F4:F1:5A": "Apple", "1C:AB:A7": "Apple",
	"00:1E:64": "Intel", "00:21:6A": "Intel", "00:24:D7": "Intel", "34:13:E8": "Intel",
	"48:51:B7": "Intel", "5C:E0:C5": "Intel", "7C:5C:F8": "Intel", "94:65:9C": "Intel",
	"A0:88:B4": "Intel", "AC:7B:A1": "Intel", "B4:6B:FC": "Intel", "D8:FC:93": "Intel",
	"E4:A4:71": "Intel", "F8:16:54": "Intel", "00:1C:BF": "Intel", "00:23:14": "Intel",
	"00:E0:4C": "Realtek", "52:54:AB": "Realtek", "00:26:82": "Realtek",
	"00:1F:A4": "Samsung", "00:21:19": "Samsung", "08:37:3D": "Samsung", "1C:5A:3E": "Samsung",
	"34:23:BA": "Samsung", "38:AA:3C": "Samsung", "5C:0A:5B": "Samsung", "78:1F:DB": "Samsung",
	"8C:71:F8": "Samsung", "B4:79:A7": "Samsung", "D0:22:BE": "Samsung", "E8:50:8B": "Samsung",
	"00:9E:C8": "Xiaomi", "0C:1D:AF": "Xiaomi", "14:F6:5A": "Xiaomi", "20:47:DA": "Xiaomi",
	"28:6C:07": "Xiaomi", "34:CE:00": "Xiaomi", "3C:BD:3E": "Xiaomi", "50:8F:4C": "Xiaomi",
	"64:09:80": "Xiaomi", "64:B4:73": "Xiaomi", "74:23:44": "Xiaomi", "78:11:DC": "Xiaomi",
	"8C:BE:BE": "Xiaomi", "98:FA:E3": "Xiaomi", "A4:DA:22": "Xiaomi", "AC:C1:EE": "Xiaomi",
	"B0:E2:35": "Xiaomi", "C4:0B:CB": "Xiaomi", "D4:97:0B": "Xiaomi", "F0:B4:29": "Xiaomi",
	"F8:A4:5F": "Xiaomi", "FC:64:BA": "Xiaomi", "10:2A:B3": "Xiaomi", "18:59:36": "Xiaomi",
	"00:E0:FC": "Huawei", "00:1E:10": "Huawei", "00:25:9E": "Huawei", "04:BD:70": "Huawei",
	"08:19:A6": "Huawei", "0C:37:DC": "Huawei", "10:47:80": "Huawei", "18:C5:8A": "Huawei",
	"20:0B:C7": "Huawei", "24:69:A5": "Huawei", "28:3C:E4": "Huawei", "34:6B:D3": "Huawei",
	"48:00:31": "Huawei", "5C:7D:5E": "Huawei", "70:72:3C": "Huawei", "78:D7:52": "Huawei",
	"84:A8:E4": "Huawei", "88:E0:56": "Huawei", "8C:34:FD": "Huawei", "9C:28:EF": "Huawei",
	"A4:99:47": "Huawei", "AC:E2:15": "Huawei", "B4:15:13": "Huawei", "C8:D1:5E": "Huawei",
	"D0:7A:B5": "Huawei", "E0:24:7F": "Huawei", "E8:08:8B": "Huawei", "F4:C7:14": "Huawei",
	"00:26:5E": "Hon Hai (Foxconn)", "00:1E:8C": "ASUS", "00:23:54": "ASUS",
	"04:D4:C4": "ASUS", "08:60:6E": "ASUS", "10:BF:48": "ASUS", "1C:87:2C": "ASUS",
	"2C:56:DC": "ASUS", "38:D5:47": "ASUS", "40:16:7E": "ASUS", "50:46:5D": "ASUS",
	"74:D0:2B": "ASUS", "AC:9E:17": "ASUS", "B0:6E:BF": "ASUS", "D8:50:E6": "ASUS",
	"00:1D:7E": "TP-Link", "00:27:19": "TP-Link", "10:FE:ED": "TP-Link",
	"14:CC:20": "TP-Link", "18:A6:F7": "TP-Link", "1C:3B:F3": "TP-Link",
	"28:2C:B2": "TP-Link", "30:B5:C2": "TP-Link", "3C:46:D8": "TP-Link",
	"50:C7:BF": "TP-Link", "54:C8:0F": "TP-Link", "60:32:B1": "TP-Link",
	"64:70:02": "TP-Link", "6C:5A:B0": "TP-Link", "74:DA:88": "TP-Link",
	"8C:21:0A": "TP-Link", "98:DA:C4": "TP-Link", "A4:2B:B0": "TP-Link",
	"B0:4E:26": "TP-Link", "C0:06:C3": "TP-Link", "C4:6E:1F": "TP-Link",
	"E8:94:F6": "TP-Link", "EC:08:6B": "TP-Link", "F4:EC:38": "TP-Link",
	"00:0C:43": "MediaTek", "00:0C:E7": "MediaTek", "1C:4B:D6": "MediaTek",
	"24:0A:C4": "Espressif", "30:AE:A4": "Espressif", "3C:71:BF": "Espressif",
	"48:3F:DA": "Espressif", "5C:CF:7F": "Espressif", "7C:DF:A1": "Espressif",
	"84:0D:8E": "Espressif", "8C:AA:B5": "Espressif", "A4:CF:12": "Espressif",
	"AC:67:B2": "Espressif", "B4:E6:2D": "Espressif", "C4:4F:33": "Espressif",
	"CC:50:E3": "Espressif", "D8:A0:1D": "Espressif", "DC:4F:22": "Espressif",
	"EC:FA:BC": "Espressif", "F4:CF:A2": "Espressif", "FC:F5:C4": "Espressif",
	"00:1A:11": "Google", "20:DF:B9": "Google", "3C:5A:B4": "Google",
	"54:60:09": "Google", "6C:AD:F8": "Google", "94:EB:2C": "Google",
	"F4:F5:D8": "Google", "F4:F5:E8": "Google", "1C:F2:9A": "Google",
	"44:65:0D": "Amazon", "50:DC:E7": "Amazon", "68:37:E9": "Amazon",
	"74:C2:46": "Amazon", "84:D6:D0": "Amazon", "A0:02:DC": "Amazon",
	"B4:7C:9C": "Amazon", "F0:27:2D": "Amazon", "FC:A1:83": "Amazon",
	"00:26:BB": "Apple (AirPort)",
	"00:15:6D": "Ubiquiti", "04:18:D6": "Ubiquiti", "24:A4:3C": "Ubiquiti",
	"44:D9:E7": "Ubiquiti", "68:D7:9A": "Ubiquiti", "74:83:C2": "Ubiquiti",
	"78:8A:20": "Ubiquiti", "80:2A:A8": "Ubiquiti", "B4:FB:E4": "Ubiquiti",
	"DC:9F:DB": "Ubiquiti", "F0:9F:C2": "Ubiquiti",
	"00:0C:42": "MikroTik", "08:55:31": "MikroTik", "18:FD:74": "MikroTik",
	"48:8F:5A": "MikroTik", "4C:5E:0C": "MikroTik", "64:D1:54": "MikroTik",
	"6C:3B:6B": "MikroTik", "74:4D:28": "MikroTik", "78:9A:18": "MikroTik",
	"B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
	"28:CD:C1": "Raspberry Pi", "D8:3A:DD": "Raspberry Pi",
	"00:1B:44": "SanDisk", "00:1D:BA": "Sony", "00:24:BE": "Sony",
	"30:F9:ED": "Sony", "78:84:3C": "Sony", "AC:9B:0A": "Sony",
	"00:1C:62": "LG", "00:1E:75": "LG", "00:22:A9": "LG", "10:68:3F": "LG",
	"2C:54:CF": "LG", "40:B0:76": "LG", "58:FD:B1": "LG", "A8:16:B2": "LG",
	"00:1F:E1": "Philips", "00:17:88": "Philips Hue", "EC:B5:FA": "Philips Hue",
	"00:17:EE": "Xiaomi",
	"00:1D:0F": "TP-Link", "9C:53:22": "Compal",
	"00:B0:0C": "Tenda", "D8:32:14": "Tenda",
	"00:1A:79": "AVM", "00:04:20": "Slim Devices", "00:1F:5B": "Apple",
	"02:00:00": "Locally administered",
	"00:16:3E": "Xen", "00:1C:42": "Parallels",
	"00:11:32": "Synology", "00:1A:8C": "Synology",
	"00:11:D9": "TiVo", "00:1F:90": "Actiontec", "00:24:36": "Actiontec",
	"00:23:CD": "Teltonika", "00:1E:42": "Teltonika",
}

// VendorFor returns a best-effort vendor name for a MAC address.
func VendorFor(mac net.HardwareAddr) string {
	if len(mac) != 6 {
		return ""
	}
	// Locally administered addresses have the second-least-significant bit of
	// the first octet set; they are randomised by the OS, not assigned.
	if mac[0]&0x02 != 0 {
		return "Randomised (private)"
	}
	key := strings.ToUpper(mac[:3].String())
	if v, ok := ouiVendors[key]; ok {
		return v
	}
	return ""
}

// IsMulticast reports whether a MAC is a group address.
func IsMulticast(mac net.HardwareAddr) bool {
	return len(mac) == 6 && mac[0]&0x01 != 0
}
