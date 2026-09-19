// language: Go, file: cmd/netcut-agent/main.go
//
// netcut-agent is the data plane. It runs natively on the host that owns the
// monitored segment (the machine on the LAN, not the container), because a
// NAT-ed container cannot reach layer 2.
//
// It discovers hosts, reports them to the control plane, receives enforcement
// directives, and applies them at layer 2. Every enforced target is released
// cleanly on shutdown, so stopping the agent heals the segment.
//
// Windows requires elevation and Npcap. Run it from an elevated prompt:
//
//	netcut-agent.exe -server https://netcut.example.com -token <agent-token>
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kevinantoniowiyonolauw/netcut/internal/arp"
	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
	"github.com/kevinantoniowiyonolauw/netcut/internal/netinfo"
	"github.com/kevinantoniowiyonolauw/netcut/internal/version"
)

type options struct {
	server    string
	token     string
	iface     string
	gateway   string
	subnet    string
	interval  time.Duration
	probeEach int
	dryRun    bool
	insecure  bool
	check     bool
	verbose   bool
	agentName string
}

func main() {
	var o options
	flag.StringVar(&o.server, "server", envOr("NETCUT_SERVER", ""), "control plane base URL, e.g. https://netcut.example.com")
	flag.StringVar(&o.token, "token", envOr("NETCUT_AGENT_TOKEN", ""), "agent credential issued by the dashboard")
	flag.StringVar(&o.iface, "iface", envOr("NETCUT_IFACE", ""), "interface to police (default: the one owning the default route)")
	flag.StringVar(&o.gateway, "gateway", envOr("NETCUT_GATEWAY", ""), "gateway IPv4 (default: discovered from the routing table)")
	flag.StringVar(&o.subnet, "subnet", envOr("NETCUT_SUBNET", ""), "CIDR to scan (default: derived from the interface)")
	flag.DurationVar(&o.interval, "interval", envDuration("NETCUT_INTERVAL", 3*time.Second), "report interval")
	flag.IntVar(&o.probeEach, "probe-every", envInt("NETCUT_PROBE_EVERY", 5), "run a full ARP sweep every N cycles (0 disables)")
	flag.BoolVar(&o.dryRun, "dry-run", envBool("NETCUT_DRY_RUN", false), "discover and report only; never transmit or enforce")
	flag.BoolVar(&o.insecure, "insecure", envBool("NETCUT_INSECURE", false), "skip TLS verification (self-signed control plane only)")
	flag.BoolVar(&o.check, "check", false, "print interface diagnostics and exit")
	flag.BoolVar(&o.verbose, "verbose", envBool("NETCUT_VERBOSE", false), "debug logging")
	flag.StringVar(&o.agentName, "name", envOr("NETCUT_AGENT_NAME", ""), "friendly name for this agent")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("netcut-agent %s (commit %s)\n", version.Version, version.Commit)
		return
	}

	level := slog.LevelInfo
	if o.verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if o.check {
		os.Exit(runCheck(log))
	}

	if err := run(log, o); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, o options) error {
	log.Info("netcut-agent starting", "version", version.Version, "os", runtime.GOOS, "dry_run", o.dryRun)

	elevated := isElevated()
	if !elevated && !o.dryRun {
		log.Warn("not running elevated: opening a capture device will fail. " +
			"Re-run this agent from an Administrator prompt (Windows) or as root (Linux).")
	}

	// ---- interface selection ----
	iface, err := selectIface(o)
	if err != nil {
		return err
	}
	log.Info("monitoring interface",
		"name", iface.Name, "ip", iface.IP, "mac", iface.MAC,
		"gateway", iface.Gateway, "subnet", iface.CIDR)

	localIP := net.ParseIP(iface.IP)
	if localIP == nil {
		return fmt.Errorf("interface %s has no parsable IPv4 address", iface.Name)
	}
	gwIP := net.ParseIP(o.gateway)
	if gwIP == nil {
		gwIP = net.ParseIP(iface.Gateway)
	}
	if gwIP == nil {
		return errors.New("no gateway could be determined; pass -gateway")
	}

	subnetCIDR := o.subnet
	if subnetCIDR == "" {
		subnetCIDR = iface.CIDR
	}
	subnet, err := netinfo.ParseSubnet(subnetCIDR)
	if err != nil {
		return err
	}
	log.Info("scan scope", "subnet", subnet.String())

	// ---- engine ----
	eng, err := arp.New(arp.Options{
		Iface:   iface.Name,
		LocalIP: localIP,
		Gateway: gwIP,
		Log:     log,
		DryRun:  o.dryRun,
	})
	if err != nil {
		return err
	}
	if err := eng.Start(); err != nil {
		if errors.Is(err, arp.ErrUnsupported) {
			return fmt.Errorf("%w\n\nRun with -dry-run to verify discovery without enforcement, or run -check to see what is missing.", err)
		}
		return err
	}
	defer eng.Stop()

	agentID := o.agentName
	if agentID == "" {
		agentID = fmt.Sprintf("%s-%s", hostname(), iface.MAC)
	}

	client := newClient(o)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Send the first heartbeat immediately so the dashboard learns the topology.
	info := buildAgentInfo(agentID, o, iface, subnet, elevated, eng)
	if err := postJSON(ctx, client, o.server+"/api/agent/hello", o.token, info, nil); err != nil {
		log.Warn("initial heartbeat failed", "err", err)
	} else {
		log.Info("registered with control plane", "server", o.server, "agent_id", agentID)
	}

	// ---- main loop ----
	tick := time.NewTicker(o.interval)
	defer tickerStop(tick)
	probeTick := time.NewTicker(60 * time.Second)
	defer tickerStop(probeTick)

	cycle := 0
	prev := map[string]arp.TargetStats{}
	resolver := newNameResolver()

	// Probe once up front so the first report is complete. In dry run the
	// bindings come from the OS cache instead, so there is nothing to probe.
	if !o.dryRun {
		go func() {
			eng.Probe(subnet, 3*time.Second)
		}()
	} else {
		log.Warn("dry-run: discovery reads the operating system's ARP cache and " +
			"nothing is transmitted; no enforcement will be applied")
	}

	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down; releasing every enforced target")
			eng.RestoreAll()
			eng.Stop()
			return nil

		case <-probeTick.C:
			if o.probeEach > 0 {
				eng.Probe(subnet, 3*time.Second)
			}

		case <-tick.C:
			cycle++
			if o.probeEach > 0 && cycle%o.probeEach == 0 {
				eng.Probe(subnet, 3*time.Second)
			}

			var neigh []arp.Neighbour
			if o.dryRun {
				// Dry run must not transmit, so discovery reads the binding
				// table the operating system has already learned. Nothing is
				// sent and no capture handle is needed.
				neigh = arpTableNeighbours(subnet)
			} else {
				neigh = eng.Neighbours()
			}
			devices := buildDevices(neigh, subnet, resolver)
			stats := eng.Stats()
			samples := diffSamples(prev, stats, o.interval)
			prev = indexStats(stats)

			rep := model.AgentReport{
				AgentID: agentID,
				TS:      time.Now().UTC(),
				Devices: devices,
				Samples: samples,
				Stats:   eng.EngineStats(),
			}

			var resp struct {
				Directives []model.Directive `json:"directives"`
			}
			if err := postJSON(ctx, client, o.server+"/api/agent/report", o.token, rep, &resp); err != nil {
				log.Warn("report failed", "err", err)
				continue
			}

			eng.SetTargets(toTargets(resp.Directives))
			log.Debug("cycle complete", "cycle", cycle, "devices", len(devices),
				"directives", len(resp.Directives))
		}
	}
}

// arpTableNeighbours converts the operating system's ARP cache into
// neighbours, optionally limited to a subnet.
func arpTableNeighbours(subnet *net.IPNet) []arp.Neighbour {
	entries, err := netinfo.ARPTable()
	if err != nil {
		return nil
	}
	out := make([]arp.Neighbour, 0, len(entries))
	for _, e := range entries {
		if subnet != nil && !subnet.Contains(e.IP) {
			continue
		}
		out = append(out, arp.Neighbour{MAC: e.MAC, IP: e.IP, Seen: time.Now()})
	}
	return out
}

// ---------------------------------------------------------------- helpers

func selectIface(o options) (*netinfo.Iface, error) {
	if o.iface != "" || o.subnet != "" {
		all, err := netinfo.Ifaces()
		if err != nil {
			return nil, err
		}
		for i := range all {
			if o.iface != "" && strings.EqualFold(all[i].Name, o.iface) {
				return &all[i], nil
			}
		}
		// An explicit subnet is enough to proceed even without a name match.
		if o.subnet != "" {
			for i := range all {
				if n, err := netinfo.ParseSubnet(o.subnet); err == nil && n.Contains(net.ParseIP(all[i].IP)) {
					return &all[i], nil
				}
			}
		}
		if o.iface != "" {
			return nil, fmt.Errorf("interface %q not found or has no IPv4 address", o.iface)
		}
	}
	best, err := netinfo.Best()
	if err != nil {
		return nil, fmt.Errorf("%w\n\nRun with -check to list the interfaces this host offers.", err)
	}
	return best, nil
}

func buildAgentInfo(agentID string, o options, iface *netinfo.Iface, subnet *net.IPNet, elevated bool, eng *arp.Engine) model.AgentInfo {
	return model.AgentInfo{
		AgentID:   agentID,
		Name:      agentID,
		Version:   version.Version,
		Iface:     iface.Name,
		IfaceKind: model.ClassifyLink(iface.Name, iface.IP),
		Subnet:    subnet.String(),
		Gateway:   iface.Gateway,
		LocalIP:   iface.IP,
		LocalMAC:  iface.MAC,
		OS:        runtime.GOOS + "/" + runtime.GOARCH,
		Elevated:  elevated,
		CapAR:     !o.dryRun,
		CapQoS:    !o.dryRun,
		Devices:   len(eng.Neighbours()),
		TS:        time.Now().UTC(),
	}
}

func buildDevices(neigh []arp.Neighbour, subnet *net.IPNet, r *nameResolver) []model.Device {
	now := time.Now().UTC()
	out := make([]model.Device, 0, len(neigh))
	seen := map[string]bool{}
	for _, n := range neigh {
		mac := strings.ToLower(n.MAC.String())
		if mac == "" || mac == "00:00:00:00:00:00" || arp.IsMulticast(n.MAC) {
			continue
		}
		if subnet != nil && n.IP != nil && !subnet.Contains(n.IP) {
			continue
		}
		if seen[mac] {
			continue
		}
		seen[mac] = true

		d := model.Device{
			MAC:      mac,
			Online:   true,
			Vendor:   arp.VendorFor(n.MAC),
			LastSeen: now,
		}
		if n.IP != nil {
			d.IP = n.IP.String()
			d.Hostname = r.lookup(n.IP.String())
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}

// diffSamples turns cumulative counters into per-interval rates.
func diffSamples(prev map[string]arp.TargetStats, cur []arp.TargetStats, interval time.Duration) []model.Sample {
	if interval <= 0 {
		interval = time.Second
	}
	secs := interval.Seconds()
	now := time.Now().UTC()
	var out []model.Sample
	for _, s := range cur {
		p, ok := prev[s.MAC]
		if !ok {
			continue
		}
		// Counters only grow; a decrease means the target was re-created.
		rxDelta := counterDelta(p.RxBytes, s.RxBytes)
		txDelta := counterDelta(p.TxBytes, s.TxBytes)
		if rxDelta == 0 && txDelta == 0 {
			continue
		}
		out = append(out, model.Sample{
			TS:    now,
			MAC:   s.MAC,
			RxBps: uint64(float64(rxDelta) / secs),
			TxBps: uint64(float64(txDelta) / secs),
		})
	}
	return out
}

func counterDelta(prev, cur uint64) uint64 {
	if cur < prev {
		return 0
	}
	return cur - prev
}

func indexStats(stats []arp.TargetStats) map[string]arp.TargetStats {
	m := make(map[string]arp.TargetStats, len(stats))
	for _, s := range stats {
		m[s.MAC] = s
	}
	return m
}

func toTargets(dirs []model.Directive) []arp.Target {
	out := make([]arp.Target, 0, len(dirs))
	for _, d := range dirs {
		// A protected device is never enforced, regardless of what arrives.
		if d.Protected {
			continue
		}
		var mode arp.Mode
		switch d.Action {
		case model.ActionBlock:
			mode = arp.ModeBlock
		case model.ActionThrottle:
			mode = arp.ModeThrottle
		default:
			continue
		}
		mac, err := net.ParseMAC(d.MAC)
		if err != nil || len(mac) != 6 {
			continue
		}
		ip := net.ParseIP(d.IP)
		out = append(out, arp.Target{
			MAC: mac, IP: ip, Mode: mode,
			CapKbps: d.CapKbps, UpKbps: d.UpKbps, Reason: d.Reason,
		})
	}
	return out
}

// ---------------------------------------------------------------- name resolver

// nameResolver does bounded reverse-DNS lookups with a cache, so a slow or
// absent resolver cannot stall the report loop.
type nameResolver struct {
	mu    sync.Mutex
	cache map[string]cacheEntry
	res   *net.Resolver
}

type cacheEntry struct {
	name string
	at   time.Time
}

func newNameResolver() *nameResolver {
	return &nameResolver{
		cache: map[string]cacheEntry{},
		res:   &net.Resolver{PreferGo: true, Dial: dialerWithTimeout(1200 * time.Millisecond)},
	}
}

func (r *nameResolver) lookup(ip string) string {
	r.mu.Lock()
	if e, ok := r.cache[ip]; ok && time.Since(e.at) < 10*time.Minute {
		r.mu.Unlock()
		return e.name
	}
	r.mu.Unlock()

	name := ""
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	names, err := r.res.LookupAddr(ctx, ip)
	cancel()
	if err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".")
	}

	r.mu.Lock()
	r.cache[ip] = cacheEntry{name: name, at: time.Now()}
	r.mu.Unlock()
	return name
}

// ---------------------------------------------------------------- http

func newClient(o options) *http.Client {
	tr := &http.Transport{
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     60 * time.Second,
		DisableCompression:  false,
	}
	if o.insecure {
		tr.TLSClientConfig = insecureTLS()
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: tr}
}

func postJSON(ctx context.Context, c *http.Client, url, token string, in any, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", token)
	req.Header.Set("User-Agent", "netcut-agent/"+version.Version)

	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return errors.New("the control plane rejected this agent token (401): check -token, or issue a new credential in the dashboard")
	}
	if resp.StatusCode >= 300 {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(ioLimit(resp.Body, 512))
		return fmt.Errorf("control plane returned %d: %s", resp.StatusCode, strings.TrimSpace(buf.String()))
	}
	if out != nil {
		return json.NewDecoder(ioLimit(resp.Body, 4<<20)).Decode(out)
	}
	return nil
}

// ---------------------------------------------------------------- platform bits

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "agent"
	}
	return h
}

func runCheck(log *slog.Logger) int {
	fmt.Println("netcut-agent diagnostics")
	fmt.Printf("  version   %s\n", version.Version)
	fmt.Printf("  os        %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  elevated  %v\n", isElevated())

	// Enforcement needs two independent things: an elevated process and a
	// loadable capture backend. Report both, because either one missing is the
	// reason nothing is applied on the wire.
	fmt.Println("\nenforcement prerequisites:")
	if isElevated() {
		fmt.Println("  [ok]   process is elevated")
	} else {
		fmt.Println("  [FAIL] not elevated - opening a capture device will be refused.")
		fmt.Println("         Re-run from an Administrator prompt (Windows) or as root (Linux).")
	}
	if err := arp.CaptureAvailable(); err == nil {
		fmt.Println("  [ok]   layer-2 capture backend is loadable")
	} else {
		fmt.Println("  [FAIL] no layer-2 capture backend:")
		for _, line := range strings.Split(err.Error(), "\n") {
			fmt.Printf("         %s\n", line)
		}
	}

	ifaces, err := netinfo.Ifaces()
	if err != nil {
		fmt.Printf("  error     %v\n", err)
		return 1
	}
	fmt.Println("\ninterfaces:")
	fmt.Printf("  %-28s %-15s %-18s %-18s %-6s %s\n", "NAME", "IP", "MAC", "GATEWAY", "USABLE", "NOTE")
	for _, i := range ifaces {
		fmt.Printf("  %-28s %-15s %-18s %-18s %-6v %s\n", truncate(i.Name, 28), i.IP, i.MAC, i.Gateway, i.Usable, i.Note)
	}
	if best, err := netinfo.Best(); err == nil {
		fmt.Printf("\nselected: %s (%s) via gateway %s\n", best.Name, best.CIDR, best.Gateway)
	} else {
		fmt.Printf("\nno interface was selected automatically: %v\n", err)
	}

	// The ARP cache is readable without elevation, so it doubles as a
	// no-transmit preview of what the agent would see.
	fmt.Println("\nneighbours already known to this host (from the ARP cache):")
	entries, err := netinfo.ARPTable()
	if err != nil {
		fmt.Printf("  could not read the ARP cache: %v\n", err)
		return 0
	}
	if len(entries) == 0 {
		fmt.Println("  (empty - run a scan, or use -dry-run and let the cache fill)")
		return 0
	}
	fmt.Printf("  %-16s %-19s %s\n", "IP", "MAC", "VENDOR")
	for _, e := range entries {
		vendor := arp.VendorFor(e.MAC)
		if vendor == "" {
			vendor = "-"
		}
		fmt.Printf("  %-16s %-19s %s\n", e.IP, e.MAC, vendor)
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func tickerStop(t *time.Ticker) { t.Stop() }

// envOr returns the environment value for key, or def.
func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
