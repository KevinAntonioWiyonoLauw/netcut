// language: Go, file: internal/fleet/fleet.go
// The fleet holds the live view of the segment: which agents are reporting,
// which devices exist, and what the current enforcement decision is for each.
// A reconciler loop folds stored state through the policy engine and publishes
// the result to every dashboard.
package fleet

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kevinantoniowiyonolauw/netcut/internal/hub"
	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
	"github.com/kevinantoniowiyonolauw/netcut/internal/policy"
	"github.com/kevinantoniowiyonolauw/netcut/internal/store"
)

// Fleet is the shared live state. All accessors are safe for concurrent use.
type Fleet struct {
	mu sync.RWMutex

	agents     map[string]model.AgentInfo
	devices    map[string]model.Device
	directives map[string]model.Directive
	results    map[string]policy.Result

	lastReport    time.Time
	lastReconcile time.Time
	reports       uint64
	reconcileErrs uint64
}

// New creates an empty fleet.
func New() *Fleet {
	return &Fleet{
		agents:     map[string]model.AgentInfo{},
		devices:    map[string]model.Device{},
		directives: map[string]model.Directive{},
		results:    map[string]policy.Result{},
	}
}

// SetAgent records a heartbeat.
func (f *Fleet) SetAgent(info model.AgentInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.agents[info.AgentID] = info
	f.lastReport = time.Now()
}

// Ingest folds an agent report into the live view and persists it.
func (f *Fleet) Ingest(ctx context.Context, st *store.Store, rep model.AgentReport) error {
	keep := make([]string, 0, len(rep.Devices))

	// The agent's own host is never enforceable. Enforcement redirects a
	// target's traffic through the agent, so poisoning the agent's own address
	// would break the host that is doing the redirecting — the one machine that
	// must keep working, and the only route back to the dashboard to undo it.
	// Windows also cycles the source port of outgoing connections, so a single
	// address can legitimately appear with several MACs; the guard covers all
	// of them.
	selfMAC := normMAC(rep.LocalMAC)
	selfIP := strings.TrimSpace(rep.LocalIP)

	f.mu.Lock()
	for _, d := range rep.Devices {
		mac := normMAC(d.MAC)
		if mac == "" {
			continue
		}
		d.MAC = mac
		d.Online = true
		if d.LastSeen.IsZero() {
			d.LastSeen = time.Now().UTC()
		}
		if selfMAC != "" && mac == selfMAC {
			d.Protected = true
		}
		if selfIP != "" && strings.TrimSpace(d.IP) == selfIP {
			d.Protected = true
		}
		f.devices[mac] = d
		keep = append(keep, mac)
	}
	f.lastReport = time.Now()
	f.reports++
	f.mu.Unlock()

	// Persist outside the lock; SQLite writes are the slow part.
	var firstSeen []model.Device
	for _, d := range rep.Devices {
		mac := normMAC(d.MAC)
		if mac == "" {
			continue
		}
		stored, err := st.Device(ctx, mac)
		isNew := err != nil
		if isNew {
			firstSeen = append(firstSeen, d)
		}
		dd := d
		dd.MAC = mac
		dd.Online = true
		if selfMAC != "" && mac == selfMAC {
			dd.Protected = true
		}
		if selfIP != "" && strings.TrimSpace(dd.IP) == selfIP {
			dd.Protected = true
		}
		if err := st.UpsertDevice(ctx, &dd); err != nil {
			return err
		}

		// The agent knows only how *it* is attached, so its value is a
		// baseline. It fills the gap when nothing better exists, and never
		// overwrites what the router reported: the router knows the actual
		// port or SSID per device, which the agent cannot see.
		if !isNew && stored != nil && stored.Connection.Kind == "" &&
			d.Connection.Kind != "" && d.Connection.Kind != model.LinkUnknown {
			if err := st.SetDeviceConnection(ctx, mac, d.Connection); err != nil {
				return err
			}
		}
	}
	if err := st.MarkOfflineExcept(ctx, keep); err != nil {
		return err
	}
	if len(rep.Samples) > 0 {
		if err := st.AddSamples(ctx, rep.Samples); err != nil {
			return err
		}
	}
	for _, d := range firstSeen {
		_ = st.AddEvent(ctx, &model.Event{
			Type: "device.discovered", Severity: "info", MAC: normMAC(d.MAC),
			Message: "new device on the segment: " + label(d),
			Actor:   "agent",
		})
	}
	return nil
}

// Reconcile reads stored intent, resolves it through the policy engine, and
// publishes the resulting directives. It is the single writer of enforcement
// state, so agents and dashboards always agree.
func (f *Fleet) Reconcile(ctx context.Context, st *store.Store, h *hub.Hub) error {
	devices, err := st.ListDevices(ctx)
	if err != nil {
		f.mu.Lock()
		f.reconcileErrs++
		f.mu.Unlock()
		return err
	}
	policies, err := st.ListPolicies(ctx)
	if err != nil {
		f.mu.Lock()
		f.reconcileErrs++
		f.mu.Unlock()
		return err
	}
	overrides, err := st.ActiveOverrides(ctx)
	if err != nil {
		f.mu.Lock()
		f.reconcileErrs++
		f.mu.Unlock()
		return err
	}

	now := time.Now()
	results := policy.Evaluate(devices, policies, overrides, now)
	directives := policy.ToDirectives(results, devices)

	// Mirror the resolved decision onto each device row so the UI and the
	// aggregate counters reflect what is actually enforced right now.
	byMAC := make(map[string]model.Device, len(devices))
	for _, d := range devices {
		byMAC[normMAC(d.MAC)] = d
	}
	for mac, r := range results {
		d, ok := byMAC[mac]
		if !ok {
			continue
		}
		d.Blocked = r.Action == model.ActionBlock
		d.Throttled = r.Action == model.ActionThrottle
		d.ArpPoisoned = r.Action == model.ActionBlock || r.Action == model.ActionThrottle
		if err := st.UpdateDeviceRuntime(ctx, &d); err != nil {
			return err
		}
	}

	dirByMAC := make(map[string]model.Directive, len(directives))
	for _, d := range directives {
		dirByMAC[normalize(d.MAC)] = d
	}

	f.mu.Lock()
	f.results = results
	f.directives = dirByMAC
	f.lastReconcile = time.Now()
	f.mu.Unlock()

	h.Broadcast(f.Snapshot())
	return nil
}

// Snapshot returns the complete live state as a single broadcastable payload.
func (f *Fleet) Snapshot() map[string]any {
	f.mu.RLock()
	defer f.mu.RUnlock()

	devices := make([]model.Device, 0, len(f.devices))
	seen := map[string]bool{}
	for _, d := range f.devices {
		devices = append(devices, d)
		seen[normalize(d.MAC)] = true
	}
	// Devices known to the database but silent this cycle still belong in the
	// snapshot; they are merged by the caller from the store. Here we only
	// expose what the agents reported plus current decisions.
	sort.Slice(devices, func(i, j int) bool { return devices[i].MAC < devices[j].MAC })

	agents := make([]model.AgentInfo, 0, len(f.agents))
	for _, a := range f.agents {
		agents = append(agents, a)
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].AgentID < agents[j].AgentID })

	results := make([]policy.Result, 0, len(f.results))
	for _, r := range f.results {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].MAC < results[j].MAC })

	return map[string]any{
		"type":           "state",
		"ts":             time.Now().UTC(),
		"devices":        devices,
		"agents":         agents,
		"decisions":      results,
		"last_report":    f.lastReport,
		"last_reconcile": f.lastReconcile,
		"reports":        f.reports,
		"agent_online":   time.Since(f.lastReport) < 30*time.Second && !f.lastReport.IsZero(),
	}
}

// Devices returns the live device set.
func (f *Fleet) Devices() []model.Device {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]model.Device, 0, len(f.devices))
	for _, d := range f.devices {
		out = append(out, d)
	}
	return out
}

// Device returns one live device.
func (f *Fleet) Device(mac string) (model.Device, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	d, ok := f.devices[normalize(mac)]
	return d, ok
}

// Agents returns the current agent set.
func (f *Fleet) Agents() []model.AgentInfo {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]model.AgentInfo, 0, len(f.agents))
	for _, a := range f.agents {
		out = append(out, a)
	}
	return out
}

// Directives returns every current directive.
func (f *Fleet) Directives() []model.Directive {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]model.Directive, 0, len(f.directives))
	for _, d := range f.directives {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}

// Results returns the current decision set keyed by MAC.
func (f *Fleet) Results() map[string]policy.Result {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make(map[string]policy.Result, len(f.results))
	for k, v := range f.results {
		out[k] = v
	}
	return out
}

// Health summarizes whether the data plane is alive.
type Health struct {
	AgentOnline     bool      `json:"agent_online"`
	AgentCount      int       `json:"agent_count"`
	DeviceCount     int       `json:"device_count"`
	DirectiveCount  int       `json:"directive_count"`
	Reports         uint64    `json:"reports"`
	ReconcileErrors uint64    `json:"reconcile_errors"`
	LastReport      time.Time `json:"last_report"`
	LastReconcile   time.Time `json:"last_reconcile"`
}

// Health returns the current data-plane health.
func (f *Fleet) Health() Health {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return Health{
		AgentOnline:     !f.lastReport.IsZero() && time.Since(f.lastReport) < 30*time.Second,
		AgentCount:      len(f.agents),
		DeviceCount:     len(f.devices),
		DirectiveCount:  len(f.directives),
		Reports:         f.reports,
		ReconcileErrors: f.reconcileErrs,
		LastReport:      f.lastReport,
		LastReconcile:   f.lastReconcile,
	}
}

// Run drives the reconcile loop until ctx is cancelled.
func (f *Fleet) Run(ctx context.Context, st *store.Store, h *hub.Hub, interval time.Duration, log *slog.Logger) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := f.Reconcile(ctx, st, h); err != nil {
				log.Warn("reconcile failed", "err", err)
			}
		}
	}
}

// RunMaintenance periodically prunes history so the database stays bounded.
func (f *Fleet) RunMaintenance(ctx context.Context, st *store.Store, retention time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n, err := st.PruneSamples(ctx, time.Now().Add(-retention)); err != nil {
				log.Warn("prune samples failed", "err", err)
			} else if n > 0 {
				log.Debug("pruned samples", "rows", n)
			}
			if _, err := st.PurgeExpiredOverrides(ctx); err != nil {
				log.Warn("purge overrides failed", "err", err)
			}
			if err := st.PruneEvents(ctx, 5000); err != nil {
				log.Warn("prune events failed", "err", err)
			}
		}
	}
}

func label(d model.Device) string {
	switch {
	case d.Alias != "":
		return d.Alias
	case d.Hostname != "":
		return d.Hostname
	case d.Vendor != "":
		return d.Vendor + " (" + d.MAC + ")"
	default:
		return d.MAC
	}
}

func normMAC(mac string) string { return normalize(mac) }

func normalize(mac string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(mac), "-", ":"))
}
