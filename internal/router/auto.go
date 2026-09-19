// language: Go, file: internal/router/auto.go
//
// Auto backend.
//
// The router model is not always known in advance, and a wrong guess produces
// no data with no explanation. This backend probes the known implementations in
// turn and delegates to the first one that returns clients, then remembers it.
//
// Probing is bounded: once every candidate has failed, further attempts are
// suppressed for a cooldown, so a router that is simply unreachable does not get
// hammered once per poll.
package router

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
)

// probeCooldown is how long to wait before probing again after total failure.
const probeCooldown = 10 * time.Minute

// Auto probes for a working backend.
type Auto struct {
	base string
	cfg  Config

	mu         sync.Mutex
	active     Client
	activeName string
	lastProbe  time.Time
	lastTried  []string
}

// NewAuto builds an auto-detecting backend.
func NewAuto(base string, cfg Config) *Auto {
	return &Auto{base: base, cfg: cfg}
}

// Name identifies the backend.
func (a *Auto) Name() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.activeName != "" {
		return "auto (" + a.activeName + ")"
	}
	return "auto"
}

// Host returns the router address.
func (a *Auto) Host() string { return a.base }

// candidates builds a fresh client per probe so no session state leaks between
// attempts.
func (a *Auto) candidates() []Client {
	return []Client{
		NewHuawei(a.base, a.cfg),
		NewOpenWrt(a.base, a.cfg),
	}
}

// Login establishes a session, probing if no backend is selected yet.
func (a *Auto) Login(ctx context.Context) error {
	a.mu.Lock()
	active := a.active
	lastProbe := a.lastProbe
	a.mu.Unlock()

	if active != nil {
		if err := active.Login(ctx); err == nil {
			return nil
		}
		// The selected backend stopped working; fall through and re-probe.
		a.mu.Lock()
		a.active = nil
		a.activeName = ""
		a.mu.Unlock()
	}

	// Do not re-probe on every poll while nothing works.
	if !lastProbe.IsZero() && time.Since(lastProbe) < probeCooldown {
		a.mu.Lock()
		tried := append([]string(nil), a.lastTried...)
		a.mu.Unlock()
		return fmt.Errorf("no router backend is responding (last probe tried %s; retrying in under %s)",
			strings.Join(tried, ", "), probeCooldown)
	}

	return a.probe(ctx)
}

// probe tries each candidate and selects the first that yields clients.
func (a *Auto) probe(ctx context.Context) error {
	var tried []string
	var lastErr error

	for _, c := range a.candidates() {
		name := c.Name()
		tried = append(tried, name)

		if err := c.Login(ctx); err != nil {
			lastErr = fmt.Errorf("%s: %w", name, err)
			continue
		}
		clients, err := c.Clients(ctx)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", name, err)
			continue
		}
		if len(clients) == 0 {
			lastErr = fmt.Errorf("%s: returned no clients", name)
			continue
		}

		a.mu.Lock()
		a.active = c
		a.activeName = name
		a.lastProbe = time.Now()
		a.lastTried = tried
		a.mu.Unlock()
		return nil
	}

	a.mu.Lock()
	a.lastProbe = time.Now()
	a.lastTried = tried
	a.mu.Unlock()
	return fmt.Errorf("no router backend worked (tried %s): %w", strings.Join(tried, ", "), lastErr)
}

// Clients returns the client table from the selected backend.
func (a *Auto) Clients(ctx context.Context) (map[string]model.Connection, error) {
	a.mu.Lock()
	active := a.active
	a.mu.Unlock()
	if active == nil {
		if err := a.Login(ctx); err != nil {
			return nil, err
		}
		a.mu.Lock()
		active = a.active
		a.mu.Unlock()
	}
	if active == nil {
		return nil, fmt.Errorf("no router backend is selected")
	}
	return active.Clients(ctx)
}

// ActiveName reports which backend was selected, for diagnostics.
func (a *Auto) ActiveName() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.activeName
}
