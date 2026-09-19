// language: Go, file: internal/router/router.go
//
// Router client.
//
// The control plane has no way to tell whether a device reached the network over
// Wi-Fi or a wired port: that is decided by the router, and only the router
// knows it. This package talks to the router's own management API and reports
// the attachment per client.
//
// Design constraints, all deliberate:
//
//   - Read only. Nothing here changes router configuration.
//   - Fully optional. With no router configured the rest of the system is
//     unchanged; devices simply carry no connection label.
//   - Non-fatal. A poll that fails records the error and returns; it never
//     blocks the reconcile loop or stops enforcement.
//   - Credentials never logged, and never included in an error message.
//
// Supported backends:
//
//   - "auto"   probe the known backends and use the first that answers
//   - "huawei" the /api/... JSON API used by Huawei home gateways
//   - "openwrt" ubus or LuCI on OpenWrt / LEDE
//   - "none"   disable router polling
package router

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
)

// ErrNotConfigured is returned when router polling is disabled or incomplete.
var ErrNotConfigured = errors.New("router polling is not configured")

// Client is a router backend.
type Client interface {
	// Name identifies the backend, for logs and the dashboard.
	Name() string
	// Host returns the address being polled.
	Host() string
	// Login establishes a session. Implementations should cache it and
	// re-authenticate on their own when it expires.
	Login(ctx context.Context) error
	// Clients returns every associated client, keyed by normalised MAC.
	Clients(ctx context.Context) (map[string]model.Connection, error)
}

// Config is the router polling configuration.
type Config struct {
	// Backend is one of: auto, huawei, openwrt, none.
	Backend string
	// Host is the router address. Required unless the backend is none.
	Host string
	// User and Password are the management credentials.
	User     string
	Password string
	// Interval is how often to poll.
	Interval time.Duration
	// Insecure skips TLS verification, for a router with a self-signed
	// certificate.
	Insecure bool
	// Timeout bounds a single request.
	Timeout time.Duration
}

// Enabled reports whether a backend is configured.
func (c Config) Enabled() bool {
	return c.Backend != "" && c.Backend != "none" && c.Host != ""
}

// Poller periodically reads the router's client table and writes the
// per-device connection into the store.
type Poller struct {
	cfg       Config
	client    Client
	sinkStore Sink
	log       *slog.Logger

	mu       sync.RWMutex
	lastOK   time.Time
	lastErr  string
	lastN    int
	backend  string
	attempts uint64
	failures uint64
}

// Sink is the narrow store interface the poller needs, so it can be tested
// without a database.
type Sink interface {
	SetDeviceConnection(ctx context.Context, mac string, c model.Connection) error
}

// New builds a poller. It returns ErrNotConfigured when polling is off, which
// the caller treats as a normal, supported state.
func New(cfg Config, sink Sink, log *slog.Logger) (*Poller, error) {
	if !cfg.Enabled() {
		return nil, ErrNotConfigured
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 60 * time.Second
	}

	client, err := newClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Poller{cfg: cfg, client: client, sinkStore: sink, log: log, backend: client.Name()}, nil
}

// newClient selects a backend.
func newClient(cfg Config) (Client, error) {
	host := normaliseHost(cfg.Host)
	switch strings.ToLower(cfg.Backend) {
	case "huawei":
		return NewHuawei(host, cfg), nil
	case "openwrt":
		return NewOpenWrt(host, cfg), nil
	case "auto":
		// Probing happens on the first poll, not here, so construction never
		// blocks startup.
		return NewAuto(host, cfg), nil
	default:
		return nil, fmt.Errorf("unknown router backend %q (use auto, huawei, openwrt or none)", cfg.Backend)
	}
}

// normaliseHost accepts "192.168.1.1", "http://192.168.1.1" or a bare hostname
// and returns a base URL without a trailing slash.
func normaliseHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if !strings.HasPrefix(h, "http://") && !strings.HasPrefix(h, "https://") {
		h = "http://" + h
	}
	return strings.TrimRight(h, "/")
}

// Run polls until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) {
	// Authenticate up front so a bad credential is reported immediately rather
	// than after the first interval.
	p.pollOnce(ctx)

	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.pollOnce(ctx)
		}
	}
}

func (p *Poller) pollOnce(ctx context.Context) {
	p.mu.Lock()
	p.attempts++
	p.mu.Unlock()

	if err := p.client.Login(ctx); err != nil {
		p.recordErr(err)
		return
	}
	clients, err := p.client.Clients(ctx)
	if err != nil {
		p.recordErr(err)
		return
	}

	applied := 0
	for mac, conn := range clients {
		if err := p.sinkStore.SetDeviceConnection(ctx, mac, conn); err != nil {
			p.log.Debug("router: could not store connection", "mac", mac, "err", err)
			continue
		}
		applied++
	}

	p.mu.Lock()
	p.lastOK = time.Now()
	p.lastErr = ""
	p.lastN = applied
	p.mu.Unlock()
	p.log.Debug("router poll complete", "backend", p.backend, "clients", applied)
}

// recordErr stores the failure without treating it as fatal.
func (p *Poller) recordErr(err error) {
	p.mu.Lock()
	p.failures++
	p.lastErr = err.Error()
	p.mu.Unlock()
	p.log.Warn("router poll failed", "backend", p.backend, "host", p.client.Host(), "err", err)
}

// Status is the poller's health, for the dashboard.
type Status struct {
	Configured bool      `json:"configured"`
	Backend    string    `json:"backend,omitempty"`
	Host       string    `json:"host,omitempty"`
	LastOK     time.Time `json:"last_ok"`
	LastError  string    `json:"last_error,omitempty"`
	Clients    int       `json:"clients"`
	Attempts   uint64    `json:"attempts"`
	Failures   uint64    `json:"failures"`
}

// Status returns the current poller health.
func (p *Poller) Status() Status {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return Status{
		Configured: true,
		Backend:    p.backend,
		Host:       p.client.Host(),
		LastOK:     p.lastOK,
		LastError:  p.lastErr,
		Clients:    p.lastN,
		Attempts:   p.attempts,
		Failures:   p.failures,
	}
}

// ------------------------------------------------------------------ helpers

// normMAC canonicalises a MAC to lower-case colon form.
func normMAC(mac string) string {
	m := strings.ToLower(strings.TrimSpace(mac))
	m = strings.ReplaceAll(m, "-", ":")
	return m
}

// validMAC reports whether a string is a usable unicast MAC.
func validMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return false
	}
	if hw[0]&0x01 != 0 { // multicast/broadcast
		return false
	}
	for _, b := range hw {
		if b != 0 {
			return true
		}
	}
	return false // all zero
}

// looksLikeMAC is a cheap pre-filter before the full parse, used when scanning
// unknown router responses.
func looksLikeMAC(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 17 {
		return false
	}
	for i, c := range s {
		if i%3 == 2 {
			if c != ':' && c != '-' {
				return false
			}
			continue
		}
		if !isHex(byte(c)) {
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
