// language: Go, file: internal/fleet/fleet_selfprotect_test.go
package fleet

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
	"github.com/kevinantoniowiyonolauw/netcut/internal/store"
)

// newStore opens a throwaway database for a test.
func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TestIngestProtectsTheAgentHostByMAC is the guard that keeps the machine
// running the agent from ever being enforced against.
//
// Enforcement redirects a target's traffic through the agent. If the agent's
// own host were enforced, the host doing the redirecting would be cut off —
// taking with it the only route back to the dashboard needed to undo it. That
// is a self-inflicted outage with no remote recovery.
func TestIngestProtectsTheAgentHostByMAC(t *testing.T) {
	st := newStore(t)
	f := New()
	ctx := context.Background()

	const selfMAC = "a8:a1:59:e3:b7:18"
	rep := model.AgentReport{
		AgentID:  "agent-1",
		TS:       time.Now().UTC(),
		LocalMAC: selfMAC,
		LocalIP:  "192.168.1.9",
		Devices: []model.Device{
			{MAC: selfMAC, IP: "192.168.1.9", Online: true},
			{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.10", Online: true},
		},
	}
	if err := f.Ingest(ctx, st, rep); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	self, ok := f.Device(selfMAC)
	if !ok {
		t.Fatal("the agent's own device was not recorded")
	}
	if !self.Protected {
		t.Error("the agent's own host is not protected; it could be enforced against " +
			"and cut off the machine doing the redirecting")
	}

	// The stored copy must be protected too, since a restart reloads from it.
	stored, err := st.Device(ctx, selfMAC)
	if err != nil {
		t.Fatalf("stored device: %v", err)
	}
	if !stored.Protected {
		t.Error("the stored copy of the agent's own device is not protected")
	}

	// An unrelated device must not be protected by this guard.
	other, _ := f.Device("aa:bb:cc:dd:ee:01")
	if other.Protected {
		t.Error("an unrelated device was protected by the self guard")
	}
}

// TestIngestProtectsEveryMACSharingTheAgentIP covers the Windows case where one
// address appears with several MACs, because the source port and thus the
// observed identity can vary. All of them must be protected: it is the IP that
// routes to the agent's own host.
func TestIngestProtectsEveryMACSharingTheAgentIP(t *testing.T) {
	st := newStore(t)
	f := New()
	ctx := context.Background()

	const selfIP = "192.168.1.9"
	rep := model.AgentReport{
		AgentID:  "agent-1",
		TS:       time.Now().UTC(),
		LocalMAC: "a8:a1:59:e3:b7:18",
		LocalIP:  selfIP,
		Devices: []model.Device{
			// The agent's own MAC.
			{MAC: "a8:a1:59:e3:b7:18", IP: selfIP, Online: true},
			// A second MAC observed at the same address.
			{MAC: "c6:40:64:11:8b:ae", IP: selfIP, Online: true},
			// A third, to be thorough.
			{MAC: "ca:30:80:f2:e1:d7", IP: selfIP, Online: true},
		},
	}
	if err := f.Ingest(ctx, st, rep); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	for _, mac := range []string{"a8:a1:59:e3:b7:18", "c6:40:64:11:8b:ae", "ca:30:80:f2:e1:d7"} {
		d, ok := f.Device(mac)
		if !ok {
			t.Errorf("device %s was not recorded", mac)
			continue
		}
		if !d.Protected {
			t.Errorf("device %s shares the agent's IP but is not protected; "+
				"enforcing it would cut off the agent's own host", mac)
		}
	}
}

// TestIngestWithoutSelfIdentityStillWorks: an older agent that sends no
// local_mac/local_ip must not break ingestion, it simply gets no self guard.
func TestIngestWithoutSelfIdentityStillWorks(t *testing.T) {
	st := newStore(t)
	f := New()

	rep := model.AgentReport{
		AgentID: "legacy",
		TS:      time.Now().UTC(),
		Devices: []model.Device{{MAC: "aa:bb:cc:dd:ee:02", IP: "192.168.1.20", Online: true}},
	}
	if err := f.Ingest(context.Background(), st, rep); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	d, ok := f.Device("aa:bb:cc:dd:ee:02")
	if !ok {
		t.Fatal("device was not recorded")
	}
	if d.Protected {
		t.Error("a device was protected without any self identity to match")
	}
}
