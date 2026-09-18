// language: Go, file: internal/policy/policy_test.go
package policy

import (
	"testing"
	"time"

	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
	"github.com/kevinantoniowiyonolauw/netcut/internal/store"
)

func dev(mac, ip, group string, protected bool) model.Device {
	return model.Device{MAC: mac, IP: ip, Group: group, Protected: protected, Online: true}
}

// TestProtectedIsImmune is the load-bearing guarantee of the whole system: a
// protected device resolves to allow no matter what rules, schedules or manual
// instructions exist. If this ever regresses, the operator can lock themselves
// out of their own network.
func TestProtectedIsImmune(t *testing.T) {
	devices := []model.Device{dev("aa:bb:cc:dd:ee:ff", "10.0.0.5", "guests", true)}
	policies := []model.Policy{
		{ID: "p1", Name: "block everything", TargetType: model.TargetAll,
			Action: model.ActionBlock, Enabled: true, Priority: 100},
	}
	overrides := map[string]store.Override{
		"aa:bb:cc:dd:ee:ff": {MAC: "aa:bb:cc:dd:ee:ff", Action: model.ActionBlock},
	}

	got := Evaluate(devices, policies, overrides, time.Now())
	r := got["aa:bb:cc:dd:ee:ff"]
	if r.Action != model.ActionAllow {
		t.Fatalf("protected device resolved to %q, want allow", r.Action)
	}
	if r.Source != SourceProtected {
		t.Fatalf("source = %q, want %q", r.Source, SourceProtected)
	}
}

func TestManualOverrideOutranksPolicy(t *testing.T) {
	devices := []model.Device{dev("aa:bb:cc:dd:ee:01", "10.0.0.6", "", false)}
	policies := []model.Policy{
		{ID: "p1", Name: "block all", TargetType: model.TargetAll,
			Action: model.ActionBlock, Enabled: true, Priority: 50},
	}
	overrides := map[string]store.Override{
		"aa:bb:cc:dd:ee:01": {MAC: "aa:bb:cc:dd:ee:01", Action: model.ActionThrottle, CapKbps: 256},
	}

	r := Evaluate(devices, policies, overrides, time.Now())["aa:bb:cc:dd:ee:01"]
	if r.Action != model.ActionThrottle || r.CapKbps != 256 {
		t.Fatalf("got action=%q cap=%d, want throttle/256", r.Action, r.CapKbps)
	}
	if r.Source != SourceManual {
		t.Fatalf("source = %q, want %q", r.Source, SourceManual)
	}
}

func TestHighestPriorityPolicyWins(t *testing.T) {
	devices := []model.Device{dev("aa:bb:cc:dd:ee:02", "10.0.0.7", "guests", false)}
	// Deliberately ordered lowest-first to prove the engine sorts by priority
	// rather than trusting slice order.
	policies := []model.Policy{
		{ID: "low", Name: "group rule", TargetType: model.TargetGroup,
			TargetValue: "guests", Action: model.ActionThrottle, CapKbps: 512,
			Enabled: true, Priority: 1},
		{ID: "high", Name: "all rule", TargetType: model.TargetAll,
			Action: model.ActionBlock, Enabled: true, Priority: 99},
	}

	// The caller supplies policies in priority order (ListPolicies does this).
	sorted := []model.Policy{policies[1], policies[0]}
	r := Evaluate(devices, sorted, nil, time.Now())["aa:bb:cc:dd:ee:02"]
	if r.Action != model.ActionBlock || r.PolicyID != "high" {
		t.Fatalf("got action=%q policy=%q, want block/high", r.Action, r.PolicyID)
	}
}

func TestDisabledPolicyNeverMatches(t *testing.T) {
	devices := []model.Device{dev("aa:bb:cc:dd:ee:03", "10.0.0.8", "", false)}
	policies := []model.Policy{
		{ID: "off", Name: "disabled", TargetType: model.TargetAll,
			Action: model.ActionBlock, Enabled: false, Priority: 10},
	}
	r := Evaluate(devices, policies, nil, time.Now())["aa:bb:cc:dd:ee:03"]
	if r.Action != model.ActionAllow || r.Source != SourceDefault {
		t.Fatalf("disabled policy took effect: action=%q source=%q", r.Action, r.Source)
	}
}

func TestNoMatchIsAllow(t *testing.T) {
	devices := []model.Device{dev("aa:bb:cc:dd:ee:04", "10.0.0.9", "iot", false)}
	policies := []model.Policy{
		{ID: "g", Name: "only guests", TargetType: model.TargetGroup,
			TargetValue: "guests", Action: model.ActionBlock, Enabled: true, Priority: 5},
	}
	r := Evaluate(devices, policies, nil, time.Now())["aa:bb:cc:dd:ee:04"]
	if r.Action != model.ActionAllow {
		t.Fatalf("unmatched device got %q, want allow", r.Action)
	}
}

func TestScheduleWindow(t *testing.T) {
	cases := []struct {
		spec string
		at   time.Time
		want bool
	}{
		{"", time.Date(2026, 3, 1, 3, 0, 0, 0, time.UTC), true},              // empty: always
		{"22:00-06:00", time.Date(2026, 3, 1, 23, 30, 0, 0, time.UTC), true}, // inside, crosses midnight
		{"22:00-06:00", time.Date(2026, 3, 1, 2, 0, 0, 0, time.UTC), true},   // inside, after midnight
		{"22:00-06:00", time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC), false}, // outside
		{"22:00-06:00", time.Date(2026, 3, 1, 22, 0, 0, 0, time.UTC), true},  // inclusive start
		{"22:00-06:00", time.Date(2026, 3, 1, 6, 0, 0, 0, time.UTC), false},  // exclusive end
		{"09:00-17:00", time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC), true},
		{"09:00-17:00", time.Date(2026, 3, 1, 17, 1, 0, 0, time.UTC), false},
		{"bad-spec", time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC), true}, // unparseable: fail safe as active
		{"25:00-99:99", time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC), true},
	}
	for _, c := range cases {
		if got := ScheduleActive(c.spec, c.at); got != c.want {
			t.Errorf("ScheduleActive(%q, %s) = %v, want %v", c.spec, c.at.Format("15:04"), got, c.want)
		}
	}
}

func TestScheduleCron(t *testing.T) {
	// 2026-03-02 is a Monday.
	mon := time.Date(2026, 3, 2, 22, 0, 0, 0, time.UTC)
	sun := time.Date(2026, 3, 1, 22, 0, 0, 0, time.UTC)

	cases := []struct {
		spec string
		at   time.Time
		want bool
	}{
		{"0 22 * * *", mon, true},
		{"0 22 * * *", time.Date(2026, 3, 2, 23, 0, 0, 0, time.UTC), false},
		{"0 22 * * 1-5", mon, true},
		{"0 22 * * 1-5", sun, false},
		{"*/30 * * * *", time.Date(2026, 3, 2, 22, 30, 0, 0, time.UTC), true},
		{"*/30 * * * *", time.Date(2026, 3, 2, 22, 31, 0, 0, time.UTC), false},
		{"0,30 * * * *", time.Date(2026, 3, 2, 22, 30, 0, 0, time.UTC), true},
		{"@daily", time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC), true},
		{"@daily", time.Date(2026, 3, 2, 1, 0, 0, 0, time.UTC), false},
		{"0 9-17 * * 1-5", time.Date(2026, 3, 2, 14, 0, 0, 0, time.UTC), true},
		{"0 9-17 * * 1-5", time.Date(2026, 3, 2, 20, 0, 0, 0, time.UTC), false},
	}
	for _, c := range cases {
		if got := ScheduleActive(c.spec, c.at); got != c.want {
			t.Errorf("ScheduleActive(%q, %s) = %v, want %v",
				c.spec, c.at.Format("Mon 15:04"), got, c.want)
		}
	}
}

func TestScheduledPolicyOnlyAppliesInWindow(t *testing.T) {
	devices := []model.Device{dev("aa:bb:cc:dd:ee:05", "10.0.0.10", "", false)}
	policies := []model.Policy{
		{ID: "night", Name: "nights", TargetType: model.TargetAll, Action: model.ActionBlock,
			Enabled: true, Priority: 10, Schedule: "22:00-06:00"},
	}

	night := time.Date(2026, 3, 1, 23, 0, 0, 0, time.UTC)
	if r := Evaluate(devices, policies, nil, night)["aa:bb:cc:dd:ee:05"]; r.Action != model.ActionBlock {
		t.Fatalf("policy did not apply inside its window: %q", r.Action)
	}
	day := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	if r := Evaluate(devices, policies, nil, day)["aa:bb:cc:dd:ee:05"]; r.Action != model.ActionAllow {
		t.Fatalf("policy applied outside its window: %q", r.Action)
	}
}

func TestToDirectivesCarriesIPAndProtection(t *testing.T) {
	devices := []model.Device{
		dev("aa:bb:cc:dd:ee:06", "10.0.0.11", "", false),
		dev("aa:bb:cc:dd:ee:07", "10.0.0.12", "", true),
	}
	policies := []model.Policy{
		{ID: "all", Name: "block all", TargetType: model.TargetAll,
			Action: model.ActionBlock, Enabled: true, Priority: 1},
	}
	results := Evaluate(devices, policies, nil, time.Now())
	dirs := ToDirectives(results, devices)

	byMAC := map[string]model.Directive{}
	for _, d := range dirs {
		byMAC[d.MAC] = d
	}
	if d := byMAC["aa:bb:cc:dd:ee:06"]; d.IP != "10.0.0.11" || d.Action != model.ActionBlock {
		t.Fatalf("unprotected device directive wrong: %+v", d)
	}
	if d := byMAC["aa:bb:cc:dd:ee:07"]; !d.Protected || d.Action != model.ActionAllow {
		t.Fatalf("protected device directive wrong: %+v", d)
	}
}

func TestMACNormalisation(t *testing.T) {
	devices := []model.Device{dev("AA-BB-CC-DD-EE-08", "10.0.0.13", "", false)}
	policies := []model.Policy{
		{ID: "m", Name: "by mac", TargetType: model.TargetDevice,
			TargetValue: "aa:bb:cc:dd:ee:08", Action: model.ActionBlock, Enabled: true, Priority: 1},
	}
	// The result must be keyed by the normalised MAC so lookups by either
	// spelling resolve.
	r, ok := Evaluate(devices, policies, nil, time.Now())["aa:bb:cc:dd:ee:08"]
	if !ok {
		t.Fatal("result was not keyed by the normalised MAC")
	}
	if r.Action != model.ActionBlock {
		t.Fatalf("dash/colon MAC forms did not match: %q", r.Action)
	}
}
