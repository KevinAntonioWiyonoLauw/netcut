// language: Go, file: internal/store/store_test.go
package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestUserRoundTrip(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()

	u := &model.User{Email: "Owner@Example.com", PasswordHash: "hash", Role: model.RoleOwner}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID == "" {
		t.Fatal("CreateUser did not assign an id")
	}

	got, err := st.UserByEmail(ctx, "owner@example.com")
	if err != nil {
		t.Fatalf("UserByEmail: %v", err)
	}
	// Email is stored and matched case-insensitively.
	if got.Email != "owner@example.com" {
		t.Errorf("email = %q, want lower-case", got.Email)
	}
	if got.Role != model.RoleOwner {
		t.Errorf("role = %q, want owner", got.Role)
	}
	if got.CreatedAt.IsZero() {
		t.Error("created_at did not survive the round trip")
	}
	if got.ID != u.ID {
		t.Errorf("id = %q, want %q", got.ID, u.ID)
	}
}

func TestUserByEmailNotFound(t *testing.T) {
	st := openTest(t)
	_, err := st.UserByEmail(context.Background(), "nobody@example.com")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestUpsertUserIsIdempotent(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	u := &model.User{Email: "a@example.com", PasswordHash: "h1", Role: model.RoleAdmin}

	created, err := st.UpsertUser(ctx, u)
	if err != nil || !created {
		t.Fatalf("first upsert: created=%v err=%v", created, err)
	}
	created, err = st.UpsertUser(ctx, &model.User{Email: "a@example.com", PasswordHash: "h2", Role: model.RoleOwner})
	if err != nil || created {
		t.Fatalf("second upsert: created=%v err=%v", created, err)
	}
	got, _ := st.UserByEmail(ctx, "a@example.com")
	if got.PasswordHash != "h1" || got.Role != model.RoleAdmin {
		t.Fatal("upsert overwrote an existing account")
	}
}

func TestCountOwners(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	if n, _ := st.CountOwners(ctx); n != 0 {
		t.Fatalf("CountOwners = %d, want 0", n)
	}
	_ = st.CreateUser(ctx, &model.User{Email: "o@example.com", PasswordHash: "h", Role: model.RoleOwner})
	_ = st.CreateUser(ctx, &model.User{Email: "a@example.com", PasswordHash: "h", Role: model.RoleAdmin})
	_ = st.CreateUser(ctx, &model.User{Email: "v@example.com", PasswordHash: "h", Role: model.RoleViewer})
	if n, _ := st.CountOwners(ctx); n != 1 {
		t.Fatalf("CountOwners = %d, want 1", n)
	}
	if n, _ := st.CountUsers(ctx); n != 3 {
		t.Fatalf("CountUsers = %d, want 3", n)
	}
}

func TestTouchLogin(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	u := &model.User{Email: "a@example.com", PasswordHash: "h", Role: model.RoleAdmin}
	_ = st.CreateUser(ctx, u)
	time.Sleep(5 * time.Millisecond)
	if err := st.TouchLogin(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := st.UserByEmail(ctx, "a@example.com")
	if !got.LastLogin.After(got.CreatedAt) {
		t.Fatalf("last_login (%v) was not advanced past created_at (%v)", got.LastLogin, got.CreatedAt)
	}
}

func TestDeviceUpsertPreservesOperatorFields(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()

	d := &model.Device{MAC: "AA-BB-CC-DD-EE-01", IP: "10.0.0.5", Vendor: "Apple", Online: true}
	if err := st.UpsertDevice(ctx, d); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}

	// The operator labels the device and protects it.
	got, err := st.Device(ctx, "aa:bb:cc:dd:ee:01")
	if err != nil {
		t.Fatal(err)
	}
	got.Alias = "My laptop"
	got.Group = "trusted"
	got.Note = "never throttle"
	got.Protected = true
	if err := st.UpdateDeviceSettings(ctx, got); err != nil {
		t.Fatal(err)
	}

	// A later scan reports a new IP but must not wipe the operator's work.
	rescan := &model.Device{MAC: "aa:bb:cc:dd:ee:01", IP: "10.0.0.9", Vendor: "Apple", Online: true}
	if err := st.UpsertDevice(ctx, rescan); err != nil {
		t.Fatal(err)
	}

	after, err := st.Device(ctx, "aa:bb:cc:dd:ee:01")
	if err != nil {
		t.Fatal(err)
	}
	if after.Alias != "My laptop" || after.Group != "trusted" || after.Note != "never throttle" {
		t.Fatalf("operator fields were clobbered by a scan: %+v", after)
	}
	if !after.Protected {
		t.Fatal("the protected flag was cleared by a scan")
	}
	if after.IP != "10.0.0.9" {
		t.Errorf("ip = %q, want the newly observed 10.0.0.9", after.IP)
	}
}

func TestDeviceUpsertDoesNotBlankIdentityOnEmptyScan(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	_ = st.UpsertDevice(ctx, &model.Device{MAC: "aa:bb:cc:dd:ee:02", IP: "10.0.0.5", Hostname: "nas", Vendor: "Synology"})
	// A scan that saw the MAC but learned nothing about it.
	_ = st.UpsertDevice(ctx, &model.Device{MAC: "aa:bb:cc:dd:ee:02", Online: true})

	got, _ := st.Device(ctx, "aa:bb:cc:dd:ee:02")
	if got.IP != "10.0.0.5" || got.Hostname != "nas" || got.Vendor != "Synology" {
		t.Fatalf("known identity was blanked: %+v", got)
	}
}

func TestMarkOfflineExcept(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	_ = st.UpsertDevice(ctx, &model.Device{MAC: "aa:bb:cc:dd:ee:03", IP: "10.0.0.6", Online: true})
	_ = st.UpsertDevice(ctx, &model.Device{MAC: "aa:bb:cc:dd:ee:04", IP: "10.0.0.7", Online: true})

	if err := st.MarkOfflineExcept(ctx, []string{"aa:bb:cc:dd:ee:03"}); err != nil {
		t.Fatal(err)
	}
	seen, _ := st.Device(ctx, "aa:bb:cc:dd:ee:03")
	gone, _ := st.Device(ctx, "aa:bb:cc:dd:ee:04")
	if !seen.Online {
		t.Error("the device that was seen was marked offline")
	}
	if gone.Online {
		t.Error("the device that was not seen is still marked online")
	}
}

func TestMarkOfflineExceptEmptyMarksAllOffline(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	_ = st.UpsertDevice(ctx, &model.Device{MAC: "aa:bb:cc:dd:ee:05", Online: true})
	if err := st.MarkOfflineExcept(ctx, nil); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Device(ctx, "aa:bb:cc:dd:ee:05")
	if got.Online {
		t.Fatal("an empty keep-list did not mark every device offline")
	}
}

func TestForgetDeviceRemovesHistory(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mac := "aa:bb:cc:dd:ee:06"
	_ = st.UpsertDevice(ctx, &model.Device{MAC: mac, IP: "10.0.0.8", Online: true})
	_ = st.AddSamples(ctx, []model.Sample{{TS: time.Now(), MAC: mac, RxBps: 100}})
	_ = st.SetOverride(ctx, &Override{MAC: mac, Action: model.ActionBlock})

	if err := st.ForgetDevice(ctx, mac); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Device(ctx, mac); !errors.Is(err, ErrNotFound) {
		t.Fatalf("device still present: %v", err)
	}
	if s, _ := st.Samples(ctx, mac, time.Time{}); len(s) != 0 {
		t.Fatalf("%d samples survived ForgetDevice", len(s))
	}
	ov, _ := st.ActiveOverrides(ctx)
	if _, ok := ov[mac]; ok {
		t.Fatal("an override survived ForgetDevice")
	}
}

func TestPolicyRoundTrip(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()

	p := &model.Policy{
		Name: "nights", TargetType: model.TargetGroup, TargetValue: "guests",
		Action: model.ActionThrottle, CapKbps: 512, UpKbps: 256,
		Schedule: "22:00-06:00", Enabled: true, Priority: 7, CreatedBy: "a@example.com",
	}
	if err := st.CreatePolicy(ctx, p); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	got, err := st.Policy(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "nights" || got.TargetType != model.TargetGroup || got.TargetValue != "guests" {
		t.Fatalf("policy identity round-tripped wrong: %+v", got)
	}
	if got.Action != model.ActionThrottle || got.CapKbps != 512 || got.UpKbps != 256 {
		t.Fatalf("policy action round-tripped wrong: %+v", got)
	}
	if !got.Enabled || got.Priority != 7 || got.CreatedAt.IsZero() {
		t.Fatalf("policy flags round-tripped wrong: %+v", got)
	}
}

func TestListPoliciesOrdersByPriority(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	_ = st.CreatePolicy(ctx, &model.Policy{Name: "low", TargetType: model.TargetAll,
		Action: model.ActionObserve, Enabled: true, Priority: 1})
	_ = st.CreatePolicy(ctx, &model.Policy{Name: "high", TargetType: model.TargetAll,
		Action: model.ActionBlock, Enabled: true, Priority: 99})
	_ = st.CreatePolicy(ctx, &model.Policy{Name: "mid", TargetType: model.TargetAll,
		Action: model.ActionThrottle, CapKbps: 100, Enabled: true, Priority: 50})

	ps, err := st.ListPolicies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"high", "mid", "low"}
	for i, w := range want {
		if ps[i].Name != w {
			t.Fatalf("policy %d = %q, want %q (order: %v)", i, ps[i].Name, w,
				[]string{ps[0].Name, ps[1].Name, ps[2].Name})
		}
	}
}

func TestUpdateAndDeletePolicy(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	p := &model.Policy{Name: "x", TargetType: model.TargetAll, Action: model.ActionBlock, Enabled: true}
	_ = st.CreatePolicy(ctx, p)

	p.Name = "y"
	p.Enabled = false
	p.Priority = 42
	if err := st.UpdatePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Policy(ctx, p.ID)
	if got.Name != "y" || got.Enabled || got.Priority != 42 {
		t.Fatalf("update did not persist: %+v", got)
	}
	if err := st.DeletePolicy(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Policy(ctx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("policy still present after delete: %v", err)
	}
}

func TestOverrideLifecycle(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mac := "aa:bb:cc:dd:ee:07"

	if err := st.SetOverride(ctx, &Override{
		MAC: mac, Action: model.ActionBlock, UpdatedBy: "a@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	ov, err := st.ActiveOverrides(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := ov[mac]
	if !ok {
		t.Fatal("the override was not stored")
	}
	if got.Action != model.ActionBlock || got.UpdatedBy != "a@example.com" {
		t.Fatalf("override round-tripped wrong: %+v", got)
	}
	if got.ExpiresAt != nil {
		t.Fatal("a permanent override reported an expiry")
	}

	// Setting again replaces rather than duplicating.
	if err := st.SetOverride(ctx, &Override{MAC: mac, Action: model.ActionThrottle, CapKbps: 256}); err != nil {
		t.Fatal(err)
	}
	ov, _ = st.ActiveOverrides(ctx)
	if len(ov) != 1 {
		t.Fatalf("%d overrides stored, want 1", len(ov))
	}
	if ov[mac].Action != model.ActionThrottle || ov[mac].CapKbps != 256 {
		t.Fatalf("override was not replaced: %+v", ov[mac])
	}

	if err := st.ClearOverride(ctx, mac); err != nil {
		t.Fatal(err)
	}
	ov, _ = st.ActiveOverrides(ctx)
	if len(ov) != 0 {
		t.Fatal("override survived ClearOverride")
	}
}

func TestExpiredOverrideIsInactiveAndPurged(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Minute)

	_ = st.SetOverride(ctx, &Override{MAC: "aa:bb:cc:dd:ee:08", Action: model.ActionBlock, ExpiresAt: &past})
	ov, _ := st.ActiveOverrides(ctx)
	if len(ov) != 0 {
		t.Fatalf("an expired override is still active: %+v", ov)
	}

	n, err := st.PurgeExpiredOverrides(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("PurgeExpiredOverrides removed %d rows, want 1", n)
	}
}

func TestFutureOverrideIsActive(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	future := time.Now().Add(time.Hour)
	_ = st.SetOverride(ctx, &Override{MAC: "aa:bb:cc:dd:ee:09", Action: model.ActionThrottle, CapKbps: 128, ExpiresAt: &future})

	ov, _ := st.ActiveOverrides(ctx)
	got, ok := ov["aa:bb:cc:dd:ee:09"]
	if !ok {
		t.Fatal("a future-dated override was not active")
	}
	if got.ExpiresAt == nil || got.ExpiresAt.Before(time.Now()) {
		t.Fatalf("expiry round-tripped wrong: %+v", got.ExpiresAt)
	}
}

func TestClearAllOverrides(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	for _, m := range []string{"aa:bb:cc:dd:ee:10", "aa:bb:cc:dd:ee:11"} {
		_ = st.SetOverride(ctx, &Override{MAC: m, Action: model.ActionBlock})
	}
	n, err := st.ClearAllOverrides(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("cleared %d overrides, want 2", n)
	}
	ov, _ := st.ActiveOverrides(ctx)
	if len(ov) != 0 {
		t.Fatal("overrides survived ClearAllOverrides")
	}
}

func TestEventsRoundTripAndFilter(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mac := "aa:bb:cc:dd:ee:12"

	_ = st.AddEvent(ctx, &model.Event{Type: "device.action", Severity: "alert", MAC: mac, Message: "blocked", Actor: "a@example.com"})
	_ = st.AddEvent(ctx, &model.Event{Type: "auth.login", Severity: "info", Message: "signed in", Actor: "a@example.com"})

	all, err := st.ListEvents(ctx, 50, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("ListEvents returned %d, want 2", len(all))
	}
	if all[0].TS.IsZero() {
		t.Fatal("event timestamp did not survive the round trip")
	}

	only, err := st.ListEvents(ctx, 50, mac)
	if err != nil {
		t.Fatal(err)
	}
	if len(only) != 1 || only[0].Message != "blocked" {
		t.Fatalf("MAC filter returned %+v", only)
	}
}

func TestPruneEventsKeepsNewest(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		_ = st.AddEvent(ctx, &model.Event{Type: "t", Message: "m"})
		time.Sleep(time.Millisecond)
	}
	if err := st.PruneEvents(ctx, 5); err != nil {
		t.Fatal(err)
	}
	evs, _ := st.ListEvents(ctx, 100, "")
	if len(evs) != 5 {
		t.Fatalf("%d events remain, want 5", len(evs))
	}
}

func TestSamplesAndPrune(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mac := "aa:bb:cc:dd:ee:13"
	now := time.Now()

	_ = st.AddSamples(ctx, []model.Sample{
		{TS: now.Add(-2 * time.Hour), MAC: mac, RxBps: 1000, TxBps: 500},
		{TS: now, MAC: mac, RxBps: 2000, TxBps: 800},
	})

	got, err := st.Samples(ctx, mac, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].RxBps != 2000 {
		t.Fatalf("Samples returned %+v, want only the recent one", got)
	}

	n, err := st.PruneSamples(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("pruned %d samples, want 1", n)
	}
}

func TestAgentTokenLifecycle(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	hash := "abc123"

	if ok, _ := st.AgentTokenValid(ctx, hash); ok {
		t.Fatal("an unregistered credential was accepted")
	}
	if err := st.CreateAgentToken(ctx, "id1", "gateway-host", hash); err != nil {
		t.Fatal(err)
	}
	if ok, _ := st.AgentTokenValid(ctx, hash); !ok {
		t.Fatal("a registered credential was rejected")
	}
	if ok, _ := st.AgentTokenValid(ctx, "different"); ok {
		t.Fatal("a wrong credential was accepted")
	}

	if err := st.TouchAgentToken(ctx, hash); err != nil {
		t.Fatal(err)
	}
	toks, err := st.ListAgentTokens(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 1 || toks[0].Name != "gateway-host" || toks[0].Revoked {
		t.Fatalf("token listing wrong: %+v", toks)
	}
	if toks[0].LastSeen.Before(toks[0].CreatedAt) {
		t.Error("last_seen is before created_at")
	}

	if err := st.RevokeAgentToken(ctx, "id1"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := st.AgentTokenValid(ctx, hash); ok {
		t.Fatal("a revoked credential was accepted")
	}
}

func TestSettings(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	if got := st.Setting(ctx, "missing", "fallback"); got != "fallback" {
		t.Fatalf("Setting default = %q, want fallback", got)
	}
	if err := st.SetSetting(ctx, "k", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(ctx, "k", "v2"); err != nil {
		t.Fatal(err)
	}
	if got := st.Setting(ctx, "k", ""); got != "v2" {
		t.Fatalf("Setting = %q, want v2", got)
	}
}

func TestStats(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()

	_ = st.UpsertDevice(ctx, &model.Device{MAC: "aa:bb:cc:dd:ee:14", Online: true, RxBps: 100, TxBps: 50})
	d := &model.Device{MAC: "aa:bb:cc:dd:ee:15", Online: true, Protected: true}
	_ = st.UpsertDevice(ctx, d)
	_ = st.CreatePolicy(ctx, &model.Policy{Name: "p1", TargetType: model.TargetAll, Action: model.ActionBlock, Enabled: true})
	_ = st.CreatePolicy(ctx, &model.Policy{Name: "p2", TargetType: model.TargetAll, Action: model.ActionBlock, Enabled: false})
	_ = st.AddEvent(ctx, &model.Event{Type: "t", Message: "m"})

	got, err := st.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Devices != 2 || got.Online != 2 || got.Protected != 1 {
		t.Fatalf("device counters wrong: %+v", got)
	}
	if got.Policies != 2 || got.ActivePol != 1 {
		t.Fatalf("policy counters wrong: %+v", got)
	}
	if got.Events != 1 {
		t.Fatalf("event counter = %d, want 1", got.Events)
	}
	if got.RxBpsTotal != 100 || got.TxBpsTotal != 50 {
		t.Fatalf("throughput totals wrong: %+v", got)
	}
}

func TestProtectedMACs(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	_ = st.UpsertDevice(ctx, &model.Device{MAC: "AA-BB-CC-DD-EE-16", Protected: true})
	_ = st.UpsertDevice(ctx, &model.Device{MAC: "aa:bb:cc:dd:ee:17"})

	got, err := st.ProtectedMACs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("%d protected MACs, want 1", len(got))
	}
	// Keys are normalised so either spelling matches.
	if !got["aa:bb:cc:dd:ee:16"] {
		t.Fatalf("protected set was not normalised: %+v", got)
	}
}

func TestReopenPreservesData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "persist.db")
	ctx := context.Background()

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.CreateUser(ctx, &model.User{Email: "keep@example.com", PasswordHash: "h", Role: model.RoleOwner})
	_ = st.UpsertDevice(ctx, &model.Device{MAC: "aa:bb:cc:dd:ee:18", IP: "10.0.0.20", Online: true})
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()

	if _, err := st2.UserByEmail(ctx, "keep@example.com"); err != nil {
		t.Fatalf("user did not survive a restart: %v", err)
	}
	d, err := st2.Device(ctx, "aa:bb:cc:dd:ee:18")
	if err != nil {
		t.Fatalf("device did not survive a restart: %v", err)
	}
	if d.IP != "10.0.0.20" {
		t.Fatalf("device ip = %q after reopen, want 10.0.0.20", d.IP)
	}
}

func TestNormMAC(t *testing.T) {
	cases := map[string]string{
		"AA:BB:CC:DD:EE:FF":     "aa:bb:cc:dd:ee:ff",
		"aa-bb-cc-dd-ee-ff":     "aa:bb:cc:dd:ee:ff",
		"  AA-BB-CC-DD-EE-FF  ": "aa:bb:cc:dd:ee:ff",
	}
	for in, want := range cases {
		if got := normMAC(in); got != want {
			t.Errorf("normMAC(%q) = %q, want %q", in, got, want)
		}
	}
}
