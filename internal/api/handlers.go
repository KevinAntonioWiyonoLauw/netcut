// language: Go, file: internal/api/handlers.go
// Device, policy, panic/reset, user and WebSocket handlers.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/kevinantoniowiyonolauw/netcut/internal/auth"
	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
	"github.com/kevinantoniowiyonolauw/netcut/internal/policy"
	"github.com/kevinantoniowiyonolauw/netcut/internal/store"
)

// stateEnvelope is what the dashboard receives on every push.
type stateEnvelope struct {
	Type      string            `json:"type"`
	TS        time.Time         `json:"ts"`
	Devices   []model.Device    `json:"devices"`
	Decisions []policy.Result   `json:"decisions"`
	Policies  []model.Policy    `json:"policies"`
	Overrides map[string]any    `json:"overrides"`
	Stats     *store.Stats      `json:"stats"`
	Health    any               `json:"health"`
	Agents    []model.AgentInfo `json:"agents"`
	// Router reports whether router polling is configured and working. The
	// dashboard uses it to explain why a device has no link label.
	Router any `json:"router"`
}

// buildState assembles the single payload that fully describes the fleet.
// The dashboard renders from this alone, so every push is self-consistent.
func (s *Server) buildState(r *http.Request) (*stateEnvelope, error) {
	ctx := r.Context()
	devices, err := s.st.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	policies, err := s.st.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	overrides, err := s.st.ActiveOverrides(ctx)
	if err != nil {
		return nil, err
	}
	stats, err := s.st.Stats(ctx)
	if err != nil {
		return nil, err
	}
	results := s.fl.Results()

	decisions := make([]policy.Result, 0, len(results))
	for _, res := range results {
		decisions = append(decisions, res)
	}
	sort.Slice(decisions, func(i, j int) bool { return decisions[i].MAC < decisions[j].MAC })

	ovOut := make(map[string]any, len(overrides))
	for mac, ov := range overrides {
		ovOut[mac] = ov
	}

	return &stateEnvelope{
		Type:      "state",
		TS:        time.Now().UTC(),
		Devices:   nonNilDevices(devices),
		Decisions: decisions,
		Policies:  nonNilPolicies(policies),
		Overrides: ovOut,
		Stats:     stats,
		Health:    s.fl.Health(),
		Agents:    nonNilAgents(s.fl.Agents()),
		Router:    s.routerStatus(),
	}, nil
}

// The helpers below guarantee that an empty collection is serialised as [] and
// not null. A client should be able to iterate the result without a nil check.

func nonNilDevices(v []model.Device) []model.Device {
	if v == nil {
		return []model.Device{}
	}
	return v
}

func nonNilPolicies(v []model.Policy) []model.Policy {
	if v == nil {
		return []model.Policy{}
	}
	return v
}

func nonNilAgents(v []model.AgentInfo) []model.AgentInfo {
	if v == nil {
		return []model.AgentInfo{}
	}
	return v
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	st, err := s.buildState(r)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not build state")
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.st.ListDevices(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list devices")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"devices":   nonNilDevices(devices),
		"decisions": s.fl.Results(),
	})
}

func (s *Server) handleGetDevice(w http.ResponseWriter, r *http.Request) {
	mac := pathMAC(r)
	d, err := s.st.Device(r.Context(), mac)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "device not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not read device")
		return
	}
	ov, _ := s.st.ActiveOverrides(r.Context())
	res := s.fl.Results()[mac]
	writeJSON(w, http.StatusOK, map[string]any{
		"device":   d,
		"decision": res,
		"override": ov[mac],
	})
}

// patchDeviceReq uses pointers so a client can update one field without
// clobbering the others.
type patchDeviceReq struct {
	Alias     *string `json:"alias"`
	Group     *string `json:"group"`
	Note      *string `json:"note"`
	Protected *bool   `json:"protected"`
}

func (s *Server) handlePatchDevice(w http.ResponseWriter, r *http.Request) {
	mac := pathMAC(r)
	var req patchDeviceReq
	if !decodeJSON(w, r, &req) {
		return
	}
	d, err := s.st.Device(r.Context(), mac)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "device not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not read device")
		return
	}
	changes := []string{}
	if req.Alias != nil {
		d.Alias = strings.TrimSpace(*req.Alias)
		changes = append(changes, "alias")
	}
	if req.Group != nil {
		d.Group = strings.TrimSpace(*req.Group)
		changes = append(changes, "group")
	}
	if req.Note != nil {
		d.Note = strings.TrimSpace(*req.Note)
		changes = append(changes, "note")
	}
	if req.Protected != nil {
		d.Protected = *req.Protected
		changes = append(changes, "protected")
	}
	if len(changes) == 0 {
		writeErr(w, http.StatusBadRequest, "no updatable field supplied")
		return
	}
	if err := s.st.UpdateDeviceSettings(r.Context(), d); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not update device")
		return
	}
	// A newly protected device must immediately stop being enforced.
	if err := s.fl.Reconcile(r.Context(), s.st, s.hub); err != nil {
		s.log.Warn("reconcile after device patch failed", "err", err)
	}
	_ = s.st.AddEvent(r.Context(), &model.Event{
		Type: "device.updated", Severity: "info", MAC: mac, Actor: user(r).Email,
		Message: "updated " + strings.Join(changes, ", ") + " for " + d.DisplayName(),
	})
	writeJSON(w, http.StatusOK, map[string]any{"device": d})
}

func (s *Server) handleForgetDevice(w http.ResponseWriter, r *http.Request) {
	mac := pathMAC(r)
	if err := s.st.ClearOverride(r.Context(), mac); err != nil {
		s.log.Warn("clear override failed", "err", err)
	}
	if err := s.st.ForgetDevice(r.Context(), mac); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "device not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not forget device")
		return
	}
	if err := s.fl.Reconcile(r.Context(), s.st, s.hub); err != nil {
		s.log.Warn("reconcile after forget failed", "err", err)
	}
	_ = s.st.AddEvent(r.Context(), &model.Event{
		Type: "device.forgotten", Severity: "warn", MAC: mac, Actor: user(r).Email,
		Message: "device removed from inventory: " + mac,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// actionReq is the manual per-device control.
//
//	duration_s == 0  -> permanent until cleared
//	duration_s  > 0  -> auto-reverts after that many seconds
type actionReq struct {
	Action    string `json:"action"`     // allow | block | throttle | observe
	CapKbps   int    `json:"cap_kbps"`   // for throttle
	UpKbps    int    `json:"up_kbps"`    // for throttle
	DurationS int    `json:"duration_s"` // 0 = permanent
	Note      string `json:"note"`
}

func (s *Server) handleDeviceAction(w http.ResponseWriter, r *http.Request) {
	mac := pathMAC(r)
	var req actionReq
	if !decodeJSON(w, r, &req) {
		return
	}
	d, err := s.st.Device(r.Context(), mac)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "device not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not read device")
		return
	}

	// Refuse to enforce on a protected device. This is the hard guarantee:
	// the operator's own hardware cannot be locked out by a mis-click.
	if d.Protected && req.Action != "allow" && req.Action != "observe" {
		writeErr(w, http.StatusConflict,
			"device is protected; clear the protected flag before enforcing on it")
		return
	}

	act := model.Action(strings.ToLower(strings.TrimSpace(req.Action)))
	switch act {
	case model.ActionAllow, model.ActionObserve:
		// Clearing enforcement.
		if err := s.st.ClearOverride(r.Context(), mac); err != nil {
			writeErr(w, http.StatusInternalServerError, "could not clear override")
			return
		}
	case model.ActionBlock, model.ActionThrottle:
		if act == model.ActionThrottle {
			if req.CapKbps <= 0 {
				writeErr(w, http.StatusBadRequest, "cap_kbps must be greater than 0 for a throttle")
				return
			}
			if req.CapKbps > 10_000_000 {
				writeErr(w, http.StatusBadRequest, "cap_kbps is implausibly large")
				return
			}
		}
		ov := &store.Override{
			MAC: mac, Action: act, CapKbps: req.CapKbps, UpKbps: req.UpKbps,
			UpdatedBy: user(r).Email, UpdatedAt: time.Now().UTC(),
		}
		if req.DurationS > 0 {
			if req.DurationS > 30*24*3600 {
				writeErr(w, http.StatusBadRequest, "duration_s exceeds 30 days")
				return
			}
			exp := time.Now().UTC().Add(time.Duration(req.DurationS) * time.Second)
			ov.ExpiresAt = &exp
		}
		if err := s.st.SetOverride(r.Context(), ov); err != nil {
			writeErr(w, http.StatusInternalServerError, "could not store override")
			return
		}
	default:
		writeErr(w, http.StatusBadRequest, "action must be one of: allow, block, throttle, observe")
		return
	}

	// Apply immediately so the UI reflects reality without waiting a tick.
	if err := s.fl.Reconcile(r.Context(), s.st, s.hub); err != nil {
		s.log.Warn("reconcile after action failed", "err", err)
	}

	msg := "manual " + string(act) + " applied to " + d.DisplayName()
	if req.CapKbps > 0 && act == model.ActionThrottle {
		msg += " (cap " + itoa(req.CapKbps) + " kbps)"
	}
	if req.DurationS > 0 {
		msg += " for " + itoa(req.DurationS) + "s"
	}
	if req.Note != "" {
		msg += " - " + req.Note
	}
	_ = s.st.AddEvent(r.Context(), &model.Event{
		Type: "device.action", Severity: severityFor(act), MAC: mac,
		Actor: user(r).Email, Message: msg,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": act})
}

func (s *Server) handleDeviceSamples(w http.ResponseWriter, r *http.Request) {
	mac := pathMAC(r)
	minutes := intQuery(r, "minutes", 60)
	if minutes <= 0 || minutes > 24*60 {
		minutes = 60
	}
	since := time.Now().Add(-time.Duration(minutes) * time.Minute)
	samples, err := s.st.Samples(r.Context(), mac, since)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not read samples")
		return
	}
	if samples == nil {
		samples = []model.Sample{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"samples": samples, "minutes": minutes})
}

// ---------------------------------------------------------------- policies

type policyReq struct {
	Name        string `json:"name"`
	TargetType  string `json:"target_type"`
	TargetValue string `json:"target_value"`
	Action      string `json:"action"`
	CapKbps     int    `json:"cap_kbps"`
	UpKbps      int    `json:"up_kbps"`
	Schedule    string `json:"schedule"`
	Window      string `json:"window"`
	Enabled     *bool  `json:"enabled"`
	Priority    int    `json:"priority"`
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	ps, err := s.st.ListPolicies(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list policies")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": nonNilPolicies(ps)})
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var req policyReq
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := validatePolicy(req, nil)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p.CreatedBy = user(r).Email
	if err := s.st.CreatePolicy(r.Context(), p); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create policy")
		return
	}
	_ = s.fl.Reconcile(r.Context(), s.st, s.hub)
	_ = s.st.AddEvent(r.Context(), &model.Event{
		Type: "policy.created", Severity: "warn", Actor: user(r).Email,
		Message: "policy created: " + p.Name,
	})
	writeJSON(w, http.StatusCreated, map[string]any{"policy": p})
}

func (s *Server) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.st.Policy(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "policy not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not read policy")
		return
	}
	var req policyReq
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := validatePolicy(req, existing)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.st.UpdatePolicy(r.Context(), p); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not update policy")
		return
	}
	_ = s.fl.Reconcile(r.Context(), s.st, s.hub)
	_ = s.st.AddEvent(r.Context(), &model.Event{
		Type: "policy.updated", Severity: "warn", Actor: user(r).Email,
		Message: "policy updated: " + p.Name,
	})
	writeJSON(w, http.StatusOK, map[string]any{"policy": p})
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.st.DeletePolicy(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "policy not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not delete policy")
		return
	}
	_ = s.fl.Reconcile(r.Context(), s.st, s.hub)
	_ = s.st.AddEvent(r.Context(), &model.Event{
		Type: "policy.deleted", Severity: "warn", Actor: user(r).Email,
		Message: "policy deleted: " + id,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func validatePolicy(req policyReq, existing *model.Policy) (*model.Policy, error) {
	p := &model.Policy{}
	if existing != nil {
		*p = *existing
	}
	p.Name = strings.TrimSpace(req.Name)
	if p.Name == "" {
		return nil, errors.New("name is required")
	}
	tt := model.TargetType(strings.ToLower(strings.TrimSpace(req.TargetType)))
	switch tt {
	case model.TargetDevice, model.TargetGroup, model.TargetAll:
		p.TargetType = tt
	default:
		return nil, errors.New("target_type must be one of: device, group, all")
	}
	p.TargetValue = strings.TrimSpace(req.TargetValue)
	if p.TargetType == model.TargetDevice {
		if p.TargetValue == "" {
			return nil, errors.New("target_value (MAC) is required when target_type is device")
		}
		p.TargetValue = strings.ToLower(strings.ReplaceAll(p.TargetValue, "-", ":"))
	}
	if p.TargetType == model.TargetGroup && p.TargetValue == "" {
		return nil, errors.New("target_value (group name) is required when target_type is group")
	}

	act := model.Action(strings.ToLower(strings.TrimSpace(req.Action)))
	switch act {
	case model.ActionBlock, model.ActionThrottle, model.ActionObserve, model.ActionAllow:
		p.Action = act
	default:
		return nil, errors.New("action must be one of: block, throttle, observe, allow")
	}
	p.CapKbps = req.CapKbps
	p.UpKbps = req.UpKbps
	if p.Action == model.ActionThrottle {
		if p.CapKbps <= 0 {
			return nil, errors.New("cap_kbps must be greater than 0 for a throttle policy")
		}
		if p.CapKbps > 10_000_000 {
			return nil, errors.New("cap_kbps is implausibly large")
		}
	}

	p.Schedule = strings.TrimSpace(req.Schedule)
	p.Window = strings.TrimSpace(req.Window)
	p.Priority = req.Priority
	if req.Enabled != nil {
		p.Enabled = *req.Enabled
	} else if existing == nil {
		p.Enabled = true
	}
	return p, nil
}

// ---------------------------------------------------------------- panic / reset

// handlePanic is the emergency stop: every non-protected device is released
// immediately. It clears all overrides and disables every policy, so the
// segment returns to a clean, unenforced state in one action.
func (s *Server) handlePanic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	devices, err := s.st.ListDevices(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not read devices")
		return
	}
	released := 0
	for _, d := range devices {
		if d.Blocked || d.Throttled {
			released++
		}
	}
	if _, err := s.st.ClearAllOverrides(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not clear overrides")
		return
	}
	policies, err := s.st.ListPolicies(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not read policies")
		return
	}
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		p.Enabled = false
		if err := s.st.UpdatePolicy(ctx, &p); err != nil {
			s.log.Warn("panic: disable policy failed", "id", p.ID, "err", err)
		}
	}
	if err := s.fl.Reconcile(ctx, s.st, s.hub); err != nil {
		s.log.Warn("reconcile after panic failed", "err", err)
	}
	_ = s.st.AddEvent(ctx, &model.Event{
		Type: "panic", Severity: "alert", Actor: user(r).Email,
		Message: "PANIC: released " + itoa(released) + " device(s) and disabled all policies",
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "released": released})
}

// handleReset clears every override and policy, returning to a clean slate.
func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if _, err := s.st.ClearAllOverrides(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not clear overrides")
		return
	}
	policies, err := s.st.ListPolicies(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not read policies")
		return
	}
	for _, p := range policies {
		_ = s.st.DeletePolicy(ctx, p.ID)
	}
	if err := s.fl.Reconcile(ctx, s.st, s.hub); err != nil {
		s.log.Warn("reconcile after reset failed", "err", err)
	}
	_ = s.st.AddEvent(ctx, &model.Event{
		Type: "reset", Severity: "warn", Actor: user(r).Email,
		Message: "all overrides cleared and all policies deleted",
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------------------------------------------------------------- users

type userReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	us, err := s.st.ListUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list users")
		return
	}
	if us == nil {
		us = []model.User{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": us})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req userReq
	if !decodeJSON(w, r, &req) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || !strings.Contains(email, "@") {
		writeErr(w, http.StatusBadRequest, "a valid email is required")
		return
	}
	role := model.Role(strings.ToLower(strings.TrimSpace(req.Role)))
	if role != model.RoleOwner && role != model.RoleAdmin && role != model.RoleViewer {
		writeErr(w, http.StatusBadRequest, "role must be one of: owner, admin, viewer")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	u := &model.User{Email: email, PasswordHash: hash, Role: role}
	if err := s.st.CreateUser(r.Context(), u); err != nil {
		writeErr(w, http.StatusConflict, "could not create user (email may already exist)")
		return
	}
	_ = s.st.AddEvent(r.Context(), &model.Event{
		Type: "user.created", Severity: "warn", Actor: user(r).Email,
		Message: "account created: " + email + " (" + string(role) + ")",
	})
	writeJSON(w, http.StatusCreated, map[string]any{"user": u})
}

func (s *Server) handlePatchUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req userReq
	if !decodeJSON(w, r, &req) {
		return
	}
	target, err := s.st.UserByID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	actor := user(r)

	if req.Role != "" {
		role := model.Role(strings.ToLower(strings.TrimSpace(req.Role)))
		if role != model.RoleOwner && role != model.RoleAdmin && role != model.RoleViewer {
			writeErr(w, http.StatusBadRequest, "role must be one of: owner, admin, viewer")
			return
		}
		// Guard against removing the last owner, which would leave the
		// installation with nobody able to manage accounts.
		if target.Role == model.RoleOwner && role != model.RoleOwner {
			if n, err := s.st.CountOwners(r.Context()); err == nil && n <= 1 {
				writeErr(w, http.StatusConflict, "cannot demote the last owner account")
				return
			}
		}
		if err := s.st.UpdateUserRole(r.Context(), id, role); err != nil {
			writeErr(w, http.StatusInternalServerError, "could not update role")
			return
		}
	}
	if req.Password != "" {
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.st.UpdateUserPassword(r.Context(), id, hash); err != nil {
			writeErr(w, http.StatusInternalServerError, "could not update password")
			return
		}
	}
	_ = s.st.AddEvent(r.Context(), &model.Event{
		Type: "user.updated", Severity: "warn", Actor: actor.Email,
		Message: "account updated: " + target.Email,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	actor := user(r)
	if id == actor.ID {
		writeErr(w, http.StatusConflict, "you cannot delete your own account")
		return
	}
	target, err := s.st.UserByID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if target.Role == model.RoleOwner {
		if n, err := s.st.CountOwners(r.Context()); err == nil && n <= 1 {
			writeErr(w, http.StatusConflict, "cannot delete the last owner account")
			return
		}
	}
	if err := s.st.DeleteUser(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not delete user")
		return
	}
	_ = s.st.AddEvent(r.Context(), &model.Event{
		Type: "user.deleted", Severity: "warn", Actor: actor.Email,
		Message: "account deleted: " + target.Email,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------------------------------------------------------------- websocket

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 32768,
	// The session cookie is same-origin; reject cross-origin upgrades.
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // non-browser client (curl, agent tooling)
		}
		host := r.Host
		for _, scheme := range []string{"http://", "https://"} {
			if strings.TrimPrefix(origin, scheme) == host {
				return true
			}
		}
		return false
	},
}

// handleWS streams live state to a dashboard.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.log.Warn("ws upgrade failed", "err", err)
		return
	}
	defer conn.Close()

	ch, cancel := s.hub.Subscribe()
	defer cancel()

	// Send the full state immediately so the UI has something to render
	// before the next reconcile tick.
	if st, err := s.buildState(r); err == nil {
		if b, err := json.Marshal(st); err == nil {
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, b); err != nil {
				return
			}
		}
	}

	// Reader: detects a closed client and answers pings.
	go func() {
		conn.SetReadLimit(1024)
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		conn.SetPongHandler(func(string) error {
			return conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		})
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				cancel()
				return
			}
		}
	}()

	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case b, ok := <-ch:
			if !ok {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, b); err != nil {
				return
			}
		case <-ping.C:
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}

func severityFor(a model.Action) string {
	switch a {
	case model.ActionBlock:
		return "alert"
	case model.ActionThrottle:
		return "warn"
	default:
		return "info"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
