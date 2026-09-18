// language: Go, file: internal/api/api.go
// HTTP surface: session auth, RBAC, security headers, REST endpoints, a
// WebSocket live feed, and the embedded dashboard.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kevinantoniowiyonolauw/netcut/internal/auth"
	"github.com/kevinantoniowiyonolauw/netcut/internal/config"
	"github.com/kevinantoniowiyonolauw/netcut/internal/fleet"
	"github.com/kevinantoniowiyonolauw/netcut/internal/hub"
	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
	"github.com/kevinantoniowiyonolauw/netcut/internal/store"
	"github.com/kevinantoniowiyonolauw/netcut/internal/version"
)

// SessionCookie is the name of the browser session cookie.
const SessionCookie = "netcut_session"

// CSRFToken is the value the dashboard must echo in the X-NetCut header on
// every state-changing request. Combined with SameSite=Lax this blocks
// cross-site form posts, which cannot set custom headers.
const CSRFToken = "1"

// Server wires the HTTP surface to the store, fleet and hub.
type Server struct {
	cfg     *config.Config
	st      *store.Store
	fl      *fleet.Fleet
	hub     *hub.Hub
	issuer  *auth.Issuer
	limiter *auth.Limiter
	log     *slog.Logger
	assets  http.Handler
	mux     *http.ServeMux
}

// New builds the server and registers every route.
func New(cfg *config.Config, st *store.Store, fl *fleet.Fleet, h *hub.Hub,
	issuer *auth.Issuer, log *slog.Logger, assets http.Handler) *Server {

	s := &Server{
		cfg:     cfg,
		st:      st,
		fl:      fl,
		hub:     h,
		issuer:  issuer,
		limiter: auth.NewLimiter(cfg.MaxLoginFails, cfg.LockoutWindow),
		log:     log,
		assets:  assets,
		mux:     http.NewServeMux(),
	}
	s.routes()
	return s
}

// Handler returns the fully wrapped HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.recoverer(s.logger(s.securityHeaders(s.mux)))
}

func (s *Server) routes() {
	m := s.mux

	// ---- public ----
	m.HandleFunc("GET /api/health", s.handleHealth)
	m.HandleFunc("GET /api/meta", s.handleMeta)
	m.HandleFunc("POST /api/auth/login", s.handleLogin)
	m.HandleFunc("POST /api/auth/logout", s.handleLogout)

	// ---- agent (credential auth, not session auth) ----
	m.HandleFunc("POST /api/agent/hello", s.agentAuth(s.handleAgentHello))
	m.HandleFunc("POST /api/agent/report", s.agentAuth(s.handleAgentReport))
	m.HandleFunc("GET /api/agent/directives", s.agentAuth(s.handleAgentDirectives))

	// ---- session ----
	m.HandleFunc("GET /api/auth/me", s.requireAuth(s.handleMe))
	m.HandleFunc("POST /api/auth/password", s.requireAuth(s.mutating(s.handleChangePassword)))

	m.HandleFunc("GET /api/state", s.requireAuth(s.handleState))
	m.HandleFunc("GET /api/stats", s.requireAuth(s.handleStats))
	m.HandleFunc("GET /api/ws", s.requireAuth(s.handleWS))

	m.HandleFunc("GET /api/devices", s.requireAuth(s.handleListDevices))
	m.HandleFunc("GET /api/devices/{mac}", s.requireAuth(s.handleGetDevice))
	m.HandleFunc("PATCH /api/devices/{mac}", s.requireAuth(s.mutating(s.requireRole(model.RoleAdmin, s.handlePatchDevice))))
	m.HandleFunc("DELETE /api/devices/{mac}", s.requireAuth(s.mutating(s.requireRole(model.RoleAdmin, s.handleForgetDevice))))
	m.HandleFunc("POST /api/devices/{mac}/action", s.requireAuth(s.mutating(s.requireRole(model.RoleAdmin, s.handleDeviceAction))))
	m.HandleFunc("GET /api/devices/{mac}/samples", s.requireAuth(s.handleDeviceSamples))

	m.HandleFunc("GET /api/policies", s.requireAuth(s.handleListPolicies))
	m.HandleFunc("POST /api/policies", s.requireAuth(s.mutating(s.requireRole(model.RoleAdmin, s.handleCreatePolicy))))
	m.HandleFunc("PATCH /api/policies/{id}", s.requireAuth(s.mutating(s.requireRole(model.RoleAdmin, s.handleUpdatePolicy))))
	m.HandleFunc("DELETE /api/policies/{id}", s.requireAuth(s.mutating(s.requireRole(model.RoleAdmin, s.handleDeletePolicy))))

	m.HandleFunc("POST /api/panic", s.requireAuth(s.mutating(s.requireRole(model.RoleAdmin, s.handlePanic))))
	m.HandleFunc("POST /api/reset", s.requireAuth(s.mutating(s.requireRole(model.RoleAdmin, s.handleReset))))

	m.HandleFunc("GET /api/events", s.requireAuth(s.handleListEvents))

	m.HandleFunc("GET /api/agents", s.requireAuth(s.handleListAgents))
	m.HandleFunc("POST /api/agents", s.requireAuth(s.mutating(s.requireRole(model.RoleOwner, s.handleCreateAgentToken))))
	m.HandleFunc("DELETE /api/agents/{id}", s.requireAuth(s.mutating(s.requireRole(model.RoleOwner, s.handleRevokeAgentToken))))

	m.HandleFunc("GET /api/users", s.requireAuth(s.requireRole(model.RoleOwner, s.handleListUsers)))
	m.HandleFunc("POST /api/users", s.requireAuth(s.mutating(s.requireRole(model.RoleOwner, s.handleCreateUser))))
	m.HandleFunc("PATCH /api/users/{id}", s.requireAuth(s.mutating(s.requireRole(model.RoleOwner, s.handlePatchUser))))
	m.HandleFunc("DELETE /api/users/{id}", s.requireAuth(s.mutating(s.requireRole(model.RoleOwner, s.handleDeleteUser))))

	// ---- dashboard ----
	m.Handle("GET /", s.assets)
}

// ---------------------------------------------------------------- middleware

type ctxKey string

const (
	ctxUser  ctxKey = "user"
	ctxAgent ctxKey = "agent"
)

// recoverer turns a panic into a 500 instead of killing the connection.
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic in handler", "path", r.URL.Path, "panic", rec)
				writeErr(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) {
	w.code = c
	w.ResponseWriter.WriteHeader(c)
}

func (s *Server) logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(sw, r)
		// Skip the WebSocket (long-lived) and static noise from the log.
		if strings.HasPrefix(r.URL.Path, "/api/ws") {
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || sw.code >= 400 {
			s.log.Info("http",
				"method", r.Method, "path", r.URL.Path,
				"status", sw.code, "ms", time.Since(start).Milliseconds(),
				"ip", clientIP(r, s.cfg.TrustedProxy))
		}
	})
}

// securityHeaders applies a strict CSP. The dashboard is fully self-contained
// (no external fonts, scripts, or images), so nothing needs to be allowed
// beyond 'self'; inline style/script are permitted because the single-page
// dashboard ships as one file.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; "+
				"frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if s.cfg.PublicURL != "" {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// requireAuth accepts either a Bearer token (API clients) or the session
// cookie (browser). Both carry the same signed claims.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := bearer(r)
		if raw == "" {
			if c, err := r.Cookie(SessionCookie); err == nil {
				raw = c.Value
			}
		}
		if raw == "" {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		claims, err := s.issuer.Parse(raw)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "session expired")
			return
		}
		u, err := s.st.UserByID(r.Context(), claims.Subject)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "account no longer exists")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxUser, u)))
	}
}

// requireRole gates a handler on the caller's role.
func (s *Server) requireRole(min model.Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := user(r)
		if u == nil {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if !u.Role.AtLeast(min) {
			writeErr(w, http.StatusForbidden, fmt.Sprintf("%s role required", min))
			return
		}
		next(w, r)
	}
}

// mutating enforces the CSRF header on state-changing requests. A cross-site
// form post cannot set a custom header, so this plus SameSite=Lax closes the
// classic CSRF hole without a token round-trip.
func (s *Server) mutating(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next(w, r)
			return
		}
		if r.Header.Get("X-NetCut") != CSRFToken {
			writeErr(w, http.StatusForbidden, "missing X-NetCut header")
			return
		}
		next(w, r)
	}
}

// agentAuth validates the shared agent credential.
func (s *Server) agentAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimSpace(r.Header.Get("X-Agent-Token"))
		if tok == "" {
			tok = strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		}
		if tok == "" {
			writeErr(w, http.StatusUnauthorized, "agent token required")
			return
		}
		sum := auth.HashToken(tok)
		ok, err := s.st.AgentTokenValid(r.Context(), sum)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "credential lookup failed")
			return
		}
		if !ok {
			writeErr(w, http.StatusUnauthorized, "invalid agent token")
			return
		}
		_ = s.st.TouchAgentToken(r.Context(), sum)
		next(w, r.WithContext(context.WithValue(r.Context(), ctxAgent, sum)))
	}
}

// ---------------------------------------------------------------- helpers

func user(r *http.Request) *model.User {
	if u, ok := r.Context().Value(ctxUser).(*model.User); ok {
		return u
	}
	return nil
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func clientIP(r *http.Request, trustedProxy bool) string {
	if trustedProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Left-most entry is the original client as recorded by the edge.
			if i := strings.IndexByte(xff, ','); i > 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
		if xr := r.Header.Get("X-Real-Ip"); xr != "" {
			return strings.TrimSpace(xr)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if v == nil {
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg, "status": code})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func pathMAC(r *http.Request) string {
	return strings.ToLower(strings.TrimSpace(r.PathValue("mac")))
}

func intQuery(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// ---------------------------------------------------------------- handlers

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	h := s.fl.Health()
	status := http.StatusOK
	body := map[string]any{
		"status":  "ok",
		"version": version.Version,
		"commit":  version.Commit,
		"time":    time.Now().UTC(),
		"agent":   h,
		"ws":      s.hub.Count(),
	}
	if !h.AgentOnline {
		// The control plane is healthy even when the data plane is silent;
		// report it as degraded so the dashboard can surface the gap.
		body["status"] = "degraded"
		body["detail"] = "no agent has reported recently; enforcement is inactive"
	}
	writeJSON(w, status, body)
}

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":            "netcut",
		"version":         version.Version,
		"commit":          version.Commit,
		"built":           version.BuildTime,
		"demo":            s.cfg.DemoMode,
		"public_url":      s.cfg.PublicURL,
		"allow_signup":    s.cfg.AllowSignup,
		"scan_interval_s": int(s.cfg.ScanInterval.Seconds()),
	})
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	ip := clientIP(r, s.cfg.TrustedProxy)

	// Throttle per account and per source address so one noisy client cannot
	// brute force a single account or sweep many accounts from one host.
	for _, key := range []string{"email:" + req.Email, "ip:" + ip} {
		if !s.limiter.Allow(key) {
			s.log.Warn("login throttled", "key", key)
			writeErr(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
			return
		}
	}

	u, err := s.st.UserByEmail(r.Context(), req.Email)
	if err != nil || u == nil || !auth.CheckPassword(u.PasswordHash, req.Password) {
		for _, key := range []string{"email:" + req.Email, "ip:" + ip} {
			s.limiter.Fail(key)
		}
		_ = s.st.AddEvent(r.Context(), &model.Event{
			Type: "auth.login_failed", Severity: "warn", Actor: req.Email,
			Message: "failed sign-in attempt from " + ip,
		})
		// Identical response for unknown account and wrong password.
		writeErr(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	for _, key := range []string{"email:" + req.Email, "ip:" + ip} {
		s.limiter.Reset(key)
	}
	_ = s.st.TouchLogin(r.Context(), u.ID)

	token, exp, err := s.issuer.Issue(u)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not issue session")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.PublicURL != "" || r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
	})
	_ = s.st.AddEvent(r.Context(), &model.Event{
		Type: "auth.login", Severity: "info", Actor: u.Email,
		Message: "signed in from " + ip,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"user": u, "token": token, "expires_at": exp,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"user": user(r)})
}

type passwordReq struct {
	Current string `json:"current_password"`
	New     string `json:"new_password"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	u := user(r)
	var req passwordReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if !auth.CheckPassword(u.PasswordHash, req.Current) {
		writeErr(w, http.StatusForbidden, "current password is incorrect")
		return
	}
	hash, err := auth.HashPassword(req.New)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.st.UpdateUserPassword(r.Context(), u.ID, hash); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not update password")
		return
	}
	_ = s.st.AddEvent(r.Context(), &model.Event{
		Type: "auth.password_changed", Severity: "warn", Actor: u.Email,
		Message: "password changed",
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	st, err := s.st.Stats(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not compute stats")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"stats":  st,
		"health": s.fl.Health(),
	})
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.st.ListEvents(r.Context(), intQuery(r, "limit", 200), r.URL.Query().Get("mac"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not read events")
		return
	}
	if events == nil {
		events = []model.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

// ---------------------------------------------------------------- agent

func (s *Server) handleAgentHello(w http.ResponseWriter, r *http.Request) {
	var info model.AgentInfo
	if !decodeJSON(w, r, &info) {
		return
	}
	if info.AgentID == "" {
		writeErr(w, http.StatusBadRequest, "agent_id is required")
		return
	}
	if info.TS.IsZero() {
		info.TS = time.Now().UTC()
	}
	s.fl.SetAgent(info)
	s.log.Info("agent heartbeat", "agent", info.Name, "iface", info.Iface,
		"subnet", info.Subnet, "elevated", info.Elevated, "arp", info.CapAR)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "server_time": time.Now().UTC()})
}

func (s *Server) handleAgentReport(w http.ResponseWriter, r *http.Request) {
	var rep model.AgentReport
	if !decodeJSON(w, r, &rep) {
		return
	}
	if rep.AgentID == "" {
		writeErr(w, http.StatusBadRequest, "agent_id is required")
		return
	}
	if err := s.fl.Ingest(r.Context(), s.st, rep); err != nil {
		s.log.Warn("ingest failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "ingest failed")
		return
	}
	// Reconcile immediately so the agent's next poll sees fresh intent.
	if err := s.fl.Reconcile(r.Context(), s.st, s.hub); err != nil {
		s.log.Warn("reconcile after report failed", "err", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"directives": s.fl.Directives(),
	})
}

func (s *Server) handleAgentDirectives(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"directives": s.fl.Directives()})
}

// ---------------------------------------------------------------- agent tokens

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	toks, err := s.st.ListAgentTokens(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list agents")
		return
	}
	if toks == nil {
		toks = []model.AgentToken{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tokens":  toks,
		"runtime": nonNilAgents(s.fl.Agents()),
	})
}

type agentTokenReq struct {
	Name string `json:"name"`
}

func (s *Server) handleCreateAgentToken(w http.ResponseWriter, r *http.Request) {
	var req agentTokenReq
	if !decodeJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "agent"
	}
	secret, err := auth.RandHex(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate credential")
		return
	}
	id, err := auth.RandHex(8)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate id")
		return
	}
	if err := s.st.CreateAgentToken(r.Context(), id, name, auth.HashToken(secret)); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not store credential")
		return
	}
	_ = s.st.AddEvent(r.Context(), &model.Event{
		Type: "agent.token_created", Severity: "warn", Actor: user(r).Email,
		Message: "agent credential created: " + name,
	})
	// The secret is returned exactly once; only its digest is stored.
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "name": name, "token": secret})
}

func (s *Server) handleRevokeAgentToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.st.RevokeAgentToken(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "agent credential not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not revoke credential")
		return
	}
	_ = s.st.AddEvent(r.Context(), &model.Event{
		Type: "agent.token_revoked", Severity: "warn", Actor: user(r).Email,
		Message: "agent credential revoked: " + id,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
