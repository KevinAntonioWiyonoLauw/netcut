// language: Go, file: internal/router/huawei_test.go
package router

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
)

// fakeGateway is a stand-in for a Huawei home gateway, with the behaviour that
// makes these APIs awkward: a session cookie, a login that must come first, and
// a host list only served to an authenticated session.
type fakeGateway struct {
	mu          sync.Mutex
	user, pass  string
	sessions    map[string]bool
	hostList    string // JSON body for the host-list endpoint
	hostPath    string // the path that serves hostList
	loginPath   string
	requireChal bool // ask for a salted response instead of the plain password
	challenge   string
	failLogin   bool
	loginHits   int
}

func newFakeGateway() *fakeGateway {
	return &fakeGateway{
		user:      "admin",
		pass:      "secret123",
		sessions:  map[string]bool{},
		hostPath:  "/api/wlan/host-list",
		loginPath: "/api/system/user_login",
		challenge: "abc123challenge",
	}
}

func (g *fakeGateway) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Anything unknown behaves like the real gateway: an HTML redirect.
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Waiting...</title></head><body></body></html>`)
	})

	mux.HandleFunc("/api/system/user_login_secret", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "0", "challenge": g.challenge,
		})
	})

	mux.HandleFunc(g.loginPath, func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.loginHits++
		g.mu.Unlock()

		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)

		if g.failLogin || body["username"] != g.user {
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "1"})
			return
		}
		if g.requireChal {
			// Only accept the salted form.
			if body["password"] == g.pass {
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "challenge_required"})
				return
			}
		} else if body["password"] != g.pass {
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "1"})
			return
		}

		sid := "session-token-xyz"
		g.mu.Lock()
		g.sessions[sid] = true
		g.mu.Unlock()
		// Real firmware sets a cookie on some models and only returns the id
		// in the body on others. This fixture does both, so either path works.
		payload := map[string]any{"error": "0", "sysauth": sid}
		buf, _ := json.Marshal(payload)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "SessionID="+sid+"; Path=/")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf)
	})

	mux.HandleFunc(g.hostPath, func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("SessionID")
		if err != nil || c.Value == "" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>Waiting...</title></html>`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, g.hostList)
	})

	return mux
}

func startGateway(t *testing.T, g *fakeGateway) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(g.handler())
	t.Cleanup(srv.Close)
	return srv
}

func huaweiClient(t *testing.T, srv *httptest.Server, g *fakeGateway) *Huawei {
	t.Helper()
	h := NewHuawei(srv.URL, Config{
		User: g.user, Password: g.pass, Timeout: 5 * time.Second,
	})
	return h
}

// TestHuaweiEndToEnd is the full path: authenticate with a session cookie, then
// read the host list and classify each client.
func TestHuaweiEndToEnd(t *testing.T) {
	g := newFakeGateway()
	g.hostList = `{"hosts":[
		{"mac":"aa:bb:cc:dd:ee:01","ip":"192.168.1.24","interfaceType":"WLAN",
		 "ssid":"HomeNet-2.4G","band":"2.4G","rate":"72Mbps","rssi":"-58"},
		{"mac":"aa:bb:cc:dd:ee:02","ip":"192.168.1.66","interfaceType":"LAN","port":"LAN1"},
		{"mac":"aa:bb:cc:dd:ee:03","ip":"192.168.1.87","interfaceType":"LAN","port":"LAN2"}
	]}`
	srv := startGateway(t, g)
	h := huaweiClient(t, srv, g)

	ctx := context.Background()
	if err := h.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}
	clients, err := h.Clients(ctx)
	if err != nil {
		t.Fatalf("Clients: %v", err)
	}
	if len(clients) != 3 {
		t.Fatalf("got %d clients, want 3", len(clients))
	}

	wireless := clients["aa:bb:cc:dd:ee:01"]
	if wireless.Kind != model.LinkWLAN {
		t.Errorf("client 1 kind = %q, want wlan", wireless.Kind)
	}
	if wireless.Detail != "HomeNet-2.4G" {
		t.Errorf("client 1 ssid = %q, want HomeNet-2.4G", wireless.Detail)
	}
	if wireless.Band != "2.4G" {
		t.Errorf("client 1 band = %q, want 2.4G", wireless.Band)
	}

	wired1 := clients["aa:bb:cc:dd:ee:02"]
	if wired1.Kind != model.LinkLAN || wired1.Port != "LAN1" {
		t.Errorf("client 2 = %+v, want lan on LAN1", wired1)
	}
	wired2 := clients["aa:bb:cc:dd:ee:03"]
	if wired2.Kind != model.LinkLAN || wired2.Port != "LAN2" {
		t.Errorf("client 3 = %+v, want lan on LAN2", wired2)
	}

	// The endpoint that worked is remembered, so the next poll skips probing.
	if h.WorkingPath() != g.hostPath {
		t.Errorf("WorkingPath = %q, want %q", h.WorkingPath(), g.hostPath)
	}
}

// TestHuaweiUnauthenticatedIsRejected: without a session the gateway serves its
// login page, which must surface as an error rather than as "no devices".
func TestHuaweiUnauthenticatedIsRejected(t *testing.T) {
	g := newFakeGateway()
	g.hostList = `{"hosts":[{"mac":"aa:bb:cc:dd:ee:01"}]}`
	srv := startGateway(t, g)

	h := NewHuawei(srv.URL, Config{User: g.user, Password: g.pass, Timeout: 5 * time.Second})
	// Deliberately skip Login.
	if _, err := h.Clients(context.Background()); err == nil {
		t.Fatal("Clients succeeded without authenticating")
	}
}

func TestHuaweiWrongCredentials(t *testing.T) {
	g := newFakeGateway()
	g.hostList = `{"hosts":[{"mac":"aa:bb:cc:dd:ee:01"}]}`
	srv := startGateway(t, g)

	h := NewHuawei(srv.URL, Config{User: "admin", Password: "wrong", Timeout: 5 * time.Second})
	err := h.Login(context.Background())
	if err == nil {
		t.Fatal("Login succeeded with a wrong password")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Errorf("error does not explain the rejection: %v", err)
	}
}

// TestHuaweiChallengeLogin covers firmware that refuses the plain password and
// requires a salted response.
func TestHuaweiChallengeLogin(t *testing.T) {
	g := newFakeGateway()
	g.requireChal = true
	g.hostList = `{"hosts":[{"mac":"aa:bb:cc:dd:ee:01","interfaceType":"WLAN","ssid":"Home"}]}`
	srv := startGateway(t, g)

	h := huaweiClient(t, srv, g)
	ctx := context.Background()
	if err := h.Login(ctx); err != nil {
		t.Fatalf("challenge login failed: %v", err)
	}
	clients, err := h.Clients(ctx)
	if err != nil {
		t.Fatalf("Clients: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("got %d clients, want 1", len(clients))
	}
	if g.loginHits < 2 {
		t.Errorf("login was attempted %d times, want at least 2 (plain, then salted)", g.loginHits)
	}
}

// TestHuaweiProbesAlternateEndpoints: the host list lives at different paths on
// different models, so the client must keep looking.
func TestHuaweiProbesAlternateEndpoints(t *testing.T) {
	g := newFakeGateway()
	g.hostPath = "/api/lan/HostInfo" // not the first candidate
	g.hostList = `{"hosts":[{"mac":"aa:bb:cc:dd:ee:01","interfaceType":"LAN","port":"LAN4"}]}`
	srv := startGateway(t, g)

	h := huaweiClient(t, srv, g)
	ctx := context.Background()
	if err := h.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}
	clients, err := h.Clients(ctx)
	if err != nil {
		t.Fatalf("Clients: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("got %d clients, want 1", len(clients))
	}
	if clients["aa:bb:cc:dd:ee:01"].Port != "LAN4" {
		t.Errorf("port = %q, want LAN4", clients["aa:bb:cc:dd:ee:01"].Port)
	}
}

// TestHuaweiReusesSession: a second call must not re-authenticate.
func TestHuaweiReusesSession(t *testing.T) {
	g := newFakeGateway()
	g.hostList = `{"hosts":[{"mac":"aa:bb:cc:dd:ee:01"}]}`
	srv := startGateway(t, g)
	h := huaweiClient(t, srv, g)
	ctx := context.Background()

	if err := h.Login(ctx); err != nil {
		t.Fatal(err)
	}
	first := g.loginHits
	if err := h.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if g.loginHits != first {
		t.Errorf("Login re-authenticated (%d -> %d); the session should be reused", first, g.loginHits)
	}
}

// TestHuaweiSessionFromBodyOnly covers firmware that returns the session id in
// the response body and sets no usable cookie. Without applying the body
// session, every host-list call would come back as the login page.
func TestHuaweiSessionFromBodyOnly(t *testing.T) {
	// A gateway that accepts a session only via the SessionID cookie, and
	// returns that id in the body rather than as Set-Cookie.
	var (
		mu       sync.Mutex
		sessions = map[string]bool{}
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>Waiting...</title></html>`)
	})
	mux.HandleFunc("/api/system/user_login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["username"] != "admin" || body["password"] != "secret123" {
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "1"})
			return
		}
		sid := "body-only-session"
		mu.Lock()
		sessions[sid] = true
		mu.Unlock()
		// Deliberately no Set-Cookie.
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "0", "sysauth": sid})
	})
	mux.HandleFunc("/api/wlan/host-list", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("SessionID")
		if err != nil {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>Waiting...</title></html>`)
			return
		}
		mu.Lock()
		ok := sessions[c.Value]
		mu.Unlock()
		if !ok {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>Waiting...</title></html>`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"hosts":[{"mac":"aa:bb:cc:dd:ee:01","interfaceType":"WLAN","ssid":"BodySess"}]}`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	h := NewHuawei(srv.URL, Config{User: "admin", Password: "secret123", Timeout: 5 * time.Second})
	ctx := context.Background()
	if err := h.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}
	clients, err := h.Clients(ctx)
	if err != nil {
		t.Fatalf("Clients: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("got %d clients, want 1", len(clients))
	}
	if c := clients["aa:bb:cc:dd:ee:01"]; c.Kind != model.LinkWLAN || c.Detail != "BodySess" {
		t.Errorf("connection = %+v, want wlan on BodySess", c)
	}
}

// TestHuaweiNoClientsIsAnError: a response with no device records must be
// reported, so the caller can tell "nothing associated" from "polling broken".
func TestHuaweiNoClientsIsAnError(t *testing.T) {
	g := newFakeGateway()
	g.hostList = `{"error":"0","total":0}`
	srv := startGateway(t, g)
	h := huaweiClient(t, srv, g)
	ctx := context.Background()

	if err := h.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Clients(ctx); err == nil {
		t.Fatal("Clients succeeded on a payload containing no devices")
	}
}

// TestPollerWritesConnections exercises the poller against the fake gateway and
// a recording sink, which is the contract the store depends on.
func TestPollerWritesConnections(t *testing.T) {
	g := newFakeGateway()
	g.hostList = `{"hosts":[
		{"mac":"AA-BB-CC-DD-EE-01","interfaceType":"WLAN","ssid":"HomeNet-5G","band":"5G"},
		{"mac":"aa:bb:cc:dd:ee:02","interfaceType":"LAN","port":"LAN1"}
	]}`
	srv := startGateway(t, g)

	sink := &recordingSink{got: map[string]model.Connection{}}
	p, err := New(Config{
		Backend: "huawei", Host: srv.URL,
		User: g.user, Password: g.pass,
		Interval: time.Hour, Timeout: 5 * time.Second,
	}, sink, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p.pollOnce(ctx)

	if len(sink.got) != 2 {
		t.Fatalf("sink received %d connections, want 2: %+v", len(sink.got), sink.got)
	}
	// Keys must be normalised, so a dash-form MAC from the router matches the
	// colon-form MAC the agent reported.
	wl, ok := sink.got["aa:bb:cc:dd:ee:01"]
	if !ok {
		t.Fatalf("dash-form MAC was not normalised: %+v", sink.got)
	}
	if wl.Kind != model.LinkWLAN || wl.Detail != "HomeNet-5G" {
		t.Errorf("wireless connection = %+v, want wlan on HomeNet-5G", wl)
	}

	st := p.Status()
	if !st.Configured || st.LastError != "" || st.Clients != 2 {
		t.Errorf("status = %+v, want a clean successful poll", st)
	}
}

// TestPollerRecordsFailureWithoutStopping: a broken router must not crash or
// block anything, only be recorded.
func TestPollerRecordsFailureWithoutStopping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	sink := &recordingSink{got: map[string]model.Connection{}}
	p, err := New(Config{
		Backend: "huawei", Host: srv.URL,
		User: "admin", Password: "x", Interval: time.Hour, Timeout: 2 * time.Second,
	}, sink, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	p.pollOnce(context.Background())
	p.pollOnce(context.Background())

	st := p.Status()
	if st.LastError == "" {
		t.Error("a failing poll recorded no error")
	}
	if st.Failures != 2 {
		t.Errorf("Failures = %d, want 2", st.Failures)
	}
	if len(sink.got) != 0 {
		t.Errorf("sink received %d entries from a failing router", len(sink.got))
	}
}

// TestNewDisabledWhenUnconfigured: with no router, construction reports
// ErrNotConfigured so the caller can treat it as normal.
func TestNewDisabledWhenUnconfigured(t *testing.T) {
	if _, err := New(Config{Backend: "none"}, &recordingSink{}, nil); err != ErrNotConfigured {
		t.Errorf("err = %v, want ErrNotConfigured", err)
	}
	if _, err := New(Config{Backend: "auto", Host: ""}, &recordingSink{}, nil); err != ErrNotConfigured {
		t.Errorf("err = %v, want ErrNotConfigured", err)
	}
}

func TestNewRejectsUnknownBackend(t *testing.T) {
	_, err := New(Config{Backend: "mystery", Host: "192.168.1.1"}, &recordingSink{}, nil)
	if err == nil {
		t.Fatal("an unknown backend was accepted")
	}
	if !strings.Contains(err.Error(), "unknown router backend") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// recordingSink captures what the poller writes.
type recordingSink struct {
	mu  sync.Mutex
	got map[string]model.Connection
}

func (s *recordingSink) SetDeviceConnection(_ context.Context, mac string, c model.Connection) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.got == nil {
		s.got = map[string]model.Connection{}
	}
	s.got[normMAC(mac)] = c
	return nil
}
