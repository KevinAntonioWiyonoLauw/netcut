// language: Go, file: internal/router/huawei_ont_test.go
package router

import (
	"context"
	"encoding/base64"
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

// TestQuoteBareIdentifiers covers the JavaScript-literal to JSON rewrite. The
// payloads come from the router's own ASP endpoints and are eval()'d there, so
// keys are unquoted identifiers.
func TestQuoteBareIdentifiers(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			"unquoted keys",
			`[{No:"1",EthType:"Lan",Status:"Up"}]`,
			`[{"No":"1","EthType":"Lan","Status":"Up"}]`,
		},
		{
			// A colon inside a string value must survive untouched. A regex
			// over the whole payload corrupts this, which is why the rewrite
			// is a scanner.
			"colon inside a value",
			`[{MAC:"00:11:22:33:44:55",IP:"192.168.1.1"}]`,
			`[{"MAC":"00:11:22:33:44:55","IP":"192.168.1.1"}]`,
		},
		{
			"comma inside a value",
			`[{Note:"a,b",No:"2"}]`,
			`[{"Note":"a,b","No":"2"}]`,
		},
		{
			"negative and dash values",
			`[{rssi:"0",DuplexMode:"-",SpeedInfo:"0"}]`,
			`[{"rssi":"0","DuplexMode":"-","SpeedInfo":"0"}]`,
		},
		{
			"empty string value",
			`[{Freq:""}]`,
			`[{"Freq":""}]`,
		},
		{
			"real booleans and nulls stay unquoted",
			`[{up:true,off:false,none:null}]`,
			`[{"up":true,"off":false,"none":null}]`,
		},
		{
			"single-quoted values are normalised",
			`[{No:'1'}]`,
			`[{"No":"1"}]`,
		},
		{
			"nested objects",
			`[{a:{b:"c"}}]`,
			`[{"a":{"b":"c"}}]`,
		},
		{
			"numeric values stay numeric",
			`[{No:1,Level:2}]`,
			`[{"No":1,"Level":2}]`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := quoteBareIdentifiers(tc.in)
			if got != tc.want {
				t.Errorf("quoteBareIdentifiers(%s)\n got %s\nwant %s", tc.in, got, tc.want)
			}
			// The result must actually be valid JSON.
			var v any
			if err := json.Unmarshal([]byte(got), &v); err != nil {
				t.Errorf("result is not valid JSON: %v", err)
			}
		})
	}
}

// TestParseONTSTopoPayload uses the exact bytes the gateway returned.
func TestParseONTSTopoPayload(t *testing.T) {
	raw := `[{APInst:"17",DevType:"EG8145V5",Level:"1",AccessType:"2",` +
		`MAC:"00:11:22:33:44:55",LanMAC:"00:11:22:33:44:55",DuplexMode:"-",` +
		`SpeedInfo:"0",QereyDetailKey:"-",TX:"0",RX:"0",rssi:"0",` +
		`IP:"192.168.1.1",Freq:""}]` + "\r\r\n"

	recs, err := parseONTScript(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	// The MAC contains colons, which a naive rewrite would have mangled.
	if got := findString(r, "MAC"); got != "00:11:22:33:44:55" {
		t.Errorf("MAC = %q, want 00:11:22:33:44:55", got)
	}
	if got := findString(r, "APInst"); got != "17" {
		t.Errorf("APInst = %q, want 17", got)
	}
	if got := findString(r, "IP"); got != "192.168.1.1" {
		t.Errorf("IP = %q, want 192.168.1.1", got)
	}
	if got := findString(r, "DevType"); got != "EG8145V5" {
		t.Errorf("DevType = %q, want EG8145V5", got)
	}
	// The field the router uses to distinguish Wi-Fi from wired.
	if got := findString(r, "AccessType"); got != "2" {
		t.Errorf("AccessType = %q, want 2", got)
	}
}

// TestParseONTSEthPayload uses the exact bytes the gateway returned.
func TestParseONTSEthPayload(t *testing.T) {
	raw := `[{No:"1",EthType:"Lan",Enable:"1",Status:"Up",Speed:"1000",Duplex:"Full"},` +
		`{No:"2",EthType:"Lan",Enable:"1",Status:"Down",Speed:"0",Duplex:"--"},` +
		`{No:"3",EthType:"Lan",Enable:"1",Status:"Down",Speed:"0",Duplex:"--"},` +
		`{No:"4",EthType:"Lan",Enable:"1",Status:"Up",Speed:"100",Duplex:"Full"}]`

	recs, err := parseONTScript(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(recs) != 4 {
		t.Fatalf("got %d records, want 4", len(recs))
	}
	up := 0
	for _, r := range recs {
		if strings.EqualFold(findString(r, "Status"), "Up") {
			up++
		}
	}
	if up != 2 {
		t.Errorf("found %d ports up, want 2", up)
	}
	if got := portLabel(findString(recs[0], "No")); got != "LAN1" {
		t.Errorf("portLabel = %q, want LAN1", got)
	}
	if got := portRate(findString(recs[0], "Speed")); got != "1000 Mbps" {
		t.Errorf("portRate = %q, want 1000 Mbps", got)
	}
}

// TestONTRecoversFromAnInvalidatedSession is the failure seen in production.
//
// This firmware permits only one admin session at a time, so any other login —
// the operator opening the router's own web UI, or a diagnostic script —
// silently invalidates ours. Data requests then return the HTML login page with
// status 200. The client must notice, re-authenticate, and retry rather than
// staying broken until its cached session expires.
func TestONTRecoversFromAnInvalidatedSession(t *testing.T) {
	g := newFakeONT()
	srv := startONT(t, g)

	c := NewHuaweiONT(srv.URL, Config{User: g.user, Password: g.pass, Timeout: 5 * time.Second})
	ctx := context.Background()

	if err := c.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Clients(ctx); err != nil {
		t.Fatalf("first Clients: %v", err)
	}
	if len(c.Status().Ports) != 4 {
		t.Fatalf("expected 4 ports on the first read")
	}

	// Another client logs in, which kills our session.
	g.invalidateSession()

	// The client must recover on its own.
	clients, err := c.Clients(ctx)
	if err != nil {
		t.Fatalf("Clients did not recover from an invalidated session: %v", err)
	}
	_ = clients

	st := c.Status()
	if len(st.Ports) != 4 {
		t.Fatalf("after recovery got %d ports, want 4", len(st.Ports))
	}
	if st.Ports[0].Status != "Up" || st.Ports[0].Speed != "1000 Mbps" {
		t.Errorf("port 1 = %+v, want LAN1 Up 1000 Mbps", st.Ports[0])
	}
	if g.loginHits < 2 {
		t.Errorf("login was attempted %d times, want at least 2 (initial + recovery)",
			g.loginHits)
	}
}

// TestONTReportsAnExpiredSessionWhenReLoginFails: if recovery is impossible the
// error must say so, rather than looking like a malformed response.
func TestONTReportsAnExpiredSessionWhenReLoginFails(t *testing.T) {
	g := newFakeONT()
	srv := startONT(t, g)

	c := NewHuaweiONT(srv.URL, Config{User: g.user, Password: g.pass, Timeout: 5 * time.Second})
	ctx := context.Background()
	if err := c.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Clients(ctx); err != nil {
		t.Fatal(err)
	}

	// Kill the session and make re-login impossible too.
	g.invalidateSession()
	g.mu.Lock()
	g.failLogin = true
	g.mu.Unlock()

	_, err := c.Clients(ctx)
	if err == nil {
		t.Fatal("Clients succeeded against a dead session with failing credentials")
	}
	if !strings.Contains(err.Error(), "no longer valid") {
		t.Errorf("error does not identify the cause: %v", err)
	}
}

// TestLooksLikeLoginPage pins what an invalidated session looks like on the
// wire, since the status code is 200 in both cases.
func TestLooksLikeLoginPage(t *testing.T) {
	loginPages := []string{
		`<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"><html>...`,
		"<html><head><title>Waiting...</title></head></html>",
		`<script>var pageName = '/';</script>`,
		`<input id="txt_Password" type="password">`,
	}
	for _, p := range loginPages {
		if !looksLikeLoginPage([]byte(p)) {
			t.Errorf("looksLikeLoginPage(%q) = false, want true", p)
		}
	}

	data := []string{
		`[{APInst:"17",DevType:"EG8145V5"}]`,
		`[{No:"1",EthType:"Lan",Status:"Up"}]`,
		"",
	}
	for _, d := range data {
		if looksLikeLoginPage([]byte(d)) {
			t.Errorf("looksLikeLoginPage(%q) = true, want false", d)
		}
	}
}

// TestParseONTScriptRejectsGarbage covers the misleading error that started
// this investigation: a login page reported as "no array in response".
func TestParseONTScriptRejectsGarbage(t *testing.T) {
	for _, in := range []string{
		"",
		"<html><title>Waiting...</title></html>",
		`{"error":"0"}`, // an object, not an array
	} {
		if recs, err := parseONTScript(in); err == nil && len(recs) > 0 {
			t.Errorf("parseONTScript(%q) returned %d records, want an error or nothing",
				in, len(recs))
		}
	}
}

// TestParseONTSession pins the cookie format, including the anonymous case.
func TestParseONTSession(t *testing.T) {
	cases := []struct {
		cookie    string
		wantSID   bool
		wantLevel int
	}{
		{"Cookie=sid=5f3a91c2e07b48d6a1f0c93e7d2b845a6c1e09f3b7d248a5c6e1f09b3d7a2c48:Language:english:id=1;path=/", true, 1},
		{"Cookie=sid=abc123:Language:english:id=-1;path=/", true, -1},
		{"Cookie=sid=abc123:Language:english:id=0;path=/", true, 0},
		{"", false, -1},
	}
	for _, tc := range cases {
		sid, level := parseONTSession(tc.cookie)
		if (sid != "") != tc.wantSID {
			t.Errorf("parseONTSession(%q) sid = %q, want present=%v", tc.cookie, sid, tc.wantSID)
		}
		if level != tc.wantLevel {
			t.Errorf("parseONTSession(%q) level = %d, want %d", tc.cookie, level, tc.wantLevel)
		}
	}
}

func TestPortLabel(t *testing.T) {
	cases := map[string]string{
		"1": "LAN1", "2": "LAN2", "4": "LAN4", "LAN1": "LAN1", "": "",
	}
	for in, want := range cases {
		if got := portLabel(in); got != want {
			t.Errorf("portLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPortRate(t *testing.T) {
	cases := map[string]string{
		"1000": "1000 Mbps", "100": "100 Mbps", "0": "", "": "", "--": "-- Mbps",
	}
	for in, want := range cases {
		if got := portRate(in); got != want {
			t.Errorf("portRate(%q) = %q, want %q", in, got, want)
		}
	}
}

// ------------------------------------------------------------------ fixtures

// fakeONT is a stand-in for the gateway: the ASP login flow, the token endpoint
// with its BOM, and the topology and port endpoints.
type fakeONT struct {
	mu sync.Mutex

	user, pass string
	sessions   map[string]bool
	topo       string
	eth        string
	stations   string
	failLogin  bool
	loginHits  int
	token      string
	// singleSession reproduces the real firmware's behaviour of allowing only
	// one admin session at a time: a new login invalidates the previous one.
	singleSession bool
	currentSID    string
	// unauth makes every data endpoint answer with the login page, which is
	// what an invalidated session looks like.
	unauth bool
}

func newFakeONT() *fakeONT {
	return &fakeONT{
		user: "admin", pass: "router-s3cret",
		sessions: map[string]bool{},
		token:    "398fafaa55e1193d5c35a1f8",
		topo: `[{APInst:"17",DevType:"EG8145V5",Level:"1",AccessType:"2",` +
			`MAC:"00:11:22:33:44:55",LanMAC:"00:11:22:33:44:55",DuplexMode:"-",` +
			`SpeedInfo:"0",QereyDetailKey:"-",TX:"0",RX:"0",rssi:"0",` +
			`IP:"192.168.1.1",Freq:""}]`,
		eth: `[{No:"1",EthType:"Lan",Enable:"1",Status:"Up",Speed:"1000",Duplex:"Full"},` +
			`{No:"2",EthType:"Lan",Enable:"1",Status:"Down",Speed:"0",Duplex:"--"},` +
			`{No:"3",EthType:"Lan",Enable:"1",Status:"Down",Speed:"0",Duplex:"--"},` +
			`{No:"4",EthType:"Lan",Enable:"1",Status:"Up",Speed:"100",Duplex:"Full"}]`,
	}
}

// invalidateSession simulates another client logging in, which on the real
// firmware kills the session this client holds.
func (g *fakeONT) invalidateSession() {
	g.mu.Lock()
	g.currentSID = ""
	g.unauth = true
	g.mu.Unlock()
}

func (g *fakeONT) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Waiting...</title></head><body></body></html>`)
	})

	// The token carries a UTF-8 BOM, exactly as the real gateway sends it.
	mux.HandleFunc("/asp/GetRandCount.asp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "\ufeff%s", g.token)
	})

	mux.HandleFunc("/login.cgi", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.loginHits++
		g.mu.Unlock()
		_ = r.ParseForm()

		// The real endpoint requires the Cookie header to be present.
		if !strings.Contains(r.Header.Get("Cookie"), "Language") {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>Waiting...</title></html>`)
			return
		}

		pw, _ := base64.StdEncoding.DecodeString(r.FormValue("PassWord"))
		if g.failLogin || r.FormValue("UserName") != g.user || string(pw) != g.pass {
			// Rejected: an anonymous session.
			w.Header().Set("Set-Cookie", "Cookie=sid=deadbeef:Language:english:id=-1;path=/")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>Waiting...</title></html>`)
			return
		}
		// The token must have arrived without its BOM.
		if r.FormValue("x.X_HW_Token") != g.token {
			w.Header().Set("Set-Cookie", "Cookie=sid=deadbeef:Language:english:id=-1;path=/")
			fmt.Fprint(w, `<html><title>Waiting...</title></html>`)
			return
		}

		sid := "5f3a91c2e07b48d6a1f0c93e7d2b845a6c1e09f3b7d248a5c6e1f09b3d7a2c48"
		g.mu.Lock()
		g.sessions[sid] = true
		g.currentSID = sid
		// A single-session gateway drops whatever session existed before.
		g.unauth = false
		g.mu.Unlock()
		w.Header().Set("Set-Cookie",
			"Cookie=sid="+sid+":Language:english:id=1;path=/")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>Waiting...</title></html>`)
	})

	// authed answers with data when the session is valid, and with the login
	// page when it is not — exactly as the real firmware does.
	authed := func(h func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			g.mu.Lock()
			dead := g.unauth
			current := g.currentSID
			g.mu.Unlock()

			c := r.Header.Get("Cookie")
			if dead || current == "" || !strings.Contains(c, current) ||
				strings.Contains(c, "id=-1") {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, `<html><head><title>Waiting...</title></head>`+
					`<script>var pageName = '/';</script></html>`)
				return
			}
			h(w, r)
		}
	}

	mux.HandleFunc("/html/amp/wificoverinfo/getTopoInfo.asp", authed(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, g.topo)
	}))
	mux.HandleFunc("/html/amp/wificoverinfo/getEthInfo.asp", authed(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("APInst") != "17" {
			return // the real endpoint returns an empty body for a wrong handle
		}
		fmt.Fprint(w, g.eth)
	}))
	mux.HandleFunc("/html/amp/wificoverinfo/apssidStation.asp", authed(func(w http.ResponseWriter, r *http.Request) {
		if g.stations != "" {
			fmt.Fprint(w, g.stations)
			return
		}
		// The real empty response.
		fmt.Fprint(w, "var stApSta = new Array(null);\r\nvar staMac = 0;\r\n")
	}))

	return mux
}

func startONT(t *testing.T, g *fakeONT) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(g.handler())
	t.Cleanup(srv.Close)
	return srv
}

// TestONTRLoginAndPorts is the end-to-end path against the fake gateway.
func TestONTRLoginAndPorts(t *testing.T) {
	g := newFakeONT()
	srv := startONT(t, g)

	c := NewHuaweiONT(srv.URL, Config{User: g.user, Password: g.pass, Timeout: 5 * time.Second})
	ctx := context.Background()

	if err := c.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}
	// Clients learns the APInst from the topology, then reads the ports.
	if _, err := c.Clients(ctx); err != nil {
		t.Fatalf("Clients: %v", err)
	}

	st := c.Status()
	if st.APInst != "17" {
		t.Errorf("APInst = %q, want 17", st.APInst)
	}
	if len(st.Ports) != 4 {
		t.Fatalf("got %d ports, want 4", len(st.Ports))
	}
	if st.Ports[0].No != "LAN1" || st.Ports[0].Status != "Up" || st.Ports[0].Speed != "1000 Mbps" {
		t.Errorf("port 1 = %+v, want LAN1 Up 1000 Mbps", st.Ports[0])
	}
	if st.Ports[1].No != "LAN2" || st.Ports[1].Status != "Down" {
		t.Errorf("port 2 = %+v, want LAN2 Down", st.Ports[1])
	}
	// Two ports are up in this fixture, so no port may be attributed to a
	// device: the gateway does not say which device is on which.
	if st.SolePort.Kind != "" {
		t.Errorf("SolePort = %+v, want empty when two ports are up", st.SolePort)
	}
}

// TestONTSolePortIsUsedWhenUnambiguous: with exactly one port up, every wired
// device is on it, which is a sound deduction.
func TestONTSolePortIsUsedWhenUnambiguous(t *testing.T) {
	g := newFakeONT()
	g.eth = `[{No:"1",EthType:"Lan",Enable:"1",Status:"Up",Speed:"1000",Duplex:"Full"},` +
		`{No:"2",EthType:"Lan",Enable:"1",Status:"Down",Speed:"0",Duplex:"--"}]`
	srv := startONT(t, g)

	c := NewHuaweiONT(srv.URL, Config{User: g.user, Password: g.pass, Timeout: 5 * time.Second})
	ctx := context.Background()
	if err := c.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Clients(ctx); err != nil {
		t.Fatal(err)
	}
	st := c.Status()
	if st.SolePort.Kind != model.LinkLAN {
		t.Fatalf("SolePort = %+v, want a LAN connection", st.SolePort)
	}
	if st.SolePort.Port != "LAN1" {
		t.Errorf("SolePort.Port = %q, want LAN1", st.SolePort.Port)
	}
	if st.SolePort.Rate != "1000 Mbps" {
		t.Errorf("SolePort.Rate = %q, want 1000 Mbps", st.SolePort.Rate)
	}
}

// TestONTWirelessStations covers a model that does report associated stations.
func TestONTWirelessStations(t *testing.T) {
	g := newFakeONT()
	g.stations = `var stApSta = new Array();` +
		`stApSta[0] = new Object();` +
		`stApSta[0].staMac = "AA-BB-CC-DD-EE-01";` +
		`stApSta[0].staRssi = "-58";` +
		`stApSta[0].staTxRate = "72";` +
		`stApSta[0].ssid = "HomeNet-2.4G";`
	srv := startONT(t, g)

	c := NewHuaweiONT(srv.URL, Config{User: g.user, Password: g.pass, Timeout: 5 * time.Second})
	ctx := context.Background()
	if err := c.Login(ctx); err != nil {
		t.Fatal(err)
	}
	clients, err := c.Clients(ctx)
	if err != nil {
		t.Fatalf("Clients: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("got %d clients, want 1: %+v", len(clients), clients)
	}
	wl, ok := clients["aa:bb:cc:dd:ee:01"]
	if !ok {
		t.Fatalf("dash-form MAC was not normalised: %+v", clients)
	}
	if wl.Kind != model.LinkWLAN {
		t.Errorf("kind = %q, want wlan", wl.Kind)
	}
	if wl.Signal != "-58 dBm" {
		t.Errorf("signal = %q, want -58 dBm", wl.Signal)
	}
	if wl.Detail != "HomeNet-2.4G" {
		t.Errorf("ssid = %q, want HomeNet-2.4G", wl.Detail)
	}
}

// TestONTRejectsBadCredentials: an anonymous session must be reported as a
// rejection, not as a success.
func TestONTRejectsBadCredentials(t *testing.T) {
	g := newFakeONT()
	srv := startONT(t, g)

	c := NewHuaweiONT(srv.URL, Config{User: g.user, Password: "wrong", Timeout: 5 * time.Second})
	err := c.Login(context.Background())
	if err == nil {
		t.Fatal("Login succeeded with a wrong password")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// TestONTStripsTheTokenBOM is the bug that made the first live attempt fail: the
// token endpoint prefixes its response with a UTF-8 BOM, and sending it as part
// of the value makes the token invalid.
func TestONTStripsTheTokenBOM(t *testing.T) {
	g := newFakeONT()
	g.token = "abc123def456"
	srv := startONT(t, g)

	c := NewHuaweiONT(srv.URL, Config{User: g.user, Password: g.pass, Timeout: 5 * time.Second})
	// The fixture rejects any token that does not match exactly, so a BOM left
	// in place would fail here.
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login with a BOM-prefixed token failed: %v", err)
	}
}

func TestONTReusesSession(t *testing.T) {
	g := newFakeONT()
	srv := startONT(t, g)
	c := NewHuaweiONT(srv.URL, Config{User: g.user, Password: g.pass, Timeout: 5 * time.Second})
	ctx := context.Background()

	if err := c.Login(ctx); err != nil {
		t.Fatal(err)
	}
	first := g.loginHits
	if err := c.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if g.loginHits != first {
		t.Errorf("Login re-authenticated (%d -> %d); the session should be reused",
			first, g.loginHits)
	}
}

func TestONTBackendIsSelectable(t *testing.T) {
	for _, name := range []string{"huawei-ont", "ont", "eg8145", "HUAWEI-ONT"} {
		c, err := newClient(Config{Backend: name, Host: "192.168.1.1"})
		if err != nil {
			t.Errorf("backend %q was not accepted: %v", name, err)
			continue
		}
		if c.Name() != "huawei-ont" {
			t.Errorf("backend %q resolved to %q", name, c.Name())
		}
	}
}

// TestAutoPrefersONT: the ONT backend must be tried before the JSON one, since
// these gateways answer unknown paths with an HTML login page.
func TestAutoPrefersONT(t *testing.T) {
	a := NewAuto("http://192.168.1.1", Config{User: "u", Password: "p"})
	cands := a.candidates()
	if len(cands) == 0 {
		t.Fatal("no candidates")
	}
	if cands[0].Name() != "huawei-ont" {
		t.Errorf("first candidate is %q, want huawei-ont", cands[0].Name())
	}
}
