// language: Go, file: internal/router/huawei_ont.go
//
// Huawei ONT backend (EG8145V5 and its siblings).
//
// These gateways are a different product line from the Huawei home gateways the
// other backend targets: the host list is not a JSON API under /api/..., but a
// set of legacy ASP pages behind a session-cookie login. This backend
// implements that flow.
//
// Login, derived from the firmware's own login script:
//
//	POST /asp/GetRandCount.asp   -> an anti-replay token (prefixed with a BOM)
//	POST /login.cgi              -> sets the session cookie
//	     UserName, PassWord (base64), Language, x.X_HW_Token=<token>
//	     with a Cookie header of "body=Language:english:id=-1"
//	the response's Set-Cookie carries the session as
//	     Cookie=sid=<id>:Language:<lang>:id=<account>
//	where id=-1 means anonymous and any higher value means authenticated.
//
// What these gateways will and will not tell you, measured on an EG8145V5:
//
//	getTopoInfo.asp  reports the gateway node itself, including its AccessType
//	                 and its APInst, which is the handle the port call needs
//	getEthInfo.asp   reports each physical port's status and negotiated speed
//	                 for a given APInst
//	apssidStation    reports associated Wi-Fi stations, but only for a
//	                 Wi-Fi-capable model and only when stations are associated
//
// There is no per-device client table on this firmware, so a device cannot be
// mapped to a port. What is reported here is therefore honest:
//
//   - when exactly one physical port is up, every wired device is on that port,
//     which is a sound deduction rather than a guess
//   - when more than one port is up, no port is claimed, because the gateway
//     does not say which device is on which
//
// Nothing in this file changes router configuration.
package router

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
)

// HuaweiONT is the legacy-ASP Huawei ONT client.
type HuaweiONT struct {
	hc *httpClient

	mu      sync.Mutex
	sid     string
	loginAt time.Time
	// apInst is the gateway's own handle, learned from getTopoInfo.
	apInst string
	// ports is the last port state read, kept for the dashboard.
	ports []ethPort
	// solePort is set when exactly one physical port is up.
	solePort model.Connection
}

// NewHuaweiONT builds the ONT backend.
func NewHuaweiONT(base string, cfg Config) *HuaweiONT {
	hc, err := newHTTPClient(base, cfg)
	if err != nil {
		hc = &httpClient{base: base, cfg: cfg}
	}
	return &HuaweiONT{hc: hc}
}

// Name identifies the backend.
func (h *HuaweiONT) Name() string { return "huawei-ont" }

// Host returns the gateway address.
func (h *HuaweiONT) Host() string { return h.hc.base }

// Login performs the ASP flow and stores the session.
func (h *HuaweiONT) Login(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sid != "" && time.Since(h.loginAt) < 20*time.Minute {
		return nil
	}

	// The token endpoint answers with a UTF-8 BOM in front of the token. Sent
	// verbatim it makes the token invalid, so it must be stripped.
	raw, err := h.hc.getRaw(ctx, "/asp/GetRandCount.asp")
	if err != nil {
		return fmt.Errorf("huawei-ont: could not get a login token: %w", err)
	}
	token := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(raw)), "\ufeff"))
	if token == "" || len(token) > 200 {
		return fmt.Errorf("huawei-ont: login token looks wrong (%d bytes)", len(token))
	}

	// The login endpoint reads its language and account state from the Cookie
	// header rather than the form, so it has to be set explicitly.
	form := url.Values{
		"UserName":     {h.hc.cfg.User},
		"PassWord":     {base64.StdEncoding.EncodeToString([]byte(h.hc.cfg.Password))},
		"Language":     {"english"},
		"x.X_HW_Token": {token},
	}
	status, header, body, err := h.hc.postFormRaw(ctx, "/login.cgi", form,
		"body=Language:english:id=-1")
	if err != nil {
		return fmt.Errorf("huawei-ont: login request failed: %w", err)
	}
	if status >= 400 {
		return fmt.Errorf("huawei-ont: login returned %d", status)
	}

	// Authentication is carried in the session cookie. The trailing id is the
	// account: -1 is anonymous, anything else is a real session.
	sc := header.Get("Set-Cookie")
	if sc == "" {
		sc = header.Get("Set-Cookie2")
	}
	sid, level := parseONTSession(sc)
	if sid == "" {
		if strings.Contains(strings.ToLower(string(body)), "too many retrials") {
			return fmt.Errorf("%w (too many failed attempts; wait a few minutes)",
				errRejected)
		}
		return fmt.Errorf("huawei-ont: %w (no session issued)", errRejected)
	}
	if level < 0 {
		return fmt.Errorf("huawei-ont: %w (anonymous session)", errRejected)
	}

	h.sid = sid
	h.loginAt = time.Now()
	// Make the session explicit for subsequent calls.
	h.hc.cookieOverride = fmt.Sprintf("Cookie=sid=%s:Language:english:id=%d", sid, level)
	return nil
}

// sessionCookieRe extracts the session id and account id from the cookie value
// "Cookie=sid=<hex>:Language:<lang>:id=<n>".
var sessionCookieRe = regexp.MustCompile(`sid=([0-9a-fA-F]+)`)
var sessionLevelRe = regexp.MustCompile(`:id=(-?\d+)`)

func parseONTSession(setCookie string) (sid string, level int) {
	level = -1
	if m := sessionCookieRe.FindStringSubmatch(setCookie); m != nil {
		sid = m[1]
	}
	if m := sessionLevelRe.FindStringSubmatch(setCookie); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			level = n
		}
	}
	return sid, level
}

// ontscript is a JavaScript object literal, as returned by the ASP endpoints.
// They are not strict JSON: keys are unquoted identifiers.
type ontscript string

// parseONTScript converts an ASP response into a list of records.
//
// The payloads are JavaScript array literals evaluated with eval() in the
// router's own UI, so keys are unquoted. The response is rewritten as JSON and
// decoded, which keeps the field values exactly as the router sent them.
func parseONTScript(raw string) ([]map[string]any, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, nil
	}
	// Isolate the array.
	start := strings.Index(s, "[")
	end := strings.LastIndex(s, "]")
	if start < 0 || end <= start {
		return nil, errors.New("no array in response")
	}
	s = quoteBareIdentifiers(s[start : end+1])

	var out []map[string]any
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// quoteBareIdentifiers rewrites a JavaScript literal as JSON.
//
// A token outside a string is a key when a colon follows it, and a value
// otherwise. Everything inside a string literal is copied through unchanged, so
// a value containing a colon or a comma cannot be corrupted — which is exactly
// what a regex over the whole payload would get wrong.
func quoteBareIdentifiers(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 32)

	i := 0
	for i < len(s) {
		c := s[i]

		if c == '"' || c == '\'' {
			// Copy the string literal, normalising it to a JSON string.
			q := c
			j := i + 1
			for j < len(s) {
				if s[j] == '\\' {
					j += 2
					continue
				}
				if s[j] == q {
					break
				}
				j++
			}
			end := j
			if end > len(s) {
				end = len(s)
			}
			inner := s[i+1 : end]
			// JSON has no \xNN escape; some payloads use it.
			inner = hexEscapeRe.ReplaceAllString(inner, `\u00$1`)
			b.WriteByte('"')
			b.WriteString(strings.ReplaceAll(inner, `"`, `\"`))
			b.WriteByte('"')
			i = end + 1
			continue
		}

		if isIdentStart(c) {
			j := i
			for j < len(s) && isIdentPart(s[j]) {
				j++
			}
			word := s[i:j]

			// A token followed by a colon is a key.
			k := j
			for k < len(s) && (s[k] == ' ' || s[k] == '	' || s[k] == '\n' || s[k] == '\r') {
				k++
			}
			isKey := k < len(s) && s[k] == ':'

			if isKey || !isJSONLiteral(word) {
				b.WriteByte('"')
				b.WriteString(word)
				b.WriteByte('"')
			} else {
				b.WriteString(word)
			}
			i = j
			continue
		}

		b.WriteByte(c)
		i++
	}
	return b.String()
}

// hexEscapeRe matches a \xNN escape, which JSON does not support.
var hexEscapeRe = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

// isJSONLiteral reports whether a bare token is a JSON literal that must stay
// unquoted.
func isJSONLiteral(w string) bool {
	switch w {
	case "true", "false", "null":
		return true
	}
	return false
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

// ethPort is one physical port as getEthInfo reports it.
type ethPort struct {
	No     string
	Type   string
	Status string
	Speed  string
	Duplex string
}

// getTopo returns the gateway node and records its APInst.
func (h *HuaweiONT) getTopo(ctx context.Context) ([]map[string]any, error) {
	status, _, body, err := h.hc.postFormRaw(ctx, "/html/amp/wificoverinfo/getTopoInfo.asp",
		url.Values{}, "")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("getTopoInfo returned %d", status)
	}
	recs, err := parseONTScript(string(body))
	if err != nil {
		return nil, fmt.Errorf("parsing getTopoInfo: %w", err)
	}
	for _, r := range recs {
		if v := findString(r, "APInst"); v != "" {
			h.mu.Lock()
			h.apInst = v
			h.mu.Unlock()
			break
		}
	}
	return recs, nil
}

// getEthPorts returns the physical ports for the gateway's APInst.
func (h *HuaweiONT) getEthPorts(ctx context.Context) ([]ethPort, error) {
	h.mu.Lock()
	inst := h.apInst
	h.mu.Unlock()
	if inst == "" {
		if _, err := h.getTopo(ctx); err != nil {
			return nil, err
		}
		h.mu.Lock()
		inst = h.apInst
		h.mu.Unlock()
	}
	if inst == "" {
		return nil, errors.New("the gateway did not report its APInst")
	}

	status, _, body, err := h.hc.postFormRaw(ctx, "/html/amp/wificoverinfo/getEthInfo.asp",
		url.Values{"APInst": {inst}}, "")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("getEthInfo returned %d", status)
	}
	recs, err := parseONTScript(string(body))
	if err != nil {
		return nil, fmt.Errorf("parsing getEthInfo: %w", err)
	}
	var ports []ethPort
	for _, r := range recs {
		ports = append(ports, ethPort{
			No:     findString(r, "No"),
			Type:   findString(r, "EthType"),
			Status: findString(r, "Status"),
			Speed:  findString(r, "Speed"),
			Duplex: findString(r, "Duplex"),
		})
	}
	return ports, nil
}

// Clients reports how the gateway says clients are attached.
//
// On this firmware there is no per-device client table, so the result is
// derived from the port state and the Wi-Fi station lists. The derivation is
// deliberately conservative: a port is only attributed to devices when it is
// the single active port.
func (h *HuaweiONT) Clients(ctx context.Context) (map[string]model.Connection, error) {
	out := map[string]model.Connection{}

	// ---- wireless stations, when this model has radios ----
	stations, err := h.wifiStations(ctx)
	if err == nil {
		for mac, c := range stations {
			out[mac] = c
		}
	}

	// ---- wired ports ----
	ports, err := h.getEthPorts(ctx)
	if err != nil && len(out) == 0 {
		return nil, err
	}

	var up []ethPort
	for _, p := range ports {
		if strings.EqualFold(p.Status, "Up") {
			up = append(up, p)
		}
	}

	// A device cannot be attributed to a port the gateway does not identify, so
	// the result carries the port state itself rather than a per-device claim.
	// Callers use this to label devices, and the summary is exposed through
	// Status so the dashboard can explain it.
	h.mu.Lock()
	h.ports = ports
	h.mu.Unlock()

	if len(up) == 1 {
		// Exactly one port is live, so every wired device is on it.
		conn := model.Connection{
			Kind:   model.LinkLAN,
			Port:   portLabel(up[0].No),
			Rate:   portRate(up[0].Speed),
			Source: "router",
		}
		h.mu.Lock()
		h.solePort = conn
		h.mu.Unlock()
	} else {
		h.mu.Lock()
		h.solePort = model.Connection{}
		h.mu.Unlock()
	}

	if len(out) == 0 && len(ports) == 0 {
		return nil, errors.New("the gateway reported no ports and no stations")
	}
	return out, nil
}

// portLabel renders a port number as LAN1, LAN2, ...
func portLabel(no string) string {
	no = strings.TrimSpace(no)
	if no == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToUpper(no), "LAN") {
		return strings.ToUpper(no)
	}
	return "LAN" + no
}

// portRate renders a negotiated speed in Mbps.
func portRate(speed string) string {
	s := strings.TrimSpace(speed)
	if s == "" || s == "0" {
		return ""
	}
	if strings.Contains(strings.ToLower(s), "mbps") {
		return s
	}
	return s + " Mbps"
}

// wifiStations collects associated stations across every radio the UI would
// offer, and reports them as wireless clients.
func (h *HuaweiONT) wifiStations(ctx context.Context) (map[string]model.Connection, error) {
	out := map[string]model.Connection{}

	// The UI passes an AP id, a band and an online flag. The ids it uses come
	// from the page itself, and are 0 and 1 on the models seen so far.
	ids := []string{"0", "1"}
	h.mu.Lock()
	if h.apInst != "" {
		ids = append(ids, h.apInst)
	}
	h.mu.Unlock()

	for _, id := range ids {
		for _, band := range []string{"2.4G", "5G"} {
			path := fmt.Sprintf("/html/amp/wificoverinfo/apssidStation.asp?%s&%s&1", id, band)
			status, _, body, err := h.hc.getRawStatus(ctx, path)
			if err != nil || status != http.StatusOK {
				continue
			}
			recs, err := parseStationScript(string(body))
			if err != nil {
				continue
			}
			for _, r := range recs {
				mac := normMAC(findString(r, "staMac", "mac"))
				if mac == "" || !validMAC(mac) {
					continue
				}
				c := model.Connection{
					Kind:   model.LinkWLAN,
					Source: "router",
					Detail: findString(r, "ssid", "wifiCoverName"),
					Band:   band,
				}
				if rssi := findString(r, "staRssi"); rssi != "" {
					c.Signal = rssi + " dBm"
				}
				if rate := findString(r, "staTxRate"); rate != "" {
					c.Rate = rate + " Mbps"
				}
				out[mac] = c
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no associated wireless stations")
	}
	return out, nil
}

// parseStationScript reads a station payload.
//
// Two shapes occur in this firmware family and the populated form could not be
// observed on the model tested (it reported no associated stations), so both are
// accepted:
//
//	array literal:  stApSta = new Array({staMac:".."},{staMac:".."})
//	assignments:    stApSta[0] = new Object(); stApSta[0].staMac = ".."
func parseStationScript(raw string) ([]map[string]any, error) {
	if i := strings.Index(raw, "new Array("); i >= 0 {
		rest := raw[i+len("new Array("):]
		// Match the closing paren of this call, not the last one in the file.
		end := strings.Index(rest, ")")
		if end >= 0 {
			inner := strings.TrimSpace(rest[:end])
			if inner != "" && inner != "null" {
				if recs, err := parseONTScript("[" + inner + "]"); err == nil && len(recs) > 0 {
					return recs, nil
				}
			}
		}
	}
	if recs := parseStationAssignments(raw); len(recs) > 0 {
		return recs, nil
	}
	return nil, errors.New("no associated stations")
}

// parseStationAssignments reads the "arr[i].field = value" style, grouping by
// index.
//
// The value pattern matches a quoted string first and otherwise stops at a
// semicolon, comma or end of line. A greedy match would swallow every following
// assignment when several share a line, which is how these payloads are
// actually emitted.
func parseStationAssignments(raw string) []map[string]any {
	assign := regexp.MustCompile(
		`([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(\d+)\s*\]\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*` +
			`("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^;,\r\n]+)`)

	byIndex := map[string]map[string]any{}
	var order []string

	for _, m := range assign.FindAllStringSubmatch(raw, -1) {
		idx, field, rawVal := m[2], m[3], strings.TrimSpace(m[4])
		if rawVal == "" || rawVal == "null" {
			continue
		}
		rec, ok := byIndex[idx]
		if !ok {
			rec = map[string]any{}
			byIndex[idx] = rec
			order = append(order, idx)
		}
		rec[field] = unquoteJSValue(rawVal)
	}

	out := make([]map[string]any, 0, len(order))
	for _, idx := range order {
		out = append(out, byIndex[idx])
	}
	return out
}

// unquoteJSValue strips surrounding quotes from a JavaScript literal.
func unquoteJSValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

// ONTStatus reports what the gateway exposes, for the dashboard.
type ONTStatus struct {
	APInst string    `json:"ap_inst,omitempty"`
	Ports  []ONTPort `json:"ports,omitempty"`
	// SolePort is set when exactly one physical port is up, in which case every
	// wired device is on it.
	SolePort model.Connection `json:"sole_port,omitempty"`
}

// ONTPort is one physical port, for display.
type ONTPort struct {
	No     string `json:"no"`
	Type   string `json:"type,omitempty"`
	Status string `json:"status"`
	Speed  string `json:"speed,omitempty"`
	Duplex string `json:"duplex,omitempty"`
}

// Status returns the gateway's port state.
func (h *HuaweiONT) Status() ONTStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := ONTStatus{APInst: h.apInst, SolePort: h.solePort}
	for _, p := range h.ports {
		st.Ports = append(st.Ports, ONTPort{
			No: portLabel(p.No), Type: p.Type, Status: p.Status,
			Speed: portRate(p.Speed), Duplex: p.Duplex,
		})
	}
	return st
}
