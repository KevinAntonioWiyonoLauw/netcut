// language: Go, file: internal/router/huawei.go
//
// Huawei home gateway backend.
//
// These gateways expose a JSON API under /api/... and authenticate with a
// session cookie. The exact endpoint set and the login handshake vary by model
// and firmware, so this backend:
//
//   - tries the plain credential POST first, then a challenge/response variant
//     if the gateway asks for one
//   - probes several known host-list endpoints and uses the first that returns
//     usable data, recording which one it was
//   - parses whatever came back structurally, so an unfamiliar schema still
//     yields results
//
// Nothing here changes gateway configuration.
package router

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
)

// Huawei is the Huawei gateway client.
type Huawei struct {
	hc *httpClient

	mu       sync.Mutex
	loggedIn bool
	loginAt  time.Time
	// workingPath remembers the endpoint that produced data, so later polls
	// skip the probing.
	workingPath string
}

// NewHuawei builds a Huawei backend.
func NewHuawei(base string, cfg Config) *Huawei {
	hc, err := newHTTPClient(base, cfg)
	if err != nil {
		// newHTTPClient only fails on a cookie-jar allocation, which cannot
		// happen with a nil public suffix list. Keep the signature simple and
		// surface it at call time.
		hc = &httpClient{base: base, cfg: cfg}
	}
	return &Huawei{hc: hc}
}

// Name identifies the backend.
func (h *Huawei) Name() string { return "huawei" }

// Host returns the gateway address.
func (h *Huawei) Host() string { return h.hc.base }

// candidate client-list endpoints, most specific first.
var huaweiHostPaths = []string{
	"/api/wlan/host-list",
	"/api/ntwk/wlanhostinfo",
	"/api/lan/HostInfo",
	"/api/lan/hostinfo",
	"/api/system/deviceinfo",
	"/api/ntwk/host-list",
	"/api/lan/deviceinfo",
	"/api/wlan/hostlist",
}

// huaweiLoginPaths are the credential endpoints seen across firmware versions.
var huaweiLoginPaths = []string{
	"/api/system/user_login",
	"/api/user/login",
	"/api/system/userlogin",
}

// sessionCookies are the cookie names Huawei firmware uses for its session.
var sessionCookies = []string{"SessionID", "sessionid", "session", "sysauth"}

// errChallengeRequired signals that the gateway wants a salted response.
var errChallengeRequired = errors.New("gateway requires a challenge response")

// errRejected signals that the gateway understood the request and refused the
// credentials. It is distinguished from a transport or wrong-endpoint error so
// that Login can report the meaningful cause.
var errRejected = errors.New("gateway rejected the credentials")

// Login authenticates and keeps the session cookie in the client jar.
func (h *Huawei) Login(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.loggedIn && time.Since(h.loginAt) < 25*time.Minute {
		return nil
	}

	var (
		rejection error // a real credential refusal, worth reporting
		other     error // a transport or wrong-endpoint error
	)
	for _, path := range huaweiLoginPaths {
		err := h.loginPlain(ctx, path)
		if err == nil {
			h.loggedIn = true
			h.loginAt = time.Now()
			return nil
		}

		if errors.Is(err, errChallengeRequired) {
			// The gateway may require a salted response instead of the raw
			// password. Ask it for a challenge and retry.
			if cerr := h.loginChallenge(ctx, path); cerr == nil {
				h.loggedIn = true
				h.loginAt = time.Now()
				return nil
			} else if errors.Is(cerr, errRejected) {
				rejection = cerr
			} else {
				other = cerr
			}
			continue
		}

		// A credential refusal is the most useful thing to report: the
		// endpoint is right and the password is wrong. A later path returning
		// an HTML page must not overwrite it.
		if errors.Is(err, errRejected) {
			if rejection == nil {
				rejection = err
			}
			continue
		}
		if other == nil {
			other = err
		}
	}

	if rejection != nil {
		return fmt.Errorf("huawei login failed: %w", rejection)
	}
	if other != nil {
		return fmt.Errorf("huawei login failed: %w", other)
	}
	return errors.New("huawei login failed: no login endpoint responded")
}

func (h *Huawei) loginPlain(ctx context.Context, path string) error {
	body := map[string]string{
		"username": h.hc.cfg.User,
		"password": h.hc.cfg.Password,
	}
	var resp map[string]any
	if err := h.hc.postJSON(ctx, path, body, &resp); err != nil {
		return err
	}
	if err := interpretLogin(resp); err != nil {
		return err
	}
	h.applySession(resp)
	return nil
}

// loginChallenge fetches a challenge and answers with
// base64(sha256(password + challenge)), which is what several Huawei firmware
// builds expect in place of the plain password.
func (h *Huawei) loginChallenge(ctx context.Context, path string) error {
	var challengeResp map[string]any
	challenge := ""
	for _, cp := range []string{"/api/system/user_login_secret", "/api/system/user-login-challenge"} {
		if err := h.hc.get(ctx, cp, &challengeResp); err == nil {
			challenge = findString(challengeResp, "challenge", "secret", "salt", "token", "nonce")
			if challenge != "" {
				break
			}
		}
	}
	if challenge == "" {
		return errors.New("gateway asked for a challenge but did not provide one")
	}

	sum := sha256.Sum256([]byte(h.hc.cfg.Password + challenge))
	body := map[string]string{
		"username": h.hc.cfg.User,
		"password": base64.StdEncoding.EncodeToString(sum[:]),
	}
	var resp map[string]any
	if err := h.hc.postJSON(ctx, path, body, &resp); err != nil {
		return err
	}
	if err := interpretLogin(resp); err != nil {
		return err
	}
	h.applySession(resp)
	return nil
}

// applySession makes sure the session from a successful login is usable.
//
// Some firmware sets a session cookie, which the cookie jar already holds.
// Others return the session id only in the response body, or set a cookie whose
// name differs from what the host list expects. When no cookie was stored under
// a name the gateway recognises, the id from the body is applied to every name
// in sessionCookies, so whichever the gateway checks is present.
func (h *Huawei) applySession(resp map[string]any) {
	if h.hc.c == nil || h.hc.c.Jar == nil {
		return
	}
	u, err := url.Parse(h.hc.base)
	if err != nil {
		return
	}

	stored := map[string]bool{}
	for _, c := range h.hc.c.Jar.Cookies(u) {
		stored[c.Name] = true
	}
	for _, want := range sessionCookies {
		if stored[want] {
			return // the jar already carries a recognised session cookie
		}
	}

	// No recognised cookie: fall back to the id in the body.
	sid := findString(resp, "sysauth", "sessionId", "sessionID", "session", "token")
	if sid == "" {
		return
	}
	for _, name := range sessionCookies {
		h.hc.c.Jar.SetCookies(u, []*http.Cookie{{Name: name, Value: sid, Path: "/"}})
	}
}

// interpretLogin decides whether a login response means success.
//
// Gateways signal this inconsistently: some return {"error":"0"}, some omit the
// field entirely on success, some return an error string. The rule used here is
// that an explicit non-zero error code, or an explicit error message, is a
// failure; a request that returned JSON with no error is a success.
//
// A refusal is wrapped in errRejected so the caller can tell a wrong password
// apart from a wrong endpoint.
func interpretLogin(resp map[string]any) error {
	// "success" is a boolean rather than a code on some firmware, and is the
	// one field whose false value must never be read as "no error reported".
	if v, ok := resp["success"]; ok {
		if b, isBool := v.(bool); isBool && !b {
			return errRejected
		}
	}

	for _, k := range []string{"error", "err", "errcode", "errorCode", "code",
		"result", "status"} {
		v, ok := resp[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case float64:
			if t != 0 {
				return fmt.Errorf("%w (code %.0f)", errRejected, t)
			}
			return nil
		case string:
			s := strings.TrimSpace(strings.ToLower(t))
			switch s {
			case "0", "", "ok", "success", "true", "none":
				return nil
			}
			if strings.Contains(s, "challenge") || strings.Contains(s, "secret") {
				return errChallengeRequired
			}
			return fmt.Errorf("%w (%s)", errRejected, t)
		case bool:
			if !t {
				return errRejected
			}
			return nil
		}
	}
	if cat := findString(resp, "errorCategory"); cat != "" {
		if strings.EqualFold(cat, "ok") {
			return nil
		}
		return fmt.Errorf("%w (%s)", errRejected, cat)
	}
	// No error indicator at all: treat as success.
	return nil
}

// Clients returns the associated clients.
func (h *Huawei) Clients(ctx context.Context) (map[string]model.Connection, error) {
	paths := huaweiHostPaths
	h.mu.Lock()
	if h.workingPath != "" {
		// Prefer the endpoint that worked last time.
		paths = append([]string{h.workingPath}, paths...)
	}
	h.mu.Unlock()

	var (
		lastErr error
		tried   []string
	)
	for _, path := range paths {
		var raw json.RawMessage
		if err := h.hc.get(ctx, path, &raw); err != nil {
			lastErr = err
			tried = append(tried, path)
			continue
		}
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			lastErr = err
			tried = append(tried, path)
			continue
		}
		records := walkDevices(decoded)
		if len(records) == 0 {
			lastErr = fmt.Errorf("%s returned no device records", path)
			tried = append(tried, path)
			continue
		}

		out := make(map[string]model.Connection, len(records))
		for _, rec := range records {
			mac := normMAC(findString(rec, "mac", "macAddress", "macAddr", "hwAddr", "physicalAddress"))
			if mac == "" || !validMAC(mac) {
				continue
			}
			conn := connectionFrom(rec)
			if conn.Kind == "" {
				conn.Kind = model.LinkUnknown
				conn.Source = "router"
			}
			// A host list that names an SSID is a wireless list; use that as a
			// fallback when the per-record fields were not conclusive.
			if conn.Kind == model.LinkUnknown {
				if ssid := findString(rec, "ssid", "wifiName"); ssid != "" {
					conn.Kind = model.LinkWLAN
					conn.Detail = ssid
				}
			}
			out[mac] = conn
		}
		if len(out) == 0 {
			lastErr = fmt.Errorf("%s returned records with no usable MAC", path)
			tried = append(tried, path)
			continue
		}

		h.mu.Lock()
		h.workingPath = path
		h.mu.Unlock()
		return out, nil
	}

	return nil, fmt.Errorf("no Huawei endpoint returned client data (tried %s): %w",
		strings.Join(tried, ", "), lastErr)
}

// WorkingPath reports which endpoint produced data, for diagnostics.
func (h *Huawei) WorkingPath() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.workingPath
}
