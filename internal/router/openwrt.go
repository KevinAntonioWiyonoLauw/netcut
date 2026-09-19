// language: Go, file: internal/router/openwrt.go
//
// OpenWrt / LEDE backend, over ubus.
//
// ubus is the standard RPC bus on OpenWrt. This backend logs in for a session
// id, then asks iwinfo for the wireless device list and each radio's associated
// stations. That yields a reliable wlan classification with SSID and signal.
//
// Wired clients are reported by the router's own client list where one exists;
// when it does not, their kind stays unknown rather than being guessed.
package router

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
)

// OpenWrt is the ubus client.
type OpenWrt struct {
	hc *httpClient

	mu      sync.Mutex
	session string
	loginAt time.Time
}

// NewOpenWrt builds an OpenWrt backend.
func NewOpenWrt(base string, cfg Config) *OpenWrt {
	hc, err := newHTTPClient(base, cfg)
	if err != nil {
		hc = &httpClient{base: base, cfg: cfg}
	}
	return &OpenWrt{hc: hc}
}

// Name identifies the backend.
func (o *OpenWrt) Name() string { return "openwrt" }

// Host returns the router address.
func (o *OpenWrt) Host() string { return o.hc.base }

// ubusEnvelope is the JSON-RPC wrapper ubus uses.
type ubusEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// call performs one ubus RPC. params must be the array ubus expects.
func (o *OpenWrt) call(ctx context.Context, method string, params any, out any) error {
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}
	var env ubusEnvelope
	if err := o.hc.postJSON(ctx, "/ubus", body, &env); err != nil {
		return err
	}
	if env.Error != nil {
		return fmt.Errorf("ubus error %d: %s", env.Error.Code, env.Error.Message)
	}
	if out != nil && len(env.Result) > 0 {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// Login obtains a ubus session id.
func (o *OpenWrt) Login(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.session != "" && time.Since(o.loginAt) < 20*time.Minute {
		return nil
	}

	params := []any{
		"00000000000000000000000000000000",
		"session",
		"login",
		map[string]string{"username": o.hc.cfg.User, "password": o.hc.cfg.Password},
	}
	var res []any
	if err := o.call(ctx, "call", params, &res); err != nil {
		return fmt.Errorf("openwrt login failed: %w", err)
	}
	if len(res) < 2 {
		return errors.New("openwrt login returned an unexpected response")
	}
	if code, ok := res[0].(float64); ok && code != 0 {
		return fmt.Errorf("openwrt login rejected the credentials (code %.0f)", code)
	}
	payload, ok := res[1].(map[string]any)
	if !ok {
		return errors.New("openwrt login returned no session payload")
	}
	sid, _ := payload["ubus_rpc_session"].(string)
	if sid == "" {
		// Some builds signal a wrong password with an access-group error here.
		if ag, ok := payload["access_group"].(map[string]any); ok {
			if name, _ := ag["name"].(string); strings.Contains(strings.ToLower(name), "unauthenticated") {
				return errors.New("openwrt rejected the credentials")
			}
		}
		return errors.New("openwrt login returned no session id (wrong credentials?)")
	}
	o.session = sid
	o.loginAt = time.Now()
	return nil
}

// Clients returns associated stations, wireless first.
func (o *OpenWrt) Clients(ctx context.Context) (map[string]model.Connection, error) {
	o.mu.Lock()
	sid := o.session
	o.mu.Unlock()
	if sid == "" {
		return nil, errors.New("openwrt session is not established")
	}

	out := map[string]model.Connection{}

	// ---- wireless stations ----
	// iwinfo devices -> ["radio0","radio1", ...]
	var devs []string
	if err := o.call(ctx, "call",
		[]any{sid, "call", "iwinfo", "devices", map[string]any{}}, &devs); err != nil {
		// Not fatal: fall through to the client list below.
		devs = nil
	}

	for _, dev := range devs {
		var res []any
		if err := o.call(ctx, "call",
			[]any{sid, "call", "iwinfo", "assoclist", map[string]string{"device": dev}}, &res); err != nil {
			continue
		}
		if len(res) < 2 {
			continue
		}
		stations, ok := res[1].(map[string]any)
		if !ok {
			continue
		}
		for mac, v := range stations {
			if !validMAC(mac) {
				continue
			}
			info, _ := v.(map[string]any)
			conn := model.Connection{
				Kind:   model.LinkWLAN,
				Source: "router",
				Detail: findString(info, "ssid"),
			}
			if conn.Detail == "" {
				conn.Detail = dev
			}
			conn.Band = normaliseBand("", dev+" "+findString(info, "band"), info)
			if sig := findInt(info, "signal"); sig != 0 {
				conn.Signal = fmt.Sprintf("%d dBm", sig)
			}
			if rate := findInt(info, "rx", "bitrate"); rate != 0 {
				conn.Rate = fmt.Sprintf("%d kbps", rate)
			}
			out[normMAC(mac)] = conn
		}
	}

	// ---- wired clients, when the router exposes a client list ----
	// Several packages provide one; try them and use whatever answers.
	for _, m := range []string{"luci", "client", "devices"} {
		var res []any
		if err := o.call(ctx, "call",
			[]any{sid, "call", m, "getClients", map[string]any{}}, &res); err != nil {
			continue
		}
		records := walkDevices(res)
		if len(records) == 0 {
			continue
		}
		for _, rec := range records {
			mac := normMAC(findString(rec, "mac", "macAddress", "hwaddr"))
			if mac == "" || !validMAC(mac) {
				continue
			}
			if _, already := out[mac]; already {
				continue // wireless information is more precise
			}
			conn := connectionFrom(rec)
			if conn.Kind == "" {
				conn.Kind = model.LinkUnknown
				conn.Source = "router"
			}
			out[mac] = conn
		}
		break
	}

	if len(out) == 0 {
		return nil, errors.New("openwrt returned no associated clients")
	}
	return out, nil
}
