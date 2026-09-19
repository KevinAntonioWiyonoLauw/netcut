// language: Go, file: internal/router/discover.go
//
// Structural field discovery.
//
// Router management APIs vary enormously between models, firmware versions and
// vendors, and their schemas are not documented. Rather than hard-code one
// model's field names and silently report nothing on every other router, this
// file locates device records structurally: it walks the response for objects
// that carry a MAC address, then reads the surrounding fields by name pattern.
//
// The consequence is that an unknown router still yields useful output, and a
// field the router does not expose is simply absent rather than wrong.
package router

import (
	"net"
	"strconv"
	"strings"

	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
)

// walkDevices recursively collects every object in a decoded JSON value that
// carries something MAC-shaped. Keys are matched case-insensitively and with
// separators removed, so MacAddress, mac_addr, mac-address and mac all match.
func walkDevices(v any) []map[string]any {
	var out []map[string]any
	seen := map[string]bool{}

	var walk func(node any, depth int)
	walk = func(node any, depth int) {
		if depth > 12 { // guard against a pathological structure
			return
		}
		switch n := node.(type) {
		case map[string]any:
			if rec, ok := asDeviceRecord(n); ok {
				key := normMAC(rec.mac)
				if key != "" && !seen[key] {
					seen[key] = true
					out = append(out, n)
				}
				// Do not descend into a matched record: nested objects inside
				// it are its own fields, not separate devices.
				return
			}
			for _, child := range n {
				walk(child, depth+1)
			}
		case []any:
			for _, child := range n {
				walk(child, depth+1)
			}
		}
	}
	walk(v, 0)
	return out
}

type deviceRecord struct {
	mac string
	raw map[string]any
}

// asDeviceRecord reports whether an object looks like a client entry.
func asDeviceRecord(m map[string]any) (deviceRecord, bool) {
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if !isMACKey(k) {
			continue
		}
		if !looksLikeMAC(s) {
			continue
		}
		if !validMAC(s) {
			continue
		}
		return deviceRecord{mac: normMAC(s), raw: m}, true
	}
	return deviceRecord{}, false
}

// isMACKey reports whether a key names a MAC address.
func isMACKey(k string) bool {
	n := normaliseKey(k)
	switch n {
	case "mac", "macaddress", "hwaddr", "hwaddress", "physicaladdress",
		"macaddr", "clientmac", "devicemac", "stationmac", "bssid":
		return true
	}
	return false
}

// normaliseKey lower-cases a key and drops separators.
func normaliseKey(k string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(k) {
		switch r {
		case '_', '-', ' ', '.', '/':
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// findString returns the first string value whose key matches one of the
// given normalised names.
func findString(m map[string]any, names ...string) string {
	want := map[string]bool{}
	for _, n := range names {
		want[normaliseKey(n)] = true
	}
	for k, v := range m {
		if !want[normaliseKey(k)] {
			continue
		}
		switch t := v.(type) {
		case string:
			if s := strings.TrimSpace(t); s != "" {
				return s
			}
		case float64:
			return strconv.FormatFloat(t, 'f', -1, 64)
		case bool:
			return strconv.FormatBool(t)
		}
	}
	return ""
}

// findInt returns the first integer value whose key matches.
func findInt(m map[string]any, names ...string) int {
	s := findString(m, names...)
	if s == "" {
		return 0
	}
	// Router APIs often append a unit, e.g. "-55 dBm" or "300M".
	s = strings.TrimSpace(s)
	num := leadingInt(s)
	return num
}

func leadingInt(s string) int {
	end := 0
	for end < len(s) && (s[end] == '-' || s[end] == '+' || (s[end] >= '0' && s[end] <= '9')) {
		end++
	}
	if end == 0 {
		return 0
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0
	}
	return n
}

// findStringAnyKey returns the first string value whose key contains one of the
// given fragments. Used for fields with unpredictable naming.
func findStringAnyKey(m map[string]any, fragments ...string) string {
	for k, v := range m {
		nk := normaliseKey(k)
		for _, f := range fragments {
			if strings.Contains(nk, normaliseKey(f)) {
				if s, ok := v.(string); ok {
					if s = strings.TrimSpace(s); s != "" {
						return s
					}
				}
			}
		}
	}
	return ""
}

// connectionFrom builds a Connection from a device record.
//
// Only what the router actually states is filled in. Nothing is inferred from
// absence, so a router that does not expose the attachment leaves the field
// empty rather than guessing wrong.
func connectionFrom(m map[string]any) model.Connection {
	c := model.Connection{Source: "router"}

	// The interface / link type, under many possible names.
	raw := strings.ToLower(strings.Join([]string{
		findString(m, "interfaceType", "ifaceType", "interface", "iface", "linkType",
			"accessType", "connectionType", "portType", "networkType", "type"),
		findStringAnyKey(m, "interfacetype", "linktype", "accesstype"),
	}, " "))

	// SSID is strong evidence of a wireless link.
	ssid := findString(m, "ssid", "wifiName", "wifiname", "wlanName", "associatedSsid",
		"essid", "wirelessSsid", "apName")
	if ssid == "" {
		ssid = findStringAnyKey(m, "ssid", "wifiname", "essid")
	}

	band := findString(m, "band", "frequency", "freq", "radioBand", "bandwidth")
	if band == "" {
		band = findStringAnyKey(m, "band", "frequency")
	}
	band = normaliseBand(band, raw, m)

	rate := findString(m, "rate", "linkRate", "speed", "txRate", "bitrate",
		"negotiatedRate", "wifiRate", "dataRate")
	if rate == "" {
		rate = findStringAnyKey(m, "rate", "speed", "bitrate")
	}

	signal := findString(m, "signal", "rssi", "signalStrength", "signalLevel", "snr")
	if signal == "" {
		signal = findStringAnyKey(m, "signal", "rssi")
	}

	port := findString(m, "port", "lanPort", "switchPort", "ethPort", "ifName", "ifname", "portName")
	if port == "" {
		port = findStringAnyKey(m, "lanport", "switchport", "portno")
	}

	switch {
	case strings.Contains(raw, "wlan") || strings.Contains(raw, "wifi") ||
		strings.Contains(raw, "wireless") || strings.Contains(raw, "wlan") ||
		strings.Contains(raw, "5g") || strings.Contains(raw, "2.4g") ||
		strings.Contains(raw, "11") || ssid != "":
		c.Kind = model.LinkWLAN
		c.Detail = ssid
		c.Band = band
	case strings.Contains(raw, "lan") || strings.Contains(raw, "ethernet") ||
		strings.Contains(raw, "eth") || strings.Contains(raw, "wired"):
		c.Kind = model.LinkLAN
		c.Port = normalisePort(port, raw)
	case strings.Contains(raw, "wan") || strings.Contains(raw, "uplink"):
		c.Kind = model.LinkWAN
	default:
		// Nothing conclusive. Report unknown rather than invent a link.
		if ssid != "" {
			c.Kind = model.LinkWLAN
			c.Detail = ssid
		} else {
			c.Kind = model.LinkUnknown
		}
	}

	c.Rate = normaliseRate(rate)
	c.Signal = normaliseSignal(signal)
	if c.Kind == model.LinkUnknown && c.Detail == "" && c.Rate == "" && c.Signal == "" && c.Port == "" {
		return model.Connection{}
	}
	return c
}

// normaliseBand derives a band label from whatever the router reported.
func normaliseBand(band, raw string, m map[string]any) string {
	b := strings.ToLower(band + " " + raw)
	switch {
	case strings.Contains(b, "6g") || strings.Contains(b, "6 ghz"):
		return "6G"
	case strings.Contains(b, "5g") || strings.Contains(b, "5 ghz") ||
		strings.Contains(b, "5180") || strings.Contains(b, "5745"):
		return "5G"
	case strings.Contains(b, "2.4") || strings.Contains(b, "2400") ||
		strings.Contains(b, "2412"):
		return "2.4G"
	}
	// Some routers report the channel instead of the band.
	if ch := findInt(m, "channel", "channelNum", "wifiChannel"); ch > 0 {
		if ch <= 14 {
			return "2.4G"
		}
		return "5G"
	}
	return ""
}

// normalisePort cleans a port label into LAN1 / LAN2 form.
func normalisePort(port, raw string) string {
	p := strings.ToUpper(strings.TrimSpace(port))
	if p == "" {
		// Try to pull "lan1" out of a free-text field.
		for _, f := range strings.Fields(raw) {
			fu := strings.ToUpper(f)
			if strings.HasPrefix(fu, "LAN") || strings.HasPrefix(fu, "ETH") {
				p = fu
				break
			}
		}
	}
	if p == "" {
		return ""
	}
	// Longest prefix first: trimming "ETH" before "ETHERNET" turns
	// "ETHERNET3" into "ERNET3".
	for _, prefix := range []string{"ETHERNET", "ETH", "PORT"} {
		p = strings.TrimPrefix(p, prefix)
	}
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "LAN") {
		if _, err := strconv.Atoi(p); err == nil {
			p = "LAN" + p
		}
	}
	return p
}

// normaliseRate tidies a rate into a consistent "N <unit>" form.
func normaliseRate(rate string) string {
	s := strings.TrimSpace(rate)
	if s == "" {
		return ""
	}
	// Split the numeric prefix from whatever unit follows it.
	i := 0
	for i < len(s) && (s[i] == '-' || s[i] == '+' || s[i] == '.' ||
		(s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	num := strings.TrimSpace(s[:i])
	unit := strings.TrimSpace(s[i:])
	if num == "" {
		return s
	}
	if unit == "" {
		// A bare number from a router is a rate in Mbps.
		return num + " Mbps"
	}
	// Canonicalise the spellings seen in the wild, e.g. "72Mbps" -> "72 Mbps".
	switch strings.ToLower(strings.ReplaceAll(unit, " ", "")) {
	case "mbps", "mbit/s", "mb/s":
		return num + " Mbps"
	case "gbps", "gbit/s", "gb/s":
		return num + " Gbps"
	case "kbps", "kbit/s", "kb/s":
		return num + " kbps"
	}
	return num + " " + unit
}

// normaliseSignal tidies a signal reading, keeping the unit when present.
func normaliseSignal(sig string) string {
	s := strings.TrimSpace(sig)
	if s == "" {
		return ""
	}
	if n := leadingInt(s); n != 0 {
		if strings.Contains(s, "%") {
			return s
		}
		// A negative value in this range is dBm.
		if n < 0 && n > -120 {
			return strconv.Itoa(n) + " dBm"
		}
		return strconv.Itoa(n) + "%"
	}
	return s
}

// firstIPv4 returns the first IPv4 address string found in a record.
func firstIPv4(m map[string]any) string {
	for _, k := range []string{"ipAddress", "ip", "ipv4", "ipAddr", "address",
		"clientIp", "hostIp", "inetAddress"} {
		if s := findString(m, k); s != "" {
			if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil && ip.To4() != nil {
				return ip.To4().String()
			}
		}
	}
	// Fall back to scanning every value for something IP-shaped.
	for _, v := range m {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil && ip.To4() != nil {
			return ip.To4().String()
		}
	}
	return ""
}
