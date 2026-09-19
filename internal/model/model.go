// language: Go, file: internal/model/model.go
// Domain types shared by the control plane (server) and the data plane (agent).
package model

import (
	"strings"
	"time"
)

// Role controls what an account may do.
type Role string

const (
	RoleOwner  Role = "owner"  // full control, may manage users and agents
	RoleAdmin  Role = "admin"  // full control over devices and policy
	RoleViewer Role = "viewer" // read-only
)

// Rank returns a comparable weight; higher wins.
func (r Role) Rank() int {
	switch r {
	case RoleOwner:
		return 3
	case RoleAdmin:
		return 2
	case RoleViewer:
		return 1
	}
	return 0
}

// AtLeast reports whether r is at least as privileged as min.
func (r Role) AtLeast(min Role) bool { return r.Rank() >= min.Rank() }

// User is a dashboard account.
type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Role         Role      `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login"`
}

// LinkKind is how a device is attached to the network.
type LinkKind string

const (
	LinkUnknown LinkKind = "unknown"
	LinkWLAN    LinkKind = "wlan" // Wi-Fi
	LinkLAN     LinkKind = "lan"  // wired Ethernet
	LinkWAN     LinkKind = "wan"  // the uplink itself
	LinkVirtual LinkKind = "virtual"
)

// Connection describes how a device reaches the network.
//
// Two sources can fill this in: the data-plane agent, which knows the interface
// it is bound to, and the router, which knows the port or SSID each client is
// on. Router data wins when present because it is per-device and authoritative.
type Connection struct {
	Kind LinkKind `json:"kind"`
	// Detail is the specific attachment: an SSID, "LAN1", "LAN2", or an
	// interface name. Empty when only the kind is known.
	Detail string `json:"detail,omitempty"`
	// Band is the radio band for a wireless link ("2.4G", "5G").
	Band string `json:"band,omitempty"`
	// Port is the switch port label for a wired link ("LAN1").
	Port string `json:"port,omitempty"`
	// Rate is the negotiated link rate or the reported Wi-Fi rate.
	Rate string `json:"rate,omitempty"`
	// Signal is the reported signal strength, when the router provides it.
	Signal string `json:"signal,omitempty"`
	// Source records where this came from: "router", "agent", or "".
	Source string `json:"source,omitempty"`
}

// Label renders a short human-readable form for the dashboard.
func (c Connection) Label() string {
	if c.Kind == "" || c.Kind == LinkUnknown {
		return ""
	}
	s := string(c.Kind)
	if c.Kind == LinkWLAN {
		if c.Detail != "" {
			s += " · " + c.Detail
		}
		if c.Band != "" {
			s += " (" + c.Band + ")"
		}
		return s
	}
	if c.Port != "" {
		return string(c.Kind) + " · " + c.Port
	}
	if c.Detail != "" {
		return string(c.Kind) + " · " + c.Detail
	}
	return s
}

// ClassifyLink decides how an interface attaches a host to the network, from
// its name and description.
//
// The agent uses this to describe its own attachment, which in turn gives every
// device it reports a baseline link kind: a device seen by an agent bound to a
// wireless interface is on Wi-Fi unless the router says otherwise.
//
// Ordering matters: a virtual adapter is reported before a wired one, because
// names like "vEthernet (WSL)" contain both markers and the virtual reading is
// the correct one.
func ClassifyLink(name, desc string) LinkKind {
	s := strings.ToLower(name + " " + desc)
	switch {
	case strings.Contains(s, "wi-fi") || strings.Contains(s, "wifi") ||
		strings.Contains(s, "wlan") || strings.Contains(s, "wireless") ||
		strings.Contains(s, "802.11"):
		return LinkWLAN
	case strings.Contains(s, "vethernet") || strings.Contains(s, "hyper-v") ||
		strings.Contains(s, "virtualbox") || strings.Contains(s, "vmware") ||
		strings.Contains(s, "docker") || strings.Contains(s, "wsl") ||
		strings.Contains(s, "tap-") || strings.Contains(s, "tun") ||
		strings.Contains(s, "loopback") || strings.Contains(s, "vpn"):
		return LinkVirtual
	case strings.Contains(s, "ethernet") || strings.Contains(s, "eth") ||
		strings.Contains(s, "lan") || strings.Contains(s, "realtek") ||
		strings.Contains(s, "intel") || strings.Contains(s, "gbe") ||
		strings.Contains(s, "802.3"):
		return LinkLAN
	}
	return LinkUnknown
}

// Device is a host observed on the monitored segment.
type Device struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Vendor   string `json:"vendor"`
	Alias    string `json:"alias"`
	Group    string `json:"group"`
	Note     string `json:"note"`
	Online   bool   `json:"online"`
	// Protected devices are exempt from every enforcement action. This is the
	// "admin device" concept: the operator's own hardware never throttles,
	// never drops, and is never cut off by a schedule.
	Protected bool `json:"protected"`
	// Blocked is the operator's explicit, persistent kill switch for a device.
	Blocked bool `json:"blocked"`
	// Throttled is the operator's explicit persistent bandwidth cap.
	Throttled bool `json:"throttled"`
	// Runtime state mirrored back from the agent.
	ArpPoisoned bool    `json:"arp_poisoned"`
	RxBps       uint64  `json:"rx_bps"`
	TxBps       uint64  `json:"tx_bps"`
	RTTms       float64 `json:"rtt_ms"`
	Packets     uint64  `json:"packets"`
	BytesRx     uint64  `json:"bytes_rx"`
	BytesTx     uint64  `json:"bytes_tx"`
	// Connection is how the device is attached (Wi-Fi or a wired port).
	Connection Connection `json:"connection"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
}

// DisplayName returns the best human label for a device.
func (d Device) DisplayName() string {
	if d.Alias != "" {
		return d.Alias
	}
	if d.Hostname != "" {
		return d.Hostname
	}
	if d.Vendor != "" {
		return d.Vendor
	}
	return d.MAC
}

// Action is what a policy does to its targets.
type Action string

const (
	ActionBlock    Action = "block"    // full cut: ARP-poison both directions
	ActionThrottle Action = "throttle" // rate-limit to CapKbps
	ActionObserve  Action = "observe"  // monitor only, no enforcement
	ActionAllow    Action = "allow"    // explicit exemption (overrides other rules)
)

// TargetType selects what a policy applies to.
type TargetType string

const (
	TargetDevice TargetType = "device" // one MAC
	TargetGroup  TargetType = "group"  // every device in a group
	TargetAll    TargetType = "all"    // every non-protected device
)

// Policy is a declarative rule. The engine evaluates policies in priority
// order (higher first) and the first match per device wins, with the single
// exception that a protected device always resolves to ActionAllow.
type Policy struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	TargetType  TargetType `json:"target_type"`
	TargetValue string     `json:"target_value"`
	Action      Action     `json:"action"`
	// CapKbps is the download cap applied by ActionThrottle (0 = symmetrical
	// use of UpKbps).
	CapKbps int `json:"cap_kbps"`
	UpKbps  int `json:"up_kbps"`
	// Schedule is an optional cron expression (5 fields). Empty = always on.
	Schedule string `json:"schedule"`
	// Window is an optional human-readable window label for the UI.
	Window      string    `json:"window"`
	Enabled     bool      `json:"enabled"`
	Priority    int       `json:"priority"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	LastApplied time.Time `json:"last_applied"`
}

// Event is an entry in the audit / activity log.
type Event struct {
	ID       int64          `json:"id"`
	TS       time.Time      `json:"ts"`
	Type     string         `json:"type"`
	Severity string         `json:"severity"` // info | warn | alert
	MAC      string         `json:"mac"`
	Message  string         `json:"message"`
	Actor    string         `json:"actor"`
	Meta     map[string]any `json:"meta,omitempty"`
}

// Sample is one bandwidth measurement point for a device.
type Sample struct {
	TS    time.Time `json:"ts"`
	MAC   string    `json:"mac"`
	RxBps uint64    `json:"rx_bps"`
	TxBps uint64    `json:"tx_bps"`
}

// AgentToken authenticates a data-plane agent to the control plane.
type AgentToken struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	Revoked   bool      `json:"revoked"`
}

// AgentInfo is the heartbeat payload an agent reports.
type AgentInfo struct {
	AgentID string `json:"agent_id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Iface   string `json:"iface"`
	// IfaceKind is how this agent's own host is attached: wlan or lan. It
	// becomes the baseline link kind for every device this agent reports,
	// because an agent bound to a wireless interface can only see wireless
	// clients. The router, when configured, overrides it per device.
	IfaceKind LinkKind  `json:"iface_kind"`
	Subnet    string    `json:"subnet"`
	Gateway   string    `json:"gateway"`
	LocalIP   string    `json:"local_ip"`
	LocalMAC  string    `json:"local_mac"`
	OS        string    `json:"os"`
	Elevated  bool      `json:"elevated"`
	CapAR     bool      `json:"cap_arp"`
	CapQoS    bool      `json:"cap_qos"`
	Devices   int       `json:"devices"`
	TS        time.Time `json:"ts"`
}

// Directive is one enforcement instruction the control plane hands an agent.
type Directive struct {
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	Action    Action `json:"action"`
	CapKbps   int    `json:"cap_kbps"`
	UpKbps    int    `json:"up_kbps"`
	Reason    string `json:"reason"`
	PolicyID  string `json:"policy_id,omitempty"`
	Protected bool   `json:"protected"`
}

// AgentReport is what an agent sends back after applying directives.
type AgentReport struct {
	AgentID string            `json:"agent_id"`
	TS      time.Time         `json:"ts"`
	Applied []Directive       `json:"applied"`
	Devices []Device          `json:"devices"`
	Samples []Sample          `json:"samples"`
	Errors  []string          `json:"errors"`
	Stats   map[string]uint64 `json:"stats,omitempty"`
	// LocalMAC and LocalIP identify the agent's own host on the segment. The
	// control plane uses them to keep that host permanently exempt from
	// enforcement: it is the machine doing the redirecting, and the only route
	// back to the dashboard to undo a mistake.
	LocalMAC string `json:"local_mac,omitempty"`
	LocalIP  string `json:"local_ip,omitempty"`
}
