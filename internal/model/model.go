// language: Go, file: internal/model/model.go
// Domain types shared by the control plane (server) and the data plane (agent).
package model

import "time"

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
	ArpPoisoned bool      `json:"arp_poisoned"`
	RxBps       uint64    `json:"rx_bps"`
	TxBps       uint64    `json:"tx_bps"`
	RTTms       float64   `json:"rtt_ms"`
	Packets     uint64    `json:"packets"`
	BytesRx     uint64    `json:"bytes_rx"`
	BytesTx     uint64    `json:"bytes_tx"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
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
	AgentID  string    `json:"agent_id"`
	Name     string    `json:"name"`
	Version  string    `json:"version"`
	Iface    string    `json:"iface"`
	Subnet   string    `json:"subnet"`
	Gateway  string    `json:"gateway"`
	LocalIP  string    `json:"local_ip"`
	LocalMAC string    `json:"local_mac"`
	OS       string    `json:"os"`
	Elevated bool      `json:"elevated"`
	CapAR    bool      `json:"cap_arp"`
	CapQoS   bool      `json:"cap_qos"`
	Devices  int       `json:"devices"`
	TS       time.Time `json:"ts"`
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
}
