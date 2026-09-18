// language: Go, file: internal/policy/policy.go
// The policy engine resolves, for every known device, exactly one enforcement
// decision. It is pure: given devices, policies and manual overrides it returns
// the full decision set, so it can be unit tested without a network or a clock.
//
// Precedence, highest first:
//
//  1. protected device  -> allow   (the operator's own hardware is immune)
//  2. manual override   -> its action (per-device, optionally expiring)
//  3. first matching policy by priority
//  4. nothing matched   -> allow
package policy

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
	"github.com/kevinantoniowiyonolauw/netcut/internal/store"
)

// Source explains why a device resolved the way it did.
type Source string

const (
	SourceProtected Source = "protected" // exempt by operator
	SourceManual    Source = "manual"    // per-device override
	SourcePolicy    Source = "policy"    // matched a rule
	SourceDefault   Source = "default"   // no rule matched
)

// Result is the resolved decision plus the reasoning shown in the UI.
type Result struct {
	MAC        string       `json:"mac"`
	Action     model.Action `json:"action"`
	CapKbps    int          `json:"cap_kbps"`
	UpKbps     int          `json:"up_kbps"`
	Source     Source       `json:"source"`
	Reason     string       `json:"reason"`
	PolicyID   string       `json:"policy_id,omitempty"`
	PolicyName string       `json:"policy_name,omitempty"`
	Protected  bool         `json:"protected"`
	// ThrottlePercent is CapKbps relative to LinkKbps, for display only.
	ThrottlePercent int `json:"throttle_percent,omitempty"`
}

// Evaluate resolves one Result per device.
//
// overrides are the active (non-expired) manual instructions. now is injected
// so schedules are deterministic under test.
func Evaluate(devices []model.Device, policies []model.Policy, overrides map[string]store.Override, now time.Time) map[string]Result {
	out := make(map[string]Result, len(devices))

	// Only enabled policies whose schedule is currently active can match.
	active := make([]model.Policy, 0, len(policies))
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		if !ScheduleActive(p.Schedule, now) {
			continue
		}
		active = append(active, p)
	}

	for _, d := range devices {
		mac := normMAC(d.MAC)

		// 1. Protected devices are unconditionally exempt. This is the
		//    guarantee that the operator's own machine can never be locked out
		//    by a rule, a schedule, or a mistake.
		if d.Protected {
			out[mac] = Result{
				MAC: mac, Action: model.ActionAllow, Source: SourceProtected,
				Protected: true, Reason: "protected device - exempt from all enforcement",
			}
			continue
		}

		// 2. Manual per-device instruction outranks any rule.
		if ov, ok := overrides[mac]; ok {
			res := Result{
				MAC: mac, Action: ov.Action, CapKbps: ov.CapKbps, UpKbps: ov.UpKbps,
				Source: SourceManual, Reason: manualReason(ov),
			}
			out[mac] = res
			continue
		}

		// 3. First matching policy wins (policies arrive priority-ordered).
		matched := false
		for _, p := range active {
			if !matches(p, d) {
				continue
			}
			out[mac] = Result{
				MAC: mac, Action: p.Action, CapKbps: p.CapKbps, UpKbps: p.UpKbps,
				Source: SourcePolicy, PolicyID: p.ID, PolicyName: p.Name,
				Reason: policyReason(p),
			}
			matched = true
			break
		}
		if matched {
			continue
		}

		// 4. Default: no enforcement.
		out[mac] = Result{
			MAC: mac, Action: model.ActionAllow, Source: SourceDefault,
			Reason: "no matching rule",
		}
	}
	return out
}

func manualReason(ov store.Override) string {
	r := "manual override"
	if ov.ExpiresAt != nil {
		r += fmt.Sprintf(" (expires %s)", ov.ExpiresAt.Local().Format("15:04:05"))
	}
	if ov.UpdatedBy != "" {
		r += " by " + ov.UpdatedBy
	}
	return r
}

func policyReason(p model.Policy) string {
	r := "policy: " + p.Name
	if p.Window != "" {
		r += " [" + p.Window + "]"
	} else if p.Schedule != "" {
		r += " [" + p.Schedule + "]"
	}
	return r
}

// matches reports whether a policy targets a device.
func matches(p model.Policy, d model.Device) bool {
	switch p.TargetType {
	case model.TargetAll:
		return true
	case model.TargetGroup:
		return d.Group != "" && strings.EqualFold(d.Group, p.TargetValue)
	case model.TargetDevice:
		return normMAC(d.MAC) == normMAC(p.TargetValue)
	}
	return false
}

// ScheduleActive reports whether a schedule spec is active at time t.
//
// Two syntaxes are accepted:
//
//	""                 always active
//	"22:00-06:00"      a time-of-day window, may cross midnight
//	"0 22 * * *"       a standard 5-field cron expression
//
// An unparseable spec is treated as always active: a typo must never silently
// disable enforcement, and it must never silently block everyone either, so
// the safe reading is "the rule is on".
func ScheduleActive(spec string, t time.Time) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return true
	}
	if strings.Contains(spec, ":") && !strings.ContainsAny(spec, " *") {
		return inWindow(spec, t)
	}
	return matchCron(spec, t)
}

var cronAliases = map[string]string{
	"@hourly":   "0 * * * *",
	"@daily":    "0 0 * * *",
	"@midnight": "0 0 * * *",
	"@weekly":   "0 0 * * 0",
	"@monthly":  "0 0 1 * *",
	"@yearly":   "0 0 1 1 *",
	"@annually": "0 0 1 1 *",
}

func matchCron(spec string, t time.Time) bool {
	if a, ok := cronAliases[strings.ToLower(spec)]; ok {
		spec = a
	}
	f := strings.Fields(spec)
	if len(f) != 5 {
		return true
	}
	return matchField(f[0], t.Minute(), 0, 59) &&
		matchField(f[1], t.Hour(), 0, 23) &&
		matchField(f[2], t.Day(), 1, 31) &&
		matchField(f[3], int(t.Month()), 1, 12) &&
		matchField(f[4], int(t.Weekday())%7, 0, 6)
}

// matchField handles "*", "a", "a-b", "*/n", "a-b/n" and comma lists.
func matchField(field string, v, lo, hi int) bool {
	field = strings.TrimSpace(field)
	if field == "" || field == "*" {
		return true
	}
	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		step := 1
		if i := strings.Index(part, "/"); i >= 0 {
			s, err := strconv.Atoi(strings.TrimSpace(part[i+1:]))
			if err != nil || s <= 0 {
				continue
			}
			step = s
			part = strings.TrimSpace(part[:i])
		}
		start, end := lo, hi
		if part != "" && part != "*" {
			if i := strings.Index(part, "-"); i > 0 {
				a, err1 := strconv.Atoi(strings.TrimSpace(part[:i]))
				b, err2 := strconv.Atoi(strings.TrimSpace(part[i+1:]))
				if err1 != nil || err2 != nil {
					continue
				}
				start, end = a, b
			} else {
				a, err := strconv.Atoi(part)
				if err != nil {
					continue
				}
				start, end = a, a
			}
		}
		if start > end {
			start, end = end, start
		}
		if v >= start && v <= end && (v-start)%step == 0 {
			return true
		}
	}
	return false
}

// inWindow parses "HH:MM-HH:MM" and reports whether t falls inside it.
func inWindow(spec string, t time.Time) bool {
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return true
	}
	start, ok1 := parseHM(parts[0])
	end, ok2 := parseHM(parts[1])
	if !ok1 || !ok2 {
		return true
	}
	cur := t.Hour()*60 + t.Minute()
	if start == end {
		return true
	}
	if start < end {
		return cur >= start && cur < end
	}
	// Window crosses midnight, e.g. 22:00-06:00.
	return cur >= start || cur < end
}

func parseHM(s string) (int, bool) {
	s = strings.TrimSpace(s)
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, false
	}
	h, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	m, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

// ToDirectives converts results into the wire format agents consume.
func ToDirectives(results map[string]Result, devices []model.Device) []model.Directive {
	byMAC := make(map[string]model.Device, len(devices))
	for _, d := range devices {
		byMAC[normMAC(d.MAC)] = d
	}
	out := make([]model.Directive, 0, len(results))
	for mac, r := range results {
		out = append(out, model.Directive{
			MAC: mac, IP: byMAC[mac].IP, Action: r.Action,
			CapKbps: r.CapKbps, UpKbps: r.UpKbps,
			Reason: r.Reason, PolicyID: r.PolicyID, Protected: r.Protected,
		})
	}
	return out
}

func normMAC(mac string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(mac), "-", ":"))
}
