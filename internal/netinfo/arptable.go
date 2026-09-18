// language: Go, file: internal/netinfo/arptable.go
package netinfo

import (
	"net"
	"sort"
	"strings"
	"time"
)

// Entry is one binding read from the operating system's ARP cache.
type Entry struct {
	IP        net.IP
	MAC       net.HardwareAddr
	IfIndex   int
	Permanent bool
	// Stale marks an entry the OS no longer considers current. Stale entries
	// are still reported but are not evidence that the host is up.
	Stale bool
}

// ARPTable reads the operating system's ARP cache.
//
// This is what makes -dry-run honest: it reveals the neighbours this host has
// already learned, without transmitting a single frame and without needing an
// elevated capture handle.
func ARPTable() ([]Entry, error) {
	raw, err := platformARPTable()
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(raw))
	for _, e := range raw {
		if e.MAC == nil || len(e.MAC) != 6 {
			continue
		}
		// Skip group addresses and the all-zero placeholder the OS writes for
		// an unresolved entry.
		if e.MAC[0]&0x01 != 0 || isZeroMAC(e.MAC) {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].IP.To4(), out[j].IP.To4()
		if a == nil || b == nil {
			return out[i].IP.String() < out[j].IP.String()
		}
		for k := 0; k < 4; k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return false
	})
	return out, nil
}

func isZeroMAC(m net.HardwareAddr) bool {
	for _, b := range m {
		if b != 0 {
			return false
		}
	}
	return true
}

// parseMACField normalises the MAC spellings the various ARP tools emit.
func parseMACField(s string) net.HardwareAddr {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	m, err := net.ParseMAC(s)
	if err != nil {
		return nil
	}
	return m
}

// StaleAfter returns the age past which a cached binding should be treated as
// unreliable. Used only for display.
func StaleAfter() time.Duration { return 2 * time.Minute }
