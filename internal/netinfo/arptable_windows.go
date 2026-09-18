//go:build windows

// language: Go, file: internal/netinfo/arptable_windows.go
package netinfo

import (
	"bufio"
	"bytes"
	"net"
	"os/exec"
	"strings"
)

// platformARPTable parses the Windows ARP cache.
//
// `arp -a` output is grouped per interface and looks like:
//
//	Interface: 192.168.1.9 --- 0xd
//	  Internet Address      Physical Address      Type
//	  192.168.1.1          00-11-22-33-44-55     dynamic
//	  192.168.1.255        ff-ff-ff-ff-ff-ff     static
//
// Only numeric rows are read, so a localised header does not break parsing.
func platformARPTable() ([]Entry, error) {
	cmd := exec.Command("arp", "-a")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	var out []Entry
	sc := bufio.NewScanner(&buf)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)

		// Interface header: "Interface: <ip> --- <index>"
		if len(fields) >= 4 && strings.HasPrefix(strings.ToLower(fields[0]), "interface") {
			continue
		}
		// A data row has exactly three fields: ip, mac, type.
		if len(fields) != 3 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil || ip.To4() == nil {
			continue
		}
		mac := parseMACField(fields[1])
		if mac == nil {
			continue
		}
		kind := strings.ToLower(fields[2])
		out = append(out, Entry{
			IP:  ip.To4(),
			MAC: mac,
			// Windows marks statically configured bindings "static"; the rest
			// are dynamic and can be invalidated at any time.
			Permanent: kind == "static",
		})
	}
	return out, sc.Err()
}
