//go:build !windows

// language: Go, file: internal/netinfo/arptable_other.go
package netinfo

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// platformARPTable parses /proc/net/arp, which looks like:
//
//	IP address       HW type     Flags       HW address            Mask     Device
//	192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
//
// Flag 0x2 is ATF_COM (complete); 0x4 is ATF_PERM. An entry without the
// complete flag has not been resolved and is skipped.
func platformARPTable() ([]Entry, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ifaces, _ := net.Interfaces()
	nameToIndex := map[string]int{}
	for _, ifc := range ifaces {
		nameToIndex[ifc.Name] = ifc.Index
	}

	var out []Entry
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil || ip.To4() == nil {
			continue
		}
		mac := parseMACField(fields[3])
		if mac == nil {
			continue
		}
		flags := parseHexField(fields[2])
		if flags&0x2 == 0 {
			continue // not complete
		}
		out = append(out, Entry{
			IP:        ip.To4(),
			MAC:       mac,
			IfIndex:   nameToIndex[fields[5]],
			Permanent: flags&0x4 != 0,
		})
	}
	return out, sc.Err()
}

// parseHexField reads a 0x-prefixed hex value, returning 0 on any malformed
// input rather than failing the whole table read.
func parseHexField(s string) int {
	s = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "0x"), "0X")
	v := 0
	for i := 0; i < len(s); i++ {
		var d int
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = int(c-'A') + 10
		default:
			return v
		}
		v = v<<4 | d
	}
	return v
}
