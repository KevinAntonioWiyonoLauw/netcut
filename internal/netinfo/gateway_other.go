//go:build !windows

// language: Go, file: internal/netinfo/gateway_other.go
package netinfo

import (
	"bufio"
	"encoding/binary"
	"net"
	"os"
	"strings"
)

// platformGateways reads the IPv4 default route from /proc/net/route.
func platformGateways() map[string]net.IP {
	out := map[string]net.IP{}

	f, err := os.Open("/proc/net/route")
	if err != nil {
		return out
	}
	defer f.Close()

	ifaces, _ := net.Interfaces()
	ipToName := map[string]string{}
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if v4 := ipnet.IP.To4(); v4 != nil {
					ipToName[v4.String()] = ifc.Name
				}
			}
		}
	}

	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first { // header row
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		dev := fields[0]
		dest, err1 := parseHexLE(fields[1])
		gw, err2 := parseHexLE(fields[2])
		if err1 != nil || err2 != nil {
			continue
		}
		if dest != 0 || gw == 0 {
			continue
		}
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, gw)
		if _, exists := out[dev]; !exists {
			out[dev] = ip
		}
	}
	_ = ipToName
	return out
}

// parseHexLE decodes a little-endian hex word from /proc/net/route.
func parseHexLE(s string) (uint32, error) {
	var v uint32
	for i := 0; i < len(s); i++ {
		var d uint32
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			d = uint32(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint32(c-'A') + 10
		default:
			return 0, errBadHex
		}
		v = v<<4 | d
	}
	return v, nil
}

var errBadHex = os.ErrInvalid
