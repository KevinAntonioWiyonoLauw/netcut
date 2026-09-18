//go:build windows

// language: Go, file: internal/netinfo/gateway_windows.go
package netinfo

import (
	"bufio"
	"bytes"
	"net"
	"os/exec"
	"strings"
)

// platformGateways reads the IPv4 default route from the Windows routing table.
//
// `route print -4` is used rather than the IP Helper API because it needs no
// elevation and no cgo. Only the numeric data lines are parsed, so a localised
// header does not break it: a default route is always the row
//
//	0.0.0.0  0.0.0.0  <gateway>  <interface-ip>  <metric>
func platformGateways() map[string]net.IP {
	out := map[string]net.IP{}

	cmd := exec.Command("route", "print", "-4")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return out
	}

	// Map interface IP -> interface name once, so the gateway can be attached
	// to the right interface.
	ipToName := map[string]string{}
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			addrs, err := ifc.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok {
					if v4 := ipnet.IP.To4(); v4 != nil {
						ipToName[v4.String()] = ifc.Name
					}
				}
			}
		}
	}

	sc := bufio.NewScanner(&buf)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		if fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" {
			continue
		}
		gw := net.ParseIP(fields[2])
		ifaceIP := fields[3]
		if gw == nil {
			continue
		}
		if name, ok := ipToName[ifaceIP]; ok {
			if _, exists := out[name]; !exists {
				out[name] = gw.To4()
			}
		}
	}
	return out
}
