// language: Go, file: internal/netinfo/netinfo.go
// Interface, subnet and neighbour discovery used by the agent to decide which
// segment it is responsible for.
package netinfo

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

// Iface describes a usable interface on this host.
type Iface struct {
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Mask    string `json:"mask"`
	CIDR    string `json:"cidr"`
	MAC     string `json:"mac"`
	Gateway string `json:"gateway"`
	Up      bool   `json:"up"`
	// Usable marks an interface that can carry layer-2 enforcement: a real
	// Ethernet address, an IPv4 subnet, and a default gateway.
	Usable bool   `json:"usable"`
	Note   string `json:"note"`
}

// LoopbackAndVirtual lists interface name fragments that never carry the
// segment we want to police.
var LoopbackAndVirtual = []string{
	"loopback", "hyper-v", "vethernet", "virtualbox", "vmware", "docker",
	"wsl", "tailscale", "zerotier", "openvpn", "tap-", "tun", "bluetooth",
	"npcap loopback", "isatap", "teredo", "wintun", "wireguard", "vpn",
	"local area connection*",
}

// Ifaces enumerates the interfaces of this host with their IPv4 configuration.
func Ifaces() ([]Iface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	gws := defaultGateways()

	var out []Iface
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			fi := Iface{
				Name: ifc.Name,
				IP:   ip4.String(),
				Mask: net.IP(ipnet.Mask).String(),
				CIDR: fmt.Sprintf("%s/%d", ip4.Mask(net.CIDRMask(ones, 32)).String(), ones),
				Up:   ifc.Flags&net.FlagUp != 0,
			}
			if len(ifc.HardwareAddr) == 6 {
				fi.MAC = ifc.HardwareAddr.String()
			}
			if gw, ok := gws[ifc.Name]; ok {
				fi.Gateway = gw.String()
			}
			fi.Usable, fi.Note = assess(fi, ifc.Flags)
			out = append(out, fi)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Usable != out[j].Usable {
			return out[i].Usable
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func assess(fi Iface, flags net.Flags) (bool, string) {
	if flags&net.FlagLoopback != 0 {
		return false, "loopback"
	}
	if !fi.Up {
		return false, "interface is down"
	}
	if fi.MAC == "" {
		return false, "no Ethernet address"
	}
	low := strings.ToLower(fi.Name)
	for _, frag := range LoopbackAndVirtual {
		if strings.Contains(low, frag) {
			return false, "virtual or tunnelled interface"
		}
	}
	if strings.HasPrefix(fi.IP, "169.254.") {
		return false, "self-assigned address (no DHCP lease)"
	}
	if fi.Gateway == "" {
		return false, "no default gateway on this interface"
	}
	return true, ""
}

// Best picks the interface most likely to be the monitored segment: the usable
// one that owns the default route.
func Best() (*Iface, error) {
	all, err := Ifaces()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].Usable {
			return &all[i], nil
		}
	}
	// Nothing scored as usable; fall back to the first non-loopback with a
	// gateway so the operator still gets a diagnosable answer.
	for i := range all {
		if all[i].Gateway != "" && !strings.HasPrefix(all[i].IP, "169.254.") {
			return &all[i], nil
		}
	}
	return nil, errors.New("no interface with an IPv4 address and a default gateway was found")
}

// ParseSubnet turns an interface CIDR into a masked network.
func ParseSubnet(cidr string) (*net.IPNet, error) {
	_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, fmt.Errorf("parse subnet %q: %w", cidr, err)
	}
	return n, nil
}

// SubnetOf derives the network for an IP and mask size.
func SubnetOf(ip string, ones int) (*net.IPNet, error) {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return nil, fmt.Errorf("parse ip %q: not IPv4", ip)
	}
	if ones < 8 || ones > 32 {
		return nil, fmt.Errorf("invalid prefix length %d", ones)
	}
	return &net.IPNet{IP: parsed.Mask(net.CIDRMask(ones, 32)), Mask: net.CIDRMask(ones, 32)}, nil
}

// InSubnet reports whether ip belongs to n.
func InSubnet(ip net.IP, n *net.IPNet) bool {
	if n == nil || ip == nil {
		return false
	}
	return n.Contains(ip)
}

// defaultGateways maps interface name to its default gateway.
func defaultGateways() map[string]net.IP {
	out := map[string]net.IP{}
	// Read the OS routing table through a small platform shim; when it is
	// unavailable the caller can still specify the gateway explicitly.
	for name, ip := range platformGateways() {
		out[name] = ip
	}
	return out
}
