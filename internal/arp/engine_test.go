// language: Go, file: internal/arp/engine_test.go
package arp

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func mac(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("ParseMAC(%q): %v", s, err)
	}
	return m
}

// TestBuildARPReplyLayout verifies the exact on-wire bytes. A single wrong
// offset here produces a frame that looks plausible but silently fails to
// poison anything, so the layout is pinned field by field.
func TestBuildARPReplyLayout(t *testing.T) {
	dst := mac(t, "aa:bb:cc:dd:ee:01")
	src := mac(t, "11:22:33:44:55:66")
	claimedMAC := mac(t, "11:22:33:44:55:66")
	claimedIP := net.ParseIP("192.168.1.1").To4()
	targetMAC := mac(t, "aa:bb:cc:dd:ee:01")
	targetIP := net.ParseIP("192.168.1.50").To4()

	f := buildARPReply(dst, src, claimedMAC, claimedIP, targetMAC, targetIP)

	if len(f) != 42 {
		t.Fatalf("frame length = %d, want 42", len(f))
	}
	if !bytes.Equal(f[0:6], dst) {
		t.Errorf("destination MAC = %v, want %v", f[0:6], dst)
	}
	if !bytes.Equal(f[6:12], src) {
		t.Errorf("source MAC = %v, want %v", f[6:12], src)
	}
	if f[12] != 0x08 || f[13] != 0x06 {
		t.Errorf("ethertype = %02x%02x, want 0806 (ARP)", f[12], f[13])
	}

	arp := f[14:]
	if htype := uint16(arp[0])<<8 | uint16(arp[1]); htype != 1 {
		t.Errorf("hardware type = %d, want 1 (Ethernet)", htype)
	}
	if ptype := uint16(arp[2])<<8 | uint16(arp[3]); ptype != 0x0800 {
		t.Errorf("protocol type = %04x, want 0800 (IPv4)", ptype)
	}
	if arp[4] != 6 || arp[5] != 4 {
		t.Errorf("hlen/plen = %d/%d, want 6/4", arp[4], arp[5])
	}
	if op := uint16(arp[6])<<8 | uint16(arp[7]); op != 2 {
		t.Errorf("operation = %d, want 2 (reply)", op)
	}
	if !bytes.Equal(arp[8:14], claimedMAC) {
		t.Errorf("sender hardware = %v, want %v", arp[8:14], claimedMAC)
	}
	if !bytes.Equal(arp[14:18], claimedIP) {
		t.Errorf("sender protocol = %v, want %v", arp[14:18], claimedIP)
	}
	if !bytes.Equal(arp[18:24], targetMAC) {
		t.Errorf("target hardware = %v, want %v", arp[18:24], targetMAC)
	}
	if !bytes.Equal(arp[24:28], targetIP) {
		t.Errorf("target protocol = %v, want %v", arp[24:28], targetIP)
	}
}

func TestBuildARPRequestLayout(t *testing.T) {
	src := mac(t, "11:22:33:44:55:66")
	srcIP := net.ParseIP("192.168.1.10").To4()
	targetIP := net.ParseIP("192.168.1.1").To4()

	f := buildARPRequest(src, srcIP, targetIP)
	if len(f) != 42 {
		t.Fatalf("frame length = %d, want 42", len(f))
	}
	broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if !bytes.Equal(f[0:6], broadcast) {
		t.Errorf("destination = %v, want broadcast", f[0:6])
	}
	arp := f[14:]
	if op := uint16(arp[6])<<8 | uint16(arp[7]); op != 1 {
		t.Errorf("operation = %d, want 1 (request)", op)
	}
	if !bytes.Equal(arp[24:28], targetIP) {
		t.Errorf("target protocol = %v, want %v", arp[24:28], targetIP)
	}
}

// TestPoisonPairIsBidirectional is the core correctness check: enforcing a
// target requires two replies with mirrored roles, one telling the target that
// the gateway is at our MAC, and one telling the gateway that the target is at
// our MAC. Either one alone leaves traffic flowing around us.
func TestPoisonPairIsBidirectional(t *testing.T) {
	localMAC := mac(t, "11:22:33:44:55:66")
	gwMAC := mac(t, "aa:aa:aa:aa:aa:aa")
	targetMAC := mac(t, "bb:bb:bb:bb:bb:bb")
	gwIP := net.ParseIP("192.168.1.1").To4()
	targetIP := net.ParseIP("192.168.1.50").To4()

	// Reply 1: to the target, claiming the gateway sits at our MAC.
	toTarget := buildARPReply(targetMAC, localMAC, localMAC, gwIP, targetMAC, targetIP)
	// Reply 2: to the gateway, claiming the target sits at our MAC.
	toGateway := buildARPReply(gwMAC, localMAC, localMAC, targetIP, gwMAC, gwIP)

	arp1, arp2 := toTarget[14:], toGateway[14:]

	if !bytes.Equal(toTarget[0:6], targetMAC) {
		t.Error("reply 1 is not addressed to the target")
	}
	if !bytes.Equal(arp1[8:14], localMAC) || !bytes.Equal(arp1[14:18], gwIP) {
		t.Error("reply 1 does not claim the gateway IP is at our MAC")
	}
	if !bytes.Equal(toGateway[0:6], gwMAC) {
		t.Error("reply 2 is not addressed to the gateway")
	}
	if !bytes.Equal(arp2[8:14], localMAC) || !bytes.Equal(arp2[14:18], targetIP) {
		t.Error("reply 2 does not claim the target IP is at our MAC")
	}
}

// TestRestoreReversesTheClaim proves release sends the truthful mapping, which
// is what lets a device recover without waiting out its ARP cache.
func TestRestoreReversesTheClaim(t *testing.T) {
	localMAC := mac(t, "11:22:33:44:55:66")
	gwMAC := mac(t, "aa:aa:aa:aa:aa:aa")
	targetMAC := mac(t, "bb:bb:bb:bb:bb:bb")
	gwIP := net.ParseIP("192.168.1.1").To4()
	targetIP := net.ParseIP("192.168.1.50").To4()

	restore := buildARPReply(targetMAC, gwMAC, gwMAC, gwIP, targetMAC, targetIP)
	arp := restore[14:]
	if !bytes.Equal(arp[8:14], gwMAC) {
		t.Error("restore does not advertise the gateway's true MAC")
	}
	if bytes.Equal(arp[8:14], localMAC) {
		t.Error("restore still advertises our MAC: the device would stay hijacked")
	}
}

func TestShaperNilWhenUncapped(t *testing.T) {
	if s := newShaper(0, 0); s != nil {
		t.Fatal("a zero cap produced a shaper; uncapped traffic must pass unconditionally")
	}
	if s := newShaper(0, 512); s == nil {
		t.Fatal("the fallback cap was ignored")
	}
}

func TestShaperCapsSustainedRate(t *testing.T) {
	// 800 kbps == 100,000 bytes/second.
	s := newShaper(800, 0)
	if s == nil {
		t.Fatal("shaper was nil")
	}

	// Drain the initial burst first.
	frame := 1500
	for i := 0; i < 100; i++ {
		s.allow(frame)
	}

	// Over 200 ms at 100 kB/s the bucket refills with ~20 kB, so roughly 13
	// full-size frames should be admitted and the rest dropped.
	time.Sleep(200 * time.Millisecond)
	admitted := 0
	for i := 0; i < 200; i++ {
		if s.allow(frame) {
			admitted++
		}
	}
	if admitted == 0 {
		t.Fatal("the shaper admitted nothing: traffic would be fully blocked instead of limited")
	}
	if admitted > 40 {
		t.Fatalf("the shaper admitted %d frames in a 200ms burst at 800kbps, which exceeds the cap", admitted)
	}
}

func TestShaperAllowsSmallFramesUnderTinyCap(t *testing.T) {
	// A 32 kbps cap must still pass the occasional small control frame.
	s := newShaper(32, 0)
	if s == nil {
		t.Fatal("shaper was nil")
	}
	time.Sleep(60 * time.Millisecond)
	if !s.allow(60) {
		t.Fatal("a 60-byte frame was dropped under a 32 kbps cap: control traffic would stall")
	}
}

func TestHostsInSkipsNetworkAndBroadcast(t *testing.T) {
	_, n, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	hosts := hostsIn(n)
	if len(hosts) != 254 {
		t.Fatalf("hostsIn(/24) returned %d hosts, want 254", len(hosts))
	}
	if hosts[0].String() != "192.168.1.1" {
		t.Errorf("first host = %s, want 192.168.1.1", hosts[0])
	}
	if hosts[len(hosts)-1].String() != "192.168.1.254" {
		t.Errorf("last host = %s, want 192.168.1.254", hosts[len(hosts)-1])
	}
	for _, h := range hosts {
		if h.String() == "192.168.1.0" || h.String() == "192.168.1.255" {
			t.Fatalf("network or broadcast address was included: %s", h)
		}
	}
}

func TestHostsInIsBounded(t *testing.T) {
	_, n, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(hostsIn(n)); got > 4096 {
		t.Fatalf("hostsIn(/8) returned %d hosts; it must be capped to avoid stalling the agent", got)
	}
}

func TestIPv4Dst(t *testing.T) {
	frame := make([]byte, 54)
	copy(frame[12:14], []byte{0x08, 0x00})
	frame[14] = 0x45 // IPv4, IHL 5
	copy(frame[30:34], net.ParseIP("192.168.1.9").To4())

	if got := ipv4Dst(frame); got == nil || got.String() != "192.168.1.9" {
		t.Fatalf("ipv4Dst = %v, want 192.168.1.9", got)
	}

	// Too short to hold a header.
	if got := ipv4Dst(frame[:20]); got != nil {
		t.Fatalf("ipv4Dst on a truncated frame = %v, want nil", got)
	}

	// Not IPv4.
	arpFrame := make([]byte, 60)
	copy(arpFrame[12:14], []byte{0x08, 0x06})
	if got := ipv4Dst(arpFrame); got != nil {
		t.Fatalf("ipv4Dst on an ARP frame = %v, want nil", got)
	}
}

func TestVendorFor(t *testing.T) {
	cases := map[string]string{
		"00:e0:fc:12:34:56": "Huawei",
		"b8:27:eb:12:34:56": "Raspberry Pi",
		"08:00:27:aa:bb:cc": "VirtualBox",
		"ac:bc:32:11:22:33": "Apple",
	}
	for in, want := range cases {
		if got := VendorFor(mac(t, in)); got != want {
			t.Errorf("VendorFor(%s) = %q, want %q", in, got, want)
		}
	}
	// A locally administered address is randomised by the OS, not a vendor.
	if got := VendorFor(mac(t, "02:11:22:33:44:55")); got != "Randomised (private)" {
		t.Errorf("locally administered MAC = %q, want the randomised label", got)
	}
}

func TestIsMulticast(t *testing.T) {
	if !IsMulticast(mac(t, "01:00:5e:00:00:01")) {
		t.Error("a multicast address was not detected")
	}
	if IsMulticast(mac(t, "aa:bb:cc:dd:ee:ff")) {
		t.Error("a unicast address was reported as multicast")
	}
}

func TestSetTargetsRefusesToEnforceOurselves(t *testing.T) {
	e, err := New(Options{LocalIP: net.ParseIP("192.168.1.9"), Log: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	e.localMA = mac(t, "11:22:33:44:55:66")
	e.gwMAC = mac(t, "aa:aa:aa:aa:aa:aa")

	e.SetTargets([]Target{
		{MAC: mac(t, "11:22:33:44:55:66"), IP: net.ParseIP("192.168.1.9"), Mode: ModeBlock},
		{MAC: mac(t, "aa:aa:aa:aa:aa:aa"), IP: net.ParseIP("192.168.1.1"), Mode: ModeBlock},
		{MAC: mac(t, "bb:bb:bb:bb:bb:bb"), IP: net.ParseIP("192.168.1.50"), Mode: ModeBlock},
	})

	if len(e.targets) != 1 {
		t.Fatalf("engine holds %d targets, want 1: it must never enforce on itself or the gateway", len(e.targets))
	}
	if _, ok := e.targets["bb:bb:bb:bb:bb:bb"]; !ok {
		t.Fatal("the legitimate target was not accepted")
	}
}

func TestSetTargetsIgnoresNonEnforcingModes(t *testing.T) {
	e, err := New(Options{LocalIP: net.ParseIP("192.168.1.9"), Log: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	e.localMA = mac(t, "11:22:33:44:55:66")

	e.SetTargets([]Target{
		{MAC: mac(t, "bb:bb:bb:bb:bb:bb"), IP: net.ParseIP("192.168.1.50"), Mode: ModeAllow},
		{MAC: mac(t, "cc:cc:cc:cc:cc:cc"), IP: net.ParseIP("192.168.1.51"), Mode: ModeObserve},
	})
	if len(e.targets) != 0 {
		t.Fatalf("allow/observe produced %d enforced targets, want 0", len(e.targets))
	}
}

func TestSetTargetsReleasesRemovedTarget(t *testing.T) {
	e, err := New(Options{LocalIP: net.ParseIP("192.168.1.9"), Log: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	e.localMA = mac(t, "11:22:33:44:55:66")
	e.gwMAC = mac(t, "aa:aa:aa:aa:aa:aa")

	e.SetTargets([]Target{
		{MAC: mac(t, "bb:bb:bb:bb:bb:bb"), IP: net.ParseIP("192.168.1.50"), Mode: ModeBlock},
	})
	if len(e.targets) != 1 {
		t.Fatalf("setup failed: %d targets", len(e.targets))
	}
	e.SetTargets(nil)
	if len(e.targets) != 0 {
		t.Fatalf("released target is still enforced: %d targets remain", len(e.targets))
	}
}

func TestSetTargetsUpdatesCap(t *testing.T) {
	e, err := New(Options{LocalIP: net.ParseIP("192.168.1.9"), Log: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	e.localMA = mac(t, "11:22:33:44:55:66")

	e.SetTargets([]Target{
		{MAC: mac(t, "bb:bb:bb:bb:bb:bb"), IP: net.ParseIP("192.168.1.50"), Mode: ModeThrottle, CapKbps: 512},
	})
	if e.targets["bb:bb:bb:bb:bb:bb"].shaperDn == nil {
		t.Fatal("no download shaper was created for a throttled target")
	}
	e.SetTargets([]Target{
		{MAC: mac(t, "bb:bb:bb:bb:bb:bb"), IP: net.ParseIP("192.168.1.50"), Mode: ModeThrottle, CapKbps: 128},
	})
	if got := e.targets["bb:bb:bb:bb:bb:bb"].stats.CapKbps; got != 128 {
		t.Fatalf("cap = %d, want 128 after update", got)
	}
}

func TestSetTargetsRejectsMalformedMAC(t *testing.T) {
	e, err := New(Options{LocalIP: net.ParseIP("192.168.1.9"), Log: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	e.localMA = mac(t, "11:22:33:44:55:66")
	e.SetTargets([]Target{
		{MAC: net.HardwareAddr{0x01, 0x02}, IP: net.ParseIP("192.168.1.50"), Mode: ModeBlock},
		{MAC: nil, IP: net.ParseIP("192.168.1.51"), Mode: ModeBlock},
	})
	if len(e.targets) != 0 {
		t.Fatalf("a malformed MAC produced %d targets", len(e.targets))
	}
}

func TestNewRequiresLocalIP(t *testing.T) {
	if _, err := New(Options{Log: discardLogger()}); err == nil {
		t.Fatal("New accepted a missing local IP")
	}
}
