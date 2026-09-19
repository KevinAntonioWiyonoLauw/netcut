// language: Go, file: internal/arp/arprelay_test.go
package arp

import (
	"encoding/binary"
	"net"
	"testing"
)

// arpFrame builds an ARP frame for the tests.
//
// oper 1 = request, 2 = reply.
func arpFrame(dstMAC, srcMAC net.HardwareAddr, oper uint16,
	senderMAC net.HardwareAddr, senderIP net.IP,
	targetMAC net.HardwareAddr, targetIP net.IP) []byte {

	f := make([]byte, 42)
	copy(f[0:6], dstMAC)
	copy(f[6:12], srcMAC)
	f[12], f[13] = 0x08, 0x06
	arp := f[14:]
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], 0x0800)
	arp[4], arp[5] = 6, 4
	binary.BigEndian.PutUint16(arp[6:8], oper)
	copy(arp[8:14], senderMAC)
	copy(arp[14:18], senderIP.To4())
	copy(arp[18:24], targetMAC)
	copy(arp[24:28], targetIP.To4())
	return f
}

var (
	bcast    = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	zeroMAC  = net.HardwareAddr{0, 0, 0, 0, 0, 0}
	localMAC = net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	gwMAC    = net.HardwareAddr{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
	peerMAC  = net.HardwareAddr{0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb}
	otherMAC = net.HardwareAddr{0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc}

	localIP = net.ParseIP("192.168.1.9")
	gwIP    = net.ParseIP("192.168.1.1")
	peerIP  = net.ParseIP("192.168.1.50")
	otherIP = net.ParseIP("192.168.1.51")
)

// engineWithPeer builds an engine holding one enforced target.
func engineWithPeer(t *testing.T) *Engine {
	t.Helper()
	e, err := New(Options{LocalIP: localIP, Log: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	e.localMA = localMAC
	e.gwMAC = gwMAC
	e.gwIP = gwIP
	e.SetTargets([]Target{{MAC: peerMAC, IP: peerIP, Mode: ModeThrottle, CapKbps: 256}})
	return e
}

// TestARPMattersOnlyForEnforcedPeers pins which ARP frames must be handled.
//
// Getting this wrong in the permissive direction adds traffic for unrelated
// devices; getting it wrong in the restrictive direction drops the ARP that
// keeps a poisoned device reachable, which breaks the whole segment.
func TestARPMattersOnlyForEnforcedPeers(t *testing.T) {
	e := engineWithPeer(t)

	cases := []struct {
		name string
		f    []byte
		want bool
	}{
		{
			// The gateway asking who has the enforced device. This is the
			// request whose answer keeps the device reachable, so it must be
			// handled or the device loses its mapping and broadcasts forever.
			"gateway asks for the enforced peer",
			arpFrame(bcast, gwMAC, 1, gwMAC, gwIP, zeroMAC, peerIP),
			true,
		},
		{
			"enforced peer asks for the gateway",
			arpFrame(bcast, peerMAC, 1, peerMAC, peerIP, zeroMAC, gwIP),
			true,
		},
		{
			"an unrelated device asks for the gateway",
			arpFrame(bcast, otherMAC, 1, otherMAC, otherIP, zeroMAC, gwIP),
			false,
		},
		{
			"the gateway asks for an unrelated device",
			arpFrame(bcast, gwMAC, 1, gwMAC, gwIP, zeroMAC, otherIP),
			false,
		},
		{
			"too short to parse",
			make([]byte, 20),
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := e.arpMatters(tc.f); got != tc.want {
				t.Errorf("arpMatters = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestARPMattersIsSafeWithNoTargets: with nothing enforced there is nothing to
// relay, and in particular no reason to touch ARP at all.
func TestARPMattersIsSafeWithNoTargets(t *testing.T) {
	e, err := New(Options{LocalIP: localIP, Log: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	e.localMA = localMAC
	e.gwMAC = gwMAC
	e.gwIP = gwIP

	f := arpFrame(bcast, gwMAC, 1, gwMAC, gwIP, zeroMAC, peerIP)
	if e.arpMatters(f) {
		t.Error("arpMatters reported interest with no targets enforced")
	}
}

// TestAnswerARPMustReassertTheRedirect is the subtle and dangerous one.
//
// Poisoning tells the gateway that the enforced device lives at our MAC. When
// the gateway later asks who has that device, answering with the device's real
// MAC would tell the truth and silently end enforcement — traffic would start
// flowing directly again while the dashboard still showed the cap as applied.
//
// The answer must therefore re-assert the redirect, exactly as the poison round
// does. A device that asks who has the gateway must likewise be told the
// gateway is at our MAC, not the gateway's real address.
func TestAnswerARPMustReassertTheRedirect(t *testing.T) {
	e := engineWithPeer(t)

	// Capture what we transmit instead of putting it on the wire.
	var sent [][]byte
	e.writeHook = func(f []byte) error {
		out := make([]byte, len(f))
		copy(out, f)
		sent = append(sent, out)
		return nil
	}

	// The gateway asks: who has the enforced peer?
	req := arpFrame(bcast, gwMAC, 1, gwMAC, gwIP, zeroMAC, peerIP)
	e.answerARP(req)

	if len(sent) != 1 {
		t.Fatalf("sent %d frames, want exactly 1 answer", len(sent))
	}
	reply := sent[0]
	arp := reply[14:]

	// The claimed MAC in the answer is at offset 8, the claimed IP at 14.
	claimedMAC := net.HardwareAddr(arp[8:14])
	claimedIP := net.IP(arp[14:18]).To4()

	if claimedIP.String() != peerIP.String() {
		t.Errorf("answered about %s, want the peer %s", claimedIP, peerIP)
	}
	if claimedMAC.String() == peerMAC.String() {
		t.Error("answered with the peer's real MAC: that tells the gateway the " +
			"truth and silently disables enforcement")
	}
	if claimedMAC.String() != localMAC.String() {
		t.Errorf("claimed MAC = %s, want our own %s so traffic keeps coming "+
			"through us", claimedMAC, localMAC)
	}
}

// TestAnswerARPForThePeerAskingAboutTheGateway covers the other direction.
func TestAnswerARPForThePeerAskingAboutTheGateway(t *testing.T) {
	e := engineWithPeer(t)

	var sent [][]byte
	e.writeHook = func(f []byte) error {
		out := make([]byte, len(f))
		copy(out, f)
		sent = append(sent, out)
		return nil
	}

	// The enforced peer asks: who has the gateway?
	req := arpFrame(bcast, peerMAC, 1, peerMAC, peerIP, zeroMAC, gwIP)
	e.answerARP(req)

	if len(sent) != 1 {
		t.Fatalf("sent %d frames, want exactly 1 answer", len(sent))
	}
	arp := sent[0][14:]
	claimedMAC := net.HardwareAddr(arp[8:14])
	claimedIP := net.IP(arp[14:18]).To4()

	if claimedIP.String() != gwIP.String() {
		t.Errorf("answered about %s, want the gateway %s", claimedIP, gwIP)
	}
	if claimedMAC.String() == gwMAC.String() {
		t.Error("told the peer the gateway's real MAC: it would bypass us and " +
			"enforcement would stop")
	}
	if claimedMAC.String() != localMAC.String() {
		t.Errorf("claimed MAC = %s, want our own %s", claimedMAC, localMAC)
	}
}

// TestAnswerARPStaysSilentWhenUninvolved: we must not answer for devices we are
// not enforcing, or we would become a second, wrong source of truth for the
// whole segment.
func TestAnswerARPStaysSilentWhenUninvolved(t *testing.T) {
	e := engineWithPeer(t)

	var sent [][]byte
	e.writeHook = func(f []byte) error {
		out := make([]byte, len(f))
		copy(out, f)
		sent = append(sent, out)
		return nil
	}

	// Two unrelated parties resolving each other.
	e.answerARP(arpFrame(bcast, otherMAC, 1, otherMAC, otherIP, zeroMAC, net.ParseIP("192.168.1.60")))
	// A reply, which is never answered.
	e.answerARP(arpFrame(localMAC, gwMAC, 2, gwMAC, gwIP, peerMAC, peerIP))
	// Our own frame, re-captured.
	e.answerARP(arpFrame(bcast, localMAC, 1, localMAC, localIP, zeroMAC, gwIP))

	if len(sent) != 0 {
		t.Errorf("sent %d frames while uninvolved, want 0", len(sent))
	}
}

// TestArpMattersWithNilGatewayIsSafe guards a nil dereference on a segment whose
// gateway has not been resolved yet.
func TestArpMattersWithNilGatewayIsSafe(t *testing.T) {
	e, err := New(Options{LocalIP: localIP, Log: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	e.localMA = localMAC
	e.gwMAC = nil
	e.gwIP = nil
	e.SetTargets([]Target{{MAC: peerMAC, IP: peerIP, Mode: ModeThrottle, CapKbps: 256}})

	// The gateway is unknown, so a peer asking for it cannot be answered, but
	// the gateway asking for a peer still matters.
	if !e.arpMatters(arpFrame(bcast, gwMAC, 1, gwMAC, gwIP, zeroMAC, peerIP)) {
		t.Error("a request for an enforced peer must matter even without a gateway")
	}
	e.answerARP(arpFrame(bcast, peerMAC, 1, peerMAC, peerIP, zeroMAC, gwIP))
}
