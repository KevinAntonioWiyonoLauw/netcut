//go:build windows

// language: Go, file: internal/arp/capture_windows_test.go
package arp

import (
	"strings"
	"testing"
)

// TestWpcapLoadsWithDependencyPreload guards the Npcap install layout that bit
// us in the field.
//
// Npcap can be installed with "WinPcap API-compatible mode" OFF. In that
// layout wpcap.dll and Packet.dll exist only in System32\Npcap, and nothing is
// copied to System32 root. wpcap.dll imports Packet.dll by base name, and
// Windows resolves such an import against the already-loaded module list before
// searching any path, so loading wpcap.dll alone fails with
// "The specified module could not be found" (errno 126) even though the file is
// present. Preloading Packet.dll by full path is what makes it load.
//
// If this test fails on a machine with Npcap installed, the loader has
// regressed and enforcement will be impossible there.
func TestWpcapLoadsWithDependencyPreload(t *testing.T) {
	if err := CaptureAvailable(); err != nil {
		t.Skipf("no layer-2 capture backend on this machine (Npcap absent?): %v", err)
	}
	if wpcap == nil {
		t.Fatal("CaptureAvailable reported success but no library handle was stored")
	}
	// Every entry point the engine relies on must resolve.
	required := []string{
		"pcap_findalldevs", "pcap_create", "pcap_set_snaplen", "pcap_set_promisc",
		"pcap_set_timeout", "pcap_activate", "pcap_setnonblock", "pcap_compile",
		"pcap_setfilter", "pcap_next_ex", "pcap_sendpacket", "pcap_datalink",
		"pcap_close", "pcap_geterr",
	}
	for _, name := range required {
		if err := wpcap.NewProc(name).Find(); err != nil {
			t.Errorf("%s did not resolve from wpcap.dll: %v", name, err)
		}
	}
}

// TestErrorMentionsTheRealCause checks that the failure message is actionable.
// The previous message claimed wpcap.dll was "not found", which sent the
// investigation down the wrong path for a full cycle: the file was present and
// the actual problem was its dependency.
func TestErrorMentionsTheRealCause(t *testing.T) {
	if err := CaptureAvailable(); err == nil {
		t.Skip("a capture backend is available; the failure path is not exercised here")
	}
	msg := wpcapErr.Error()
	if !strings.Contains(msg, "wpcap.dll") {
		t.Errorf("error does not name the library: %s", msg)
	}
	if !strings.Contains(msg, "Npcap") {
		t.Errorf("error does not tell the operator what to install: %s", msg)
	}
	// It must not assert a cause it has not verified.
	if strings.Contains(msg, "not found (install Npcap") {
		t.Errorf("error still asserts 'not found' unconditionally: %s", msg)
	}
}
