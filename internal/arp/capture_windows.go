//go:build windows

// language: Go, file: internal/arp/capture_windows.go
//
// Layer-2 capture and injection on Windows via Npcap's wpcap.dll, bound
// directly through syscall so the agent stays a single static binary with no
// cgo and no C toolchain at build time.
//
// Npcap is required (Wireshark installs it, and it is present on most machines
// that already do packet-level work). The DLL is located through the standard
// search path, which includes C:\Windows\System32\Npcap.
//
// Pointer discipline: every address that arrives from the DLL is carried as an
// unsafe.Pointer and offset with unsafe.Add, never as uintptr arithmetic. That
// keeps the code inside the rules the GC and go vet expect for FFI.
package arp

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// errTimeout signals that no frame was available within the read budget.
var errTimeout = errors.New("capture read timeout")

func isTimeout(err error) bool { return errors.Is(err, errTimeout) }

// captureDevice is the platform capture surface the engine depends on.
type captureDevice interface {
	ReadPacket(timeout time.Duration) ([]byte, error)
	WritePacket(frame []byte) error
	LinkType() int
	Close() error
}

const (
	pcapErrBufSize = 256
	// pcap_pkthdr on Windows is struct timeval {int32,int32} + uint32 caplen +
	// uint32 len, so caplen sits at offset 8. On Linux, where long is 64 bits,
	// it would be 16; this file is Windows-only.
	offPcapCaplen = 8
	// Offsets into pcap_if_t (64-bit): next *pcap_if_t, name *char,
	// description *char, addresses *pcap_addr, flags uint32.
	offIfNext  = 0
	offIfName  = 8
	offIfDesc  = 16
	offIfAddrs = 24
	// Offsets into pcap_addr: next *pcap_addr, addr *sockaddr, then netmask,
	// broadaddr, dstaddr.
	offAddrNext = 0
	offAddrAddr = 8
	// A sockaddr_in carries sin_family (uint16) then sin_port, then sin_addr.
	offSockFamily = 0
	offSockAddr   = 4
	afINET        = 2
)

var (
	wpcapOnce sync.Once
	wpcap     *syscall.LazyDLL
	wpcapErr  error

	procFindAllDevs  *syscall.LazyProc
	procCreate       *syscall.LazyProc
	procSetSnaplen   *syscall.LazyProc
	procSetPromisc   *syscall.LazyProc
	procSetTimeout   *syscall.LazyProc
	procSetImmediate *syscall.LazyProc
	procSetBufSize   *syscall.LazyProc
	procActivate     *syscall.LazyProc
	procSetNonblock  *syscall.LazyProc
	procCompile      *syscall.LazyProc
	procSetFilter    *syscall.LazyProc
	procNextEx       *syscall.LazyProc
	procSendPacket   *syscall.LazyProc
	procDataLink     *syscall.LazyProc
	procClose        *syscall.LazyProc
	procGetErr       *syscall.LazyProc
	procFreeCode     *syscall.LazyProc
	procFreeAllDevs  *syscall.LazyProc
	procStat         *syscall.LazyProc
)

// loadWpcap resolves wpcap.dll and every entry point once.
func loadWpcap() error {
	wpcapOnce.Do(func() {
		// Npcap can be installed with "WinPcap API-compatible mode" OFF, in
		// which case wpcap.dll and Packet.dll live only in the Npcap directory
		// and no copies are placed in System32 root.
		//
		// That matters because wpcap.dll imports Packet.dll by base name, and
		// Windows resolves such an import against the already-loaded module
		// list before searching any path. So loading Packet.dll by full path
		// first satisfies the dependency; without it wpcap.dll fails with
		// "The specified module could not be found" even though the file is
		// sitting right there. Verified: errno 126 without, loads with.
		dirs := []string{
			`C:\Windows\System32\Npcap`,
			`C:\Windows\System32`,
			`C:\Program Files\Npcap`,
		}

		var lastErr error
		for _, d := range dirs {
			// Best effort: in a WinPcap-compatible install Packet.dll is
			// already resolvable, and preloading is then a no-op.
			_ = syscall.NewLazyDLL(d + `\Packet.dll`).Load()

			dll := syscall.NewLazyDLL(d + `\wpcap.dll`)
			if err := dll.Load(); err == nil {
				wpcap = dll
				break
			} else {
				lastErr = err
			}
		}
		if wpcap == nil {
			// Last attempt through the default search order.
			dll := syscall.NewLazyDLL("wpcap.dll")
			if err := dll.Load(); err == nil {
				wpcap = dll
			}
		}
		if wpcap == nil {
			wpcapErr = fmt.Errorf("%w: could not load wpcap.dll (%v). Install Npcap from https://npcap.com; if it is already installed, re-run its installer and tick \"Install Npcap in WinPcap API-compatible Mode\", or add %s to the PATH",
				ErrUnsupported, lastErr, `C:\Windows\System32\Npcap`)
			return
		}

		need := []struct {
			dst  **syscall.LazyProc
			name string
		}{
			{&procFindAllDevs, "pcap_findalldevs"},
			{&procCreate, "pcap_create"},
			{&procSetSnaplen, "pcap_set_snaplen"},
			{&procSetPromisc, "pcap_set_promisc"},
			{&procSetTimeout, "pcap_set_timeout"},
			{&procSetBufSize, "pcap_set_buffer_size"},
			{&procActivate, "pcap_activate"},
			{&procSetNonblock, "pcap_setnonblock"},
			{&procCompile, "pcap_compile"},
			{&procSetFilter, "pcap_setfilter"},
			{&procNextEx, "pcap_next_ex"},
			{&procSendPacket, "pcap_sendpacket"},
			{&procDataLink, "pcap_datalink"},
			{&procClose, "pcap_close"},
			{&procGetErr, "pcap_geterr"},
			{&procFreeCode, "pcap_freecode"},
			{&procFreeAllDevs, "pcap_freealldevs"},
		}
		for _, n := range need {
			p := wpcap.NewProc(n.name)
			if err := p.Find(); err != nil {
				wpcapErr = fmt.Errorf("%w: %s missing from wpcap.dll: %v", ErrUnsupported, n.name, err)
				return
			}
			*n.dst = p
		}
		// Optional entry points: absent in older WinPcap builds.
		if p := wpcap.NewProc("pcap_set_immediate_mode"); p.Find() == nil {
			procSetImmediate = p
		}
		if p := wpcap.NewProc("pcap_stats"); p.Find() == nil {
			procStat = p
		}
	})
	return wpcapErr
}

// CaptureAvailable reports whether a layer-2 capture backend can be loaded.
//
// It exists so -check can tell the operator whether enforcement is even
// possible on this machine, before they wonder why nothing is being applied.
// It loads the library but opens no device and transmits nothing.
func CaptureAvailable() error { return loadWpcap() }

type pcapHandle struct {
	p       unsafe.Pointer
	mu      sync.Mutex
	closed  bool
	linkTyp int
}

// openCapture activates a pcap handle on the interface owning ip, filtered to
// the traffic the engine actually needs.
func openCapture(ifaceName string, ip net.IP, filter string) (captureDevice, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := loadWpcap(); err != nil {
		return nil, err
	}

	devName, err := findDeviceName(ifaceName, ip)
	if err != nil {
		return nil, err
	}

	errBuf := make([]byte, pcapErrBufSize)
	namePtr, err := syscall.BytePtrFromString(devName)
	if err != nil {
		return nil, err
	}

	handle, _, _ := procCreate.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(&errBuf[0])),
	)
	if handle == 0 {
		return nil, fmt.Errorf("pcap_create(%s): %s", devName, cString(errBuf))
	}
	h := uintptrToPtr(handle)

	fail := func(what string, rc uintptr) (captureDevice, error) {
		msg := getErr(h)
		procClose.Call(handle)
		return nil, fmt.Errorf("%s failed (rc=%d): %s", what, int32(rc), msg)
	}

	// A 4 MB kernel buffer absorbs a burst arriving faster than the Go side
	// drains it, which is exactly what a throttle produces.
	if rc, _, _ := procSetBufSize.Call(handle, uintptr(4<<20)); int32(rc) != 0 {
		_ = rc // non-fatal: the default buffer is used
	}
	if rc, _, _ := procSetSnaplen.Call(handle, uintptr(65535)); int32(rc) != 0 {
		return fail("pcap_set_snaplen", rc)
	}
	if rc, _, _ := procSetPromisc.Call(handle, 1); int32(rc) != 0 {
		return fail("pcap_set_promisc", rc)
	}
	// A 1 ms timeout keeps reads responsive without spinning.
	if rc, _, _ := procSetTimeout.Call(handle, 1); int32(rc) != 0 {
		return fail("pcap_set_timeout", rc)
	}
	if procSetImmediate != nil {
		if rc, _, _ := procSetImmediate.Call(handle, 1); int32(rc) != 0 {
			return fail("pcap_set_immediate_mode", rc)
		}
	}
	if rc, _, _ := procActivate.Call(handle); int32(rc) != 0 {
		msg := getErr(h)
		procClose.Call(handle)
		return nil, fmt.Errorf("pcap_activate failed (rc=%d): %s - on Windows the agent must run elevated and Npcap must be installed with the WinPcap API-compatible option", int32(rc), msg)
	}

	if filter != "" {
		if err := applyFilter(h, filter); err != nil {
			procClose.Call(handle)
			return nil, err
		}
	}

	nbErr := make([]byte, pcapErrBufSize)
	if rc, _, _ := procSetNonblock.Call(handle,
		uintptr(unsafe.Pointer(&nbErr[0])), 1); int32(rc) != 0 {
		procClose.Call(handle)
		return nil, fmt.Errorf("pcap_setnonblock failed: %s", cString(nbErr))
	}

	lt, _, _ := procDataLink.Call(handle)
	return &pcapHandle{p: h, linkTyp: int(int32(lt))}, nil
}

func applyFilter(h unsafe.Pointer, filter string) error {
	fp, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return err
	}
	// struct bpf_program is opaque here; pcap only needs a stable buffer.
	var prog [64]byte
	if rc, _, _ := procCompile.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&prog[0])),
		uintptr(unsafe.Pointer(fp)),
		1,          // optimize
		0xffffff00, // netmask, only relevant to broadcast/multicast primitives
	); int32(rc) != 0 {
		return fmt.Errorf("pcap_compile(%q) failed: %s", filter, getErr(h))
	}
	defer procFreeCode.Call(uintptr(unsafe.Pointer(&prog[0])))
	if rc, _, _ := procSetFilter.Call(uintptr(h), uintptr(unsafe.Pointer(&prog[0]))); int32(rc) != 0 {
		return fmt.Errorf("pcap_setfilter failed: %s", getErr(h))
	}
	return nil
}

// ReadPacket returns the next captured frame, or errTimeout if none arrived.
func (h *pcapHandle) ReadPacket(timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	for {
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			return nil, errTimeout
		}
		var hdr, data unsafe.Pointer
		rc, _, _ := procNextEx.Call(
			uintptr(h.p),
			uintptr(unsafe.Pointer(&hdr)),
			uintptr(unsafe.Pointer(&data)),
		)
		h.mu.Unlock()

		switch int32(rc) {
		case 1: // a packet is available
			if hdr == nil || data == nil {
				return nil, errTimeout
			}
			caplen := *(*uint32)(unsafe.Add(hdr, offPcapCaplen))
			if caplen == 0 || caplen > maxFrame {
				return nil, errTimeout
			}
			// pcap owns this buffer until the next call, so copy it out.
			out := make([]byte, caplen)
			copy(out, unsafe.Slice((*byte)(data), caplen))
			return out, nil
		case 0: // timeout, no packet
			if time.Now().After(deadline) {
				return nil, errTimeout
			}
			// Yield briefly rather than spinning on the DLL.
			time.Sleep(500 * time.Microsecond)
		case -2: // EOF / device closed
			return nil, errTimeout
		default:
			return nil, fmt.Errorf("pcap_next_ex failed (rc=%d): %s", int32(rc), getErr(h.p))
		}
	}
}

// WritePacket injects a raw Ethernet frame.
func (h *pcapHandle) WritePacket(frame []byte) error {
	if len(frame) == 0 {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return errors.New("capture handle is closed")
	}
	rc, _, _ := procSendPacket.Call(
		uintptr(h.p),
		uintptr(unsafe.Pointer(&frame[0])),
		uintptr(int32(len(frame))),
	)
	if int32(rc) != 0 {
		return fmt.Errorf("pcap_sendpacket failed: %s", getErr(h.p))
	}
	return nil
}

// LinkType returns the pcap datalink type (1 == Ethernet).
func (h *pcapHandle) LinkType() int { return h.linkTyp }

// Close releases the handle. It is safe to call more than once.
func (h *pcapHandle) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	if h.p != nil {
		procClose.Call(uintptr(h.p))
		h.p = nil
	}
	return nil
}

func getErr(handle unsafe.Pointer) string {
	if procGetErr == nil || handle == nil {
		return "unknown error"
	}
	p, _, _ := procGetErr.Call(uintptr(handle))
	if p == 0 {
		return "unknown error"
	}
	return cstr(uintptrToPtr(p))
}

// uintptrToPtr reinterprets a value returned by a syscall as a pointer.
//
// This is the single place in the package where a uintptr becomes an
// unsafe.Pointer, which go vet's unsafeptr check flags by design. The value is
// a C pointer owned by wpcap, never an address inside the Go heap, so the
// hazard that check exists for does not apply here. CI runs vet with
// -unsafeptr=false for this reason; see .github/workflows/build.yml.
func uintptrToPtr(v uintptr) unsafe.Pointer { return unsafe.Pointer(v) }

// cString reads a NUL-terminated C string out of a fixed buffer.
func cString(buf []byte) string {
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

// cstr reads a NUL-terminated C string, capped so a malformed pointer cannot
// walk off into unmapped memory.
func cstr(p unsafe.Pointer) string {
	const limit = 4096
	if p == nil {
		return ""
	}
	buf := make([]byte, 0, 128)
	for i := 0; i < limit; i++ {
		b := *(*byte)(unsafe.Add(p, i))
		if b == 0 {
			break
		}
		buf = append(buf, b)
	}
	return string(buf)
}

// findDeviceName locates the Npcap device that owns ip, falling back to a
// description match and finally to the sole device present.
func findDeviceName(ifaceName string, ip net.IP) (string, error) {
	var head unsafe.Pointer
	errBuf := make([]byte, pcapErrBufSize)
	if rc, _, _ := procFindAllDevs.Call(
		uintptr(unsafe.Pointer(&head)),
		uintptr(unsafe.Pointer(&errBuf[0])),
	); int32(rc) != 0 {
		return "", fmt.Errorf("pcap_findalldevs failed: %s", cString(errBuf))
	}
	if head == nil {
		return "", fmt.Errorf("%w: no capture devices were enumerated", ErrUnsupported)
	}
	defer procFreeAllDevs.Call(uintptr(head))

	type dev struct{ name, desc string }
	var devs []dev

	for node := head; node != nil; {
		namePtr := *(*unsafe.Pointer)(unsafe.Add(node, offIfName))
		descPtr := *(*unsafe.Pointer)(unsafe.Add(node, offIfDesc))
		next := *(*unsafe.Pointer)(unsafe.Add(node, offIfNext))

		d := dev{}
		if namePtr != nil {
			d.name = cstr(namePtr)
		}
		if descPtr != nil {
			d.desc = cstr(descPtr)
		}
		if d.name != "" {
			devs = append(devs, d)
		}
		node = next
	}
	if len(devs) == 0 {
		return "", fmt.Errorf("%w: no capture devices were enumerated", ErrUnsupported)
	}

	// 1. Match the IPv4 address of the interface we were asked for.
	if ip != nil {
		if name, ok := deviceByIP(head, ip); ok {
			return name, nil
		}
	}
	// 2. Match the friendly name against the adapter description.
	if ifaceName != "" {
		for _, d := range devs {
			if d.desc != "" && containsFold(d.desc, ifaceName) {
				return d.name, nil
			}
			if containsFold(d.name, ifaceName) {
				return d.name, nil
			}
		}
	}
	// 3. Only one device: unambiguous.
	if len(devs) == 1 {
		return devs[0].name, nil
	}

	names := make([]string, 0, len(devs))
	for _, d := range devs {
		names = append(names, fmt.Sprintf("%s (%s)", d.desc, d.name))
	}
	return "", fmt.Errorf("could not match interface %q / %s to an Npcap device; available: %v",
		ifaceName, ip, names)
}

// deviceByIP walks each device's address list looking for ip.
func deviceByIP(head unsafe.Pointer, ip net.IP) (string, bool) {
	target := ip.To4()
	if target == nil {
		return "", false
	}
	want := uint32(target[0])<<24 | uint32(target[1])<<16 | uint32(target[2])<<8 | uint32(target[3])

	for node := head; node != nil; {
		namePtr := *(*unsafe.Pointer)(unsafe.Add(node, offIfName))
		addrList := *(*unsafe.Pointer)(unsafe.Add(node, offIfAddrs))
		next := *(*unsafe.Pointer)(unsafe.Add(node, offIfNext))

		for a := addrList; a != nil; {
			sock := *(*unsafe.Pointer)(unsafe.Add(a, offAddrAddr))
			nextAddr := *(*unsafe.Pointer)(unsafe.Add(a, offAddrNext))
			if sock != nil {
				family := *(*uint16)(unsafe.Add(sock, offSockFamily))
				if family == afINET {
					// sockaddr_in.sin_addr is stored in network byte order.
					raw := *(*uint32)(unsafe.Add(sock, offSockAddr))
					got := uint32(raw&0xff)<<24 | uint32((raw>>8)&0xff)<<16 |
						uint32((raw>>16)&0xff)<<8 | uint32((raw>>24)&0xff)
					if got == want && namePtr != nil {
						return cstr(namePtr), true
					}
				}
			}
			a = nextAddr
		}
		node = next
	}
	return "", false
}

func containsFold(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	h, n := []rune(lower(haystack)), []rune(lower(needle))
	if len(n) > len(h) {
		return false
	}
	for i := 0; i+len(n) <= len(h); i++ {
		if string(h[i:i+len(n)]) == string(n) {
			return true
		}
	}
	return false
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
