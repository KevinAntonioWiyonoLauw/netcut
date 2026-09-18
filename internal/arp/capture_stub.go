//go:build !windows

// language: Go, file: internal/arp/capture_stub.go
//
// The engine's control-plane logic is portable, but the frame I/O is not:
// on Linux it needs AF_PACKET with CAP_NET_RAW. That backend is not built
// here, so on non-Windows platforms the agent reports the limitation clearly
// instead of pretending to enforce anything.
package arp

import (
	"errors"
	"net"
	"time"
)

var errTimeout = errors.New("capture read timeout")

func isTimeout(err error) bool { return errors.Is(err, errTimeout) }

type captureDevice interface {
	ReadPacket(timeout time.Duration) ([]byte, error)
	WritePacket(frame []byte) error
	LinkType() int
	Close() error
}

func openCapture(ifaceName string, ip net.IP, filter string) (captureDevice, error) {
	return nil, ErrUnsupported
}
