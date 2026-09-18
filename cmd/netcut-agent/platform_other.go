// language: Go, file: cmd/netcut-agent/platform_other.go
//go:build !windows

package main

import (
	"crypto/tls"
	"os"
)

// isElevated reports whether this process is running as root, which is what
// opening a raw capture socket requires on Linux.
func isElevated() bool { return os.Geteuid() == 0 }

// insecureTLS returns a TLS config that skips certificate verification. It is
// only reachable through the explicit -insecure flag.
func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in via -insecure
}
