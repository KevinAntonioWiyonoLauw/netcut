// language: Go, file: cmd/netcut-agent/platform_windows.go
//go:build windows

package main

import (
	"crypto/tls"

	"golang.org/x/sys/windows"
)

// isElevated reports whether this process holds Administrator privileges.
// Opening an Npcap capture device requires it.
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// insecureTLS returns a TLS config that skips certificate verification. It is
// only reachable through the explicit -insecure flag, for a self-signed
// control plane during bring-up.
func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in via -insecure
}
