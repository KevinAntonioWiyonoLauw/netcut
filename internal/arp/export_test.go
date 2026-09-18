// language: Go, file: internal/arp/export_test.go
package arp

import (
	"io"
	"log/slog"
)

// discardLogger returns a logger that writes nowhere, for tests.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}
