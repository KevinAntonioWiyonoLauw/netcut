// language: Go, file: cmd/netcut-agent/util.go
package main

import (
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// envBool parses a boolean environment variable.
func envBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// envInt parses an integer environment variable.
func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// envDuration parses a Go duration environment variable.
func envDuration(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

// ioLimit wraps r so at most n bytes are read. It bounds error-body reads and
// response decoding so a hostile or broken peer cannot exhaust memory.
func ioLimit(r io.Reader, n int64) io.Reader {
	return io.LimitReader(r, n)
}

// dialerWithTimeout returns a resolver dialer that gives up quickly, so a
// reverse-DNS lookup cannot stall the report loop.
func dialerWithTimeout(d time.Duration) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: d}
		return dialer.DialContext(ctx, network, address)
	}
}
