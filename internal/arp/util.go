// language: Go, file: internal/arp/util.go
package arp

import (
	"context"
	"time"
)

// contextContext is an alias kept so engine.go reads naturally where it takes
// a cancellation scope for ARP resolution.
type contextContext = context.Context

// contextWithTimeout is a thin wrapper so engine.go does not need the context
// import for a single call site.
func contextWithTimeout(d time.Duration) (contextContext, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
