// language: Go, file: internal/api/api_test.go
package api

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// hijackableRecorder is a ResponseWriter that supports hijacking, standing in
// for what net/http hands a real handler.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	// The caller only checks that the assertion succeeded, so a nil conn is
	// fine here.
	return nil, nil, nil
}

// TestStatusWriterForwardsHijack is a regression test for a bug that made every
// WebSocket upgrade fail with "response does not implement http.Hijacker".
//
// The logger middleware wraps the ResponseWriter to record the status code.
// Because the wrapper only embedded http.ResponseWriter, it hid the Hijack
// method the WebSocket upgrader asserts for, so the dashboard never received
// live updates — while every REST call kept working, which is why it went
// unnoticed.
func TestStatusWriterForwardsHijack(t *testing.T) {
	base := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
	sw := &statusWriter{ResponseWriter: base, code: http.StatusOK}

	hj, ok := http.ResponseWriter(sw).(http.Hijacker)
	if !ok {
		t.Fatal("the wrapped writer does not satisfy http.Hijacker; " +
			"the WebSocket upgrade would fail")
	}
	if _, _, err := hj.Hijack(); err != nil {
		t.Fatalf("Hijack returned an error: %v", err)
	}
	if !base.hijacked {
		t.Error("Hijack was not forwarded to the underlying writer")
	}
}

// TestStatusWriterHijackOnUnsupportedWriter: a writer that genuinely cannot be
// hijacked must produce a clear error, not a panic.
func TestStatusWriterHijackOnUnsupportedWriter(t *testing.T) {
	sw := &statusWriter{ResponseWriter: httptest.NewRecorder(), code: http.StatusOK}
	if _, _, err := sw.Hijack(); err == nil {
		t.Error("Hijack succeeded on a writer that does not support it")
	}
}

// TestStatusWriterRecordsCode checks the wrapper still does its actual job.
func TestStatusWriterRecordsCode(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec, code: http.StatusOK}
	sw.WriteHeader(http.StatusTeapot)
	if sw.code != http.StatusTeapot {
		t.Errorf("code = %d, want %d", sw.code, http.StatusTeapot)
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("underlying writer saw %d, want %d", rec.Code, http.StatusTeapot)
	}
}

// TestStatusWriterUnwrap: http.ResponseController reaches the underlying writer
// through Unwrap, which is how optional behaviour should be accessed.
func TestStatusWriterUnwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec, code: http.StatusOK}
	if sw.Unwrap() != http.ResponseWriter(rec) {
		t.Error("Unwrap did not return the underlying writer")
	}
}

// TestStatusWriterFlushIsSafe: Flush must not panic when the underlying writer
// cannot flush.
func TestStatusWriterFlushIsSafe(t *testing.T) {
	sw := &statusWriter{ResponseWriter: httptest.NewRecorder(), code: http.StatusOK}
	sw.Flush() // must not panic
}
