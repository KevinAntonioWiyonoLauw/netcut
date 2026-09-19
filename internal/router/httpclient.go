// language: Go, file: internal/router/httpclient.go
package router

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// httpClient is the shared transport for the HTTP-based router backends.
//
// It carries a cookie jar, because every router API in scope authenticates with
// a session cookie. It is also deliberately quiet: it never logs a request
// body, since bodies carry credentials.
type httpClient struct {
	base string
	c    *http.Client
	cfg  Config
}

func newHTTPClient(base string, cfg Config) (*httpClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	tr := &http.Transport{
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     60 * time.Second,
		DisableCompression:  false,
	}
	if cfg.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in for a self-signed router
	}
	return &httpClient{
		base: strings.TrimRight(base, "/"),
		cfg:  cfg,
		c: &http.Client{
			Timeout:   timeout,
			Transport: tr,
			Jar:       jar,
			// A router that answers with a redirect to its login page is a
			// failure, not a location to follow silently.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects (router is redirecting to its login page)")
				}
				return nil
			},
		},
	}, nil
}

// postJSON sends a JSON body and decodes a JSON response into out.
func (h *httpClient) postJSON(ctx context.Context, path string, body any, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return h.do(ctx, http.MethodPost, path, "application/json", buf, out)
}

// postForm sends an application/x-www-form-urlencoded body.
func (h *httpClient) postForm(ctx context.Context, path string, form url.Values, out any) error {
	return h.do(ctx, http.MethodPost, path, "application/x-www-form-urlencoded",
		[]byte(form.Encode()), out)
}

// get performs a GET and decodes the response into out.
func (h *httpClient) get(ctx context.Context, path string, out any) error {
	return h.do(ctx, http.MethodGet, path, "", nil, out)
}

func (h *httpClient) do(ctx context.Context, method, path, contentType string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, h.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", "netcut-router/1.0")

	resp, err := h.c.Do(req)
	if err != nil {
		// Strip any credentials that a wrapped error might carry.
		return fmt.Errorf("request to %s failed: %w", path, sanitise(err))
	}
	defer resp.Body.Close()

	// Bound the read: a misbehaving router should not be able to exhaust memory.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%s returned %d (authentication failed)", path, resp.StatusCode)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned %d", path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	// Some router endpoints answer with text/plain that is actually JSON.
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return fmt.Errorf("%s returned an empty body", path)
	}
	if err := json.Unmarshal(trimmed, out); err != nil {
		// A login page returned where JSON was expected is the common case and
		// deserves a clearer message than a parse error.
		if bytes.Contains(bytes.ToLower(trimmed[:min(len(trimmed), 512)]), []byte("<html")) {
			return fmt.Errorf("%s returned an HTML page, not JSON (the router redirected to its login page)", path)
		}
		return fmt.Errorf("%s did not return JSON: %w", path, err)
	}
	return nil
}

// sanitise removes a password that may have been echoed into an error.
func sanitise(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	// url.Error includes the full URL, which is fine, but guard anyway.
	if strings.Contains(msg, "password=") {
		msg = strings.ReplaceAll(msg, "password=", "password=<redacted>")
		return fmt.Errorf("%s", msg)
	}
	return err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
