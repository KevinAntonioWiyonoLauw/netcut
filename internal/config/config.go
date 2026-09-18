// language: Go, file: internal/config/config.go
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the control-plane configuration, entirely environment driven.
type Config struct {
	Addr            string
	DBPath          string
	DataDir         string
	JWTSecret       string
	TokenTTL        time.Duration
	AdminEmail      string
	AdminPassword   string
	PublicURL       string
	AllowSignup     bool
	DemoMode        bool
	ScanInterval    time.Duration
	PollInterval    time.Duration
	SampleRetention time.Duration
	LogLevel        string
	TrustedProxy    bool
	MaxLoginFails   int
	LockoutWindow   time.Duration
}

// Load reads configuration from the environment, applying safe defaults.
func Load() (*Config, error) {
	c := &Config{
		Addr:            env("NETCUT_ADDR", ":8080"),
		DBPath:          env("NETCUT_DB", "/data/netcut.db"),
		DataDir:         env("NETCUT_DATA_DIR", "/data"),
		JWTSecret:       os.Getenv("NETCUT_JWT_SECRET"),
		TokenTTL:        envDur("NETCUT_TOKEN_TTL", 12*time.Hour),
		AdminEmail:      env("NETCUT_ADMIN_EMAIL", ""),
		AdminPassword:   os.Getenv("NETCUT_ADMIN_PASSWORD"),
		PublicURL:       strings.TrimRight(env("NETCUT_PUBLIC_URL", ""), "/"),
		AllowSignup:     envBool("NETCUT_ALLOW_SIGNUP", false),
		DemoMode:        envBool("NETCUT_DEMO", false),
		ScanInterval:    envDur("NETCUT_SCAN_INTERVAL", 30*time.Second),
		PollInterval:    envDur("NETCUT_POLL_INTERVAL", 2*time.Second),
		SampleRetention: envDur("NETCUT_SAMPLE_RETENTION", 24*time.Hour),
		LogLevel:        env("NETCUT_LOG_LEVEL", "info"),
		TrustedProxy:    envBool("NETCUT_TRUSTED_PROXY", true),
		MaxLoginFails:   envInt("NETCUT_MAX_LOGIN_FAILS", 8),
		LockoutWindow:   envDur("NETCUT_LOCKOUT_WINDOW", 10*time.Minute),
	}
	if c.JWTSecret == "" {
		return nil, fmt.Errorf("NETCUT_JWT_SECRET is required (generate one with: openssl rand -hex 32)")
	}
	if len(c.JWTSecret) < 32 {
		return nil, fmt.Errorf("NETCUT_JWT_SECRET must be at least 32 characters")
	}
	if c.AdminPassword == "" && c.AdminEmail != "" {
		return nil, fmt.Errorf("NETCUT_ADMIN_EMAIL set but NETCUT_ADMIN_PASSWORD is empty")
	}
	return c, nil
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envInt(k string, def int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envDur(k string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
