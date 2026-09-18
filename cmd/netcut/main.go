// language: Go, file: cmd/netcut/main.go
// NetCut — network access control for a segment you own.
//
// The control plane (this binary, running in Docker) owns intent, policy,
// audit and the dashboard. The data plane (the netcut-agent binary, running
// natively on the gateway host) performs the actual ARP-level enforcement,
// because a NAT-ed container can never reach the LAN at layer 2.
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kevinantoniowiyonolauw/netcut/internal/api"
	"github.com/kevinantoniowiyonolauw/netcut/internal/auth"
	"github.com/kevinantoniowiyonolauw/netcut/internal/config"
	"github.com/kevinantoniowiyonolauw/netcut/internal/fleet"
	"github.com/kevinantoniowiyonolauw/netcut/internal/hub"
	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
	"github.com/kevinantoniowiyonolauw/netcut/internal/store"
	"github.com/kevinantoniowiyonolauw/netcut/internal/version"
)

//go:embed all:web
var webFS embed.FS

func main() {
	var (
		showVersion = flag.Bool("version", false, "print version and exit")
		healthcheck = flag.Bool("healthcheck", false, "probe the local health endpoint and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("netcut %s (commit %s, built %s)\n", version.Version, version.Commit, version.BuildTime)
		return
	}

	log := newLogger()
	if *healthcheck {
		os.Exit(runHealthcheck(log))
	}

	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log.Info("starting netcut",
		"version", version.Version, "commit", version.Commit,
		"addr", cfg.Addr, "db", cfg.DBPath, "demo", cfg.DemoMode)

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := bootstrap(ctx, cfg, st, log); err != nil {
		return err
	}

	h := hub.New()
	fl := fleet.New()

	// Seed the fleet with what the database already knows so a restart does
	// not blank the dashboard while waiting for the first agent report.
	if err := fl.Reconcile(ctx, st, h); err != nil {
		log.Warn("initial reconcile failed", "err", err)
	}

	assets, err := dashboardFS()
	if err != nil {
		return err
	}

	issuer := auth.NewIssuer(cfg.JWTSecret, cfg.TokenTTL)
	srv := api.New(cfg, st, fl, h, issuer, log, assets)

	go fl.Run(ctx, st, h, cfg.PollInterval, log)
	go fl.RunMaintenance(ctx, st, cfg.SampleRetention, log)

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown requested")
	case err := <-errCh:
		return fmt.Errorf("http server: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Warn("graceful shutdown failed", "err", err)
	}
	log.Info("stopped")
	return nil
}

// bootstrap creates the initial owner account from the environment on first
// run, and registers the configured agent credential. Both are idempotent.
func bootstrap(ctx context.Context, cfg *config.Config, st *store.Store, log *slog.Logger) error {
	if cfg.AdminEmail != "" && cfg.AdminPassword != "" {
		n, err := st.CountUsers(ctx)
		if err != nil {
			return err
		}
		hash, err := auth.HashPassword(cfg.AdminPassword)
		if err != nil {
			return fmt.Errorf("admin password: %w", err)
		}
		created, err := st.UpsertUser(ctx, &model.User{
			Email: cfg.AdminEmail, PasswordHash: hash, Role: model.RoleOwner,
		})
		if err != nil {
			return fmt.Errorf("create owner: %w", err)
		}
		if created {
			log.Info("owner account created", "email", cfg.AdminEmail)
			_ = st.AddEvent(ctx, &model.Event{
				Type: "bootstrap.owner_created", Severity: "warn",
				Actor: "system", Message: "initial owner account created: " + cfg.AdminEmail,
			})
		} else if n == 0 {
			log.Warn("owner account already present")
		}
	} else if n, _ := st.CountUsers(ctx); n == 0 {
		log.Warn("no owner account exists and NETCUT_ADMIN_EMAIL/PASSWORD are unset; " +
			"the dashboard will be unusable until an account is created")
	}
	return nil
}

func dashboardFS() (http.Handler, error) {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil, fmt.Errorf("embed web: %w", err)
	}
	return http.FileServer(http.FS(sub)), nil
}

func newLogger() *slog.Logger {
	level := slog.LevelInfo
	switch os.Getenv("NETCUT_LOG_LEVEL") {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

// runHealthcheck probes the local HTTP endpoint for the container healthcheck.
func runHealthcheck(log *slog.Logger) int {
	addr := os.Getenv("NETCUT_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	host := addr
	if host[0] == ':' {
		host = "127.0.0.1" + addr
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + host + "/api/health")
	if err != nil {
		log.Error("healthcheck failed", "err", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Error("healthcheck unhealthy", "status", resp.StatusCode)
		return 1
	}
	return 0
}
