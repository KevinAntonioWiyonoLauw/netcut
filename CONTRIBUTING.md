# Contributing

Thanks for considering a contribution. This is a small project, so the process
is deliberately light.

## Getting set up

```bash
git clone https://github.com/kevinantoniowiyonolauw/netcut.git
cd netcut
go mod download
go test ./...
```

Requirements: Go 1.24 or newer. No C toolchain is needed — the agent binds the
capture library at runtime rather than through cgo, so everything
cross-compiles.

To try the whole thing locally:

```bash
go build ./cmd/netcut
NETCUT_JWT_SECRET=$(openssl rand -hex 32) \
NETCUT_ADMIN_EMAIL=dev@example.com \
NETCUT_ADMIN_PASSWORD=devpassword \
NETCUT_DB=/tmp/netcut-dev.db \
  ./netcut
```

The dashboard is at <http://localhost:8080>. You do not need an agent to work on
the control plane: `POST /api/agent/report` with any registered agent token is
enough to simulate a fleet.

## Before opening a pull request

```bash
gofmt -l .          # should print nothing
go vet -unsafeptr=false ./...
go test -race ./...
```

CI runs exactly these, so a green local run means a green build.

If you touch `go.mod`, regenerate `go.sum` for every shipped target rather than
just your own platform:

```powershell
powershell -NoProfile -File .\tidy.ps1
```

`go mod tidy` resolves for the host platform only. This module builds for
Windows (the agent binds Npcap through `syscall`) and for Linux (the
control-plane image), so a Linux-only tidy drops hashes a Windows build needs
and a Windows-only tidy adds ones Linux does not. `tidy.ps1` resolves all three
targets and keeps the union, which is valid for each of them.

Note on `-unsafeptr=false`: the Windows capture backend binds `wpcap.dll`
directly through `syscall`, so C pointers legitimately cross the uintptr to
pointer boundary. Every such value is a C pointer owned by the library, never a
Go heap address. `internal/arp/capture_windows.go` explains this at the single
place it happens.

## What tends to be accepted

- Bug fixes, with a test that fails before the fix
- New policy actions or schedule forms, with tests for the boundary cases
- Improvements to device identification
- Documentation corrections — if something in the README is wrong, that is a
  real bug

## What needs discussion first

Open an issue before starting on:

- A new data-plane backend (for example, a Linux capture implementation)
- Changes to the enforcement model
- Anything that adds a runtime dependency to the control-plane image

The image is deliberately dependency-free: pure-Go SQLite, an embedded
dashboard, no Node, no external database. Keeping it that way is a feature.

## Style

- Comments explain *why*, not *what*. A comment restating the code is noise.
- Errors are values, wrapped with context as they travel up.
- Prefer the standard library. Add a dependency only when it earns its place.
- Table-driven tests for logic with boundary cases.
- Timestamps are stored as integer milliseconds. Do not reintroduce a driver's
  own date rendering; that is what the convention exists to avoid.

## Reporting a security issue

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the MIT
License, as described in [LICENSE](LICENSE).
