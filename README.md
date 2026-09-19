# NetCut

**Network access control for a segment you own.** See every device on your
network, then decide what each one is allowed to do — block it, cap its
bandwidth, or leave it alone — from a single dashboard.

NetCut is built for the ordinary situation: you pay for the connection, other
devices share it, and you want the link to stay usable without walking around
changing settings on hardware you may not even control.

```
  dashboard (browser)
        │  HTTPS
        ▼
  ┌───────────────┐        policy, audit, live state
  │   netcut      │◀────────────────────────────┐
  │ control plane │                             │ reports + directives
  └───────────────┘                             │
        ▲                                       │
        │  reverse proxy (Traefik/nginx/Caddy)  │
        │                                       │
  ┌─────────────────────────────────────────────┴───┐
  │  netcut-agent   (native, on the gateway host)   │
  │  layer-2 enforcement on the monitored segment   │
  └─────────────────────────────────────────────────┘
```

## Why an agent instead of just a container

A container on Docker Desktop, or any NAT-ed container, cannot reach your LAN
at layer 2. Its traffic is translated, so it has no view of the segment and no
way to act on it. Enforcement therefore has to happen on the host that owns the
segment, and that is what `netcut-agent` is for.

The split is deliberate:

| | Runs where | Does |
|---|---|---|
| **netcut** (control plane) | Container, VM, or bare metal | Accounts, policy, audit log, dashboard, live state |
| **netcut-agent** (data plane) | Natively on the gateway host | Discovers hosts, applies enforcement, reports telemetry |

You can run the control plane on its own first and confirm the dashboard works
before any enforcement exists.

## Features

### Devices
- Automatic discovery of every host on the segment, with vendor identification
  from the MAC prefix
- **Link type** — each device is labelled `wlan` (with its SSID and band),
  `lan` (with its switch port), or `wan`. Read from the router, so it is
  per-device and authoritative
- Live status, addresses, session age, and per-device throughput
- Labels, groups, and free-form notes
- **Protected devices** — a device marked protected is exempt from *every*
  rule, schedule, and manual action. Mark your own hardware protected first and
  it can never be cut off, by accident or otherwise.

### Enforcement
- **Block** — traffic from and to the device stops, while its link stays up
- **Throttle** — a bandwidth cap applied in both directions; the device's own
  link is untouched and TCP backs off on its own
- **Observe** — record activity without changing anything
- **Allow** — explicit exemption
- Every action can be permanent or timed; timed actions revert on their own

### Policies
- Declarative rules: target everything, a group, or one device
- Actions: block, throttle, observe, allow
- Schedules as a time-of-day window (`22:00-06:00`, crossing midnight is fine)
  or a standard 5-field cron expression (`0 22 * * 1-5`, `*/30 * * * *`)
- Priority-ordered; the first match per device wins
- A protected device always resolves to allow, whatever the rules say

### Operations
- **Panic release** — one action stops all enforcement and disables every
  policy, returning the segment to normal
- Audit log of every decision and administrative change
- Accounts with three roles: `owner` (everything, including accounts),
  `admin` (devices and policy), `viewer` (read-only)
- Live dashboard over a WebSocket, plus a REST API
- Bounded history: samples and events are pruned automatically

## Link type: Wi-Fi or wired

Knowing *how* a device is attached is what tells you whether to look at Wi-Fi or
at a cable. NetCut gets this from two places, in order of authority:

| Source | Knows | Fills in |
|---|---|---|
| **Router** (optional) | The actual SSID or switch port per client | `wlan · <SSID> (band)` or `lan · LAN1` |
| **Agent** | Only its own attachment | A baseline for devices the router has not reported |

The router is the only thing that can see a per-device attachment, so this needs
it configured. Two backends are supported, plus auto-detection:

```yaml
environment:
  - NETCUT_ROUTER_HOST=192.168.1.1      # turns polling on
  - NETCUT_ROUTER_BACKEND=auto           # auto | huawei | openwrt | none
  - NETCUT_ROUTER_USER=admin
  - NETCUT_ROUTER_PASSWORD=...
  - NETCUT_ROUTER_INTERVAL=60s
```

With `auto`, NetCut probes the known backends and uses the first that answers.
Credentials are read-only: NetCut never changes router configuration.

| Backend | For |
|---|---|
| `huawei` | Huawei home gateways (`/api/...` JSON API) |
| `openwrt` | OpenWrt / LEDE, over ubus and iwinfo |
| `none` | Disable polling |

Two design choices worth knowing:

- **Unknown is reported as unknown.** A device the router does not describe is
  labelled `unknown`, never guessed. A wrong label is worse than no label.
- **Field discovery is structural.** Router APIs differ by model and firmware
  and are undocumented, so NetCut locates device records by finding MAC-shaped
  values and reads the surrounding fields by name pattern. An unfamiliar router
  still produces useful output.

Check it any time:

```bash
curl -b jar http://localhost:8080/api/router
```

That reports whether polling is configured, which backend answered, how many
clients it returned, and the last error if a poll failed. The dashboard shows
the same thing as a banner, so a missing link column always explains itself.

## Quick start

### 1. Control plane

```bash
git clone https://github.com/kevinantoniowiyonolauw/netcut.git
cd netcut
cp .env.example .env
openssl rand -hex 32          # paste into NETCUT_JWT_SECRET
$EDITOR .env                  # set NETCUT_ADMIN_EMAIL and NETCUT_ADMIN_PASSWORD
docker compose up -d
```

Open <http://localhost:8080> and sign in with the account from `.env`.

Or run it directly:

```bash
go build ./cmd/netcut
NETCUT_JWT_SECRET=$(openssl rand -hex 32) \
NETCUT_ADMIN_EMAIL=you@example.com \
NETCUT_ADMIN_PASSWORD=change-me \
  ./netcut
```

### 2. Agent

Issue a credential in the dashboard (**Agents → Issue a credential**), then run
the agent on the host that owns the segment. On Windows, from an **elevated**
prompt:

```powershell
netcut-agent.exe -check                      # show the interfaces it can see
netcut-agent.exe -server http://<host>:8080 -token <credential>
```

On Linux, as root:

```bash
./netcut-agent -check
./netcut-agent -server http://<host>:8080 -token <credential>
```

Always start with `-dry-run` on a new network. It discovers and reports hosts
without transmitting anything, so you can confirm the agent sees the right
segment before it is able to change anything:

```bash
./netcut-agent -dry-run -server http://<host>:8080 -token <credential>
```

### 3. Protect yourself

Before creating any rule, open the dashboard, find your own device, and press
**Protect**. A protected device cannot be blocked or limited by anything.

## How enforcement works

The agent keeps a forged address mapping in place for each device under
enforcement, in both directions, so the device's traffic passes through the
host running the agent. That position is what makes the controls possible:

- **Block** drops the frames instead of forwarding them.
- **Throttle** admits frames only as fast as a token bucket allows, and drops
  the excess. The cap is enforced in both directions.

Releasing a device restores the truthful mapping immediately, so it recovers at
once rather than waiting for its own cache to expire. The same restoration runs
on agent shutdown and on panic release, so no device is left stranded by a
crash or a restart.

This operates purely on your own segment, between devices that share a
connection you control. Nothing is installed on, or required of, any other
device.

## Configuration

All configuration is environment driven. See `.env.example` for the annotated
list. The essentials:

| Variable | Default | Meaning |
|---|---|---|
| `NETCUT_JWT_SECRET` | — | **Required.** Signs session tokens. 32+ characters. |
| `NETCUT_ADMIN_EMAIL` | — | First account, created only when the user table is empty. |
| `NETCUT_ADMIN_PASSWORD` | — | Password for that account. Change it in the dashboard. |
| `NETCUT_PUBLIC_URL` | — | Browser-visible origin. Enables Secure cookies and HSTS. |
| `NETCUT_DB` | `/data/netcut.db` | Database path. |
| `NETCUT_POLL_INTERVAL` | `2s` | How often intent is folded into directives. |
| `NETCUT_SAMPLE_RETENTION` | `24h` | How much bandwidth history to keep. |
| `NETCUT_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. |
| `NETCUT_ROUTER_HOST` | — | Router address. Setting it enables link-type polling. |
| `NETCUT_ROUTER_BACKEND` | `auto` | `auto`, `huawei`, `openwrt`, or `none`. |
| `NETCUT_ROUTER_USER` | — | Router management user. |
| `NETCUT_ROUTER_PASSWORD` | — | Router management password. |
| `NETCUT_ROUTER_INTERVAL` | `60s` | How often to poll the router. |

## API

Every dashboard action is a REST call, so anything can be automated. The
endpoints that matter most:

```bash
# Sign in and keep the session cookie
curl -c jar -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"..."}'

# List devices with the current decision for each
curl -b jar http://localhost:8080/api/state

# Block one device for an hour
curl -b jar -X POST http://localhost:8080/api/devices/<mac>/action \
  -H 'X-NetCut: 1' -H 'Content-Type: application/json' \
  -d '{"action":"block","duration_s":3600,"note":"why"}'

# Limit it to 512 kbps
curl -b jar -X POST http://localhost:8080/api/devices/<mac>/action \
  -H 'X-NetCut: 1' -H 'Content-Type: application/json' \
  -d '{"action":"throttle","cap_kbps":512,"up_kbps":512}'

# Release it
curl -b jar -X POST http://localhost:8080/api/devices/<mac>/action \
  -H 'X-NetCut: 1' -H 'Content-Type: application/json' \
  -d '{"action":"allow"}'
```

Any state-changing request needs the `X-NetCut: 1` header. It is a CSRF guard:
a cross-site form post cannot set a custom header, so this plus `SameSite=Lax`
closes the hole without a token round-trip.

### Agents

```bash
# Register an agent credential (returns the secret exactly once)
curl -b jar -X POST http://localhost:8080/api/agents \
  -H 'X-NetCut: 1' -H 'Content-Type: application/json' \
  -d '{"name":"gateway-host"}'

# What an agent sends and receives
curl -X POST http://localhost:8080/api/agent/report \
  -H 'X-Agent-Token: <credential>' -H 'Content-Type: application/json' \
  -d '{"agent_id":"a1","devices":[...]}'
```

## Deployment behind a reverse proxy

Set `NETCUT_PUBLIC_URL` to the exact public origin, and keep the published port
on loopback:

```yaml
environment:
  NETCUT_PUBLIC_URL: https://netcut.example.com
ports:
  - "127.0.0.1:8080:8080"
```

With Traefik:

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.docker.network=proxy"
  - "traefik.http.routers.netcut.rule=Host(`netcut.example.com`)"
  - "traefik.http.routers.netcut.entrypoints=web"
  - "traefik.http.services.netcut.loadbalancer.server.port=8080"
networks: [proxy]
```

The dashboard uses a WebSocket (`/api/ws`), so the proxy must allow connection
upgrades — Traefik, nginx, and Caddy all do this by default.

## Security

- Passwords hashed with bcrypt at cost 12
- Session tokens are HS256 JWTs, algorithm-pinned, with a required expiry and
  an issuer check
- Agent credentials stored only as SHA-256 digests and shown once
- Login throttled per account **and** per source address
- Identical response for an unknown account and a wrong password
- `HttpOnly`, `SameSite=Lax`, and `Secure` (when a public URL is set) cookies
- Strict Content-Security-Policy, `X-Frame-Options: DENY`, `nosniff`
- The container runs unprivileged with a read-only root filesystem, all
  capabilities dropped, and `no-new-privileges`
- The last owner account cannot be demoted or deleted

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## Building

```bash
go build ./...                 # both binaries
go test -race ./...            # full suite
go vet ./...                   # static analysis
docker build -t netcut:local . # image
```

The agent cross-compiles for Windows and Linux with no C toolchain, because the
capture backend binds the system library directly rather than going through
cgo:

```bash
GOOS=windows GOARCH=amd64 go build -o netcut-agent.exe ./cmd/netcut-agent
```

Pushing to `main` publishes a multi-arch image (`linux/amd64`, `linux/arm64`)
to GitHub Container Registry. Pushing a `vX.Y.Z` tag additionally attaches the
agent binaries to the release.

## Requirements

**Control plane:** nothing beyond a container runtime. The SQLite driver is
pure Go and the dashboard is embedded in the binary, so there is no external
database, no Node, and no assets to serve.

**Agent, Windows:** Windows 10/11, [Npcap](https://npcap.com) (installed with
Wireshark, or on its own with the *WinPcap API-compatible mode* option), and an
elevated prompt.

**Agent, Linux:** a kernel with `AF_PACKET` (any modern one) and root.

## Troubleshooting

**The dashboard says "no agent".** The control plane is running but nothing is
enforcing. Check that the agent is running, that its credential is valid, and
that it can reach the control plane URL. `netcut-agent -check` prints the
interfaces it can see.

**The agent exits with "wpcap.dll not found".** Install Npcap, and make sure the
WinPcap API-compatible mode is enabled during setup.

**The agent says it is not elevated.** Restart it from an Administrator prompt.
Discovery works unelevated; opening a capture device does not.

**Nothing is enforced even though the dashboard shows the right decisions.**
Confirm the agent is on the segment you meant, not a virtual or tunnelled
interface. `netcut-agent -check` marks each interface usable or not and says
why. Virtual adapters (Hyper-V, WSL, VirtualBox, VPN) are excluded on purpose.

**A device is still limited after I released it.** The agent restores the real
mapping when a target is released, and again on shutdown. If enforcement state
and reality ever disagree, press **Panic release**: it stops everything and
restores the segment.

## Layout

```
cmd/netcut/           control plane (dashboard embedded)
cmd/netcut-agent/     data plane (native, on the gateway host)
internal/api/         HTTP surface, RBAC, WebSocket
internal/arp/         layer-2 engine: poisoning, forwarding, shaping
internal/auth/        bcrypt, JWTs, credential digests, rate limiting
internal/config/      environment configuration
internal/fleet/       live state and the reconcile loop
internal/hub/         WebSocket fan-out
internal/model/       shared types
internal/netinfo/     interface and gateway discovery
internal/policy/      the decision engine
internal/router/      router polling: link type per device
internal/store/       SQLite persistence
```

## License

MIT — see [LICENSE](LICENSE).
