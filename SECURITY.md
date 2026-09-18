# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](../../security/advisories/new) rather than in
a public issue. Include a description, the affected version or commit, and a
minimal reproduction if you have one. You can expect an initial response within
a few days.

## Scope

NetCut is a network management tool. It is designed to control devices on a
network segment that the operator owns and administers. It is not intended to
be used against networks, devices, or infrastructure that the operator does not
control.

## Threat model

The deployment assumed here is a single operator, or a small trusted group,
managing a segment they are responsible for. Within that model:

- The control plane is treated as a trusted service. An attacker who already
  has code execution on the host running it, or on the host running an agent,
  is outside the threat model.
- The agent credential is a bearer token. Anyone holding it can submit device
  reports and receive directives. Treat it as a secret; revoke and reissue from
  the dashboard if it may have leaked.
- Traffic on the monitored segment is not protected by NetCut. It manages
  access; it does not encrypt anything.

## What is protected

| Area | Measure |
|---|---|
| Passwords | bcrypt, cost 12, per-password salt |
| Session tokens | HS256 JWT, algorithm pinned, expiry required, issuer checked |
| Agent credentials | Stored as SHA-256 digests only; the secret is shown once |
| Brute force | Per-account and per-source-address throttling |
| Account enumeration | Identical response for unknown account and wrong password |
| Session theft | `HttpOnly`, `SameSite=Lax`, `Secure` when a public URL is set |
| CSRF | `SameSite=Lax` plus a required custom header on every mutation |
| Clickjacking | `X-Frame-Options: DENY` and `frame-ancestors 'none'` |
| Injection | Parameterised SQL throughout; no string-built queries from input |
| Privilege escalation | Role checks on every privileged route; the last owner cannot be removed |
| Container escape | Unprivileged user, read-only root, all capabilities dropped |

## Known limitations

- **No multi-factor authentication.** Sessions are password-only.
- **No TLS termination.** Deploy behind a reverse proxy that provides HTTPS.
  `NETCUT_PUBLIC_URL` must be set so cookies are marked `Secure`.
- **Rate limiting is in-process.** It resets when the service restarts and is
  not shared across replicas.
- **No account lockout notification.** Failed sign-ins are recorded in the
  audit log but nothing is sent to the operator.
- **The audit log is local.** It is bounded and pruned; export it externally if
  you need long-term retention.

## Operational guidance

1. Set `NETCUT_PUBLIC_URL` to the real HTTPS origin in any deployment that is
   not purely local, so cookies are `Secure` and HSTS is sent.
2. Keep the published port on loopback and let the reverse proxy be the only
   path in.
3. Protect your own device before creating any rule.
4. Change the bootstrap admin password after the first sign-in, and remove any
   account you do not need.
5. Give people `viewer` unless they need more.
6. Revoke agent credentials that are no longer in use.
7. Back up the data volume. It holds the account table, the policy set, and the
   audit log.
