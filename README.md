---
title: host-health-mcp
author: Albert 'Tigr' Zenkoff <albert@tigr.net>
---

# host-health-mcp

A read-only health-check surface for a Linux host fleet, exposed to
MCP-speaking clients (operator workstations, ChatOps relays,
automation pipelines).

The repository ships three artefacts from one `.deb`:

- **`host-health-mcp-daemon`** — the network-facing side. Listens
  on an mTLS HTTPS endpoint, validates client certificates against
  an operator-provided CA bundle, dispatches structured `/v1/<tool>`
  calls, and emits one audit entry per call to journald.
- **`host-health-mcp-helper`** — a root-side helper service the
  daemon talks to over a unix socket for the few reads that need
  privilege (smartctl, WireGuard, AIDE, audit). The helper has
  the only capability grant; the daemon runs unprivileged.
- **`host-health-mcp-plugin`** — the MCP-side client that exposes
  the daemon's surface to MCP-speaking clients. Runs on the
  operator workstation or a designated relay.

This README is the entry point. For mechanics, follow the
cross-links into [`doc/`](doc/).

## 1. What this is

A standardised way to ask one or more Linux hosts a fixed set of
operationally meaningful questions — uptime, mount usage,
filesystem health, ban-set contents, certificate expiry, mail
queue, kernel state, sockets, sensors, firewall ruleset, and so
on — without pulling in heavyweight observability tooling and
without granting the caller shell access.

The current surface is 19 tools (`system`, `systemd_units`,
`storage`, `network`, `dns`, `mail`, `certs`, `backup`, `sensors`,
`security`, `logs`, `updates`, `kernel`, `pressure`, `sockets`,
`workload`, `manifest`, `host_firewall`, `host_firewall_lookup`).
Each one returns a typed JSON envelope under a stable wire schema.

Per-tool reference: [`doc/tools.md`](doc/tools.md).

## 2. Boundary

What this is **not** — every item is a deliberate scope cut, not a
limitation to fix later.

- **Not a mutator.** No tool path may write to the filesystem
  (beyond `/var/lib/host-health-mcp/`), send a signal, modify a
  sysctl, route, rule, mount, or systemd unit. The daemon's binary
  contains no code path that performs a state-changing syscall.
  Read-only is enforced by a custom build-time linter, not by
  convention.
- **Not an inventory system.** The operator brings the target
  list, the network ACLs, the credential rollout, the
  configuration management. None of that is implemented here.
- **Not a deployment tool.** This repo produces one `.deb`. How
  it lands on a host, when it gets restarted, how the manifest is
  updated — operator concern.
- **Not a metric backend.** Calls are synchronous request/reply.
  There is no push, no streaming, no historical retention beyond
  what `journalctl` keeps from the audit log.
- **No CRL or OCSP.** Cert revocation is operator PKI policy
  ([`doc/install.md`](doc/install.md) §2 covers the rotation
  posture).

Full boundary statement: [`doc/REQUIREMENTS.txt`](doc/REQUIREMENTS.txt)
§3, §6.

## 3. Architecture in one diagram

```
operator workstation                target host
+--------------------+               +--------------------------------+
| MCP client         |               |  host-health-mcp-daemon        |
|   (Claude, etc.)   |               |    unprivileged uid            |
|                    |               |    NoNewPrivileges=yes         |
|   host-health-mcp- |  mTLS HTTPS   |    empty cap set               |
|   plugin <--------------+--------->|    /v1/<tool>                  |
+--------------------+               |       |                        |
                                     |       | unix socket            |
                                     |       | (SO_PEERCRED)          |
                                     |       v                        |
                                     |  host-health-mcp-helper        |
                                     |    root                        |
                                     |    NoNewPrivileges=yes         |
                                     |    CapabilityBoundingSet =     |
                                     |    manifest-templated union    |
                                     +--------------------------------+
                                                |
                                                | os/exec  (smartctl,
                                                v          nft, lvs, etc.)
                                            kernel / subprocesses
```

Key invariants:

- The daemon's only path to a subprocess goes through the helper
  socket. `os/exec` is forbidden in the daemon by linter; the
  forbidden-call list is enforced at build time.
- Per-tool, per-caller token-bucket rate limiting on the daemon.
- The helper accepts only peer connections whose `SO_PEERCRED`
  uid matches `daemon_user` in `helper.yml`.
- TLS is `RequireAndVerifyClientCert` + a `VerifyConnection` hook
  that rejects leaves missing `extendedKeyUsage = clientAuth`.

Engineering detail with rationale: [`doc/design-overview.md`](doc/design-overview.md).

## 4. Threat posture (one paragraph)

Trust model is mTLS in, journald audit out. The CA bundle the
daemon trusts is operator-provided; presenting a valid client
cert from that CA is the only authentication. There is no
session, no token store, no second factor — short-lived client
certs are the recommended rotation posture. The daemon emits one
structured audit entry per call (caller CN/SAN, tool, args,
duration, ok/reject) and never logs the response body. The
helper sanitises every byte of subprocess output that crosses the
socket; raw stderr stays inside the helper, only sha256 + a
200-byte sanitised prefix reach the daemon.

Detailed threat surface, residual risks R1–R5, and per-constraint
justification: [`doc/threat-model.md`](doc/threat-model.md).

## 5. Deployment

Step-by-step single-host install:
[`doc/install.md`](doc/install.md).

Quick orientation:

1. Build (or fetch) the `.deb` for the target arch.
2. Install with `dpkg`. The post-install scriptlet creates the
   `host-health-mcp` system user and enables (but does not start)
   the two systemd units.
3. Place PKI material under `/etc/host-health-mcp/tls/`. From
   1.12.0 onward, every client cert MUST carry
   `extendedKeyUsage = clientAuth` — see install §2.2 for the
   pre-flight verification.
4. Author `/etc/host-health-mcp/manifest.yml` for this host.
   `enabled_tools[]` drives the helper unit's
   `CapabilityBoundingSet` via the post-install caps generator.
5. Author `/etc/host-health-mcp/daemon.yml` for this host's bind
   address, allowlists, and rate-limit buckets.
6. Start the helper first, then the daemon.
   `systemctl start host-health-mcp-helper.service`,
   then `systemctl start host-health-mcp.service`.

Fleet rollout — target inventory, credential provisioning, ACL
push, restart cadence — is operator infrastructure and not
shipped here.

## 6. Operator workflow

Once the daemon is running:

```
curl --cacert /path/to/ca.pem \
     --cert  /path/to/operator.pem \
     --key   /path/to/operator.key \
     --tlsv1.3 \
     -X POST -d '{}' \
     https://<host>:8443/v1/system
```

returns the canonical envelope:

```json
{
  "host": "...",
  "as_of": "2026-05-16T...",
  "cache_age_s": 0,
  "schema_version": "0.6.0",
  "data": { ... per-tool shape ... },
  "warnings": []
}
```

The MCP plugin wraps these calls so an MCP-speaking client can
issue them by name. The plugin is launched per the MCP host's
plugin configuration; it dials the daemon over mTLS using the
operator's client cert.

Typical questions the surface answers — see
[`doc/tools.md`](doc/tools.md) for the full per-tool reference:

| Question | Tool |
|---|---|
| Is this host up? Reboot pending? Disk filling? | `system` |
| Which systemd units are degraded? | `systemd_units` |
| SMART status, mdraid sync, ZFS pool errors? | `storage` |
| Is the apt lock held? Pending updates? | `updates` |
| Mail queue depth, deferred count? | `mail` |
| Live SSH/auth log sample? | `logs` |
| Which IPs are banned right now? | `host_firewall` |
| Is `10.0.0.0/24` referenced anywhere in the firewall? | `host_firewall_lookup` |
| Which sockets are listening? | `sockets` |
| Cert expiry on the bundles I care about? | `certs` |

Caching: each tool declares a default TTL. Within that window
repeated calls from the same caller hit cache and report
`cache_age_s > 0`. The cache is keyed on (tool, request body
sha256); different queries don't collide.

Per-call rate limit: each (caller, tool) pair has a token bucket.
Defaults are conservative; tune in `daemon.yml`
under `expensive_tool_buckets`.

## 7. Upgrade and compatibility

Wire schema follows semver-style additive minors. The plugin and
daemon compare versions on first contact per session; a
major-version mismatch is hard-incompatible (cell C4).

Compatibility cells C1–C4 and the upgrade ordering:
[`doc/version-matrix.md`](doc/version-matrix.md).

Per-release deltas: [`doc/changelog.md`](doc/changelog.md).

Current release: **1.14.1** (wire schema **0.6.0**).

Upgrade procedure on a single host:

1. Stop the daemon. The helper can keep running.
   `systemctl stop host-health-mcp.service`.
2. `dpkg -i host-health-mcp_<new>_<arch>.deb`.
3. Re-run the caps templating if `enabled_tools[]` changed:
   `/usr/local/share/host-health-mcp/caps-template.sh`,
   `systemctl daemon-reload`,
   `systemctl restart host-health-mcp-helper.service`.
4. Start the daemon.
5. Confirm with `curl … /v1/manifest`.

There is no SIGHUP / SIGUSR1 reload path on either binary;
configuration and TLS material changes are applied via
`systemctl restart`.

## 8. When something is wrong

Three places to look, in order:

1. **`journalctl -u host-health-mcp -n 100`** — daemon errors
   (TLS handshake, manifest parse, unknown-tool route, rate
   limit).
2. **`journalctl -u host-health-mcp-helper -n 100`** — helper-side
   subprocess errors. Errors here carry a structured code
   (`tool_missing`, `tool_failed`, `deadline`,
   `output_truncated`, `parse_failed`) and a `stderr_sha256`
   fingerprint that identifies what to investigate.
3. **`errors[]` in the tool response body** — for tools that
   report per-source partial failures (`storage.smart[].error`,
   `updates.apt_lock_state`, `dns` per-probe, the firewall tools).
   Each entry carries the helper-side code without forwarding raw
   subprocess bytes.

Common diagnoses:

- **TLS `bad_certificate` after upgrading to 1.12.0+** — the
  client cert is missing `extendedKeyUsage = clientAuth`. Pre-
  flight verification at install.md §2.2.
- **Tool returns `tool_disabled`** — the tool name is not in
  the host's `manifest.yml` `enabled_tools[]`. Add it and restart
  (don't forget the caps templating step).
- **Tool returns `rate_limited`** — caller exhausted the per-
  (caller, tool) bucket. Drop cadence or tune
  `expensive_tool_buckets` in `daemon.yml`.
- **Helper sub-tool returns `output_truncated`** — the
  underlying binary produced more stdout than the helper's cap.
  As of 1.13.0 `nft -j list ruleset` uses a separate 32 MiB
  ceiling; the standard cap is 256 KiB. If a new op trips this
  on a real fleet host, the fix shape is the
  `helper/exec.RunCapped` primitive (see 1.13.0 changelog).

Audit consumption:

```
journalctl -u host-health-mcp -t host-health-mcp -o json --since "5 min ago"
```

Payload bodies are never logged. Each entry carries caller
identity (CN/SAN from the verified client cert), tool name,
structured args, response size, duration, and either `result=ok`
or a reject reason.

Operational baseline check (run on every host after install /
upgrade):

```
sudo systemd-analyze security host-health-mcp.service
sudo systemd-analyze security host-health-mcp-helper.service
```

## 9. Repository map

```
host-health-mcp/
├── README.md                       this file
├── CLAUDE.md                       implementing-engineer brief
├── doc/                            design artefacts and reference
│   ├── ARCHITECT_BRIEF.txt
│   ├── REQUIREMENTS.txt
│   ├── design-overview.md
│   ├── threat-model.md
│   ├── version-matrix.md
│   ├── schema-draft.yaml
│   ├── install.md
│   ├── tools.md
│   └── changelog.md
├── daemon/                         Go module — daemon + helper
├── plugin/                         Go module — MCP plugin
└── build/                          reproducible build orchestration
    ├── build.sh
    ├── nfpm/
    ├── postinst/
    ├── systemd/
    └── dist/                       build output, gitignored
```

## 10. Building from source

```
./build/build.sh
```

Produces `.deb` artefacts for `linux/amd64` and `linux/arm64`
under `build/dist/` with a `SHA256SUMS` manifest. Requires Go
(toolchain pinned in `daemon/go.mod`) and `nfpm` (install via
`go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest`).

Build reproducibility is functional, not byte-identical; the
canonical artefact identity is the SHA-256 recorded in
`build/dist/SHA256SUMS` at release time. See
[`doc/design-overview.md`](doc/design-overview.md) §10.1 for the
trade-off.
