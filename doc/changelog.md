---
title: Host Health MCP - Changelog
author: Albert 'Tigr' Zenkoff <albert@tigr.net>
---

# 1.2.1 (2026-05-14)

## Helper

- Helper unix socket and its runtime directory `/run/host-health-mcp/`
  are now chowned to `root:host-health-mcp` at startup so the daemon
  (running as an unprivileged user) can traverse the dir and connect
  to the socket. Previously both were `root:root` and every helper
  call failed with `permission denied`, blocking SMART, mdraid, LVM,
  zpool, btrfs, postqueue, wireguard, apt, needrestart, journal,
  AIDE, auditd, reboot, and nft ops.
- New `daemon_group` key in `helper.yml` (defaults to
  `host-health-mcp`).
- Base helper unit now ships with `CapabilityBoundingSet=CAP_CHOWN`;
  the `caps-template.sh` postinst always unions `CAP_CHOWN` into the
  generated drop-in.

# 1.2.0 (2026-05-14)

## Plugin

- Schema-version handshake (version-matrix C1-C4): on the first
  non-manifest call per host per session, the plugin probes the
  daemon's `/v1/manifest`, extracts `schema_version`, and caches the
  classification. A major-version mismatch returns
  `schema_incompatible` for every subsequent call to that host
  without a network round-trip.
- Plugin module gains `internal/schema` with the compile-time
  `SchemaVersion` constant, kept in lockstep with the daemon at
  release time.

# 1.1.0 (2026-05-14)

## Plugin

- MCP server lifecycle implemented: `initialize` (advertises
  protocolVersion 2024-11-05 and the `tools` capability),
  `notifications/initialized` (no-op), `ping`. Notifications with
  no `id` are recognised and never produce a response.
- `tools/list` emits a JSON-Schema `inputSchema` declaring a per-call
  `host` string argument on every tool (REQ 7.2). `additionalProperties:
  false`.
- `tools/call` returns the MCP content-array shape with `isError` on
  tool-execution failures; JSON-RPC errors remain for protocol-level
  faults (bad params, unknown method).
- `client.Client` is now process-wide: TLS material is loaded once and
  the `http.Transport` pools connections per host. Target host is
  supplied per call. A single plugin registration in an MCP client
  reaches every fleet host without restart.

## Build

- `build/build.sh` cross-builds the plugin alongside daemon and
  helper for both amd64 and arm64; vet and test cover the plugin
  module too. The plugin is not packaged into the `.deb` (it runs on
  the operator workstation, not the target host).
- Release version embedded into all three binaries via
  `-X main.buildID=$VERSION`. `--version` flags print the release
  tag.

# 1.0.0 (2026-05-14)

## Schema

- Schema version: `0.1.0`. First public draft of the wire shape;
  every later release should bump per the rules in
  `doc/version-matrix.md` (minor on additive, major on remove or
  rename).

## Daemon

- All 17 tools (REQ 4.1-4.17) register and respond.
- mTLS HTTP listener with TLS 1.3+, `RequireAndVerifyClientCert`,
  configurable `max_concurrent_handshakes`, structured error
  envelope on every non-2xx.
- Two-level token-bucket rate limiter (per-caller global +
  per-(caller, tool) for expensive tools).
- Global in-process cache with TTL eviction + `singleflight`
  coalescing of concurrent misses + per-tool helper-fan-out cap.
- Sole `os/exec` chokepoint at `internal/daemon/helperinvoke/`,
  enforced at build time by the project's `forbidden`-call linter.
- Per-source error reporting on three tools whose data sources are
  inherently unstable: `storage.smart[].error`,
  `updates.apt_lock_state`, `dns` per-probe time-bound.

## Helper

- Helper as a separate systemd unit, daemon connects via unix
  socket. `NoNewPrivileges=yes` on both units; helper's caps come
  from its own unit config (templated at install).
- 14 ops implemented: `read_audit_status`, `read_aide_summary`,
  `read_reboot_marker`, `smart_summary`, `mdraid_detail`,
  `lvm_report`, `zpool_status`, `btrfs_scrub`, `postqueue`,
  `wireguard_show`, `apt_pending`, `needrestart`, `journal_query`,
  `nft_table_counts`.
- Length-prefixed JSON frame protocol, 16 KiB body cap.
- Stderr fingerprinted (bytes count + sha256), never forwarded to
  the daemon.
- `SO_PEERCRED` uid check on every accepted connection.
- WireGuard parser strips private and preshared keys inside the
  helper before any byte crosses the socket.

## Plugin

- Exposes all 17 daemon tools as MCP tools over stdio JSON-RPC.
  Configurable target host / port / cert paths / DNS suffix /
  tool-name prefix via environment variables.

## Build

- Single Go module under `daemon/` covers both the daemon and the
  helper. Plugin is its own module under `plugin/`.
- `build/build.sh` drives the full release build: vet, test,
  forbidden-call linter, cross-compile for `linux/amd64` and
  `linux/arm64` with `CGO_ENABLED=0 -trimpath -ldflags='-buildid=
  -X main.buildID=<git-sha>'`, `nfpm`-driven `.deb` per arch,
  `SHA256SUMS`.
- Reproducibility: functional, not byte-identical (design §10.1).
  `SOURCE_DATE_EPOCH` propagated for hygiene; `toolchain` directive
  in `go.mod` pins the Go patch version.

## Tests

- Foundational packages covered: `proto` (frame round-trip + cap),
  `cache` (TTL + singleflight), `ratelimit` (global + per-tool +
  per-caller isolation), `redact` (allowlist + fuzz target).
- HTTP server negative tests: client cert required, envelope shape,
  unknown tool returns structured `unknown_tool` not net/http's
  plain-text 404, oversize body rejected.
- Helper parsers: WireGuard secret strip invariant, LVM JSON,
  AIDE log summary, zpool status, apt-get -s upgrade counts,
  dpkg held packages.
