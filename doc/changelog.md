---
title: Host Health MCP - Changelog
author: Albert 'Tigr' Zenkoff <albert@tigr.net>
---

# Unreleased

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
