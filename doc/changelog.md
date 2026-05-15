---
title: Host Health MCP - Changelog
author: Albert 'Tigr' Zenkoff <albert@tigr.net>
---

# 1.9.0 (2026-05-15)

## Helper

- `read_audit_status` no longer shells out to `auditctl`. The op
  speaks NETLINK_AUDIT directly: opens an `AF_NETLINK / SOCK_RAW /
  NETLINK_AUDIT` socket, issues `AUDIT_GET` (msg type 1000), parses
  the kernel's `audit_status` reply.
- **Why this matters.** audit-userspace 4.0.x (Debian 13, Ubuntu
  24.04) tightened the read/control split: `auditctl` refuses to
  run any subcommand — including read-only `-s` — without
  `CAP_AUDIT_CONTROL` in the effective set. The check
  (`audit_can_control()`) is applied at the top of `main()` and
  does not fall back on `geteuid()==0`. Granting `CAP_AUDIT_CONTROL`
  to the helper just to read status would have been a needless
  privilege expansion. The kernel's own `AUDIT_GET` check is
  `netlink_capable(skb, CAP_AUDIT_READ)` per `kernel/audit.c`, so
  going straight to netlink honours the actual policy while keeping
  the helper at the lower cap.
- Pure stdlib + `golang.org/x/sys/unix` (already a dependency). No
  CGO, no `libaudit`. Implementation is ~120 lines in
  `internal/helper/ops/audit_netlink.go`.
- Presence semantics shift slightly: `present:false` now means
  "kernel built without `CONFIG_AUDIT`" rather than "auditctl
  binary not installed". The daemon's binary-detection cross-check
  (binary present, helper says no) remains and still warns when
  the two disagree.
- No change to `last_rotation_ts`: still derived from the newest
  numbered file in `/var/log/audit/`.

# 1.8.0 (2026-05-15)

## Wire schema

- Schema version bumped to **0.3.0** (additive-minor; C2-compatible
  with 0.2.0 clients).
- `storage.smart[].smartctl_exit_code` (optional `*int`): surfaces
  smartctl's raw exit code when it is non-zero but the JSON output
  is still complete (status-bit-only exits — bits 2-7 of smartctl's
  bit-encoded exit per `man smartctl §EXIT STATUS`).

## Helper

- `smart_summary`: smartctl's exit code is a bit field, not a
  pass/fail signal. Bits 0 (`command line did not parse`) and 1
  (`device open failed`) are real failures; bits 2-7 are status
  flags that travel alongside a valid JSON body (`SMART command
  failed`, `prefail thresholds`, `error log records present`, etc.).
  The helper now passes status-bit-only exits through to the parser
  instead of dropping the entire response. Fox's FORESEE 512GB SSD
  (exit 4 — one SMART command unsupported) now returns model,
  smart_overall, temperature, and power-on hours instead of
  `tool_failed`.
- `exec.Run`: returns captured stdout alongside the error on
  non-zero exit. Callers that ignore stdout on error (every existing
  call site) keep their previous behaviour; smart_summary uses the
  body to decide whether to parse despite the bit-encoded exit.

## Install

- `caps-template.sh` now emits both `CapabilityBoundingSet=` and
  `AmbientCapabilities=` into the helper drop-in. Bounding carries
  `CAP_CHOWN + <per-op caps>`; ambient carries `<per-op caps>` only
  (CAP_CHOWN stays out of ambient because only the helper process
  itself does chown, not its subprocesses). The ambient half matters
  because tools like `auditctl` introspect their own effective set
  rather than falling back on `euid==0`; under
  `NoNewPrivileges=yes`, an empty ambient set causes those tools to
  observe zero capabilities even though the parent is root. Fixes
  `auditctl exited non-zero / stderr=You must be root to run this
  program.` on fox.

# 1.7.0 (2026-05-15)

## Wire schema

- Schema version bumped to **0.2.0** (additive-minor; version-matrix
  C2 forward-compatible with 0.1.0 clients).
- Per-source error blocks gain four optional fields: `argv`,
  `exit_code`, `stderr_sha256`, `stderr_prefix`. Today populated on
  `storage.smart[].error`; the same fields will appear on any
  future per-source error block.

## Daemon

- Helper-invocation errors now carry the full subprocess argv, exit
  code, SHA-256 of stderr (was already in the wire frame, now
  surfaced), and a sanitised 200-char prefix of stderr. This
  collapses an entire class of "did the fix land?" round-trips into
  a single canary call — the operator can see exactly what was
  executed and why it failed.
- `storage.smart[].error` populates the new fields directly from the
  helper response.
- `HelperError.Error()` (used in `warnings[]` entries) now includes
  argv, exit code, and stderr prefix so non-storage tools also
  benefit even though their per-source error blocks haven't been
  extended yet.
- `updates.last_apt_update_ts`: probe order extended to cover
  modern apt's stamp file. Tries `update-stamp` (apt >= 2.4) and
  `update-success-stamp` (legacy), taking the freshest mtime.
  Warning lists both names when neither exists.

## Helper

- `exec.classify` populates the new `Argv` and `StderrPrefix` fields
  on `dispatch.Error` for every failure mode (deadline, truncation,
  tool-missing, generic non-zero exit). Argv is the full subprocess
  command vector; `StderrPrefix` is byte-level control-char
  sanitised and capped at 200 chars before crossing the unix socket.
  Raw stderr is still kept inside the helper.

# 1.6.0 (2026-05-15)

## Daemon

- **Critical envelope bug**: every tool's `warnings[]` slice was
  silently dropped at the HTTP boundary. The cache stored only
  `Data`, and `writeEnvelope` was called with `nil` warnings on both
  cache-hit and cache-miss paths. Every "no silent nulls" warning
  emitted by tools since 1.0.0 was being thrown away before reaching
  the operator. Fixed: `cache.Entry` now carries `Warnings` too;
  cache miss and hit paths both propagate it through to the envelope.
- `updates.last_apt_update_ts`: warns when
  `/var/lib/apt/periodic/update-success-stamp` is absent instead of
  silently leaving the field null.
- `security` AIDE wiring: new manifest key `aide_log_path`. When
  set, the daemon stats it for `last_run_ts`, parses
  `Total number of differences:` or `Added/Removed/Changed entries:`
  for `change_count`, and `AIDE found (NO) differences` for a
  derived `last_exit_code` (0 / 1).

## Helper

- `smart_summary` for NVMe: invocation now passes `-d nvme` when the
  device matches `^nvme[0-9]+n[0-9]+$`. The smartctl auto-detect
  heuristic walks `/sys/class/block/` and on some kernel versions
  fails to discover the NVMe device type from a namespace path.
  Forcing the device type makes the call deterministic across
  kernels.
- `read_audit_status.last_rotation_ts`: rotated-file scan no longer
  requires `.gz` suffix. auditd's own ROTATE action does not gzip;
  the previous filter missed every plain-rotated file. Now matches
  `audit.log.<N>` and `audit.log.<N>.gz`.

# 1.5.0 (2026-05-15)

## Daemon

- `updates.unattended_upgrades_enabled`: detection moved from a
  filename glob (`/etc/apt/apt.conf.d/*unattended-upgrades*`) plus
  ReadDir of `/var/log/unattended-upgrades` to `apt-config dump`,
  which is what apt itself consults. The glob missed the canonical
  `20auto-upgrades` file shipped with the unattended-upgrades
  package; the log directory is `root:root 0750` and the daemon
  user couldn't traverse it. Both combined to a hard false negative
  on otherwise correctly-configured hosts.
- `updates.unattended_upgrades_last_run_ts`: now read from the
  mtime of `/var/log/unattended-upgrades/unattended-upgrades.log`
  via the helper.
- `updates.unattended_upgrades_last_exit_code`: populated from the
  trailing status line in the log per the script's conventions
  (`All upgrades installed` → 0, `No packages found that can be
  upgraded unattended` → 0, `Upgrade failed` → 1).

## Helper

- New op `unattended_upgrades_status`: runs `apt-config dump` for
  enable-state and parses
  `/var/log/unattended-upgrades/unattended-upgrades.log` for
  last-run and exit code. Treats `apt-config` absent as
  not-a-Debian-host (enabled=false, no error). Parser is covered
  by table-driven tests.

# 1.4.1 (2026-05-15)

## Daemon

- `security.rkhunter`: scan moved to the helper. `/var/log/rkhunter.log`
  is `root:adm 0640` on Debian; the daemon (an unprivileged user not
  in `adm`) could stat the path but not read its body, so
  `warning_count` came back null even when the log was full of
  `Warning:` lines. The helper has `CAP_DAC_READ_SEARCH` when the
  operator enables the security tool.
- `security` no-silent-nulls pass:
  - Warn explicitly when AIDE's DB mtime is present but
    `change_count` is null (operator's cron wrapper writes elsewhere
    than `/var/log/aide/aide.log`).
  - Warn explicitly when the daemon detects the auditd binary but
    the helper's `read_audit_status` reports `Present:false`
    (auditctl not installed or unreachable).
  - Warn explicitly when rkhunter's binary is present but no log
    exists, or when the log exists but the helper can't read it.
  - Distinguish the debsums "timer present but never triggered" case
    from "no timer at all"; emit a precise warning per case
    (previously both fell through the same misleading message).

## Helper

- `read_audit_status`: distinguish `auditctl` missing (return
  `Present:false`, no error) from `auditctl` present but failing
  (return an error so the daemon's `warnings[]` surfaces the cause).
  Previously the latter was silently converted to `Present:false`,
  contradicting the daemon's binary detection.
- New op `rkhunter_summary`: stats `/var/log/rkhunter.log` for mtime
  and counts `Warning:` lines; runs as root so it can read
  `root:adm` logs the daemon can't.

# 1.4.0 (2026-05-15)

## Daemon

- `security.debsums_or_equivalent`: when debsums is installed, the
  tool now reads `last_run_ts` and `modified_count` from a manifest-
  declared `debsums_log_path` (file mtime + line count over lines
  beginning with `/`). When no path is configured the tool falls
  back to `debsums-check.timer`'s `LastTriggerUSec` for
  `last_run_ts` only. When neither is available a warning surfaces
  the gap instead of silently returning null. New manifest key
  `debsums_log_path` (string, defaults to null).
- `security.ssh_logins` gains a journal-only fallback: when neither
  `/var/log/auth.log` nor `/var/log/secure` is present, the daemon
  calls the helper's new `ssh_journal_counts` op and uses the
  journalctl-derived counts.
- `backup`: state-file-first source order. The operator's backup
  wrapper deposits
  `/var/lib/host-health-mcp/backup-state.json` carrying the four
  envelope fields (last_start_ts, last_end_ts, last_exit_code,
  last_archive_label); the tool returns them verbatim. Falls back to
  the manifest's `backup_log_path` and the 1.3.0 backend auto-probe
  when the state file is absent. Manifest gains `backup_state_path`
  (override; defaults to the documented contract location). No
  backup-tool passphrases or backend-specific code in the daemon or
  helper — wrappers translate their tool's output into the shared
  JSON shape.

## Helper

- New op `ssh_journal_counts`: runs `journalctl --boot -u ssh.service
  --output=cat --no-pager` and counts via prefix-match on `Accepted `
  and `Failed `. Returns `present=false` when journalctl is absent.
- New op `systemd_timer_last_trigger`: parameterised by a `.timer`
  unit name; runs `systemctl show <unit> --property=LastTriggerUSec
  --value` and returns the parsed timestamp. The helper validates
  the unit name (must end in `.timer`, must not contain whitespace,
  slashes, or NUL). Reaches systemd over dbus internally via
  systemctl, keeping the helper static (REQ 5.4).

## Docs

- `build/examples/manifest.yml` documents `debsums_log_path`,
  `backup_state_path`, and the backup state-file source-precedence
  contract.

# 1.3.0 (2026-05-15)

## Daemon

- `security` tool: fail2ban current-ban count wired through the
  helper. `intrusion_prevention.current_ban_count` returns the sum of
  `Currently banned:` across every fail2ban jail; `-1` signals that
  the backend is present but the helper couldn't query
  `fail2ban-server` (look in `warnings[]` for the reason).
- `security` tool: rkhunter warning_count parser added (counts
  `Warning:` lines in `/var/log/rkhunter.log`).
- `security` tool: SSH login counters now fall back to
  `/var/log/secure` when `/var/log/auth.log` is absent.
- `backup` tool: auto-probes well-known log paths by backend
  (`borg`, `borgmatic`, `restic`, `rsnapshot`, `duplicity`) when the
  manifest's `backup_log_path` is null. The response always carries a
  warning naming the probed paths so the operator can pin the right
  one in the manifest.
- `updates` tool: when the helper succeeds but returns an empty
  `lock_state`, a warning is surfaced instead of silently leaving the
  default `"unknown"` with no explanation.

## Helper

- New op `fail2ban_status`: invokes `fail2ban-client status` and the
  per-jail status to sum `Currently banned:` counts. Returns
  `present=false` when the binary is absent; surfaces a hard error
  when the binary is present but the server isn't reachable.

## Docs

- `build/examples/manifest.yml`: `backup_log_path` documents the
  auto-probe behaviour.

# 1.2.2 (2026-05-15)

## Daemon, Helper

- Both binaries now ping the systemd watchdog at half the configured
  `WatchdogSec` interval. The unit files declared `Type=notify` and
  `WatchdogSec=30s` per REQ 9.2 but neither process emitted
  `WATCHDOG=1` after the initial `READY=1`, so systemd killed and
  restarted them every ~30s. Symptom: calls that hit the dead window
  failed with `connection refused`; calls that hit the live window
  succeeded.
- Watchdog goroutine activates only when `WATCHDOG_USEC` is set in
  the environment (systemd injects it on `Type=notify` units with
  `WatchdogSec=`). Outside systemd the watchdog loop never starts.

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
