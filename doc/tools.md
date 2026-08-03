---
title: Host Health MCP - Tool Reference
author: Albert 'Tigr' Zenkoff <albert@tigr.net>
date: 2026-05-14
---

Per-tool reference. The wire schema is the contract; this document
exists for human consumption. Field names, types, and constraints
match `schema-draft.yaml`. Every tool returns the common envelope
shape described in REQUIREMENTS section 4: `host`, `as_of`,
`cache_age_s`, `schema_version`, `data`, optional `warnings[]`.

# Routing

All tools are POSTed under `/v1/<tool>`. Tools that take no
arguments still accept (and require) a `{}` body for uniformity.
Tools that take arguments declare a typed request shape below.

# Error handling

Tool failures surface as the structured error envelope per
`schema.ErrorEnvelope` with one of the codes from
`schema/errors.go`: `auth_required`, `auth_failed`, `unknown_tool`,
`tool_disabled`, `bad_argument`, `rate_limited`, `tool_timeout`,
`tool_failed`, `schema_incompatible`, `internal_error`. Three tools
report per-source failures **within** the data block rather than
failing the call: `storage.smart[].error`, `updates.apt_lock_state`,
and `dns` (per-probe bool plus envelope warning). All other tools
follow the "tool fails as a whole" rule.

# Argument matching

Every value that can influence what a tool does is matched by one of a
small number of disciplines. This section is the single place they are
enumerated; the per-tool sections below repeat the bounds in context
but do not restate the discipline.

Three of the nineteen tools decode a request body at all: `logs`,
`firewall`, `firewall_lookup`. The other sixteen ignore the body
entirely — their handler signature discards it — and are driven solely
by values passed in from `manifest.yml` at construction time.

## Envelope-level bounds

These apply to every request regardless of tool:

  - Request bodies are read through a limit reader and rejected with
    `body_too_large` above **4 KiB**.
  - An empty body is normalised to `{}`; a body that is not valid JSON
    is rejected before it reaches the cache.
  - The three tools that decode a body use a strict decoder
    (`DisallowUnknownFields`), so an unrecognised JSON key is a
    `bad_argument` error, not a silent ignore.
  - Helper-to-daemon response frames are capped at **4 MiB**, bounding
    the volume of subprocess-derived data independently of the
    request.

## Caller-supplied arguments

| Tool | Argument | Discipline | Bound / allowed values |
|------|----------|------------|------------------------|
| `logs` | `severity` | closed enum, map lookup | `emerg`, `alert`, `crit`, `err`, `warning`; default `warning` |
| `logs` | `window` | closed enum, map lookup | `15m`, `1h`, `6h`, `24h`; default `1h` |
| `logs` | `source` | closed enum, map lookup | `journal`, `audit`; default `journal` |
| `firewall` | `mode` | closed enum | `summary` (default, also the empty value) or `detail`; `detail` additionally requires the manifest's `detail_mode_allowed`. Any other value is `bad_argument` |
| `firewall` | `table` | structured split on the first `/` | `<family>/<name>`, both halves non-empty; anything else is `bad_argument`. Only the first `/` separates, so `inet/a/b` names table `a/b`. Never reaches a subprocess or a path — used only as an in-process map-key comparison |
| `firewall` | `include_set_elements` | boolean | JSON `true` / `false`; default `false` |
| `firewall_lookup` | `query` | parsed into a type | Required, non-blank. Parsed helper-side by `net/netip` — `ParsePrefix` then `ParseAddr`; anything that is not a valid IPv4/IPv6 address or CIDR is rejected with `bad_param`. Never string-matched, never used as a path or argv element. The audit-log copy is truncated to 64 runes |
| `firewall_lookup` | `include_set_elements` | boolean | JSON `true` / `false`; default `false` |

No other tool accepts caller input. In particular `systemd_units`
(selector is manifest-only), `storage`, `security` and `workload`
expose no argument by which a caller can name a device, unit, path or
plugin.

Both `firewall` arguments fail closed as of 2.2.1. `mode` is checked
against the closed set `{"", "summary", "detail"}` and anything else is
`bad_argument`; before 2.2.1 the only test was the helper's
`mode == "detail"`, so a typo degraded silently to summary output.
`table` must parse as `<family>/<name>` with both halves non-empty;
before 2.2.1 a value that did not split left the helper's filter unset,
and an unset filter matched everything, so a malformed filter returned
the entire ruleset instead of narrowing it. The helper re-checks the
filter and refuses an unparseable one as a second layer.

## Manifest-supplied values

Operator-controlled, read once at startup. They are not caller input,
but they are the other half of what bounds a tool's behaviour.

| Tool | Key | Discipline | Bound / allowed values |
|------|-----|------------|------------------------|
| `systemd_units` | `whitelisted_units[]` | exact names, startup-validated | Non-blank; no `*`, `?` or `[`. Unbounded in length |
| `systemd_units` | `whitelisted_unit_patterns[]` | fnmatch globs, resolved by systemd | Non-blank; not composed solely of metacharacters. Result capped at 100 units |
| `workload.nginx_apache` | `access_log_path` | **none** | Free string; see below |
| `workload.nginx_apache` | `access_log_window_minutes` | bounded integer | `1`..`1440`; default 60. Out-of-range or non-numeric is a hard error from the plugin |
| `workload.nginx_apache` | `access_log_tail_bytes` | bounded integer | Non-negative; default 256 KiB; hard-capped helper-side at 4 MiB |
| `firewall` | `detail_mode_allowed` | boolean | Gates `mode: detail` irrespective of what the caller asks for |
| `firewall` | `max_set_elements_per_set` | bounded integer | Default 2000; hard-capped helper-side at 40000 |
| `firewall` | `max_rule_text_bytes` | bounded integer | Default 65536 when unset or non-positive; hard-capped helper-side at 1 MiB since 2.2.1 (previously floor-only, so an arbitrarily large value removed the only bound on inline rules per chain) |
| `firewall` | `ban_sets[]` | literal strings | Used as map keys (`family/table/name`); no per-field validation |
| `storage` | `btrfs_mountpoints[]` | anchored regex plus a filesystem-type check | See `btrfsMountPathRE` below |
| `certs` | `cert_paths[]`, `cert_renewal_units[]` | none | Parallel lists; read by the daemon, never passed to a subprocess |

`workload.nginx_apache.access_log_path` is the one value in the whole
surface with no allow-list. It is passed to the helper, which runs as
root, and opened directly: `os.Stat` then `os.Open`, with no
`O_NOFOLLOW`, no prefix constraint, and no canonicalisation. The only
check is that the resolved target is a regular file — and because
`os.Stat` follows symlinks, a symlink to a regular file is followed.
An operator who misconfigures this key can therefore cause the helper
to read the tail of any root-readable regular file on the host; the
parsed 4xx/5xx counts, not the bytes, are what crosses the socket, but
the read itself is unconstrained. This is accepted only because the
value is operator-supplied and never caller-supplied: no request body
can reach it. Treat it with the same care as any other root-context
path in `manifest.yml`.

## Helper-side validation

Several tools reach an underlying binary through a helper op. Op
parameters are not caller arguments, but they are the validation layer
that stands between a tool and a subprocess argv, so they belong in
the same picture. Every one of these patterns is fully anchored, and
`helperexec` builds argv slices directly — there is no `sh -c`
anywhere in the ops package, so these guard argv content, not shell
metacharacters.

| Pattern | Op | Validates |
|---------|-----|-----------|
| `deviceRE` — <code>^(sd[a-z]+&#124;nvme[0-9]+n[0-9]+&#124;vd[a-z]+&#124;hd[a-z]+&#124;xvd[a-z]+)$</code> | `smart_summary` | Device name, before `/dev/` prefixing. The daemon's own pre-filter in `storage` is a convenience, not the boundary — this is |
| `nvmeRE` — `^nvme[0-9]+n[0-9]+$` | `smart_summary` | Runs after `deviceRE` has passed, only to decide whether to add `-d nvme`. Not itself a gate |
| `mdraidNameRE` — `^md[0-9]+$` | `mdraid_detail` | Array name, before `/dev/` prefixing |
| `btrfsMountPathRE` — `^(/[A-Za-z0-9_-]+)+$` | `btrfs_scrub` | Mountpoint. Backed by a second, independent gate: `statfs(2)` must report `BTRFS_SUPER_MAGIC`. The window between the statfs and the exec is a known, accepted TOCTOU |
| `timerUnitRE` — `^[A-Za-z0-9][A-Za-z0-9._@-]*\.timer$` | `systemd_timer_last_trigger` | Unit name. Call sites pass literals only (e.g. `debsums-check.timer`) |
| `paramRE` — `^severity=(...) window=(...) source=(...)$` | `journal_query` | The whole structured parameter string the `logs` tool builds. Deliberately redundant with the tool's enum check; the approved values are then translated through fixed switch statements into `journalctl` argv, so no caller string reaches argv even in literal form |
| `jailNameRE` — `^[A-Za-z][A-Za-z0-9._-]{0,63}$` | `fail2ban_status` | Not an op parameter — the op takes none. Filters jail names parsed **out of** `fail2ban-client status` output before they are fed back into a second invocation |
| `wgPublicKeyRE` — `^[A-Za-z0-9+/]{42,43}=?$` | `wireguard_show` | Not an op parameter. Validates each public key parsed out of `wg show all dump` before it enters the result |

The remaining fifteen ops take no parameter at all: their argv is
fixed at compile time and contains no caller- or operator-influenced
element.

# Tools

## `system` (REQ 4.1, CORE)

Uptime, load, memory, swap, per-mount disk usage, kernel, distro,
time-sync, reboot-required. All data read locally from `/proc`,
`/etc/os-release`, and `statfs(2)`; no helper involvement.

Cache TTL default: 15 s. Timeout default: 3 s.

## `systemd_units` (REQ 4.2, CORE)

Per-unit state for the units selected by `manifest.yml`. Source:
system D-Bus (no helper). The caller supplies nothing — neither unit
names nor patterns; the selector is entirely operator-controlled.

Per-unit fields, identical in both arrays: `name`, `load_state`,
`active_state`, `sub_state`, `result`, `exec_main_status`,
`active_enter_ts`, `active_exit_ts`, `restart_count`.

### Selector

Two independent manifest keys, each feeding its own response array:

| Manifest key                | Response array   | Resolved by                 |
|-----------------------------|------------------|-----------------------------|
| `whitelisted_units`         | `units[]`        | `ListUnitsByNames` (exact)  |
| `whitelisted_unit_patterns` | `pattern_units[]`| `ListUnitsByPatterns` (glob)|

`whitelisted_units` is unchanged from earlier releases: exact unit
names, resolved by name. systemd **synthesises** a row for any name it
does not recognise, carrying `load_state: "not-found"` and empty
`active_state` / `sub_state`. That is deliberate and useful — it is
how a caller learns that a unit the operator declared is absent, as
opposed to present-and-stopped.

`whitelisted_unit_patterns` (2.2.0+) holds fnmatch globs (`*`, `?`,
`[...]`) matched by systemd itself, with the same semantics as
`systemctl list-units '<pattern>'`. Two differences from the exact
list follow inherently from how systemd resolves patterns:

  - Only **loaded** units can match. A unit that is installed but has
    never been loaded does not appear at all.
  - A pattern that matches nothing is indistinguishable from the
    units being absent. There is no not-found row on this path. Name
    a unit in `whitelisted_units` when you need to be told it is
    missing.

The keys are kept separate rather than inferred from an entry's
content because the two halves resolve through different D-Bus calls
with materially different semantics — one can report a unit as absent,
the other cannot. Which of the two an operator intended should be
stated rather than guessed from punctuation.

### Disjointness and the cap

The two arrays are **disjoint**. A unit that is both named exactly and
matched by a pattern appears only in `units[]`, never in both, so a
consumer reading the two together cannot double-count it.

Keeping them separate makes the 2.2.0 change additive by
construction: a consumer written before 2.2.0 reads `units[]` and sees
exactly what it saw before, and pattern-discovered units cannot leak
into an existing dashboard or alert rule unless the consumer opts in
by reading the new array. The provenance distinction is also
operationally real — a `not-found` row in `units[]` means "a unit I
declared is missing" and is usually worth alerting on, whereas a unit
disappearing from `pattern_units[]` is routine (`php8.2-fpm`
superseded by `php8.3-fpm`).

`pattern_units[]` is capped at **100 units**. Each unit costs two
further D-Bus round trips against a 3 s budget, so a broad pattern
such as `*.service` would otherwise exhaust the deadline on any normal
host. Past the cap the array is truncated and the envelope carries:

```
systemd_units: whitelisted_unit_patterns resolved to <n> units,
capped at 100; narrow the patterns
```

`units[]` is never truncated — it is enumerated by hand in the
manifest and is therefore self-limiting.

### Startup validation

These are hard startup failures, not warnings; the daemon refuses to
start:

  - a glob metacharacter (`*`, `?`, `[`) in a `whitelisted_units`
    entry — the error points the operator at
    `whitelisted_unit_patterns`. Passed to `ListUnitsByNames` such an
    entry would match nothing and come back as a synthesised
    not-found row, which reads as "the unit is missing";
  - an empty or blank entry in either list;
  - a pattern consisting solely of metacharacters (`*`, `**`, `?*`),
    which would match every unit on the host.

The `manifest` tool echoes both keys, so a caller can see the selector
it is being served without reading `manifest.yml`.

Cache TTL default: 15 s. Timeout default: 3 s.

## `network` (REQ 4.3, CORE)

Interfaces, default routes, nft table+counter view, resolver,
IPv6-policy compliance.

  - Interface metadata from `/sys/class/net`; per-interface IPv4
    and IPv6 addresses via netlink (`RTM_GETADDR`). The loopback
    interface is included so callers see `lo`'s `127.0.0.1/8` and
    `::1/128`.
  - Default routes from `/proc/net/route` and
    `/proc/net/ipv6_route`.
  - `nft_table_counts` populated via the helper's `nft_table_counts`
    op. Absent nftables surface as an empty map.
  - `ipv6_policy_compliant` evaluated against
    `manifest.yml`'s `ipv6_policy` setting.

Cache TTL default: 30 s. Timeout default: 2 s.

## `dns` (REQ 4.4, CORE)

Resolver in use plus three time-bounded probes: self-hostname,
operator-configured external probe, operator-configured filter
canary. Per-probe deadline 800 ms; probes that exceed it report
`false` plus an envelope warning. NXDOMAIN on the canary is the
expected honest-resolver outcome and is not surfaced as a warning.

Cache TTL default: 30 s. Timeout default: 3 s.

## `security` (REQ 4.5, CORE)

Presence and (where the helper ops have run) deep state of AIDE,
auditd, rkhunter, debsums; intrusion-prevention backend in use;
recent SSH login counters.

`ssh_logins` reports `accepted_recent`, `failed_recent`, and a
`window` discriminator. The two counts cover a **different window
depending on the source**, and `window` names it so the number is
never ambiguous:

  - `since_log_rotation` — counted from the live `/var/log/auth.log`
    (Debian) or `/var/log/secure` (RHEL-family). The window is
    whatever logrotate keeps in the current file.
  - `last_24h` — counted from the systemd journal
    (`journalctl --since='24 hours ago' -u ssh.service`) on hosts
    with no file source. The journal path is bounded to 24h rather
    than the full boot because a since-boot walk of `ssh.service`
    on a long-uptime host iterates the entire boot and exceeds the
    per-op deadline.
  - `unavailable` — neither source was readable; `accepted_recent`
    and `failed_recent` are `null` (distinct from a genuine `0`).

Renamed from `accepted_since_boot` / `failed_since_boot` in schema
1.0.0 (release 2.0.0) — an authorised breaking change; a plugin
built against schema 0.x fails closed against a 1.0.0 daemon per
version-matrix cell C4.

`failed_recent` includes any of: post-auth `Failed` lines
(password/publickey), preauth disconnects
(`Disconnected from ... [preauth]`), preauth connection closes
(`Connection closed by ... [preauth]`), and
`kex_exchange_identification` errors. The pre-1.16.1 counter only
matched `Failed `; on key-only fleets that pattern never fires
because scanners disconnect during key exchange, so the counter
was permanently zero. Both file and journal paths recognise the
broader set. The file path also handles the OpenSSH 9.8+ split
daemon (`sshd[PID]` and `sshd-session[PID]`) that landed in
Debian 13.

The journal path detects insufficient retention: when the host has
been up longer than 24h but the journal's oldest retained entry
starts after the 24h cutoff, the daemon emits an envelope warning
`ssh_logins: journal retains less than 24h — oldest entry ...;
last_24h counters reflect only ~Xh of the 24h window`. Counters
still ship — but the operator sees they cover only the retained
tail. A host booted less than 24h ago naturally has a shorter span
and is not flagged. Volatile journald (`Storage=volatile` in
`journald.conf`) and aggressive `SystemMaxUse` / `RuntimeMaxUse`
are the typical triggers.

Uptime caveat: on a host whose uptime is under 24h the `last_24h`
counts necessarily cover only since boot, and on a volatile journal
they cover only the current boot's runtime — which may be shorter
than 24h **without** a truncation warning (the warning fires only
for hosts up longer than 24h). Cross-reference uptime from the
`system` tool when the host may have rebooted inside the window.
If a file-based source (`/var/log/auth.log` or `/var/log/secure`)
cannot be read to completion — e.g. a pathological over-long line —
the daemon does not report its partial counts as authoritative: it
emits `security: auth log read incomplete (...)` and falls back to
the journal (`last_24h`) path.

  - `aide_or_equivalent`: presence by binary; deep fields from the
    helper's `read_aide_summary` op (last-run timestamp from
    `/var/lib/aide/aide.db` mtime; change count from
    `/var/log/aide/aide.log`).
  - `auditd`: presence by binary; queue depth and lost-event count
    from the helper's `read_audit_status` op (parses `auditctl -s`).

Cache TTL default: 60 s. Timeout default: 5 s.

## `certs` (REQ 4.6, CORE)

For each manifest-declared `cert_paths` entry, returns subject,
issuer, `not_after`, `days_remaining`, and the matching
`renewal_unit` from the parallel `cert_renewal_units` list.

Cache TTL default: 5 min. Timeout default: 3 s.

## `mail` (REQ 4.7, CORE)

MTA detected by canonical binary presence. Queue depth from the
helper's `postqueue` op (Postfix only). Last successful send from
`/var/log/mail.log` mtime as a coarse signal.

Cache TTL default: 60 s. Timeout default: 3 s.

## `backup` (REQ 4.8, CORE)

`backend` echoes the manifest value. `last_end_ts` from
`backup_log_path` mtime. Returns the not-configured warning when no
log path is set. Repository URLs, passphrases, credentials and
archive contents never appear by construction.

Cache TTL default: 5 min. Timeout default: 2 s.

## `workload` (REQ 4.9, OPTIONAL)

Map keyed by compile-time-registered plugin name. Plugins are
selected via build tags (`WORKLOAD_TAGS=` in `build.sh`); the
default build ships `wl_wireguard`, `wl_postfix`, `wl_dovecot`,
`wl_nginx_apache`. Manifest references to plugins not compiled in
cause the daemon to refuse to start (REQ 8.2).

  - `wireguard`: delegates to the helper's `wireguard_show` op.
    The helper strips private and preshared keys before any byte
    crosses to the daemon (design §7.3.1).
  - `postfix`: wraps the `postqueue` op. Reports both `queue_depth`
    (from the `postqueue -p` trailer summary) and `deferred_count`
    (from per-message header lines whose queue-id indicator suffix
    is neither `*` for active nor `!` for hold). Envelope addresses
    and queue identifiers are not retained on either side of the
    socket.
  - `dovecot`: delegates to the helper's `dovecot_status` op.
    `process_state` derives from `systemctl is-active
    dovecot.service` and is one of `active`, `inactive`, `failed`,
    `activating`, `deactivating`, `unknown`, or the synthetic
    `not_installed` when the unit cannot be found.
    `connection_count` is a line count of `doveadm who -1`; per-
    session columns (username, remote address) are not retained.
  - `nginx_apache`: delegates to the helper's `nginx_apache_status`
    op. `server` is `nginx`, `apache`, or `none`. `worker_count`
    is derived from `/proc/<pid>/comm` counts using the master-
    minus-one heuristic (a known limitation: edge cases with
    multiple master-like processes round low). `recent_4xx` /
    `recent_5xx` are integer counts of HTTP 4xx / 5xx responses
    over the configured window, parsed from a bounded tail-read
    of the configured access log inside the helper process. Raw
    log bytes never cross the helper-to-daemon socket (REQ 6.2).
    `recent_window_minutes` reports the window actually covered;
    `recent_coverage` is `full` (tail covered the configured
    window), `partial` (tail covered a shorter span), or
    `unavailable` (no path configured, file unreadable, or no
    parseable timestamps). When `recent_coverage` is
    `unavailable`, `recent_4xx` and `recent_5xx` are `null` —
    NOT zero. A null is "can't measure"; zero is "measured zero
    errors".

`workload_plugin_config` is a top-level manifest map keyed by
plugin name; the value is a string-to-string map specific to that
plugin. Today only `nginx_apache` consumes a config:

```yaml
workload_plugin_config:
  nginx_apache:
    access_log_path: /var/log/nginx/access.log
    # access_log_window_minutes: 60   (default; 1..1440)
    # access_log_tail_bytes: 262144   (default 256 KiB; max 4 MiB)
```

The access log must be in combined or common log format. See
`doc/install.md` §3.4 for the full description.

Cache TTL default: 30 s. Timeout default: 5 s.

## `logs` (REQ 4.10, CORE)

Request shape: `{ "severity": "<lvl>", "window": "<dur>", "source":
"<src>" }`. `lvl` in `{emerg, alert, crit, err, warning}`. `dur` in
`{15m, 1h, 6h, 24h}`. `src` in `{journal, audit}`.

All three fields are optional; empty fields fall back to defaults
(`severity=warning`, `window=1h`, `source=journal`). This matches the
MCP-routed wire shape from 1.15.2+ where the plugin forwards `{}` for
no-arg calls. The MCP plugin (1.16.0+) also surfaces the three fields
in the tool's `inputSchema`, so MCP clients can override any of them
per call.

The helper invokes `journalctl --output=json` with bounded args and
parses the JSON lines into typed entries. The daemon runs each
sample message through the §6.3 redaction filter before placing it
in the envelope.

Cache TTL default: 15 s. Timeout default: 5 s.

## `manifest` (REQ 4.11, CORE)

Daemon self-description. `schema_version`, `daemon_version`,
`build_id`, `started_at_ts`, `enabled_tools`,
`enabled_workload_plugins`, `whitelisted_units`,
`whitelisted_unit_patterns`. Required for plugins to negotiate
schema-version compatibility (REQ 7.2; `doc/version-matrix.md`).

`whitelisted_unit_patterns` is new in 2.2.0 (wire schema 1.1.0,
additive); it is the glob half of the tool 4.2 selector and is
always present, as `[]` when no patterns are configured.

Cache TTL default: 60 s. Timeout default: 1 s.

## `updates` (REQ 4.12, CORE)

`apt_lock_state` enum (`acquired` / `contended` / `unknown`).
Security and regular update counts (`null` when the lock cannot be
acquired). Held packages (sorted). `last_apt_update_ts` from
`/var/lib/apt/periodic/update-success-stamp` mtime.
`unattended_upgrades_enabled` and `unattended_upgrades_last_run_ts`
from `/var/log/unattended-upgrades/` presence and newest-file
mtime. `needrestart_pending_services` (sorted) from the helper's
`needrestart` op.

Cache TTL default: 60 s. Timeout default: 8 s.

## `storage` (REQ 4.13, CORE)

  - `mdraid`: one entry per array in `/proc/mdstat`, populated via
    the helper's `mdraid_detail` op.
  - `lvm_vgs` and `lvm_lvs`: populated via the helper's `lvm_report`
    op (parses `vgs`/`lvs --reportformat=json`).
  - `smart`: per-device entry from the helper's `smart_summary` op
    (parses `smartctl --json -a /dev/<dev>`). Per-device collection
    failure populates `error: {code, message}` rather than failing
    the whole call.
  - `btrfs`: one entry per `manifest.yml` `btrfs_mountpoints` entry,
    populated via the helper's `btrfs_scrub` op. The helper
    independently verifies via `statfs(2)` that each path is
    BTRFS_SUPER_MAGIC.
  - `zfs_pools`: populated via the helper's `zpool_status` op
    (parses `zpool list -H -o name` + `zpool status <name>` per
    pool).

Per-call helper fan-out capped at 8 (design §7.4); larger device
sets sequence beyond the cap.

Cache TTL default: 60 s. Timeout default: 10 s.

## `kernel` (REQ 4.14, CORE)

Decoded taint flags, MCE / EDAC error counters, OOM kills since
boot, last panic indicator (kdump-derived if present), recognised
cmdline keys (names only, never values).

Cache TTL default: 60 s. Timeout default: 1 s.

## `pressure` (REQ 4.15, CORE)

PSI averages from `/proc/pressure/{cpu,io,memory}`. Five blocks:
`cpu`, `io_some`, `io_full`, `memory_some`, `memory_full`. Each
either a `{avg10, avg60, avg300, total_us}` object or `null` on
hosts without PSI support.

Cache TTL default: 15 s. Timeout default: 1 s.

## `sockets` (REQ 4.16, CORE)

Set of `{proto, family, addr, port}` listening sockets. Source:
`/proc/net/{tcp,tcp6,udp,udp6}`. No PID or process information.

Cache TTL default: 30 s. Timeout default: 1 s.

## `sensors` (REQ 4.17, OPTIONAL)

Per-chip readings from `/sys/class/hwmon`: temperatures (°C), fan
speeds (RPM), voltages. Empty `chips` array on hosts without hwmon
(typical for VMs). Optional, manifest-gated.

Cache TTL default: 15 s. Timeout default: 2 s.

## `firewall` (1.13.0+, OPTIONAL)

> Renamed from `host_firewall` in 1.15.0. Pre-1.15.0 builds
> exposed this tool as `/v1/host_firewall`; from 1.15.0 it is
> `/v1/firewall`. Update operator clients and `enabled_tools[]`
> manifests at the same time as the daemon upgrade.

Read-only inspection of the host's nftables ruleset, sets, and a
synthesised per-source ban view. Source: `nft -j list ruleset`
plus per-set `nft -j list set <family> <table> <name>` when
inline elements are requested.

### Request

| Field                  | Type   | Default     | Notes                                                  |
|------------------------|--------|-------------|--------------------------------------------------------|
| `mode`                 | string | `"summary"` | `"summary"` or `"detail"`. Detail adds rule bodies.    |
| `table`                | string | `""`        | Filter to one table, formatted `<family>/<name>`.      |
| `include_set_elements` | bool   | `false`     | Populate `elements[]` per set up to the manifest cap.  |

### Response data

- `backend` — `"nftables"` or `"none"` (the latter when nft is not
  installed or no tables exist).
- `nft_version` — best-effort version string from `nft --version`.
- `ruleset_hash_sha256` — sha256 over the raw `nft -j list
  ruleset` bytes. Reproduce with `nft -j list ruleset | sha256sum`.
  Suitable as a fleet-wide diff key.
- `tables[]` — per-table `{ family, name, chain_count, set_count,
  map_count, rule_count }`.
- `chains[]` — `{ family, table, name, type, hook, prio, policy,
  rule_count, rules[] }`. `rules[]` populated only when
  `mode="detail"` AND `firewall.detail_mode_allowed=true` in the
  manifest. Each rule carries `handle`, `expr` (the compact-JSON
  encoding of nftables' expression array — not the rendered text
  form), and an optional `counter` `{packets, bytes}`.
- `sets[]` — `{ family, table, name, type, flags[], size_limit,
  element_count, elements[], elements_truncated, is_map }`.
  `elements[]` populated only when `include_set_elements=true`.
- `bans` — `{ total_active_v4, total_active_v6, by_set[] }`.
  `by_set[]` rows correspond 1:1 with the manifest's
  `firewall.ban_sets`. A ban_set the manifest names but nft does
  not report carries `count: 0` plus a warning.
- `errors[]` — structured per-op errors (see schema
  `HelperOpError`) on partial failures.

Cache TTL default: 30 s. Timeout default: 6 s.

### Manifest

```yaml
firewall:
  enabled: true
  ban_sets:
    - { family: inet, table: net-ban,  name: banned_v4, source: net-ban }
    - { family: inet, table: net-ban,  name: banned_v6, source: net-ban }
    - { family: inet, table: crowdsec, name: crowdsec-blacklists, source: crowdsec }
  detail_mode_allowed: true
  max_set_elements_per_set: 2000
  max_rule_text_bytes: 65536
```

`max_set_elements_per_set` is capped server-side at 40000 to
bound the helper-to-daemon response under `MaxResponseFrame`
(4 MiB in schema 0.5.0). Hosts whose ban sets exceed that
ceiling report `elements_truncated: true` plus the live
`element_count`.

### Limitations

- iptables-legacy is not enumerated. Hosts using legacy iptables
  exclusively report `backend: "none"`.
- `expr` is JSON-encoded, not nft's text rendering. Reconstructing
  the textual form would require re-implementing the userspace nft
  printer; operators wanting the text form should call `nft list
  ruleset` directly on the host.

## `firewall_lookup` (1.14.0+, OPTIONAL)

> Renamed from `host_firewall_lookup` in 1.15.0. Same migration
> note as `firewall` above.

Search the host's nftables ruleset for any reference to a given
IPv4/IPv6 address or CIDR. Intended for fleet queries of the form
"is this IP banned anywhere?" and "which host's policy is letting
X through?". A single `nft -j list ruleset` call per invocation;
all matching is performed in-process.

### Request

| Field                  | Type    | Default | Notes                                            |
|------------------------|---------|---------|--------------------------------------------------|
| `query`                | string  | —       | Required. IPv4/IPv6 address or CIDR.             |
| `include_set_elements` | bool    | `false` | Populate `sets[]` with per-element hits.         |

### Response data

- `query`, `query_kind` (`ipv4_addr` | `ipv6_addr` |
  `ipv4_cidr` | `ipv6_cidr`).
- `matches[]` — rule hits. Each entry:
  - `match_kind` — `saddr_exact`, `daddr_exact`,
    `saddr_in_subnet`, `daddr_in_subnet`, `set_member`, or
    `set_subset_overlap`.
  - `family`, `table`, `chain`, `rule_handle`.
  - `rule_text` — compact JSON encoding of nftables' expression
    array.
  - `operator`, `matched_value`, optional `set_name`.
- `sets[]` — set/map element hits (only when
  `include_set_elements=true`). Each entry:
  - `match_kind` — `set_member` or `set_subset_overlap`.
  - `family`, `table`, `set`, `element_key`.
  - Optional `expires_s`, `timeout_s` for timeout-flagged sets.
- `searched_tables`, `searched_chains`, `searched_rules`,
  `searched_sets` — coverage counters.
- `errors[]` — structured per-op errors (schema `HelperOpError`).

Cache TTL default: 30 s. Timeout default: 6 s.

### Match semantics

`match_kind` describes the **relationship** between query and
rule, not the shape of the rule itself. A rule pinning a single
literal IP still gets `saddr_in_subnet` when the caller queried a
covering CIDR — the use case "show me everything touching
10.0.0.0/24" must surface every single-address rule inside that
range. The full matrix:

| Query  | Rule rhs           | match_kind                                  |
|--------|--------------------|---------------------------------------------|
| IP     | literal IP equal   | `saddr_exact` / `daddr_exact`               |
| IP     | prefix covering IP | `saddr_in_subnet` / `daddr_in_subnet`       |
| IP     | range covering IP  | `saddr_in_subnet` / `daddr_in_subnet`       |
| IP     | anon-set member    | `saddr_in_subnet` / `daddr_in_subnet`       |
| IP     | `@setname` (IP ∈ set) | `set_member`                             |
| CIDR   | literal IP inside  | `saddr_in_subnet` / `daddr_in_subnet`       |
| CIDR   | prefix overlapping | `saddr_in_subnet` / `daddr_in_subnet`       |
| CIDR   | range overlapping  | `saddr_in_subnet` / `daddr_in_subnet`       |
| CIDR   | `@setname` (overlap) | `set_subset_overlap`                      |

In short: `*_exact` requires both sides to be single addresses and
equal. Anything broader on either side that still overlaps the
query produces `*_in_subnet` (literal/prefix/range rhs) or
`set_subset_overlap` (set reference, CIDR query).

### Manifest gating

Shares `firewall.enabled` with `firewall`. If the firewall
block is disabled, this tool returns an empty payload plus the
`firewall: disabled in manifest` warning.

### Limitations

- Only `ip` and `ip6` `saddr` / `daddr` payload matches are
  considered. Layer-4 and link-layer rules are skipped.
- `rule_text` is JSON, not nft's textual rendering. See
  `firewall` tool docs for the rationale.

# Helper op reference

Internal — the daemon's `internal/helperinvoke` package is the only
caller. Listed here so reviewers can find each implementation. The
authoritative list is the `AllOps` slice in
`daemon/internal/shared/proto/ops.go` (23 entries).

| Op token                     | File                                                | Caps required (helper unit)             |
|------------------------------|-----------------------------------------------------|-----------------------------------------|
| `read_audit_status`          | `internal/helper/ops/audit_status.go`               | `CAP_AUDIT_READ`                        |
| `read_aide_summary`          | `internal/helper/ops/aide_summary.go`               | `CAP_DAC_READ_SEARCH`                   |
| `read_reboot_marker`         | `internal/helper/ops/reboot_marker.go`              | none                                    |
| `smart_summary`              | `internal/helper/ops/smart_summary.go`              | `CAP_SYS_RAWIO`, `CAP_DAC_READ_SEARCH`  |
| `mdraid_detail`              | `internal/helper/ops/mdraid.go`                     | `CAP_DAC_READ_SEARCH`                   |
| `lvm_report`                 | `internal/helper/ops/lvm.go`                        | `CAP_DAC_READ_SEARCH`                   |
| `zpool_status`               | `internal/helper/ops/zpool.go`                      | `CAP_SYS_ADMIN`                         |
| `btrfs_scrub`                | `internal/helper/ops/btrfs.go`                      | `CAP_DAC_READ_SEARCH`                   |
| `postqueue`                  | `internal/helper/ops/postqueue.go`                  | none                                    |
| `wireguard_show`             | `internal/helper/ops/wireguard.go`                  | `CAP_NET_ADMIN`                         |
| `apt_pending`                | `internal/helper/ops/apt_pending.go`                | none                                    |
| `needrestart`                | `internal/helper/ops/needrestart.go`                | none                                    |
| `journal_query`              | `internal/helper/ops/journal.go`                    | none (root reads the journal directly)  |
| `nft_table_counts`           | `internal/helper/ops/nft.go`                        | `CAP_NET_ADMIN`                         |
| `fail2ban_status`            | `internal/helper/ops/fail2ban.go`                   | none                                    |
| `ssh_journal_counts`         | `internal/helper/ops/ssh_journal.go`                | none (root reads the journal directly)  |
| `systemd_timer_last_trigger` | `internal/helper/ops/systemd_timer.go`              | none                                    |
| `rkhunter_summary`           | `internal/helper/ops/rkhunter.go`                   | `CAP_DAC_READ_SEARCH`                   |
| `unattended_upgrades_status` | `internal/helper/ops/unattended_upgrades.go`        | none                                    |
| `firewall_inspect`           | `internal/helper/ops/firewall.go`                   | `CAP_NET_ADMIN`                         |
| `firewall_lookup`            | `internal/helper/ops/firewall_lookup.go`            | `CAP_NET_ADMIN`                         |
| `dovecot_status`             | `internal/helper/ops/dovecot.go`                    | none                                    |
| `nginx_apache_status`        | `internal/helper/ops/nginx_apache.go`               | `CAP_DAC_READ_SEARCH`                   |

The capability generator (`/usr/sbin/host-health-mcp-caps-template`)
maps the manifest's `enabled_tools[]` and `workload_plugins[]` to the
union of required caps and writes them to the helper unit's drop-in.
