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

# Tools

## `system` (REQ 4.1, CORE)

Uptime, load, memory, swap, per-mount disk usage, kernel, distro,
time-sync, reboot-required. All data read locally from `/proc`,
`/etc/os-release`, and `statfs(2)`; no helper involvement.

Cache TTL default: 15 s. Timeout default: 3 s.

## `systemd_units` (REQ 4.2, CORE)

Per-unit state for every name in `manifest.yml`'s
`whitelisted_units`. Source: system D-Bus (no helper). Per-unit
fields: `name`, `load_state`, `active_state`, `sub_state`, `result`,
`exec_main_status`, `active_enter_ts`, `active_exit_ts`,
`restart_count`. Caller cannot supply unit names.

Cache TTL default: 15 s. Timeout default: 3 s.

## `network` (REQ 4.3, CORE)

Interfaces, default routes, nft table+counter view, resolver,
IPv6-policy compliance.

  - Interfaces from `/sys/class/net`; IPv6 addresses from
    `/proc/net/if_inet6`.
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
SSH login counters from `/var/log/auth.log`.

`ssh_logins.failed_since_boot` includes any of: post-auth `Failed`
lines (password/publickey), preauth disconnects
(`Disconnected from ... [preauth]`), preauth connection closes
(`Connection closed by ... [preauth]`), and
`kex_exchange_identification` errors. The pre-1.16.1 counter only
matched `Failed `; on key-only fleets that pattern never fires
because scanners disconnect during key exchange, so the counter
was permanently zero. Both file (`/var/log/auth.log`) and journal
paths now recognise the broader set. The file path also handles
the OpenSSH 9.8+ split daemon (`sshd[PID]` and `sshd-session[PID]`)
that landed in Debian 13.

The journal path (1.16.2+) detects volatile-journal truncation:
if the journal's oldest retained entry for the current boot is
more than 10 minutes after the kernel `btime`, the daemon emits
an envelope warning `ssh_logins: journal truncated — oldest entry
... vs boot ...`. Counters still ship — but the operator sees
that they cover only the retained window rather than the full
boot. Volatile journald (`Storage=volatile` in `journald.conf`)
and aggressive `SystemMaxUse` / `RuntimeMaxUse` are the typical
triggers.

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
  - `postfix`: wraps the `postqueue` op for queue depth.
  - `dovecot`, `nginx_apache`: registered placeholders today;
    `Collect` returns "not yet implemented" until the operator-
    facing data sources are pinned.

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
`enabled_workload_plugins`, `whitelisted_units`. Required for
plugins to negotiate schema-version compatibility (REQ 7.2;
`doc/version-matrix.md`).

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
caller. Listed here so reviewers can find each implementation:

| Op token            | File                                                | Caps required (helper unit)             |
|---------------------|-----------------------------------------------------|-----------------------------------------|
| `read_audit_status` | `internal/helper/ops/audit_status.go`               | `CAP_AUDIT_READ`                        |
| `read_aide_summary` | `internal/helper/ops/aide_summary.go`               | `CAP_DAC_READ_SEARCH`                   |
| `read_reboot_marker`| `internal/helper/ops/reboot_marker.go`              | none                                    |
| `smart_summary`     | `internal/helper/ops/smart_summary.go`              | `CAP_SYS_RAWIO`, `CAP_DAC_READ_SEARCH`  |
| `mdraid_detail`     | `internal/helper/ops/mdraid.go`                     | `CAP_DAC_READ_SEARCH`                   |
| `lvm_report`        | `internal/helper/ops/lvm.go`                        | `CAP_DAC_READ_SEARCH`                   |
| `zpool_status`      | `internal/helper/ops/zpool.go`                      | `CAP_SYS_ADMIN`                         |
| `btrfs_scrub`       | `internal/helper/ops/btrfs.go`                      | `CAP_DAC_READ_SEARCH`                   |
| `postqueue`         | `internal/helper/ops/postqueue.go`                  | none                                    |
| `wireguard_show`    | `internal/helper/ops/wireguard.go`                  | `CAP_NET_ADMIN`                         |
| `apt_pending`       | `internal/helper/ops/apt_pending.go`                | none                                    |
| `needrestart`       | `internal/helper/ops/needrestart.go`                | none                                    |
| `journal_query`     | `internal/helper/ops/journal.go`                    | none (root reads the journal directly)  |
| `nft_table_counts`  | `internal/helper/ops/nft.go`                        | `CAP_NET_ADMIN`                         |
| `firewall_inspect`  | `internal/helper/ops/firewall.go`                   | `CAP_NET_ADMIN`                         |
| `firewall_lookup`   | `internal/helper/ops/firewall_lookup.go`            | `CAP_NET_ADMIN`                         |

The `caps-template.sh` post-install scriptlet maps the manifest's
`enabled_tools[]` and `workload_plugins[]` to the union of required
caps and writes them to the helper unit's drop-in.
