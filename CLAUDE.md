# host-health-mcp

A read-only Linux host health-check service. Two cooperating artefacts:

- A **host daemon** that runs on the target host and answers structured
  RPC queries about local health over an mTLS HTTP/JSON listener.
- An **MCP plugin** that exposes the daemon's surface to MCP-speaking
  clients. Plugin runs on the operator workstation, on the target host,
  or on a designated relay.

Deployment integration (target inventory, network ACLs, credential
provisioning, configuration management, rollout) is **out of scope** for
this repository.

## Source of truth

Before changing anything, read these in order:

1. `doc/ARCHITECT_BRIEF.txt` - role brief for the implementing engineer.
2. `doc/REQUIREMENTS.txt` - binding contract. Currently at Rev 2. Section 4
   is the tool surface (REQ 4.1-4.17 = 17 tools at gate; the implementation
   has grown by additive minor releases to 19 — `firewall` from 1.13.0 and
   `firewall_lookup` from 1.14.0 — without renaming or removing any field,
   so REQ 7.3 minor-additive holds). Section 6 is the security boundary;
   every constraint there is non-negotiable. Section 12 lists the
   architect-delegated decisions.
3. `doc/design-overview.md` - implementation-level decisions with rationale
   tied back to REQUIREMENTS section numbers.
4. `doc/schema-draft.yaml` - OpenAPI 3.1 wire schema covering the registered
   tools plus the shared response envelope and structured error shape. The
   wire `schema_version` constant (`SchemaVersion` in
   `daemon/internal/shared/schema/envelope.go` and
   `plugin/internal/schema/version.go`) is the authoritative version
   string; the OpenAPI document's own `info.version` is a separate header
   and is not the wire contract.
5. `doc/threat-model.md` - assumptions, in-scope and not-defended threats,
   per-constraint justification for REQ section 6, residual risks R1-R5.
6. `doc/version-matrix.md` - plugin/daemon compatibility matrix C1-C4.

Tool numbers in this file (`4.13` etc.) refer to sections of
`doc/REQUIREMENTS.txt`.

## Layout

```
host-health-mcp/
├── README.md                       repository entry point for operators
├── CLAUDE.md                       (this file)
├── doc/                            design artefacts; the contract
│   ├── ARCHITECT_BRIEF.txt
│   ├── REQUIREMENTS.txt
│   ├── design-overview.md
│   ├── schema-draft.yaml
│   ├── threat-model.md
│   ├── version-matrix.md
│   ├── tools.md
│   ├── install.md
│   ├── changelog.md
│   └── security-audit-2026-05-24.md  audit closed in 1.17.0
├── daemon/                         Go module - daemon and helper share one
│   ├── cmd/
│   │   ├── daemon/main.go          -> /usr/local/sbin/host-health-mcp-daemon
│   │   └── helper/main.go          -> /usr/local/sbin/host-health-mcp-helper
│   └── internal/
│       ├── daemon/                 daemon-only packages
│       │   ├── audit/              audit-log emission (REQ 6.5)
│       │   ├── cache/              global in-process cache + singleflight
│       │   ├── config/             daemon.yml + manifest.yml parsing
│       │   ├── helperinvoke/       SOLE site for daemon-side os/exec-equivalent;
│       │   │                       unix-socket client to the helper service
│       │   ├── httpserver/         TLS listener, routing, request handling
│       │   ├── ratelimit/          two-level token-bucket limiter (REQ 6.6)
│       │   ├── redact/             positive-list redaction filter (REQ 6.3)
│       │   └── tools/              one package per tool; the registered
│       │                           set is 19 (REQ 4.1-4.17 plus
│       │                           firewall, firewall_lookup)
│       ├── helper/                 helper-only packages
│       │   ├── config/             helper.yml parsing
│       │   ├── dispatch/           op dispatcher; closed compile-time enum
│       │   ├── exec/               SOLE site for helper-side os/exec
│       │   ├── ops/                one file per op + per-op parser
│       │   │                       and test (see design §7.3); 23 ops
│       │   └── server/             unix-socket listener; SO_PEERCRED check
│       └── shared/                 packages used by both binaries
│           ├── proto/              helper-socket frame types; AllOps
│           │                       enumerates the 23 op tokens
│           └── schema/             hand-coded Go shapes that mirror
│                                   doc/schema-draft.yaml (envelope,
│                                   error envelope, strict decoder)
├── plugin/                         Go module - MCP plugin
│   ├── cmd/plugin/main.go
│   └── internal/
│       ├── mcp/                    MCP protocol handling
│       ├── client/                 HTTP client to the daemon's listener
│       └── schema/                 plugin-side SchemaVersion constant
│                                   (kept in lockstep with daemon)
└── build/                          reproducible build orchestration
    ├── build.sh                    drives a full release build
    ├── nfpm/                       .deb packaging configs per arch
    ├── postinst/                   post-install scripts including
    │                               caps-template.sh (REQ 6.7, L-5)
    ├── examples/                   daemon.yml, helper.yml, manifest.yml
    ├── systemd/                    host-health-mcp.service +
    │                               host-health-mcp-helper.service
    └── dist/                       build output, gitignored
```

`internal/` is deliberately deep so the boundary between daemon, helper,
and shared code is enforced by Go's `internal` rule, not by convention
alone.

## Hard constraints to remember

These are restatements of design and requirements decisions. Read the
linked sections before treating any constraint as flexible.

- **Read-only by construction.** No tool path may write to the filesystem
  (beyond `/var/lib/host-health-mcp/`), invoke a process that changes
  state, send a signal, modify a sysctl, route, rule, mount, or systemd
  unit. The daemon binary contains no code path that performs a state-
  changing syscall from any tool implementation. (REQ 6.1; design §7.4.)
- **No `os/exec` outside the chokepoints.** A custom build-time linter
  rejects `os/exec`, `syscall.ForkExec`, and write-mode
  `os.OpenFile`/`os.Create` from every package except
  `daemon/internal/daemon/helperinvoke/` (daemon side, socket client to
  helper) and `daemon/internal/helper/exec/` (helper side, the only place
  that invokes underlying tools). Adding a tool that needs a subprocess
  means adding an op to the helper, not relaxing the linter.
- **No opaque passthrough.** The helper parses each underlying tool's
  output inside its own process and returns typed fields over the unix
  socket. Raw subprocess bytes never enter the daemon. Particularly:
  WireGuard private and preshared keys are stripped inside the helper
  parser before any byte crosses the socket (design §7.3.1). (REQ 6.2.)
- **No daemon-side CRL or OCSP.** Cert revocation is operator PKI policy.
  The daemon enforces the configured CA bundle plus `notAfter` at TLS
  handshake time. Rotation is `systemctl restart` only - no SIGHUP, no
  SIGUSR1, no runtime poll. (Design §5; REQ 8.3.)
- **Privsep via two systemd units, not setuid.** The daemon runs as
  `host-health-mcp:host-health-mcp` with `NoNewPrivileges=yes` and empty
  capabilities. The helper runs as root via its own systemd unit (also
  `NoNewPrivileges=yes`) with a `CapabilityBoundingSet` templated from
  `manifest.yml` at install time. No setuid bit on either binary.
  (Design §7; REQ 3.4, 9.2.)
- **Workload plugins are compile-time only.** Loadable shared objects are
  forbidden. Plugins register in `init()` and are selected via build
  tags. (REQ 4.9; design §9.)
- **Per-source error reporting on three tools only.** `storage.smart[]`
  (per-device `error` block), `updates` (`apt_lock_state`), and `dns`
  (per-probe time-bound + envelope warning) report sub-source failures
  inline. Every other tool follows the strict "tool fails as a whole"
  rule. (REQ 4.12, 4.13; design §7.3.2.)
- **`additionalProperties` policy is split.** Workload schemas and
  request bodies are strict; non-workload response data shapes are
  lenient so the version-matrix C2 forward-compat promise holds
  uniformly. (Design §6; version-matrix §3.)
- **Functional reproducibility, not byte-identical.** The build is not
  diffoscope-clean across hosts and is not pursued as such. The canonical
  artefact identity is the SHA-256 recorded in `build/dist/SHA256SUMS` at
  release time. (Design §10.1.)

## Status

Design gate is closed. Implementation complete and building clean
across both arches; `.deb` packages produced for every released
tag.

The tool surface has grown past the original REQ 4.1-4.17 set
through additive minor releases. The current registered set is 19
top-level tools: the 17 from REQ section 4 plus `firewall`
(1.13.0+) and `firewall_lookup` (1.14.0+). `README.md` §1 lists
the names; `doc/tools.md` is the per-tool reference; the
registration call sites live in `daemon/cmd/daemon/main.go`.

All 23 helper ops are implemented and registered. The full list is
in `daemon/internal/shared/proto/ops.go` (`AllOps`):
`read_audit_status`, `read_aide_summary`, `read_reboot_marker`,
`smart_summary`, `mdraid_detail`, `lvm_report`, `zpool_status`,
`btrfs_scrub`, `postqueue`, `wireguard_show`, `apt_pending`,
`needrestart`, `journal_query`, `nft_table_counts`,
`fail2ban_status`, `ssh_journal_counts`,
`systemd_timer_last_trigger`, `rkhunter_summary`,
`unattended_upgrades_status`, `firewall_inspect`,
`firewall_lookup`, `dovecot_status`, `nginx_apache_status`.

All four workload plugins (`wireguard`, `postfix`, `dovecot`,
`nginx_apache`) are implemented. They register at compile time via
build tags (`wl_wireguard`, `wl_postfix`, `wl_dovecot`,
`wl_nginx_apache`); the default build ships all four. As of
1.19.0, `nginx_apache` reads recent 4xx/5xx counts from the access
log directly via a bounded tail-read inside the helper process;
the 1.18.0 design that required an operator-supplied summary JSON
file (cron-built) was withdrawn so that the daemon does not depend
on operator-side data pipelines.

Tests: foundational packages and parsers covered. Proto framing,
cache + singleflight, two-level rate-limiter (including the
`(sustained=0,burst=0)` rejection and the `enabled: false` path),
redactor with explicit scrub classes (positive- and negative-keep
plus an extended fuzz corpus), schema strict-decode, HTTP server
negative tests (unknown-tool routing, oversize body, audit-args
extraction on fresh and cache-hit paths). Helper parsers covered:
wireguard, LVM, zpool, AIDE log, apt-get -s upgrade, dpkg held,
postqueue (parser tests including `*`/`!` exclusion), dovecot
(`parseDoveadmWho` including the user-literally-named-`username`
edge case), nginx_apache (six `parseAccessLogTail` cases plus two
`readAccessLogTail` cases), mdraid (`mdraidDetailFromExport`
fallback trigger and no-fallback paths), ssh-journal classifier
plus `/proc/stat` btime parser and the volatile-journal truncation
probe, server-detection, network `addrs[]` regression, plugin
client mTLS fail-closed branches. Integration tests against a
live host are still to come.

REQ 9.5 docs in place: `doc/install.md`, `doc/tools.md`,
`doc/changelog.md`. Examples under `build/examples/`.

Packages: `build/build.sh` produces signed-checksum `.deb`
artefacts for `linux/amd64` and `linux/arm64`. nfpm installed via
`go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest`.

## Style and conventions

- Author/signature on any document is `Albert 'Tigr' Zenkoff
  <albert@tigr.net>`.
- Documentation is plain professional technical writing. No fluff, no
  emoji, no marketing tone.
- Commit subjects are descriptive and short; no co-authored trailers.
- Go: standard library first; `golang.org/x/sync/singleflight` for cache-
  miss coalescing; `github.com/coreos/go-systemd/v22` for sd_notify,
  watchdog, journald native protocol. No CGO. Targets `linux/amd64` and
  `linux/arm64`. `toolchain` directive in `go.mod` pins the patch
  version.
- No comments that restate the code. Comments exist to capture a non-
  obvious "why" (a kernel quirk, a workaround for a specific bug, a
  constraint that's not derivable from reading the code).

## When in doubt

The brief instruction stands: if you believe a requirement is wrong or
unworkable, stop, write a short proposal, request approval. Do not
silently deviate.
