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
   is the tool surface (17 tools, REQ 4.1-4.17). Section 6 is the security
   boundary; every constraint there is non-negotiable. Section 12 lists the
   architect-delegated decisions.
3. `doc/design-overview.md` - implementation-level decisions with rationale
   tied back to REQUIREMENTS section numbers.
4. `doc/schema-draft.yaml` - OpenAPI 3.1 wire schema covering all 17 tools,
   shared response envelope, structured error shape.
5. `doc/threat-model.md` - assumptions, in-scope and not-defended threats,
   per-constraint justification for REQ section 6, residual risks R1-R5.
6. `doc/version-matrix.md` - plugin/daemon compatibility matrix C1-C4.

Tool numbers in this file (`4.13` etc.) refer to sections of
`doc/REQUIREMENTS.txt`.

## Layout

```
host-health-mcp/
├── CLAUDE.md                       (this file)
├── doc/                            design artefacts; the contract
│   ├── ARCHITECT_BRIEF.txt
│   ├── REQUIREMENTS.txt
│   ├── design-overview.md
│   ├── schema-draft.yaml
│   ├── threat-model.md
│   ├── version-matrix.md
│   ├── tools.md                    (not yet written; REQ 9.5)
│   ├── install.md                  (not yet written; REQ 9.5)
│   ├── changelog.md                (not yet written; REQ 9.5)
│   └── examples/                   (not yet written; REQ 13)
│       ├── daemon.yml
│       ├── helper.yml
│       └── manifest.yml
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
│       │   └── tools/              one package per tool 4.1-4.17
│       ├── helper/                 helper-only packages
│       │   ├── config/             helper.yml parsing
│       │   ├── dispatch/           op dispatcher; closed compile-time enum
│       │   ├── exec/               SOLE site for helper-side os/exec
│       │   ├── ops/                one file per op (see design §7.3)
│       │   ├── parse/              per-tool output parsers (smartctl JSON,
│       │   │                       lvs JSON, /proc/mdstat, etc.)
│       │   └── server/             unix-socket listener; SO_PEERCRED check
│       └── shared/                 packages used by both binaries
│           ├── proto/              helper-socket frame types
│           └── schema/             types generated from doc/schema-draft.yaml
├── plugin/                         Go module - MCP plugin
│   ├── cmd/plugin/main.go
│   └── internal/
│       ├── mcp/                    MCP protocol handling
│       └── client/                 HTTP client to the daemon's listener
└── build/                          reproducible build orchestration
    ├── build.sh                    drives a full release build
    ├── nfpm/                       .deb packaging configs per arch
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

Design gate is closed. Implementation skeleton in place and building
clean across both arches.

All 17 tools per REQ 4.1-4.17 register and respond. Depth varies:

- Full implementations: `manifest`, `system`, `pressure`, `kernel`,
  `sockets`, `dns`, `mail` (queue depth via helper), `certs`,
  `backup` (mtime-based signal), `sensors`, `systemd_units`,
  `updates` (helper round-trip), `storage` (per-device error
  reporting via helper), `workload` (compile-time plugin
  framework; wireguard plugin real, postfix near-real, dovecot +
  nginx_apache stubs), `logs` (helper journal_query + redactor),
  `network`, `security` (presence-only MVP - deep fields await
  helper ops).
- Helper ops implemented: `read_reboot_marker`, `smart_summary`,
  `mdraid_detail`, `lvm_report`, `postqueue`, `apt_pending`,
  `needrestart`, `wireguard_show` (with PSK + private-key strip),
  `journal_query`.
- Helper ops still stubbed: `read_audit_status` (netlink dialog),
  `read_aide_summary` (binary file parser), `zpool_status`,
  `btrfs_scrub`.
- Tests: foundational packages covered (proto, cache, ratelimit,
  redact, lvm parser, wireguard parser). Tool packages await
  integration tests.

The four documents still to produce per REQ 9.5 are `doc/tools.md`,
`doc/install.md`, `doc/changelog.md`, and the `doc/examples/` set.

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
