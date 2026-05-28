---
title: Host Health MCP - Design Overview
author: Albert 'Tigr' Zenkoff <albert@tigr.net>
date: 2026-05-14
status: Draft - for review before implementation begins
---

# 1. Purpose

This document records the implementation-level choices that
REQUIREMENTS.txt section 12 delegates to the architect. Each choice cites
the governing requirement section. Alternatives that were considered and
rejected are listed with reasons.

# 2. Summary of choices

| Concern                | Choice                                          | Requirement |
|------------------------|-------------------------------------------------|-------------|
| Implementation language | Go (>= 1.22)                                   | 5.4         |
| Wire protocol          | HTTP/JSON over TLS, OpenAPI 3.1 schema          | 7.1         |
| Authentication         | mTLS with per-caller client certificate         | 6.4         |
| Revocation             | Operator-managed cert rotation (no daemon CRL)  | 6.4         |
| Cache backend          | In-process map with per-tool TTL                | 5.1, 12     |
| Privilege separation   | Helper as systemd-managed service; unix socket  | 6.7, 12     |
| Rate limiting          | Two-level: per-caller bucket + per-tool buckets | 6.6, 12     |
| Workload plugin model  | Compile-time registry with build tags           | 4.9, 12     |
| Build shape            | Static ELF, `.deb` for amd64 and arm64          | 5.4, 9.1    |
| Path prefix            | `host-health-mcp`                               | 9.3         |
| Binary name            | `host-health-mcp-daemon`                        | 9.3         |

# 3. Implementation language: Go

Pinned toolchain: Go 1.22 series. Exact patch version recorded in
`go.mod` and reproduced by the build script.

Rationale:

- Section 5.4 expresses a single-static-binary preference. `go build`
  with `CGO_ENABLED=0` produces a fully static ELF that links no host
  libc, on both target architectures, from a single build host.
- Section 6 demands that a compromised authenticated caller not lead
  to host compromise. The highest-risk surfaces in this design are
  the redaction filter, `/proc` and `/sys` parsing, the journald
  reader, and the systemd D-Bus client. In Go these are bounds-checked
  and memory-safe; a malformed input produces a recovered panic and a
  per-tool error envelope, not a memory-corruption primitive.
- The standard library covers TLS, HTTP, JSON, and regex. Systemd
  integration (sd_notify, journald native protocol, watchdog) is
  provided by `github.com/coreos/go-systemd/v22` without linking
  `libsystemd`.
- Build reproducibility is achieved through `-trimpath`,
  `-ldflags='-buildid='`, and pinned `go.sum`. Section 9.1 requires
  reproducible builds.

Trade-offs accepted:

- Statically linking the Go runtime puts the binary in the 15-25 MiB
  range. Acceptable for a `.deb` delivery.
- Idle resident memory is roughly 15-30 MiB once the GC has settled,
  comfortably under the section 5.3 budget of 64 MiB.
- GC pause times at this scale are sub-millisecond and do not
  jeopardise the per-tool timeout budget in section 5.1.

Rejected alternatives:

- C/C++ with Debian-packaged dependencies. Modern C++ closes some
  gaps but does not eliminate lifetime errors, use-after-move,
  unchecked `operator[]`, or concurrent data races on shared state.
  Published empirical CVE data from Microsoft, Chrome, and Android
  put the memory-safety bug rate in modern C++ roughly an order of
  magnitude above Go for comparable network-exposed services.
- Rust. Comparable or better safety story; rejected on build-toolchain
  weight and dependency-graph depth against an essentially identical
  operational outcome.

# 4. Wire protocol: HTTP/JSON over TLS

Each tool is exposed as a single endpoint under `/v1/<tool>`. The
method is `POST`. Tools that take no arguments accept an empty `{}`
body for uniformity. The response is a JSON object conforming to the
common envelope defined in REQUIREMENTS section 4.

Rationale:

- Section 7.1 names operator-debuggability as the deciding factor and
  calls out "curl-able is a plus". A TLS client cert and a `curl
  --cert ... --key ... -X POST -d '{}'` reproduces any production
  call.
- The surface is small (11 endpoints), strictly request-response, no
  streaming, no subscription. The code-generation and performance
  arguments for gRPC do not apply at this size.
- OpenAPI 3.1 is human-readable, supports `$ref` composition for the
  envelope, and has mature Go tooling (`oapi-codegen`).

Versioning:

- The URL prefix `/v1/` tracks the major version of the schema, per
  section 7.3.
- The exact semver of the schema embedded in the daemon is reported
  through the `schema_version` field of every response envelope and
  through the `manifest` tool.
- The plugin negotiates compatibility through the `manifest` tool on
  first contact per session and fails closed on a major-version
  mismatch (section 7.2).

# 5. Authentication: mTLS

The listener requires a client certificate. The daemon verifies the
chain against the CA bundle at `client_ca_path`. The Subject's
Common Name, or the first DNS SAN if CN is unset, is recorded as
the `caller_identity` in the audit log defined by section 6.5.

Rationale:

- Section 6.4 lists both mTLS and bearer tokens as acceptable. The
  choice is the architect's.
- Caller identity is bound to a cryptographic credential the daemon
  verifies without contacting a third party. No shared-secret leak
  risk through journald, backups, or operator screenshots.

Revocation:

- The daemon does not implement CRL or OCSP. Revocation is the
  responsibility of the operator's PKI tooling. The daemon
  enforces only what is in the CA bundle and the certificate's
  `notAfter` field at TLS handshake time; rotation cadence is
  whatever the operator's PKI policy dictates.
- Cert rotation at the daemon is operator-driven: write new
  material, `systemctl restart`. This matches section 8.3 (no
  SIGHUP) and avoids the "CRL refresh that only fires on restart"
  pseudo-mitigation that an earlier draft proposed.
- The daemon does NOT implement runtime TLS material reload (no
  `SIGHUP`, no `SIGUSR1`, no internal refresh poll). Each cert
  rotation produces a full `systemctl restart`, which drains
  in-flight audit state and resets per-caller rate-limit buckets.
  Operators choosing short-lived certs (sub-daily) accept this
  churn as the cost of their PKI cadence; the daemon does not
  mitigate it.

Trade-off accepted:

- Operator provisioning is heavier than dropping a bearer token in a
  file. This cost is paid once per host pair, not per call.
- Daily or sub-daily cert rotation produces daily journald restart
  events and momentary rate-bucket resets. Consistent with REQ 8.3.

# 6. Cache backend

An in-process map keyed by `(tool, request_args_hash)` holds the most
recent response payload, the build timestamp, and the configured TTL
for that tool. A `sync.RWMutex` guards the map. Tool implementations
take a read lock to look up, a write lock to insert. A background
sweeper runs every `min(TTL)/2` seconds to evict expired entries.

**Cache scope: global, not per-caller.** A cached payload constructed
in response to caller A's request is served to caller B if B's
request has the same `(tool, args)` key and the entry is within TTL.
The data is operator-host state and does not vary by caller identity,
so per-caller partitioning would only multiply memory. The visible
consequence is that `cache_age_s` can leak coarse timing information
about other callers' query cadence to a caller who polls; this is a
low-resolution channel bounded by the rate limiter (section 8) and
the configured TTL.

**Cache hit accounting:** cache hits debit the per-caller rate-limit
buckets on the same rule as fresh reads. There is no special-case
cheap-hit accounting. The rate limiter is the canonical metering
surface; the cache is an internal performance optimisation that does
not change the metering.

**Audit log:** no `cache_hit` field is added to the envelope. The
existing `cache_age_s` (REQ 4) already conveys hit-vs-fresh at the
response layer; the audit log records `caller_identity`, `tool`,
`args`, `size_bytes`, `duration_ms`, `result` as REQ 6.5 specifies
and no more.

**Single-flight under cache miss.** Concurrent cache misses for the
same `(tool, args)` key from different callers coalesce into a
single underlying read via `golang.org/x/sync/singleflight`. This
removes the helper-fork-storm case in which N callers each trigger
their own privileged invocation. Coalesced waiters each pay their
own rate-limit debit when their wait returns.

Rationale:

- Section 5.1 requires in-process caching with a minimum default
  TTL of 15 s. No on-disk cache.
- Section 12 delegates the choice. A plain map plus `RWMutex` is
  sufficient at the maximum cache size implied by this surface
  (roughly one entry per tool, one per workload plugin). Bounded
  LRU and `sync.Map` were considered and rejected as over-engineered
  at this scale.

# 7. Privilege separation: helper as systemd-managed service

The package ships two cooperating systemd units (REQ 3.4, 9.2). The
**daemon** runs as `host-health-mcp:host-health-mcp` with
`NoNewPrivileges=yes`, empty capability bounding set, and zero
ambient capabilities. The **helper** runs as `root` under its own
unit with an explicit per-need `CapabilityBoundingSet` and
`SystemCallFilter`. The bounding set is **templated at install
time** from the per-host `manifest.yml`: the post-install scriptlet
reads `enabled_tools[]` and `workload_plugins[]`, computes the
union of required capabilities across the enabled ops (see §7.3
table), and writes a drop-in
`/etc/systemd/system/host-health-mcp-helper.service.d/caps.conf`
with the resulting `CapabilityBoundingSet=` line. An operator who
does not enable ZFS does not pay `CAP_SYS_ADMIN`; an operator who
does not enable WireGuard does not pay `CAP_NET_ADMIN`. Operator
changes to `manifest.yml` regenerate the drop-in on `systemctl
daemon-reload && systemctl restart host-health-mcp-helper.service`. The two communicate over a unix socket at
`/run/host-health-mcp/helper.sock` (owner `root:host-health-mcp`,
mode `0660`); the helper verifies via `SO_PEERCRED` that the
connecting peer's uid is the daemon's uid before accepting any
request frame.

There is no setuid bit on disk. Both binaries are mode `0755`,
owner `root:root`. The helper's privilege comes entirely from its
systemd unit configuration, which means the daemon's
`NoNewPrivileges=yes` setting (REQ 3.4) does not interfere with the
helper acquiring privilege — the daemon never `execve`s the helper.

This is a deliberate revision of two earlier drafts:

- An OpenSSH-style fork-and-drop-caps model in one Go binary was
  abandoned because correct implementation required strict ordering
  of `capset()` (zero effective + permitted) before `PR_CAPBSET_DROP`
  (seal bounding), required `fork+execve` rather than bare fork (a
  bare `fork()` from a Go runtime is undefined behaviour because the
  runtime is multi-threaded by the time `main()` returns), and
  required `PR_SET_PDEATHSIG=SIGKILL` post-exec in the child to
  prevent privileged-orphan reparenting. The surface of ways to get
  this subtly wrong was disproportionate to the security gain.
- A setuid-root helper binary on disk was abandoned because
  `NoNewPrivileges=yes` on the daemon's unit (REQ 3.4) strips
  setuid semantics from every subsequent `execve` by the daemon;
  the helper would run as the daemon's uid, not root, and every
  privileged read would fail.

## 7.1 Wire protocol between daemon and helper

The daemon connects to the helper's unix socket. Each request is a
length-prefixed JSON frame. The length prefix is a fixed
little-endian uint32. The helper rejects any frame whose declared
length exceeds **16 KiB** (closing the connection) before reading
the body; this is more than ample for `op` plus a parameter and
bounds the cost of a daemon-side RCE attempting to OOM the helper.
The daemon enforces the same cap on responses it accepts.

Frame body:

```
{ "op": "<subcommand-token>", "param": "<optional whitelisted string>" }
```

`op` is a value drawn from a compile-time Go enum on both sides.
`param` is present only for ops that take a parameter. The helper
validates `param` against the per-op whitelist before invoking any
underlying tool.

Each response is a length-prefixed JSON frame:

```
{ "status": "ok"  , "data":  { ...typed-fields... } }
{ "status": "err" , "code":  "<one of the error codes below>",
                    "stderr_bytes": <int>,
                    "stderr_sha256": "<hex>",
                    "tool_exit": <int|null> }
```

The helper **does its own parsing** of underlying tool output. The
JSON `data` block contains typed fields extracted by the helper;
the daemon never receives raw stdout from a subprocess. This
preserves REQ 6.2's "no opaque passthrough of subprocess stdout"
across the helper→daemon boundary, not just at the network edge.

Helper-side error codes:

| Code              | Meaning                                                                |
|-------------------|------------------------------------------------------------------------|
| `bad_op`          | Unknown `op` token.                                                    |
| `bad_param`       | Parameter failed whitelist for the given op.                           |
| `tool_missing`    | The underlying tool binary is not installed.                           |
| `tool_failed`     | The underlying tool exited non-zero or wrote unparseable output.       |
| `output_truncated`| The underlying tool exceeded the per-op output bound.                  |
| `deadline`        | The helper-side deadline for the op fired before the tool returned.    |
| `internal`        | Catch-all for unexpected helper failures.                              |

The daemon maps these codes onto its own structured tool errors via
`internal/helperinvoke`.

## 7.2 Helper hygiene

- Helper environment is sanitised at startup to
  `{ PATH=/usr/sbin:/usr/bin:/sbin:/bin, LANG=C, LC_ALL=C }`.
  `LD_PRELOAD`, `LD_LIBRARY_PATH`, and locale-driven
  parser-confusion attacks are closed at the helper boundary.
- External commands are invoked via `os/exec.CommandContext` with
  literal-by-literal `argv` slices. No shell, no `sh -c`, no
  environment-variable substitution.
- Captured stdout is bounded to a per-op maximum (default 256 KiB).
  Exceeding the bound returns `output_truncated`.
- Stderr from each tool is fingerprinted, and a sanitised
  length-capped prefix is forwarded for operator diagnostics. The
  helper records `stderr_bytes` and `stderr_sha256` for forensic
  correlation; a sanitised `stderr_prefix` (≤200 bytes, non-printable
  bytes remapped) accompanies it on per-source error blocks. Before
  this prefix leaves the daemon it is routed through the daemon-side
  positive-list redactor (§6, REQ 6.3) inside
  `helperinvoke.HelperError.AsOpError()`, so any token not on the
  safe set collapses to `<redacted>`. This places the redaction
  responsibility on the daemon — which holds the operator's
  allowlists — rather than on the helper, which does not. Subprocess
  argv is forwarded under the same per-source error structure for
  operator diagnostics; its parameter is constrained by the helper's
  op-specific whitelist and is treated as a structural identifier
  (threat-model R5).
- Each op has a deadline. The helper enforces it via
  `context.WithTimeout` and `Cmd.Cancel`-then-`SIGKILL` 500 ms
  later. The op-side deadline is `(daemon's per-tool timeout) -
  500 ms` so the helper finishes before the daemon's outer timeout
  trips.

## 7.3 Op surface (initial)

| Op token            | Reads / invokes                                       | Param             | Whitelist                                                  | Caps required   |
|---------------------|-------------------------------------------------------|-------------------|------------------------------------------------------------|-----------------|
| `read_audit_status` | audit netlink (`NETLINK_AUDIT`)                       | none              | —                                                          | `AUDIT_READ`    |
| `read_aide_summary` | `/var/lib/aide/aide.db` header                        | none              | —                                                          | `DAC_READ_SEARCH` |
| `read_reboot_marker`| `/var/run/reboot-required` presence + length          | none              | —                                                          | none            |
| `smart_summary`     | `smartctl --json -a /dev/<dev>`                       | block-device name | `^(sd[a-z]+\|nvme[0-9]+n[0-9]+\|vd[a-z]+\|hd[a-z]+\|xvd[a-z]+)$` (no trailing partition digits) | `SYS_RAWIO`, `DAC_READ_SEARCH` |
| `mdraid_detail`     | `mdadm --detail --export /dev/<array>`                | array name        | `^md[0-9]+$`                                               | `DAC_READ_SEARCH` |
| `lvm_report`        | `lvs --reportformat=json` + `vgs --reportformat=json` | none              | —                                                          | `DAC_READ_SEARCH` |
| `zpool_status`      | `zpool status -j`                                     | none              | —                                                          | `SYS_ADMIN`     |
| `btrfs_scrub`       | `btrfs scrub status -R /<mountpoint>`                 | mountpoint        | `^(/[A-Za-z0-9_-]+)+$` **and** `statfs(2)` confirms `f_type == BTRFS_SUPER_MAGIC` | `DAC_READ_SEARCH` |
| `postqueue`         | `postqueue -p`                                        | none              | —                                                          | none (postdrop gid)|
| `wireguard_show`    | `wg show all dump`                                    | none              | —                                                          | `NET_ADMIN`     |
| `apt_pending`       | `apt-get -s upgrade`                                  | none              | —                                                          | none            |
| `needrestart`       | `needrestart -b -p`                                   | none              | —                                                          | none            |

For tools whose underlying source is accessible to an unprivileged
user (4.1, 4.2 via D-Bus, 4.3 via `netlink-route`, 4.10 via the
journald API, 4.14 via `/proc` and `/sys`, 4.15 via
`/proc/pressure`, 4.16 via `NETLINK_SOCK_DIAG`), the daemon reads
directly. The helper is consulted only for the ops above.

### 7.3.1 WireGuard parser discipline

`wireguard_show` parses `wg show all dump` inside the helper. The
parser drops the interface row's private-key field (column 1) and
the preshared-key column from every peer row before constructing
the response payload. Endpoints are reported verbatim. Public keys
are validated against `^[A-Za-z0-9+/]{42,43}=?$` (base64 of 32
bytes). Anything that fails parsing fails the op with `tool_failed`.

### 7.3.2 Per-source error reporting

Three tools return per-source error annotations rather than failing
as a whole (per the operator's call on inherently-unstable
sources):

- `storage`: each `SmartSummary` entry carries an optional `error`
  block. A wedged smartctl on one drive returns the drive's row
  with `error: { code, message }` and `smart_overall: null`; the
  other drives' entries are populated normally. Section 4.13 of
  REQUIREMENTS is amended to record this shape.
- `updates`: when `apt_pending` cannot acquire the dpkg frontend
  lock, the response carries `apt_lock_state: "contended"` and the
  upgrade counts are reported as null; other fields (held packages,
  needrestart, unattended-upgrades) are unaffected.
- `dns`: each probe has a strict per-probe deadline. A probe that
  exceeds the deadline reports `false` for its bool field; the
  envelope's `warnings[]` is populated with `dns: <probe-name>
  timed out after <ms>`.

Tools other than these three follow REQ 5.2: subsystem failure
returns the tool-level `tool_failed` error envelope; the operator
addresses the root cause and re-queries.

## 7.4 Daemon-side discipline

A single Go package, `internal/helperinvoke`, is the **only** place
in the daemon source tree where the helper socket is contacted and
the **only** place `os/exec` is permitted. The package exposes
enum-typed Go calls (one function per helper op); the subcommand
token strings are constructed inside the package from a closed Go
enum, never from any caller-influenced value. The custom
forbidden-call linter rejects `os/exec`, `syscall.ForkExec`, and
write-mode `os.OpenFile`/`os.Create` from every other package.

Concurrency control:

- `golang.org/x/sync/singleflight` keyed on `(tool, args)` ensures
  that a cache miss from N concurrent callers triggers exactly one
  helper invocation; the other callers wait for the shared result.
- A per-call helper-fan-out cap (default 8) bounds the maximum
  concurrent helper ops a single tool call may produce. The
  `storage` tool — which can invoke `smart_summary` per block device
  — sequences beyond the cap.
- Every helper call is bound to the originating request's
  `context.Context`. If the daemon's per-tool timeout fires or the
  client disconnects, the cancellation propagates to the helper
  socket, the helper aborts the op, kills the child tool, and
  returns `deadline`.

## 7.5 Implementation language

Both binaries are Go (>= 1.22, per §3). The helper is Go too,
revising an earlier draft that proposed C. Reason: the helper now
parses output from each underlying tool — smartctl JSON, postqueue
text, lvs JSON, /proc/mdstat — which is a parser surface large
enough that memory safety is load-bearing. A small C helper is
defensible when the helper does only three file/netlink reads;
once the helper does meaningful parsing, Go is the safer choice.

## 7.6 Alternatives considered and rejected

- **Fork-and-drop-caps within one Go binary.** Correctness pitfalls
  per the second draft; abandoned.
- **Setuid-root helper exec'd by the daemon.** Defeated by REQ 3.4's
  `NoNewPrivileges=yes` on the daemon; abandoned.
- **`AmbientCapabilities` on the daemon without privsep.** Every
  goroutine handling a network request would carry
  `CAP_DAC_READ_SEARCH`, defeating the point of running unprivileged.
- **`systemd-run --uid=root` transient unit per privileged read.**
  Requires a privileged D-Bus method call, external dependency,
  harder to audit than a dedicated unit.

**Accepted trade-off — continuous root daemon vs ephemeral helper.**
The earlier setuid-exec model would have had a privileged process
exist only for the duration of one privileged read; the present
design has the helper running as root continuously. Steady-state
attack surface is therefore larger by construction. Mitigations
that justify accepting this: no setuid bit on disk (helper is
ordinary mode `0755`); systemd hardening on the helper unit
(`NoNewPrivileges=yes`, per-need `CapabilityBoundingSet`,
`SystemCallFilter`, `ProtectSystem=strict`, `ProtectHome=yes`,
`PrivateTmp=yes`); the helper's parser surface is Go (memory-safe);
and the integrity story collapses to a single audit target (the
helper binary on disk plus its unit file). The earlier ephemeral
model is what the OpenSSH-style fork-and-drop-caps draft and the
setuid-helper draft both attempted; both turned out to have
correctness surfaces (PR_CAPBSET_DROP semantics, NNP-defeats-setuid)
that were larger than the continuous-helper attack-surface delta.

# 8. Rate limiting

A two-level token-bucket limiter sits in front of every accepted
request:

- **Per-caller global bucket.** Sustained 30 req/min, burst 10
  (defaults from REQ 6.6). Keyed by `caller_identity` derived from
  the verified client certificate.
- **Per-(caller, tool) buckets for expensive tools.** The set of
  expensive tools is configurable in `daemon.yml` under
  `expensive_tool_buckets`. Defaults: `logs`, `workload`, `storage`
  (because SMART reads and zpool status are slow). Each bucket has
  its own sustained and burst values; they are debited *in addition
  to* the global bucket, so a caller that burns their `logs` budget
  has not consumed the global budget for `manifest`.

Rejection is a structured `rate_limited` error envelope per REQ 6.6
and per the schema. The limiter never sleeps a worker.

In addition, the TLS listener has a configurable
`max_concurrent_handshakes` ceiling (default 16). Above the ceiling,
new connections are dropped at accept time without progressing to
TLS handshake. This bounds the handshake-CPU amplification of an
attacker who can land TCP connections but not produce a valid
client certificate.

Internal data structure: a single mutex-guarded map of token
buckets, swept on a slow tick to reclaim entries for callers that
have been quiet. The map size is bounded by the count of valid
caller identities in the CA bundle, which is small.

# 9. Workload plugin model

Each workload plugin (REQ 4.9) is a Go package that registers itself
in an `init()` function with the daemon's plugin registry. The plugin
exports its tool name, its typed input and output structs, and a
single `Collect(ctx) (any, error)` entry point.

Build tags select the set of plugins compiled into a given binary:

- `wl_postfix`, `wl_dovecot`, `wl_nginx_apache`, `wl_wireguard` are
  the four named in section 4.9.
- Default build (`-tags=''`) includes all of the above.
- Operators who want a minimal binary may rebuild with the smaller
  tag set; the manifest must reference only the compiled-in plugins
  or the daemon refuses to start (section 8.2).

Loadable shared objects are forbidden by section 4.9 and are not used.

# 10. Build shape

Output:

- `host-health-mcp_<version>_amd64.deb`
- `host-health-mcp_<version>_arm64.deb`

Each package installs:

```
/usr/local/sbin/host-health-mcp-daemon                  (Go ELF, no setuid)
/usr/local/sbin/host-health-mcp-helper                  (Go ELF, no setuid;
                                                         runs as root via
                                                         its systemd unit)
/lib/systemd/system/host-health-mcp.service             (daemon unit)
/lib/systemd/system/host-health-mcp-helper.service      (helper unit)
/etc/host-health-mcp/daemon.yml.example
/etc/host-health-mcp/helper.yml.example
/etc/host-health-mcp/manifest.yml.example
/usr/share/doc/host-health-mcp/{tools.md,threat-model.md,changelog.md,schema.yaml,version-matrix.md}
```

The post-install scriptlet creates the system user `host-health-mcp`
with no shell and no home (the state directory `/var/lib/host-health-mcp`
serves as `HOME` only for systemd's `ProtectHome` model). It enables
the unit; it does not start it, so the operator places real
configuration before first start.

`build/build.sh` drives the build. Inputs: a clean checkout and a
pinned Go toolchain. The script:

1. Reads the Go toolchain version from `go.mod`'s `toolchain`
   directive (an exact pin such as `toolchain go1.22.5`, not the
   minimum `go 1.22` directive) and verifies the local toolchain
   matches.
2. Sets `SOURCE_DATE_EPOCH` from the HEAD commit's author timestamp.
   The Go linker and `nfpm` honour this for embedded timestamps;
   it is included for hygiene, not as a guarantee of byte-identical
   output.
3. Runs `go vet`, `go test ./...`, and the architect-chosen linter
   set (REQ 10.2): `staticcheck`, `govulncheck`, and a custom
   forbidden-call linter that rejects `os/exec`,
   `syscall.ForkExec`, and write-mode `os.OpenFile`/`os.Create` from
   every package except `internal/helperinvoke/` (in the daemon
   source tree) and `internal/exec/` (in the helper source tree).
4. Builds **both** the daemon and the helper for
   `GOOS=linux GOARCH=amd64` and `GOOS=linux GOARCH=arm64` with
   `CGO_ENABLED=0 -trimpath
   -ldflags='-buildid= -X main.buildID=<git-sha>'`. Both binaries
   share the same Go module so a single `go build ./cmd/daemon
   ./cmd/helper` per arch produces both.
5. Stages the per-architecture tree (two binaries, two unit files,
   example configs, documentation) and invokes `nfpm` to produce
   the `.deb`.
6. Writes `SHA256SUMS` into `build/dist/`.

## 10.1 Reproducibility: scope and accepted trade-off

The build is **functionally reproducible**: the same source tree at
the same commit, built with the same pinned Go toolchain, produces
binaries whose runtime behaviour is equivalent across builders. `go.sum` pins module
content hashes; `-trimpath` strips local paths from the binary;
`-buildid=` zeroes the Go build ID; the `toolchain` directive in
`go.mod` pins the exact Go patch version.

The build is **not byte-identical** across builders. Builders running
on different host distributions, with different working-directory
paths, different `umask`, different system timezone, or different
`nfpm` patch versions will produce `.deb` artefacts that differ in
embedded path strings, `ar`-archive ordering, mtime entries, and
similar build-host artefacts. Pursuing byte equality would require
pinning `nfpm`, normalising `TZ`/`LC_ALL`/`umask` in the build
script, freezing `GOPROXY`/`GOSUMDB`, and gating CI on `diffoscope`.

We do not pursue byte-identical reproducibility. The complexity is
disproportionate to the operational benefit at this artefact's
scale, and the same security goal — "the binary the operator runs is
the binary the maintainer built" — is met by the canonical
SHA-256 of each released `.deb` being recorded at release time in
`build/dist/SHA256SUMS` and signed alongside the `.deb` in the
package repository. Reproduction is a maintainer-side property
covered by signing, not a builder-side property covered by
diffoscope.

# 11. Open items

None blocking. The following are deferred to dedicated documents:

- Exact plugin set and per-plugin output schema beyond the four
  named in section 4.9, plus shapes for the new tools 4.12-4.17:
  `doc/tools.md`.
- Per-tool latency, idle RSS, and audit-log volume from the canary
  burn-in (REQ 10.3): `doc/install.md`.
- Compatibility matrix for schema-version drift between plugin and
  daemon: `doc/version-matrix.md` (drafted alongside this design
  overview).
