---
title: Host Health MCP - Threat Model (Initial)
author: Albert 'Tigr' Zenkoff <albert@tigr.net>
date: 2026-05-14
status: Draft - for review before implementation begins
---

# 1. Purpose

This document records, before implementation begins, the threat model
that the host-health-mcp daemon is designed to withstand. It states
the assumptions the daemon makes about its environment, lists the
threats it actively defends against, and lists the threats it does
not. For each hard constraint in REQUIREMENTS.txt section 6 it
records the underlying reasoning so that future changes to the
implementation can be checked against the original intent.

The document is initial. Once the canary deployment in REQUIREMENTS
section 10.3 has run, the install report will be folded back into
sections 7 and 8 below.

# 2. Asset inventory

The daemon protects the following on the host:

- **Host state integrity.** No tool path may change host state.
  A compromised caller must not be able to use the daemon to start,
  stop, or reconfigure anything on the host.
- **Sensitive file contents.** /etc material with credentials,
  /home and /root, /var/lib material for stateful services, any
  directory the operator declared sensitive in the manifest.
- **Cryptographic material.** TLS keys (server and client side),
  VPN/overlay private and preshared keys, backup repository
  credentials, SSH host keys, mail-relay credentials.
- **Caller-identity attestation.** The audit log is the operator's
  primary record of who called what; a forged caller identity in
  the log is a serious failure.
- **Daemon process integrity.** The daemon itself must not become
  a pivot from a network position to a higher-privilege position
  on the host.

# 3. Assumptions

The daemon assumes:

- **The host kernel is uncompromised.** A rootkit at the kernel
  level can lie to any reader; defending against this is out of
  scope.
- **The operator-supplied PKI is sound.** The CA bundle at
  `client_ca_path` issues certificates to identified callers only,
  and revocation is operationally maintained.
- **The TLS library is sound.** Go's `crypto/tls` and the underlying
  curves and ciphers are taken on trust.
- **The systemd-service hardening shipped in the unit file is
  actually applied.** The packaging delivers the unit; the operator
  installs it without weakening it.
- **The daemon and helper binaries on disk have not been tampered
  with.** Local-disk integrity is the operator's problem (AIDE,
  IMA, dpkg signature verification on the installed package, etc.).
  Neither binary carries a setuid bit; the helper's privilege comes
  from its own systemd unit configuration. Write access to
  `/usr/sbin/` already implies a privileged compromise
  outside this daemon's defensive scope. Neither binary re-verifies
  itself at runtime.
- **The host filesystem is not adversarial above the daemon.** A
  process running as root that can write anywhere can defeat the
  daemon trivially. The threat model is concerned with remote
  callers and with the daemon's own process boundary.

# 4. Threats in scope

T1. **Compromise of a single caller credential.** An attacker
    obtains a valid client certificate or its private key. The
    attacker can authenticate to the daemon as the credential's
    owner. The daemon must ensure that this position grants only
    read access to the structured tool surface and confers no path
    to host modification, no path to raw secret material, and no
    pivot to other systems.

T2. **Malformed input from an authenticated caller.** The caller
    sends syntactically valid but semantically malicious payloads
    (oversize bodies, unicode confusables in enums, deeply nested
    JSON). The daemon must reject anything outside the schema and
    must not crash, hang, or amplify the load.

T3. **Malformed input from the host environment.** A subsystem
    being queried returns malformed data (a truncated /proc file,
    a wedged dbus reply, a journald entry with binary garbage in
    the message field). The daemon must isolate the failure to the
    affected tool, log it, and return a partial-data response with
    a warning. A wedged subsystem must not stall the rest of the
    daemon.

T4. **Resource exhaustion by an authenticated caller.** The caller
    issues a flood of requests, especially of expensive ones (log
    scan, full peer enumeration, integrity-check summary). The
    daemon must rate-limit per-caller and per-tool and must never
    throttle by sleeping in-process (sleeping a request blocks a
    worker; sleeping enough requests starves the server).

T5. **Exfiltration via log samples.** The caller asks for log
    samples in a tight loop hoping that some unredacted secret will
    flow through. Default redaction must be positive-list: anything
    the redactor does not recognise as safe is replaced with
    `<redacted>`. New patterns are admitted only by config change.

T6. **Side-channel inference of host state through tool timing.**
    The caller measures per-tool response time hoping to infer the
    presence of files, the state of services, or the value of
    counters. The daemon does not actively defend against fine
    timing measurements (no constant-time padding), but caching at
    the configured TTL bounds the visible jitter, and rate limits
    bound the rate at which timing samples can be taken.

T7. **Authenticated caller pivoting through DNS probes.** The tool
    surface in section 4.4 makes real DNS queries. A caller cannot
    choose the probe targets (they come from the daemon config),
    so the caller cannot use the daemon to elicit DNS traffic to
    an arbitrary host. The set of outbound destinations the daemon
    can contact is exactly the set in `daemon.yml`.

T8. **Tampered configuration file.** An attacker with write access
    to /etc/host-health-mcp/ before daemon start can change probe
    targets, redaction rules, the CA bundle, or sensitive-dir
    lists. The daemon does not re-verify config integrity. This is
    explicitly outside the daemon's defense: the file is mode 0640
    root:daemon-user; protection is the host's responsibility.

T9. **Caller identity forgery in the audit log.** A caller submits
    a self-issued client certificate whose subject impersonates
    another caller. The daemon prevents this by verifying the chain
    against the CA bundle: any certificate that validates was
    issued by the operator-trusted CA, which is responsible for
    not reusing subject names.

T10. **Forced downgrade via schema-version negotiation.** A
     compromised plugin tells the caller that the daemon supports
     fewer fields than it does, hoping that the caller falls back
     to a lower-fidelity report. The daemon's `manifest` tool is
     authoritative, and the plugin fails closed on version
     mismatch (REQ 7.2). The caller observes the daemon-reported
     schema version directly through the envelope.

# 5. Threats explicitly not defended

The daemon does not defend against:

- **Local root on the target host.** A root-owned attacker on the
  host can read everything the daemon can read, modify the daemon
  binary, modify its config, and forge journald entries. Defending
  against this would require attestation primitives that are not
  in this artefact's scope.
- **Compromise of the operator's CA.** If the CA private key leaks
  the attacker can issue arbitrary client certificates. Operator's
  problem, not the daemon's.
- **Supply-chain compromise of the Go toolchain or dependencies.**
  The build pins `go.sum` for module hashes and the build script
  verifies the Go toolchain checksum, but a successful attack on
  the Go release process or on `golang.org/x/crypto` is not
  detected here.
- **Side channels in shared hardware.** Spectre-class CPU side
  channels, hyperthreading-induced timing leaks, and similar are
  out of scope.
- **Physical access to the host.** Anyone with the disk can read
  the TLS server key, the CA bundle, and the daemon binary. The
  daemon does not encrypt its state at rest.
- **Denial of service by network flooding.** A flood at the TCP
  layer or a TLS-handshake flood will starve the daemon's listener.
  The operator's network-layer ACL is the first line of defence;
  the daemon's rate limiter exists for authenticated flows.
- **Cross-host pivoting through a compromised daemon.** The daemon
  initiates no outbound traffic except the DNS probes in section
  4.4, so even a code-execution bug inside the daemon process gives
  the attacker no built-in path to other hosts. This is a property
  of the design, not an active defence.

# 6. Justification per REQUIREMENTS section 6

## 6.1 Read-only by construction

A compromised caller's blast radius is bounded by what the daemon
can do. By construction the daemon cannot:

- write to the filesystem (other than its own state directory),
- send signals,
- spawn arbitrary processes,
- modify any kernel state via sysctl, route, netlink, or D-Bus
  method call that mutates.

The daemon's Go source forbids `os/exec` and `syscall.ForkExec`
calls in every package except `internal/helperinvoke/`, by a custom
build-time linter (REQ 10.2). The daemon process holds no
capabilities at runtime; the systemd unit sets
`NoNewPrivileges=yes`, `CapabilityBoundingSet=` (empty),
`AmbientCapabilities=` (empty). Every privileged read is delegated
to the helper service over a unix socket (see
`doc/design-overview.md` §7). The helper dispatches on a closed
compile-time enum of op tokens and parses underlying tool output
inside its own process; only typed values cross back to the daemon.
The systemd unit applies `SystemCallFilter=@system-service` with
explicit subtractions for state-changing families where the allow
set permits them. The net effect is defence in depth: even if a
tool implementation has a bug that wants to invoke an unintended
syscall, the seccomp filter rejects it; even if the helper
mis-parses an underlying tool's output, raw bytes from that tool
never enter the daemon's memory.

## 6.2 No raw file content passthrough

Bulk file contents are how secrets escape. The daemon constructs
every output value from its own code, so any value the caller
sees has been observed and consciously placed in the schema. We
specifically forbid:

- returning `journald` message bodies verbatim from the `logs`
  tool. The log sample passes through the redactor and is then
  truncated.
- returning `/etc/*` contents from any tool. The `certs` tool reads
  X.509 material but returns named fields, not the file.
- returning subprocess `stdout` from the helper service to the
  caller. The helper parses each underlying tool's output in its
  own process and returns typed fields over the unix socket; raw
  subprocess bytes never enter the daemon.

The shape allowed for filesystem facts is one of: stat tuple,
presence count, key-only listing, named field from a structured
file.

## 6.3 Redaction filter

The redactor is positive-list. Tokens that match the safe set
(bare service names, the operator-configured allowlist of IP
ranges, plain ASCII words up to a length limit) pass; everything
else collapses to `<redacted>`. The fuzz suite at section 10.2 of
the requirements exercises bypass attempts: unicode normalisation
forms, RTL-override codepoints, embedded null bytes, base64 blobs
of various lengths, redactor input that looks like a regex.

Default scrub set is documented in `doc/install.md`. Operators may
add patterns but cannot loosen the positive-list discipline. Two
mechanisms exist. The built-in classes are compiled-in scrubbers,
selected by name. Since 2.3.0 an operator may additionally supply RE2
patterns through `log_redaction_rules`; these are compiled at startup
(a pattern that does not compile is fatal) and applied ahead of every
built-in rule. They can only ever scrub MORE than the defaults — there
is no syntax for exempting a token the positive list would drop.

## 6.4 Authentication and authorisation

mTLS is the chosen mechanism (rationale in `doc/design-overview.md`
section 5). The justification for placing the boundary here:

- A network ACL alone cannot identify which caller within an
  allowed subnet made a call; mTLS issues a verifiable identity.
- Bearer tokens are vulnerable to verbatim copy through any system
  that handles them (logs, ticketing systems, screenshots). mTLS
  identities can be tied to a private key that never leaves the
  caller host.
- mTLS naturally supports rotation through certificate expiry,
  which the operator can drive without the daemon participating.

The daemon refuses to start with `bind_addr` on a public interface
unless `public_bind_acknowledged: true` is set in `daemon.yml`. The
acknowledgement is a deliberate operator action; the daemon does
not infer it.

## 6.5 Audit

Audit completeness is what makes the read-only surface useful in
incident response. Every accepted call records:

- `caller_identity` derived from the verified client certificate,
- the `tool` name and the structured `args` (which are enums only,
  see REQ 4.10),
- the response `size_bytes` and `duration_ms`,
- the `result` (ok or one of the structured error codes from the
  schema).

Rejected calls record the same envelope plus an explicit
`reject_reason`. Logs flow through journald with
`SyslogIdentifier=host-health-mcp`; the operator's existing
journald-to-SIEM pipeline picks them up without custom integration.

The daemon does not log payload bodies. A separate trace mode for
debugging is explicitly excluded from the deliverable to remove the
"trace mode left on in production" failure class.

## 6.6 Rate limiting

The limiter is two-level. A per-caller global token bucket
(30 req/min sustained, burst 10) caps total request rate per
caller and blocks brute-force surface exploration. Per-(caller,
tool) buckets cap individual expensive tools (`logs`, `workload`,
`storage` by default; configurable via `expensive_tool_buckets` in
`daemon.yml`) so that exhausting one expensive budget does not
starve the cheap ones. Both buckets must permit a request for it
to proceed; either rejecting denies the call. Rejection is
structured (`rate_limited` error code) and the daemon never
throttles by sleeping a request - sleeping consumes a worker. The
limiter is an in-process map of token buckets keyed by
`caller_identity` (and by `(caller_identity, tool)` for the
per-tool buckets), swept on a slow tick to reclaim quiet entries.

In addition, the TLS listener applies a
`max_concurrent_handshakes` ceiling (default 16) at the accept
layer. Above the ceiling, new connections are dropped before the
expensive handshake CPU is incurred. This bounds the
handshake-amplification attack from a client that can land TCP
connections but cannot present a valid client certificate, which
the application-layer rate limiter alone cannot see.

## 6.7 Privilege separation

The package ships two cooperating systemd units. The daemon runs
as `host-health-mcp:host-health-mcp` with `NoNewPrivileges=yes`,
empty `CapabilityBoundingSet`, and empty `AmbientCapabilities`.
The helper runs as `root` under its own systemd unit with an
explicit per-need `CapabilityBoundingSet` and `SystemCallFilter`.

Communication is via a unix socket at
`/run/host-health-mcp/helper.sock`, owner `root:host-health-mcp`,
mode `0660`. The helper rejects connections whose `SO_PEERCRED`
uid is not the daemon's uid.

Properties relied on:

- **No setuid bit on disk.** Both binaries are mode `0755` owner
  `root:root`. The helper's privilege comes from its unit config.
  An on-host attacker with write access to `/usr/sbin/` is
  already outside the threat model.
- **Closed dispatch.** Each request frame from daemon to helper
  carries an `op` token from a compile-time Go enum on both sides
  plus, where applicable, a parameter validated by the helper
  against an op-specific whitelist. No path, shell string, or
  free-form caller input reaches the helper.
- **No raw stdout passthrough.** The helper parses output from
  each underlying tool inside its own process and returns typed
  fields over the socket. Raw subprocess stdout never enters the
  daemon. This applies REQ 6.2's "no opaque passthrough" to the
  helper→daemon boundary as well as to the daemon→network
  boundary.
- **Stderr is fingerprinted, and a length-capped prefix is
  forwarded through the daemon-side redactor.** The helper's
  response includes `stderr_bytes` and `stderr_sha256` for forensic
  correlation, plus a sanitised, length-capped (≤200 bytes)
  `stderr_prefix` for operator diagnostics on per-source error
  blocks. The prefix is processed through the daemon-side
  positive-list redactor (§6.3) before it leaves the daemon, so any
  content not on the safe set (drive serial numbers, peer
  identifiers, VG/LV UUIDs that fall outside the allowlist regexes)
  collapses to `<redacted>`. Subprocess argv is also forwarded as
  part of the helper-op-error structure for operator diagnostics
  (binary path plus operator-validated parameter); argv is treated
  as structural identifiers per R5.
- **Sanitised environment.** The helper sets `PATH`, `LANG`,
  `LC_ALL` only. `LD_PRELOAD`, `LD_LIBRARY_PATH`, and similar
  env-driven escalation paths are closed off.
- **No shell.** External commands are invoked via
  `os/exec.CommandContext` with literal-by-literal `argv`. No
  `system()`, no `popen()`, no environment substitution.
- **Bounded outputs and deadlines.** Each op has a per-call
  deadline and an output-size bound. Exceeding either fails the
  op rather than blocking or buffering indefinitely.

Sudo rules are not used. Per-call `systemd-run --uid=root` was
considered and rejected on D-Bus dependency. A fork-and-drop-caps
single-binary model was the chosen design in one draft and was
rejected on complexity grounds. A setuid-root helper exec'd by
the daemon was the chosen design in a subsequent draft and was
rejected because REQ 3.4's `NoNewPrivileges=yes` on the daemon
strips setuid semantics from every subsequent `execve` — the
helper would have run as the daemon's uid, not root, and every
privileged read would have failed.

## 6.8 Egress

The daemon's outbound connection set is exactly:

- DNS queries to the resolvers it uses for the `dns` tool, with
  targets drawn from `dns_probe_targets` in `daemon.yml`,
- nothing else.

There is no phone-home, no update check, no telemetry. The set is
enumerable from the config; the install verification step in REQ
10.3 reads `ss` and `nft` counters after a 24h burn-in to confirm.

# 7. Language-choice safety justification

The implementation language is Go (rationale in
`doc/design-overview.md` section 3). The threat-model relevance is:

- The high-risk surfaces — redaction filter, /proc and /sys parsing,
  journald reader, systemd D-Bus client — are bounds-checked and
  memory-safe in Go. Malformed input produces a recovered panic
  reported as a structured per-tool error, not a memory-corruption
  primitive.
- The privileged-read surface is the helper service, a Go binary
  managed by its own systemd unit. The helper parses output from
  each underlying tool inside its own process (smartctl JSON,
  postqueue text, lvs JSON, /proc/mdstat) and returns typed fields
  over a unix socket. An earlier draft proposed a small C helper
  exec'd by the daemon; that was abandoned both because REQ 3.4's
  `NoNewPrivileges=yes` defeats setuid and because the parsing
  surface — once the helper takes on tool-output parsing — is
  large enough that memory safety matters. Go is the safer choice
  for the helper too.
- The Go runtime's goroutine and channel model maps cleanly onto
  per-tool timeouts via `context.Context`. A wedged subsystem
  cancels at the timeout and the goroutine is collected.
- Modern C++ was considered and rejected on memory-safety grounds.
  Empirical CVE data from Microsoft, Chrome, and Android (published
  reports between 2019 and 2024) consistently put memory-safety
  bugs at roughly an order of magnitude higher rate in modern C++
  than in Go for comparable network-exposed services. Rust would
  improve the rate further but the operational delta against Go is
  small while the build-toolchain weight is meaningful.

# 8. Residual risk and open items

R1. **Side-channel timing of cached vs uncached responses.** The
    `cache_age_s` field of the envelope already reveals cache state
    to a legitimate caller; an attacker observing latency observes
    the same signal less precisely. No active mitigation planned.

R2. **Information density of per-tool warnings.** A `warnings`
    array entry can leak more than the operator intends if a
    subsystem error message is constructed at error time and
    forwarded verbatim. Mitigation: tool implementations construct
    warning strings from a fixed catalogue of message templates;
    free-form interpolation of subsystem strings into a warning is
    forbidden by code review and exercised by the security test
    set in REQ 10.2.

R3. **Certificate revocation latency.** The daemon does not
    implement CRL or OCSP. A revoked client certificate remains
    accepted until either the certificate's own `notAfter` passes
    or the operator restarts the daemon with an updated CA bundle.
    Revocation cadence is therefore a function of the operator's
    PKI policy. The daemon takes no opinion on cert lifetime; it
    enforces what's configured at handshake time.

R4. **MCP plugin trust boundary.** The plugin runs on the operator
    workstation or relay; if compromised it cannot read host
    secrets via the daemon (REQ 6.2 forbids them being returned)
    but can spam the audit log and consume rate budget. This is
    accepted: a compromised operator workstation is downstream of
    the daemon's threat model.

R5. **Operator-authored structural identifiers cross the wire.**
    Several fields in the read surface carry operator-authored
    structural identifiers verbatim: nft counter names
    (`nft_table_counts.hit_counters[].name`), systemd unit names,
    interface names, mountpoints, certificate subjects, mdraid
    array names, LVM VG/LV names, ZFS pool names, and subprocess
    argv (including operator-validated path/device parameters)
    surfaced in per-source `HelperOpError.argv`. These are in scope
    for the read surface by design — they are the very identifiers
    an operator needs to interpret a health report.
    The §6.3 redactor applies to unbounded application-emitted log
    content (`samples[].message` from journald and audit) and to
    free-form failure-reason strings, not to structural
    identifiers. The trade-off is explicit: an operator who
    encodes intent in a structural identifier (e.g. a counter
    named `dropped_by_default_policy`, an LV named `prod_db`) is
    choosing to make that intent visible to authorised callers.
