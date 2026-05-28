---
title: Host Health MCP - Security Audit Report
author: Albert 'Tigr' Zenkoff <albert@tigr.net>
date: 2026-05-24
scope: full source tree at HEAD (8ceec3e)
mode: read-only audit; no remediations applied
---

# Executive summary

The codebase realises the privilege-separation, mTLS, helper-chokepoint, and
read-only-by-construction shape that REQUIREMENTS Rev 2 and the design
overview promise. The TLS configuration on both daemon listener and plugin
client is sound (TLS 1.3, mTLS, EKU + leaf-template checks, no
InsecureSkipVerify anywhere). The unix-socket SO_PEERCRED check is present
and correct. The build-time forbidden-call linter exists and is invoked by
`build.sh`. `os/exec` is genuinely contained to the two designed
chokepoints.

The defects that matter are mostly **drifts between code and the
threat-model / design contract**, not classic injection bugs. The most
load-bearing of these is a deliberate post-design addition of subprocess
`stderr_prefix` and `argv` to helper error responses (schema 0.2.0/0.4.0)
that **directly contradicts** the threat-model § 6.7 and design § 7.2
guarantee that "stderr is fingerprinted, not forwarded." This is now part
of the wire shape that the plugin and external callers consume, so a fix
requires either reversing the design decision or amending the threat model
and recording the change explicitly.

Other significant findings: the daemon does not enforce
`manifest.enabled_tools[]` (every compiled tool is always exposed, REQ 8.2
"no silent degradation" partially violated); the audit-log entry is
missing the `args` and `helper_ops` fields the Entry struct already
declares (REQ 6.5 "enum argument values" not recorded); the positive-list
redactor admits AWS-style keys and email addresses verbatim because the
safe-token regex covers them (the test acknowledges this for AWS keys);
and the response cache is unbounded in entry count.

Nothing observed in this pass amounts to remote code execution or a
read-only-rule break that would let an authenticated caller mutate host
state. The compromised-caller threat (T1) remains well-bounded by
construction. The findings below describe defensive-depth gaps and
information-leakage paths an authenticated caller can exercise within
their rate budget.

---

# Counts by severity

| Severity      | Count |
|---------------|-------|
| Critical      | 0     |
| High          | 3     |
| Medium        | 9     |
| Low           | 7     |
| Informational | 5     |

---

# Findings

## H-1. Helper-to-daemon response forwards subprocess stderr prefix to caller — contradicts threat model § 6.7 / design § 7.2

**Severity**: High
**Location**:
- `daemon/internal/shared/proto/frame.go:52-62` (Response.StderrPrefix, Argv)
- `daemon/internal/helper/dispatch/dispatch.go:33-41` (Error.StderrPrefix, Argv)
- `daemon/internal/helper/exec/exec.go:325-384` (classify() populates StderrPrefix from sanitised subprocess stderr)
- `daemon/internal/shared/schema/error.go:17-30` (HelperOpError forwarded in the response data block exposes Argv and StderrPrefix to the caller)
- `daemon/internal/daemon/helperinvoke/helperinvoke.go:120-130, 162-171, 176-185`

**What is wrong**:
Threat model § 6.7 and design overview § 7.2 explicitly say:

> "Stderr from each tool is **not** forwarded to the daemon. The helper
> records only `stderr_bytes` and `stderr_sha256` in its response and the
> audit-log entry…"
>
> "Raw stderr from invoked tools — which can carry drive serial numbers,
> peer identifiers, VG/LV UUIDs — never enters the daemon's audit log."

Today the helper does the opposite: it copies up to 200 bytes of
subprocess stderr (after a non-printable-byte sanitisation that only
remaps control bytes to `.`, no allowlist application) into the response
frame as `StderrPrefix`, and the full subprocess command vector — including
operator-controlled parameters like the block-device name in
`smart_summary` or the mountpoint in `btrfs_scrub` — into `Argv`. Both
fields flow into `schema.HelperOpError.{StderrPrefix,Argv}` which is part
of every tool's response data block when any sub-op fails (storage,
security, firewall, firewall_lookup, updates, mail, network).

The dispatch.go comment block on lines 26-32 acknowledges this is a
deliberate post-design schema change ("Argv and StderrPrefix were added in
schema 0.2.0") but the threat model has not been updated and the design
overview still asserts the original guarantee. This is a contract break
between code and threat model.

**Why it is wrong**:
The original constraint exists because subprocess stderr is exactly where
the kind of data REQ 6.2 wants kept out of the response leaks from:
smartctl prints serial numbers; mdadm prints disk UUIDs; lvs prints volume
group UUIDs; wg complains about peer endpoints. The sanitiser at
`exec.go:394-410` ONLY remaps non-printable bytes; it applies no allowlist
and no redaction. An attacker who can engineer a sub-op failure (e.g. by
yanking a SMART drive cable or by waiting for a normal transient lvm
hiccup) gets 200 bytes of raw operator-environment text per failed call,
bounded only by their rate budget.

**How to fix** (architectural decision):
Either (a) revert the schema addition: keep `StderrSHA256` and
`StderrBytes`, drop `StderrPrefix` and `Argv` from the wire response and
from `schema.HelperOpError`; or (b) accept the change and amend
`doc/threat-model.md` § 6.7 and `doc/design-overview.md` § 7.2 explicitly,
record the rationale in `doc/changelog.md`, and at minimum apply the
daemon-side redactor's positive-list to `StderrPrefix` before it leaves
the daemon. Operator-controlled-only param round-trip through `Argv` may
or may not be acceptable depending on what shows up there (the
operator-supplied AIDE log paths, BTRFS mountpoints, smart device names
are all already in REQ R5's "structural identifiers" carve-out, so Argv
alone is defensible — but stderr_prefix is not).

---

## H-2. Default positive-list redactor admits AWS-style access keys, emails, and 64-char base64 blobs verbatim — REQ 6.3 partially violated

**Severity**: High
**Location**:
- `daemon/internal/daemon/redact/redact.go:38-43` (regex `^[A-Za-z][A-Za-z0-9._@:-]{0,63}$`)
- `daemon/internal/daemon/redact/redact_test.go:39-42` (the test acknowledges `AKIA0123456789ABCDEF` passes verbatim)

**What is wrong**:
REQ 6.3 says: "Default filter must scrub: bearer tokens (common regex
shapes), email addresses, IPv4/IPv6 addresses outside operator-configured
allowlist ranges, file paths under operator-declared sensitive directories,
base64 blobs longer than 32 characters."

The current safe-token regex `^[A-Za-z][A-Za-z0-9._@:-]{0,63}$`:

- Matches an entire email address (`albert@tigr.net`) as one token. REQ
  6.3 says emails should be scrubbed; here they pass.
- Matches AWS access key IDs (`AKIA…`, `ASIA…`) as one 20-char ASCII
  token. The existing test asserts this passes ("ASCII id within 64 chars
  passes") — but REQ 6.3 explicitly names "bearer tokens (common regex
  shapes)" as a scrub class.
- Matches any 33-64-character ASCII identifier that starts with a letter,
  including JWT-like opaque tokens and base64 blobs up to 64 chars (REQ
  6.3 sets the threshold at "longer than 32").
- Does not enforce the configured `sensitive_dirs` from `daemon.yml`
  (REQ 6.3 names "file paths under operator-declared sensitive
  directories" — that list is read into config but never consulted by the
  redactor).

The fuzz suite at `redact_fuzz_test.go` only checks panic-freedom and
output-length growth; it does not assert that any of the REQ-6.3 classes
are scrubbed.

**Why it is wrong**:
REQ 6.3 spells the scrub classes out and says positive-list. "Positive
list" does not mean "anything that looks like an identifier". The token
shape is so broad that, on the only call path that exercises the redactor
(`logs.Sample.Message` from `journalctl`), any process-emitted secret that
fits in 64 ASCII chars travels straight through.

**How to fix**:
- Tighten the safe-token shape: drop `@`, `:`, drop the upper length bound
  to something like 32, and treat any token with `.`+`@` (email shape) as
  scrubbed.
- Add explicit "common-shape" scrub rules per REQ 6.3 that run BEFORE the
  safe-token check: AWS keys (`(?:AKIA|ASIA)[A-Z0-9]{16}`), JWT triples
  (`[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`), generic >32-char
  base64 runs, then email shape.
- Consume the configured `sensitive_dirs` and replace any token starting
  with one of those prefixes.
- Update the test set so an `albert@tigr.net`, a 40-char base64 string, an
  AWS key, and a `/etc/<sensitive-dir>/foo` all collapse to `<redacted>`.

---

## H-3. `manifest.enabled_tools[]` is silently ignored — every compiled tool is always exposed, contradicting REQ 8.2

**Severity**: High
**Location**:
- `daemon/internal/daemon/config/config.go:46` (field parsed)
- `daemon/cmd/daemon/main.go` (no consumer of `manifestCfg.EnabledTools`)
- `daemon/cmd/daemon/main.go:144` (manifest tool reports `reg.Names()` — i.e. compiled-in, not enabled-in-manifest)

**What is wrong**:
REQ 8.2: "The daemon must refuse to start if the manifest references a
tool or plugin that is not compiled in. No silent degradation."

The daemon validates `workload_plugins[]` against the compiled-in set
(main.go:129-137). It does NOT validate `enabled_tools[]` against
anything, and it never consults `enabled_tools[]` to actually gate which
tools serve requests. The manifest's `enabled_tools` is parsed and then
discarded. The `manifest` tool reports `EnabledTools = reg.Names()`, so
the caller sees the compiled-in set whether the operator opted in or not.

**Why it is wrong**:
An operator who removes a tool from `enabled_tools` in `manifest.yml`
expects that tool to stop responding (per REQ 8.2). Today it continues to
respond. This is "silent degradation" in the opposite direction: silent
non-degradation. It also means the operator-stated attack surface (the
manifest contract) does not match the actual attack surface.

**How to fix**:
- At startup, intersect the registered tool set with
  `manifestCfg.EnabledTools` (if non-empty). Refuse to start if
  `enabled_tools` names a tool not compiled in. If `enabled_tools` is
  empty, accept the historical "all tools" shape with a warning.
- Have `manifest.Snapshot.EnabledTools` reflect the post-intersect set,
  not `reg.Names()`.

---

## M-1. Audit log omits the `args`, `helper_ops`, and reject-reason envelope fields the Entry struct already declares — REQ 6.5 partially violated

**Severity**: Medium
**Location**:
- `daemon/internal/daemon/audit/audit.go:16-25` (Entry has Args, HelperOps)
- `daemon/internal/daemon/audit/audit.go:45-69` (logger uses Args but no call site populates it; HelperOps is not printed at all)
- `daemon/internal/daemon/httpserver/httpserver.go:180-186, 218-224, 251-257` (Entry construction never sets Args or HelperOps)

**What is wrong**:
REQ 6.5: "Every accepted call is logged with: caller identity, tool name,
**enum argument values**, response size, duration, result status. Logs go
to journald with a distinct SyslogIdentifier."

The Entry struct declares `Args map[string]string` and `HelperOps
[]string`, but no call site populates them. The logger does render Args
deterministically when present, but it is always empty, and HelperOps is
not rendered at all (dead field).

Knock-on effect: tools 4.10 (logs) and 4.13 (storage with smart devices)
have caller-influenced enum/path arguments that REQ 6.5 explicitly wants
recorded. Without the args field, a forensic reviewer who is presented
with "logs was called at T" cannot tell which severity/window/source
triple was requested.

**Why it is wrong**:
Audit completeness is the foundation of T1's mitigation (a compromised
caller credential gets bounded read access, and the audit log records
exactly which reads). Missing the args field defeats that.

**How to fix**:
- In `httpserver.handleToolBody` (and the cache-hit branch), after the
  tool's Request struct is parsed, copy its enum-valued fields into the
  Entry.Args map. The logs tool's severity/window/source are the
  canonical example; storage's smart device name should be recorded;
  firewall_lookup's query should be recorded.
- Either populate `HelperOps` per call from the helperinvoke layer (the
  daemon currently has no surface for this) or remove the field as dead.

---

## M-2. `stderr_prefix` sanitiser does not apply the redactor's allowlist or any sensitive-dir rules

**Severity**: Medium
**Location**: `daemon/internal/helper/exec/exec.go:394-410`

**What is wrong**:
`sanitiseStderrPrefix` only remaps non-printable bytes to `.`. The
in-line comment acknowledges the gap: "the redactor's allowlist is not
consulted here because the helper does not know the operator's network
config." So the daemon-side redactor that REQ 6.3 says must process
"every sample" through a positive-list filter is bypassed for stderr
prefixes that surface in `schema.HelperOpError.StderrPrefix`.

This is the same field flagged in H-1; this finding is the redaction
half if the H-1 architectural decision keeps `StderrPrefix`.

**How to fix**:
If `StderrPrefix` stays in the wire shape: route it through
`redact.Filter` on the daemon side before placing it in the response.
The daemon already has the configured allowlists; the helper does not,
and that asymmetry is fine — redaction is a daemon-side concern by REQ
6.3.

---

## M-3. `BindAddrIsPublic` produces a warning but does not refuse to start — design and threat-model say it refuses

**Severity**: Medium
**Location**:
- `daemon/cmd/daemon/main.go:69-71` (warning only, no fatal)
- `doc/design-overview.md` § 6.4 references / `doc/threat-model.md` § 6.4: "The daemon refuses to start with `bind_addr` on a public interface unless `public_bind_acknowledged: true` is set in `daemon.yml`."

**What is wrong**:
REQ 6.4 itself says "must produce a startup warning unless the operator
explicitly acknowledges it in config", which the code matches. But the
threat model § 6.4 promises stronger behaviour ("refuses to start") that
the code does not implement. This is a documentation/reality drift.

**Why it is wrong**:
An operator who reads the threat model and decides public bind needs the
explicit ack expects the daemon to fail closed. With current behaviour the
daemon logs a warning and continues. Either tighten the code or relax the
threat model.

**How to fix**:
Decide which doc is canonical. If threat-model is canonical, change
`main.go:69-71` to `log.Fatalf` when `BindAddrIsPublic() &&
!PublicBindAcknowledged`. If REQ is canonical, edit the threat model.

---

## M-4. `needrestart -b -p` is not deterministically read-only — depends on operator's `/etc/needrestart/needrestart.conf`

**Severity**: Medium
**Location**: `daemon/internal/helper/ops/needrestart.go:20-21`

**What is wrong**:
`needrestart -b -p` runs in batch + nagios-output mode but does not
override the `$nrconf{restart}` config key. On a host where the operator
has set `$nrconf{restart} = 'a';` in `/etc/needrestart/needrestart.conf`,
batch invocation will restart services. REQ 6.1 makes read-only
non-negotiable; this op trusts operator config to remain that way.

**Why it is wrong**:
Read-only-by-construction means the daemon's code path enforces it
regardless of operator config. Right now it does not. The likelihood of
the failure mode is low (most operators leave restart=i) but the
guarantee is unconditional in REQ 6.1.

**How to fix**:
Pass an explicit `-r l` (list mode) on the command line. With
`-r l -b -p`, needrestart will not restart services regardless of the
config file. Add the equivalent override flag and document the
invariant.

---

## M-5. Response cache is unbounded in entry count

**Severity**: Medium
**Location**: `daemon/internal/daemon/cache/cache.go:36-46, 88-128`

**What is wrong**:
The cache is a plain `map[string]Entry` with no size cap. The sweeper
deletes only expired entries. Keys are derived from `(tool, canonical
JSON of body)`; tools with caller-influenced bodies (logs,
firewall_lookup, firewall, storage with future query knobs) let a single
caller, within 30 req/min, instantiate ~30 fresh entries/min. Across all
17 tools that's ~500 entries/min, ~30k entries/hour per caller. Entry
payloads can be tens of KiB.

**Why it is wrong**:
This is bounded denial-of-service but unbounded memory. On a host with
the documented idle-RSS budget of 64 MiB (REQ 5.3) and a `logs` payload
of 20 samples × few-KiB-each per cache entry, a single authenticated
caller can drive the daemon over budget by varying the request body
within 1-2 hours.

**How to fix**:
- Add a per-tool cache-entry count cap (default ~16, configurable in
  `daemon.yml`).
- Or hash the canonicalised body into a fixed bucket size (LRU keyed by
  tool, with a small per-tool size).
- Either way, expose the limit so operators can shrink it for
  memory-constrained hosts.

---

## M-6. Plugin client falls back to system root CAs when `CAPath` is empty

**Severity**: Medium
**Location**: `plugin/internal/client/client.go:47-61`

**What is wrong**:
When `Config.CAPath` is empty, the client builds `tls.Config` without
setting `RootCAs`, which means Go defaults to the system root store. A
deployment that forgets to set `HOSTHEALTH_CA_PATH` will silently accept
any daemon server certificate signed by any public CA the system
trusts. This is documented ("empty uses system roots") but it is also a
foot-gun: the routine deployment for this project is an internal-PKI
operator CA, never a public CA.

**Why it is wrong**:
The internal-CA cert is the entire authentication leg between plugin and
daemon. Falling back to public CAs means a misconfigured plugin will
happily talk to a MITM whose certificate any of Let's Encrypt /
DigiCert / etc. issued.

**How to fix**:
- Refuse to start the plugin when `CAPath` is empty unless an explicit
  `HOSTHEALTH_TRUST_SYSTEM_ROOTS=1` opt-in is set (mirroring the
  daemon's `public_bind_acknowledged` pattern).
- Or always require an explicit CA bundle and document accordingly.

---

## M-7. `MaxResponseFrame = 4 MiB` permits a 256× amplification of memory between an attacker request and the daemon allocation

**Severity**: Medium
**Location**: `daemon/internal/shared/proto/frame.go:28-33, 95-112`

**What is wrong**:
The helper-to-daemon response frame cap is 4 MiB; the read code on the
daemon side allocates the full declared length up front
(`body := make([]byte, n)` at frame.go:107) before reading. A daemon-side
component that issues a helper call gets to allocate up to 4 MiB per
in-flight call. With the helperinvoke fan-out cap of 8, that is 32 MiB
of allocation under a worst-case helper response.

The cap was raised from 256 KiB → 4 MiB in schema 0.5.0 to support
firewall ban-set elements, which can run to tens of thousands of entries.
That justification is real but the consequence — combined with the cache
unboundedness above (M-5) — is meaningful.

**Why it is wrong**:
Idle RSS budget of 64 MiB (REQ 5.3) versus a per-call worst-case alloc of
~4 MiB means an attacker who can engineer a large firewall response on a
host with a big ban set can push the daemon comfortably over its idle
budget, especially combined with cache retention of the same blob.

**How to fix**:
- Stream-decode the response frame into a known typed structure with
  per-field bounds, rather than allocate the entire raw body up front.
- Or keep the up-front allocation but enforce a lower cap (~1 MiB) and
  paginate firewall responses for the few sets that exceed it.

---

## M-8. Helper sub-process `argv` (which echoes the operator-validated parameter) crosses the socket and surfaces in the response data block

**Severity**: Medium
**Location**:
- `daemon/internal/helper/exec/exec.go:325-384` (argv copied into dispatch.Error)
- `daemon/internal/shared/schema/error.go:17-30` (forwarded into response)

**What is wrong**:
Less severe than H-1's stderr_prefix because the operator-validated
parameters (block-device names, mountpoints, systemd timer unit names)
are already structural identifiers per threat-model R5. But the threat
model does not exempt the *full subprocess argv* — including the binary
path — from REQ 6.2's "no opaque passthrough" rule. The full path
`/usr/sbin/smartctl` is uninteresting; the trailing `/dev/sdX` is
already in R5; the middle flags (`--json -a -d nvme`) are
implementation details that a caller does not need.

This is the design-decision half of H-1. The fix for H-1 should also
decide whether `Argv` stays.

**How to fix**:
Decision item alongside H-1. If kept, document explicitly in the threat
model that argv is part of the surface.

---

## M-9. Empty bucket config means "no limit" — operator misconfiguration can disable per-tool rate limiting silently

**Severity**: Medium
**Location**: `daemon/internal/daemon/ratelimit/ratelimit.go:140-143`

**What is wrong**:

```
if b.cfg.SustainedPerMin == 0 && b.cfg.Burst == 0 {
    return true
}
```

An operator writing
```yaml
expensive_tool_buckets:
  logs:
    sustained_per_min: 0
    burst: 0
```
gets unlimited logs traffic. The intent is probably "the operator wants
to disable per-tool limiting for this tool", but it is also the natural
result of a typo (missing keys default to zero; YAML unmarshalling does
not warn). The schema does not constrain these to be > 0.

**Why it is wrong**:
REQ 6.6 lists per-tool buckets as part of the defence; an accidental
zero silently removes that defence with no startup warning.

**How to fix**:
Reject `(0, 0)` at config load time with a clear message. If "disable
the per-tool bucket" is a real use case, give it an explicit
`enabled: false` key rather than overloading zero.

---

## L-1. Schema-declared `additionalProperties: false` on request bodies is not enforced — Go json.Unmarshal is lenient

**Severity**: Low
**Location**: every `Tool.Handle` that does `json.Unmarshal(body, &req)` (logs, firewall, firewall_lookup, future expansion)

**What is wrong**:
`doc/schema-draft.yaml` declares request bodies with
`additionalProperties: false`; `doc/design-overview.md` § 6 says "Workload
schemas and request bodies are strict; non-workload response data shapes
are lenient". Go's default `json.Unmarshal` is lenient (unknown fields
silently ignored). The daemon does not use a `json.Decoder` with
`DisallowUnknownFields()`.

**Why it is wrong**:
A caller can send `{"severity":"warning","window":"1h","source":"journal","gimme_secrets":true}` and the request will be accepted; the daemon will silently ignore the extra field. This is the same surface that schema-tightening is supposed to close off (typo detection, opt-in evolution).

**How to fix**:
Use `json.NewDecoder(bytes.NewReader(body))` with
`dec.DisallowUnknownFields()` in every tool that parses a request body.

---

## L-2. `wireguard_show` parser silently skips peer rows with column counts other than 5 or ≥8

**Severity**: Low
**Location**: `daemon/internal/helper/ops/wireguard.go:93-146`

**What is wrong**:
The parser dispatches on `len(fields) == 5` (interface header) or
`len(fields) >= 8` (peer row). Any other column count is dropped silently.
If `wg show all dump` ever emits a transitional 6 or 7-column row, those
peers vanish from the report without a warning.

**Why it is wrong**:
The redaction discipline expressly fails the op on parser failure
elsewhere (line 98-101); the silent-drop behaviour for unusual column
counts is inconsistent with that and could mask a real upstream-format
change.

**How to fix**:
Return `CodeToolFailed` when a row's column count is neither header nor
peer-row shape; or at minimum log a structured warning that bubbles up
to the envelope.

---

## L-3. `fail2ban-client status <jail>` argv accepts an attacker-controlled-name only if fail2ban-client itself accepts it

**Severity**: Low
**Location**: `daemon/internal/helper/ops/fail2ban.go:49`

**What is wrong**:
The jail name comes from parsing fail2ban-client's own `status` output;
the helper does not validate it before re-invoking
`fail2ban-client status <jail>`. If a local attacker can already configure
fail2ban to add a jail named `-h` (improbable; fail2ban's own validators
reject most flag-like names), the helper would pass `-h` as argv to
fail2ban-client. The risk is bounded by "fail2ban-client must already
accept the name" and by the operator running fail2ban at all.

**Why it is wrong**:
Defence in depth: argv parameters that look like flags should be
prevented by a positive regex at the helper layer, identical in spirit to
the smart_summary and mdraid_detail device-name regexes.

**How to fix**:
Add a `^[A-Za-z][A-Za-z0-9._-]{0,63}$` regex against parsed jail names
before invocation. Drop jails that fail the check with a soft warning.

---

## L-4. `BtrfsScrub` has a TOCTOU between `statfs(2)` and `btrfs scrub status -R <param>`

**Severity**: Low
**Location**: `daemon/internal/helper/ops/btrfs.go:48-62`

**What is wrong**:
`statfs(2)` confirms the mountpoint is btrfs, then the helper invokes
`btrfs scrub status -R <param>` against that same path. A privileged
local actor could replace the mountpoint between the two calls. Given
the helper runs as root and the mountpoint comes from manifest.yml (not
from the caller), the practical exploitability is "local root already
won." This is a defence-in-depth note.

**Why it is wrong**:
The threat model is out of scope for local root, so this is
informational. Recording it because future hardening (e.g. open mount fd
+ fstatfs and pass the fd via /proc/self/fd/N) would close it.

**How to fix**:
None required by threat model. If pursued, open an fd against the
mountpoint, call `fstatfs(2)` on it, and pass the fd via
`/proc/self/fd/N` to btrfs(8). Probably not worth the complexity for the
benefit.

---

## L-5. systemd unit lacks `IPAddressDeny=`/`IPAddressAllow=` despite REQ 6.8 saying "outbound destinations are enumerable from config"

**Severity**: Low
**Location**: `build/systemd/host-health-mcp.service`

**What is wrong**:
REQ 6.8: "The complete set of outbound destinations the daemon may
contact must be enumerable from the configuration. Anything not
enumerated is forbidden."

The daemon's systemd unit does not impose any kernel-level egress
restriction. Today the daemon makes DNS queries to whatever resolver
libc picks; tomorrow a code bug or a bored attacker could open a
connection anywhere. systemd's `IPAddressDeny=any` plus an explicit
`IPAddressAllow=` for DNS would enforce REQ 6.8 at the kernel layer
rather than relying on the absence of code paths.

**Why it is wrong**:
"By construction" plus "enforced by kernel" is stronger than "by
construction." The work to add a `IPAddressDeny=` line is trivial.

**How to fix**:
Add to `host-health-mcp.service`:
```
IPAddressDeny=any
IPAddressAllow=localhost
IPAddressAllow=<DNS resolver subnets from daemon.yml>
```
Document the allow set in `doc/install.md`.

---

## L-6. `tools/sockets` reads `/proc/net/{tcp,udp}*` rather than `sock_diag(7)` as REQ 4.16 mandates

**Severity**: Low
**Location**: `daemon/internal/daemon/tools/sockets/sockets.go:46-65`

**What is wrong**:
REQ 4.16: "Source: kernel netlink diag socket (sock_diag(7))."

The implementation reads `/proc/net/tcp{,6}` and `/proc/net/udp{,6}`. The
functional output (listening tuples) is approximately equivalent but the
requirement is explicit. This is a documentation/reality drift, not a
security defect — both sources require no privileges.

**How to fix**:
Either retitle the REQ to "/proc/net/<proto> or sock_diag(7)" or
re-implement via `NETLINK_SOCK_DIAG`.

---

## L-7. `MaxLineLength` for `RunStreaming` is 1 MiB per line; legitimate journalctl output never approaches this, but a malicious or buggy producer can drive 1 MiB allocations per scanner.Scan()

**Severity**: Low
**Location**: `daemon/internal/helper/exec/exec.go:229, 286-291`

**What is wrong**:
`bufio.Scanner.Buffer(make([]byte, 64*1024), MaxLineLength)` allows the
scanner to grow up to 1 MiB per line. Combined with the helper's per-op
deadline and the daemon's per-tool fan-out cap, the worst case is
bounded, but in the journal-output-cat path (`SshJournalCounts`) the
scanner runs per-line for the entire boot's worth of ssh.service
entries. The 1 MiB cap is a per-line maximum, not aggregate.

**How to fix**:
On hosts that ship operator-controlled journal entries (rare for ssh),
lower the cap further (~16 KiB). For the legitimate ssh.service line
length (~120 bytes for the pubkey-hash variant) 16 KiB is still ample.

---

## I-1. Cache key derivation falls back to raw-byte hashing on canonicalisation failure (now unreachable because of the JSON-valid gate in httpserver)

**Severity**: Informational
**Location**: `daemon/internal/daemon/cache/cache.go:74-84` (the fallback) and `daemon/internal/daemon/httpserver/httpserver.go:169-173` (the gate that makes the fallback unreachable)

**Note**:
The cache's `canonicaliseJSON` returns the raw bytes when JSON parsing
fails. The HTTP server now rejects non-JSON bodies before reaching this
path. The fallback is dead defence; recording it as informational so the
next reviewer doesn't worry. Comment in cache.go already calls this out.

---

## I-2. `caps-template.sh` `grep -qw <tool>` extracts tools by word-boundary match — operator typos in `manifest.yml` are silently ignored

**Severity**: Informational
**Location**: `build/postinst/caps-template.sh:67-83`

**Note**:
The script silently emits a CapabilityBoundingSet with only `CAP_CHOWN`
if `enabled_tools` is empty or contains misspelled tool names. The
helper unit will then run with insufficient privileges, the helper's
ops will fail with `Permission denied`, and the operator will see
puzzling tool-failure warnings. This is an operator-experience issue,
not a security one, but worth flagging.

**Suggested fix**: emit a stderr warning when no matching tool is found,
and document the expected `enabled_tools` strings explicitly in
`doc/install.md`.

---

## I-3. `Argv` in HelperOpError exposes the literal `/dev/sdX` etc. — already in R5's structural-identifier carve-out, but worth recording

**Severity**: Informational
**Location**: `daemon/internal/shared/schema/error.go:26`

**Note**:
Linked to H-1 / M-8. The threat model would need to add "subprocess argv"
to the R5 structural-identifier list to make the current shape
contractually defensible.

---

## I-4. `host-health-mcp.service` declares `MemoryDenyWriteExecute=yes` on a Go binary

**Severity**: Informational
**Location**: `build/systemd/host-health-mcp.service:35`

**Note**:
This is good for hardening but stdlib Go does not JIT. Recording so the
next reviewer doesn't second-guess the line. It is in fact load-bearing
in case a future code path tries to invoke an FFI library that mprotects
+x, and acts as a tripwire for that.

---

## I-5. Plugin client does not enforce a CA-bundle pinning beyond Go's chain validation

**Severity**: Informational
**Location**: `plugin/internal/client/client.go:47-61`

**Note**:
This is intentional given the operator-PKI model; recording because a
deployment that wants stricter pinning (HPKP-style, leaf-or-intermediate
fingerprint pin) would need to extend `tls.Config.VerifyConnection`. Out
of scope for the current threat model.

---

# What I did not audit deeply

For honesty:

- I did not exhaustively read every daemon-side tool's data-collection
  code. I scanned for the high-risk surfaces (caller-supplied paths,
  argv-construction sites, file writes, signal sends) and read in detail
  the tools that touch helper ops with parameters (storage, btrfs, smart,
  firewall, firewall_lookup, logs, systemd_timer). Coverage of pressure,
  sensors, certs, kernel, sockets, network was lighter — I confirmed they
  do not accept caller input and do not write the filesystem.

- I did not run the build / linter / test suite. Findings rely on
  reading the code, not executing it. The forbidden-call linter source
  was read and verified against the chokepoint list; I did not
  empirically confirm it catches every variant of the calls it claims
  to.

- I did not audit the `staticcheck` / `govulncheck` outputs (build.sh
  treats them as optional).

- I did not exercise the fuzz harness (`redact_fuzz_test.go`) — the
  harness asserts only panic-freedom and bounded growth, which I read
  from the source.

- I did not review the workload plugins beyond confirming the
  build-tag + init() registration pattern (REQ 4.9). The `dovecot` and
  `nginx_apache` plugins return "not yet implemented"; the wireguard
  plugin is a thin pass-through to the helper op that is itself audited.

- I did not check that operator-supplied YAML cannot include a billion-
  laughs-style nested anchor expansion. `gopkg.in/yaml.v3` does not
  expand entities like libxml2 does, but I did not verify against the
  current upstream.

---

# Verdict

The contract this codebase enforces is genuinely strong on the points
that matter most: the daemon process holds no privilege; the helper is
the sole executor of state-changing-capable binaries; argv is built from
closed enums and per-op whitelists rather than from caller input; mTLS
identifies the caller cryptographically; the response cache is global
and rate-limited. The path from "compromised caller credential" to
"any host-side primitive that could pivot" is closed.

The improvements above are mostly about closing documented-but-eroded
contract edges (H-1 stderr_prefix, H-2 redactor, H-3 enabled_tools, M-1
audit args). None block a production deployment; all should be on the
fix list before the next release tag in a security-sensitive
environment. The single change most worth doing first is **H-2
(redactor)** because it is the only finding whose realistic exploit path
(secrets-shaped tokens in journal logs leaking through the `logs` tool)
is exercised by every legitimate use of the daemon, not by a
constructed attack.

---

Albert 'Tigr' Zenkoff <albert@tigr.net>
