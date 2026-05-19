---
title: Host Health MCP - Changelog
author: Albert 'Tigr' Zenkoff <albert@tigr.net>
---

# 1.16.0 (2026-05-19)

## Plugin

- **Per-tool MCP arguments now work.** Before this release the
  plugin's `tools/list` only declared `host` in every tool's
  `inputSchema`, and `tools/call` always sent `{}` as the daemon
  request body. Any tool that needed arguments was unreachable
  via MCP — `firewall_lookup` rejected calls because `query` was
  empty, `firewall` could not select `mode`/`table`, and `logs`
  only worked at all because of the 1.15.2 default-fallback fix.
- **`mcp.Tool` carries `ArgsProperties` / `ArgsRequired`.** The
  plugin's `inputSchemaFor` merges the per-tool properties into
  the schema (alongside the implicit `host`) and `tools/call`
  marshals every non-`host` argument into the daemon body. The
  routing argument `host` is always stripped from the body so it
  cannot collide with a tool's own field.
- **Tools that gained MCP arguments:**
  - `logs` — `severity`, `window`, `source` (all optional, enum-
    typed, defaults match the 1.15.2 daemon-side fallback).
  - `firewall` — `mode`, `table`, `include_set_elements` (all
    optional).
  - `firewall_lookup` — `query` (required), `include_set_elements`
    (optional).
- All other tools keep their argument-less surface; the plugin
  still sends `{}` for them, so the daemon-side handlers do not
  change.
- **No daemon change.** Wire schema stays at 0.7.0. Operators
  only need to upgrade the plugin binary; daemon hosts on 1.15.2
  remain compatible. Old plugin clients keep working against new
  daemons (they just continue to send `{}` and miss out on the
  new arguments).
- Regression tests in `plugin/internal/mcp/mcp_test.go` cover
  the `host`-strip wire shape, per-tool `inputSchema` emission,
  end-to-end argument forwarding into the daemon body, and the
  unchanged `{}` body for argument-less tools.

# 1.15.2 (2026-05-19)

## Daemon

- **`logs` tool now answers MCP-routed calls.** Every fleet host
  returned `tool_failed` on `host_logs` since the tool was first
  introduced. Root cause: the MCP plugin's tool inputSchema only
  exposes the `host` argument, so the call body forwarded to the
  daemon is always `{}`. The daemon-side `logs` handler validated
  the request against the REQ 4.10 enum tables (severity,
  window, source) and rejected the zero-value request before
  ever reaching the helper. Direct HTTP callers that supplied the
  fields explicitly were unaffected; only the MCP path was
  broken.
- **Fix:** apply documented defaults before validation —
  `severity=warning`, `window=1h`, `source=journal`. These match
  the tool's stated purpose ("recent log markers") and the
  cache-TTL / expensive-tool buckets the rest of the deployment
  already assumes. Direct HTTP callers can still override any of
  the three fields explicitly; the enum tables remain the source
  of truth for accepted values, so an unknown value (e.g.
  `severity=loud`) still fails validation.
- Regression test in `daemon/internal/daemon/tools/logs/logs_test.go`
  covers the empty-body default path, the partial-override path,
  and that the enum tables still reject unknown values.
- No wire-schema change; schema stays at 0.7.0. Plugin binary
  needs no update — only the daemon.

# 1.15.1 (2026-05-16)

## Plugin

- **Plugin-side tool list catches up with the daemon.** The two
  firewall tools (`firewall`, `firewall_lookup`) shipped on the
  daemon in 1.13.0 / 1.14.0 / 1.15.0 but were never added to the
  plugin's hardcoded tool list at `plugin/cmd/plugin/main.go`. As
  a result MCP clients that connected through the plugin saw 17
  tools instead of the full 19, and could not invoke the
  firewall surface even on hosts where the daemon exposed it.
  Same class of miss as the 1.14.2 daemon-side mirror fix — both
  sides of a feature need to land at the same release, and 1.13/
  1.14 only updated the daemon side.
- No daemon or wire-schema change; the daemon was always correct.
  Schema stays at 0.7.0. Operators only need to upgrade the
  plugin binary on the workstation / relay.

# 1.15.0 (2026-05-16)

Breaking surface change: the firewall tools are renamed to match
the short-name convention every other tool in the registry
already follows.

## **Operator migration required**

| Old (≤1.14.2)             | New (1.15.0+)        |
|---------------------------|----------------------|
| `host_firewall`           | `firewall`           |
| `host_firewall_lookup`    | `firewall_lookup`    |

What needs updating at the same time as the daemon upgrade:

1. **MCP plugin / operator client call sites** — every
   `/v1/host_firewall[_lookup]` URL becomes
   `/v1/firewall[_lookup]`.
2. **`/etc/host-health-mcp/manifest.yml`** — every
   `enabled_tools[]` entry that listed `host_firewall` or
   `host_firewall_lookup` must use the new name. The daemon
   refuses to register a tool whose name does not appear in
   `enabled_tools[]`.
3. **Caps templating** — re-run
   `/usr/local/share/host-health-mcp/caps-template.sh` after the
   manifest edit. The generator now matches `firewall` and
   `firewall_lookup` (short form). Pre-1.15.0 deploys that
   listed `firewall` in the manifest silently failed to add
   `CAP_NET_ADMIN` to the helper unit, surfacing as fleet-wide
   "Operation not permitted" on `nft -j list ruleset`. This is
   the canary finding that motivated the rename — short names
   match the operator's natural mental model and remove the
   footgun.
4. `systemctl daemon-reload`, restart the helper, restart the
   daemon.

## Daemon

- `Tool.Name()` for the firewall introspection tool returns
  `"firewall"`; for the lookup tool, `"firewall_lookup"`. HTTP
  routes change accordingly.

## Caps templating

- `build/postinst/caps-template.sh` matches short names
  (`firewall`, `firewall_lookup`) when walking
  `enabled_tools[]`. Both add `CAP_NET_ADMIN` to the helper
  unit's capability union; the `add` helper deduplicates, so
  enabling both costs nothing extra.

## Wire schema (0.7.0)

- Tool name rename is a breaking surface change. Schema bumps
  `0.6.0` → `0.7.0` per the version-matrix rule that name
  changes are not field-additive. Major bump (1.0.0) was
  considered but `host_firewall*` had only been in the wire for
  ~24 hours of canary deploy; the rename is treated as an
  early-stage correction.

## Helper

- Helper op tokens (`firewall_inspect`, `firewall_lookup`) are
  unchanged. The rename only affects the daemon's HTTP tool
  surface and the manifest's `enabled_tools[]` vocabulary.

# 1.14.2 (2026-05-16)

## Daemon

- **`host_firewall_lookup` wire shape fix**. Canary on a public-
  target host reported every `matches[].match_kind` as empty
  string and `sets[]` always nil even with
  `include_set_elements=true`. Root cause was a missed mirror on
  the daemon side: when the helper-side types were refactored to
  the fleet-manager spec (`match_kind`, `rule_handle`,
  `rule_text`, parallel `sets[]`) during 1.14.0, the daemon's
  `Match` type still carried the pre-refactor JSON tags
  (`kind`, `handle`, `expr`, no `Sets` field). All renamed
  fields silently dropped on JSON unmarshal. Rule-level
  identification still worked because `family`/`table`/`chain`/
  `matched_value` retained their tags. The daemon-side `Match`
  now mirrors helper-side `FirewallRuleMatch` exactly, and a new
  `SetHit` type covers the `sets[]` entries.
- Regression test `TestData_FullEnvelope` drives a full canned
  helper response through the unmarshal path and asserts both
  arrays populate.

# 1.14.1 (2026-05-16)

## Docs

- `tools.md`: tightened the `host_firewall_lookup` match-semantics
  section. Behavior is unchanged from 1.14.0 — a CIDR query
  against a rule pinning a single literal IP inside that range
  was already classified as `saddr_in_subnet` / `daddr_in_subnet`
  (test `TestFirewallLookup_CIDRQueryAgainstLiteralRule` covers
  this) — but the spec text glossed over the case. The full
  query × rhs matrix is now explicit so operators don't have to
  infer the rule from the implementation.

# 1.14.0 (2026-05-16)

New tool `host_firewall_lookup` — given an IPv4/IPv6 address or
CIDR, report every chain rule and set element across the host's
nftables ruleset that references it. The intended fleet use is
"is this address banned anywhere?" and "which host's policy is
letting X through?" without pulling and grepping the full ruleset
per host. Schema bumps to `0.6.0` (additive: one new tool).

## Daemon

- **New tool `host_firewall_lookup`** (POST `/v1/host_firewall_lookup`).
  Request: `{ "query": "<ip-or-cidr>", "include_set_elements": false }`.
  Response data:
  - `query`, `query_kind` (`ipv4_addr` | `ipv6_addr` |
    `ipv4_cidr` | `ipv6_cidr`).
  - `matches[]` — one entry per rule hit. Carries `family`,
    `table`, `chain`, `rule_handle`, `rule_text` (compact JSON
    expr), `field` (`saddr`/`daddr`), `operator`,
    `matched_value`, optional `set_name`, and the discriminated
    `match_kind`:
    - `saddr_exact` / `daddr_exact`
    - `saddr_in_subnet` / `daddr_in_subnet`
    - `set_member` / `set_subset_overlap`
  - `sets[]` — one entry per set/map element hit. Carries
    `family`, `table`, `set`, `element_key`, optional
    `expires_s` / `timeout_s`, and `match_kind` (`set_member` or
    `set_subset_overlap`). Populated only when
    `include_set_elements=true`.
  - `searched_tables`, `searched_chains`, `searched_rules`,
    `searched_sets` — coverage counters so a no-match result is
    distinguishable from an empty ruleset.
- Cache TTL default 30 s, per-call timeout 6 s. Cache key
  includes the request body so different queries don't collide.
- Manifest gating shares the existing `firewall.enabled` flag —
  operators who disable firewall introspection turn off both
  tools at once.

## Helper

- **New op `firewall_lookup`** runs a single `nft -j list ruleset`
  call (RunCapped, 32 MiB ceiling) and performs all matching
  in-process. Same caps profile as `firewall_inspect`
  (`CAP_NET_ADMIN`). Set-membership is computed once per
  invocation and reused for rules referencing `@setname`, so
  even hosts with 69k-entry ban sets run a single linear pass.

## Wire schema (0.6.0)

- Additive: new top-level tool `host_firewall_lookup` with data
  block as described above.

## Out of scope (deliberate)

- No `rule_text` rendering in nft's textual form. `rule_text`
  carries the compact JSON of the expression array; rebuilding
  nft's userspace renderer is not implemented. Operators wanting
  the readable rule body can still call `nft list ruleset` on the
  host or use `host_firewall mode=detail`.
- No MAC-address or port lookups. The matcher only considers
  ip / ip6 saddr/daddr payload expressions. Layer-4 and link-
  layer matches are a separate concern.

# 1.13.1 (2026-05-16)

## Helper

- `nft_table_counts`: swap `helperexec.Run` to `RunCapped` with the
  same 32 MiB ceiling the new `firewall_inspect` op uses. Modern
  nft -j prints the whole document on one JSON line; on hosts with
  large ban sets the prior 256 KiB stdout cap returned
  output_truncated, which the daemon-side network tool reported as
  empty per-table counts. Same root cause as the 1.13.0
  RunCapped introduction; the bug had been latent since the network
  tool went in.

# 1.13.0 (2026-05-16)

New tool `host_firewall` for read-only inspection of nftables
ruleset, sets, and synthesised per-source ban counts. Schema bumps
to `0.5.0` (additive: one new tool, no field renames or removals).

## Daemon

- **New tool `host_firewall`** (POST `/v1/host_firewall`). Returns
  backend identification, nft version, sha256 of the raw `nft -j
  list ruleset` bytes (fleet-diff key), per-table chain/set/rule
  counts, per-chain metadata (and rule bodies in detail mode),
  per-set metadata (and inline elements when explicitly requested),
  and a synthesised `bans` view that maps manifest-declared ban
  sets onto live element counts.
- Cache TTL default 30 s, per-call timeout 6 s (cap at REQ 5.1's
  10 s). If the manifest's `firewall.enabled` is false the
  response is empty plus a `firewall: disabled in manifest`
  warning.

## Helper

- **New op `firewall_inspect`** runs `nft -j list ruleset` and
  optionally `nft -j list set …` per ban-set. Inline element
  return is capped (defaults: 2000 per set, hard cap 40000) so the
  helper-to-daemon response stays under `proto.MaxResponseFrame`.
- **New primitive `helper/exec.RunCapped`**. Captures a single
  subprocess's stdout up to a caller-supplied byte budget without
  the line-orientation that `RunStreaming` enforces (bufio.Scanner,
  1 MiB per line). Required because modern nft userspace prints
  `-j` output as one JSON line that can run to many megabytes on
  fleet hosts with sizeable ban sets. Truncation surfaces as a
  return flag, not a structured fault — the caller asked for a
  budget. On budget hit the child is SIGTERMed promptly so the
  call doesn't pin the outer deadline.

## Wire schema (0.5.0)

- Additive: new top-level tool `host_firewall` with data block as
  described in `tools.md`.
- `proto.MaxResponseFrame` bumped from 256 KiB to 4 MiB. This
  changes the helper-daemon protocol invariant; both binaries
  ship from the same `.deb` and are version-locked, so no
  forward/backward-compat shim is needed. The bump unblocks tools
  whose typed result includes caller-tunable per-element lists.

## Manifest

- New `firewall:` block under the host manifest:
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
  Operators with hosts whose ban sets exceed 2000 entries and who
  want fleet-wide inline element visibility may raise the per-set
  cap up to 40000; the helper enforces a hard ceiling at that
  value to bound response framing.

## Caps templating

- `host_firewall` in `manifest.yml`'s `enabled_tools` adds
  `CAP_NET_ADMIN` to the helper unit's capability union.
  `nft list ruleset` reads kernel nftables state over a
  `NFNL_SUBSYS_NFTABLES` netlink socket; unprivileged callers
  cannot enumerate tables on stock kernels.

## Out of scope (deliberate)

- No iptables-legacy enumeration. The fleet runs nftables; if a
  host genuinely uses `iptables-legacy` the tool reports
  `backend: "none"` and a warning. A future op may add
  iptables-legacy as its own primitive.
- No connection-tracking dump (`conntrack -L`); separate tool if
  needed.
- No mutation paths (unban, flush, reload). The daemon is read-
  only by construction.

# 1.12.1 (2026-05-15)

## Helper

- `helper/exec.RunStreaming`: new line-streaming primitive that
  invokes a subprocess and calls a visitor on each stdout line
  without buffering. Per-call memory is bounded by `MaxLineLength`
  (1 MiB) regardless of total output volume.
- `ssh_journal_counts` now uses `RunStreaming` with a
  closure-captured accumulator. Resolves the accumulator-reuse case where
  even after the 1.9.5 `journalctl --grep` pre-filter, the
  ssh.service journal still ran 451 KiB on long-uptime public-target
  hosts (driven by ~120-byte "Accepted publickey … SHA256:…" lines).
  Streaming removes the cap concern entirely; the pre-filter is
  retained because it halves the bytes journalctl emits.
- Regression test `TestRunStreaming_NoBufferCap` drives `seq 1
  200000` (~1.16 MiB) through `RunStreaming` and confirms every
  line is visited without tripping a cap.

# 1.12.0 (2026-05-15)

Two audit findings that needed coordinated rollout: TLS client-cert
template enforcement and the helper deadline budget design promised
since 1.0.0 but never enforced.

## **Operator pre-flight required before deploying 1.12.0**

Every operator and host client certificate MUST carry
`extendedKeyUsage = clientAuth`. See `doc/install.md §2.2`. Existing
fleet certs minted without an EKU stanza will be rejected with TLS
`bad_certificate` after the upgrade. Rotate through one renewal
cycle first.

## Daemon

- **A1.5 — TLS template enforcement**. `tls.Config.VerifyConnection`
  runs after chain verification and rejects:
  - leaves marked as CAs (basicConstraints CA:TRUE);
  - leaves missing `ExtKeyUsageClientAuth`;
  - leaves with empty Subject CN AND no DNS SAN.
  Chain-to-CA verification alone was the previous bar; that left
  the daemon implicitly trusting whatever the operator's CA
  template happened to emit. The contract is now explicit.
- **C1 — helper deadline budget**. `helperinvoke.Call` now sets the
  helper-socket deadline `HelperDeadlineBudget` (500ms) earlier
  than the daemon's `ctx.Deadline()`. The design (§7.2) called for
  this since 1.0.0 — both timers previously fired at the same
  instant and the helper's reply could lose the race. The 500ms
  matches `helper/exec.KillGrace` so the helper has room to
  SIGTERM->SIGKILL its subprocess and still drain a reply.
  - **Operator-visible**: per-tool budgets shorten by 500ms. The
    example `daemon.yml` bumps `storage`, `logs`, and `updates`
    timeouts by 500ms; fleet operators tuned at the margin should
    do the same.

## Docs

- `doc/install.md` §2.2 documents the EKU requirement, the
  pre-flight openssl check, and the CSR generation pattern.
- `build/examples/daemon.yml` bumps the documented per-tool
  timeouts by 500ms.

# 1.11.0 (2026-05-15)

A1.2 from the audit: extend the structured per-source error pattern
(originally only on `storage.smart[].error`) to every helper-backed
tool, and stop putting argv/exit/stderr_prefix into `warnings[]`
strings. Same diagnostics, structured + redactable; the privacy
posture improves without losing operator-side observability.

## Wire schema

- Schema version bumped to **0.4.0** (additive-minor; version-matrix
  C2 forward-compatible with 0.3.0 clients).
- New `schema.HelperOpError` type defined in
  `daemon/internal/shared/schema/error.go`. Fields: `op` (omitempty;
  helper op name when used in a tool-level array), `code`, `message`,
  `argv`, `exit_code`, `stderr_sha256`, `stderr_prefix`. The shape
  matches and replaces `storage.SmartError`.
- Every helper-backed tool's `Data` gains an optional
  `errors[]` field of `HelperOpError`. Populated with one entry per
  failed helper call.

## Daemon

- `helperinvoke.HelperError.Error()` no longer formats argv, exit
  code, or stderr prefix into the returned string — only `helper:
  <code>: <message>`. Callers that need the structured diagnostics
  go through `helperinvoke.OpErrorFrom(err)` / `(*HelperError).AsOpError()`.
- New `helperinvoke.OpErrorFrom(err) *schema.HelperOpError` and
  `helperinvoke.CodeOf(err) string` helpers.
- `storage.SmartError` removed; `storage.smart[].error` uses the
  shared `schema.HelperOpError` (wire-compatible — same JSON shape).
- `security`, `updates`, `mail`, `network`, and `storage` all now
  populate `errors[]` on helper-call failures and emit code-only
  `warnings[]` strings (`<tool>: <op>: <code>`). The argv, exit code,
  stderr SHA-256, and 200-char stderr prefix live in the structured
  field where they can be inspected or redacted at the egress.
- `logs` returns the helper error as a tool-level failure (envelope
  `error.code = "tool_failed"` with a fixed `error.message`); no
  warnings-side leak, no per-source field needed.

## Operator-visible

- Warnings strings shrink to short codes. If a downstream parser
  was extracting argv/stderr from warning strings, it should now
  read `data.errors[].argv` etc. instead.
- For tools whose data uses per-element error blocks
  (`storage.smart[]`), behaviour is unchanged.

# 1.10.0 (2026-05-15)

Safe wave from the 1.9.5 security/quality audit. Each finding is
operator-side approved as non-breaking and applied independently;
see the changelog detail per commit.

## Daemon

- **A1.1 — cache + httpserver**: cache key uses the full SHA-256
  (no longer truncated to 16 bytes; the 128-bit truncation gave a
  2^64 birthday-collision surface for a global cache). httpserver
  rejects bodies that fail `json.Valid` with a structured 400
  `bad_argument` before they reach the cache; previously
  `canonicaliseJSON` fell back to raw-byte hashing on parse error,
  letting a caller pollute the cache with one entry per
  byte-distinct invalid variant.
- **A1.3 — audit**: `caller`, `tool`, `result`, `reject_reason`,
  and individual `args` map values are `%q`-quoted; args keys are
  sorted before render. Prevents future log parsers from being
  mangled by control characters or `=`/`]` in cert CommonNames.
- **A1.7 — `systemd_timer_last_trigger`**: positive-regex unit
  validation (`^[A-Za-z0-9][A-Za-z0-9._@-]*\.timer$`); previously
  the negative `ContainsAny` filter accepted leading `-` which
  systemctl parses as a flag.
- **A1.8 — `helperinvoke.Call`**: ctx.Done() watcher closes the
  conn on bare cancellation (the prior `SetDeadline(ctx.Deadline())`
  only fired when ctx carried a deadline). Plugin always sets a
  deadline so no observable change today; fixes the bare-cancel
  case for future direct callers.
- **B1.2 — `ratelimit.bucket.refund`**: updates `lastTouched` when
  refunding a global token to a caller whose tool-bucket take
  failed. Without this, a caller hammering a per-tool cap could
  loop indefinitely while appearing idle to the sweeper.
- **B1.4 — daemon main**: cache sweeper goroutine selects on
  `ctx.Done()` for clean shutdown, matching the pattern
  `ratelimit.RunSweeper` already uses.

## Helper

- **B2.5 — `unattended_upgrades_status`**: log Stat failure is no
  longer fatal. `Enabled` comes from `apt-config dump` and is
  returned even when the log dir read fails — turning a hard error
  into a degraded-data response. Fleet has seen the slow-storage
  rotation race trip the previous path.
- **B2.6/B2.7/B2.8 — dead code**: removed an empty `if
  !errors.Is(err, fs.ErrNotExist)` branch in `audit_status`, an
  unused `*int exit` return slot in `aide_summary.parseAideLog`,
  and the `_ = strconv.Atoi` import-keepers in `mdraid` and
  `apt_pending`. Two unused stdlib imports removed in turn.

## Plugin

- **A1.10 — client `ResolveHost`**: explicit IPv6-literal handling.
  Bracketed forms (`[fe80::1]`, `[fe80::1]:8443`) parsed correctly;
  bare unbracketed IPv6 rejected with a clear error asking the
  caller to bracket. Previously `strings.Count(s, ":") == 1` for
  `fe80::1` evaluated to `no port` and the resolver emitted
  malformed `fe80::1:8443`. This deployment uses IPv4 hostnames so no
  visibility today; removes a latent footgun for IPv6-only routing.

## Build

- **B4.1/B4.3 — forbidden-call linter**: added `os.StartProcess`,
  `syscall.Exec`, `syscall.StartProcess`, and
  `golang.org/x/sys/unix.Exec` to the rejected-symbol set. All four
  bypass `os/exec` to fork or replace the current process,
  defeating the chokepoint discipline the existing rules enforce.
  Dot-import / underscore-import of `os/exec` are already caught
  by the import-path check at the import line, which fires before
  any unqualified usage could matter.

## Deferred from this wave (per operator-side coordination)

- **A1.2** — stderr/argv leakage in `warnings[]` strings. Operator-
  side wants the structured per-source error block extended to
  every helper-backed tool first, then the stderr crumbs dropped
  from the strings. Scheduled for 1.11.0.
- **A1.5 + C1** — TLS client-cert `clientAuth` EKU enforcement and
  helper deadline budget. Both require ansible-side coordination
  (CSR template patch + forced cert rotation across the fleet, then
  per-tool timeout bumps). Scheduled for 1.12.0.
- **A1.9, A2.10, A2.9, C8, C10, B5** — skipped / deferred per
  operator-side verdict (see audit-response handoff).

# 1.9.5 (2026-05-15)

## Helper

- `ssh_journal_counts`: pass `--grep=^(Accepted|Failed) ` to
  `journalctl` so the line filtering happens server-side. Hosts with
  long uptime and noisy public surfaces (relays, public service
  endpoints) emit hundreds of KiB of `ssh.service` journal entries
  per boot; piping the unfiltered stream into the helper blew past
  the 256 KiB stdout cap, the cappedWriter returned
  `*truncatedError`, the subprocess got SIGPIPE'd, and the resulting
  `*exec.ExitError` masked the truncation cause — the op reported a
  generic `tool_failed exit=-1` instead of `output_truncated`. With
  `--grep`, the bytes crossing the pipe are bounded by the count of
  matching lines.
- `exec.Run`: cappedWriter now carries a sticky `truncated` flag.
  Run checks it after `cmd.Wait()` and substitutes a fresh
  `*truncatedError` for whatever `cmd.Run` reported, so truncation
  is surfaced as the proximate cause regardless of which signal
  killed the subprocess. Closes a latent bug that would have hit any
  future helper op whose tool produces large output. Regression
  tests added in `internal/helper/exec/exec_test.go` covering the
  truncation-masked-by-signal case, the happy path, and the
  tool-missing classification.

# 1.9.4 (2026-05-15)

## Privacy

- Privacy scrub. Go module path changed from
  `tigr.net/host-health-mcp/{daemon,plugin}` to dotless
  `host-health-mcp/{daemon,plugin}` across 43 files. Changelog
  narrative for 1.8.0 genericised (specific canary hostname and
  NVMe model removed). `git filter-branch` rewrote three commit
  message bodies that named a specific fleet host and referenced an
  external ansible repository commit; tags 1.6.0 → 1.9.3 remapped
  onto the rewritten commits.

# 1.9.3 (2026-05-15)

## Daemon

- `security.aide_or_equivalent.change_count`: on a clean AIDE run
  (`AIDE found NO differences between database and filesystem`),
  AIDE 0.19.x omits the `Total number of differences:` header and
  the per-class `Added/Removed/Changed entries:` lines entirely.
  Inferring change_count from the headline match (0 when the
  clean-state phrase appears) closes the last null in the canary's
  security envelope; previously every clean run emitted
  "change_count unparseable" alongside an exit_code:0.

# 1.9.2 (2026-05-15)

## Helper

- `read_audit_status`: drop `NLM_F_ACK` from the `AUDIT_GET` request.
  When `NLM_F_ACK` is set the kernel emits two messages — a leading
  `NLMSG_ERROR` with errno=0 (the ack), then the actual
  `AUDIT_GET` payload. The recv loop in 1.9.0-1.9.1 read only the
  first message, saw `NLMSG_ERROR`, and returned "bare ack, no
  AUDIT_GET reply". Without `NLM_F_ACK` the kernel sends a single
  `AUDIT_GET` reply; one recv, no state machine.
- `queue_depth` and `lost_events` now populate alongside the
  filesystem-derived `last_rotation_ts`.

# 1.9.1 (2026-05-15)

## Correction to 1.9.0

The 1.9.0 release note claimed: *"The kernel's actual check for
AUDIT_GET is netlink_capable(skb, CAP_AUDIT_READ) per
kernel/audit.c."* That was wrong. Empirical testing on Debian 13's
6.12.x kernels: `AUDIT_GET` issued via raw netlink with only
`CAP_AUDIT_READ` returns `EPERM`; the same call with
`CAP_AUDIT_CONTROL` succeeds. `audit_netlink_ok()` routes
`AUDIT_GET` through the same case block as `AUDIT_SET`,
`AUDIT_ADD_RULE`, `AUDIT_DEL_RULES` — all governed by
`CAP_AUDIT_CONTROL`. `CAP_AUDIT_READ` only gates `audit_bind()`
for the multicast audit-event stream (rsyslog, auditd-plugins,
laurel).

## Install

- `caps-template.sh`: the `security` row now adds
  `CAP_AUDIT_CONTROL` (instead of `CAP_AUDIT_READ`) when the manifest
  enables the security tool. The cap is picked up into both
  `CapabilityBoundingSet` and `AmbientCapabilities` of the drop-in
  by the existing emit logic; ambient is required because the
  netlink call is in-process (`netlink_capable` checks the helper's
  own effective set, not a subprocess's).
- Helper unit doc-comment updated.

## Helper

- `read_audit_status` is now best-effort: an `AUDIT_GET` failure no
  longer suppresses the filesystem-derived `last_rotation_ts`. The
  op returns a partial result with `queue_depth`/`lost_events` null,
  `last_rotation_ts` populated from `/var/log/audit/` if available,
  and `netlink_error` carrying the failure string. The daemon
  surfaces `netlink_error` as a warning. Previously a netlink EPERM
  caused the entire op to return an error and the rotation
  timestamp was dropped along with the netlink fields.
- New `netlink_error` field on the `AuditStatus` helper response.

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
  instead of dropping the entire response. A canary NVMe SSD whose
  firmware does not implement every SMART subcommand (exit 4 — one
  SMART command unsupported) now returns model, smart_overall,
  temperature, and power-on hours instead of `tool_failed`.
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
  the canary's `auditctl exited non-zero / stderr=You must be root
  to run this program.` failure on hosts where the security tool is
  enabled.

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
