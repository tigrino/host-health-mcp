---
title: Host Health MCP - Plugin / Daemon Compatibility Matrix
author: Albert 'Tigr' Zenkoff <albert@tigr.net>
date: 2026-05-14
status: Draft - companion to design-overview.md and schema-draft.yaml
---

# 1. Purpose

REQUIREMENTS section 7.3 mandates semantic versioning on the wire
schema and says the plugin negotiates a daemon's schema version
through the `manifest` tool on first contact per session. REQ 7.2
says the plugin must fail closed on incompatible schema versions.
What "incompatible" means at minor and patch granularity was not
spelled out; this document closes that gap.

# 2. Negotiation

When the plugin opens a session to a daemon:

1. The plugin issues a `manifest` call.
2. The daemon returns its `schema_version` (full semver) and
   `daemon_version` (full semver).
3. The plugin compares the daemon's `schema_version` against the
   `schema_version` the plugin was built against.
4. The plugin classifies the pair into one of the compatibility
   cells in section 3 and acts on the resulting policy.

The plugin caches the result for the duration of the session. It
does not re-check on every tool call.

# 3. Compatibility matrix

In the table, `D` is the daemon's `schema_version`; `P` is the
plugin's compiled `schema_version`. The columns are major / minor
/ patch axes, comparing P against D.

| Cell | Major   | Minor      | Patch  | Result            | Behaviour                                                                                  |
|------|---------|------------|--------|-------------------|--------------------------------------------------------------------------------------------|
| C1   | P == D  | P == D     | any    | Compatible        | Normal operation.                                                                          |
| C2   | P == D  | P  < D     | any    | Forward-compat    | Plugin proceeds. Daemon may emit fields the plugin doesn't know; plugin ignores them.      |
| C3   | P == D  | P  > D     | any    | Tool-level check  | Plugin compares the daemon's `enabled_tools[]` against the set of tools the plugin needs. Missing tool: plugin fails that tool's calls with `schema_incompatible`. Tool present but emitted shape lacks a field the plugin needs: surfaces as `schema_incompatible` at parse time. No field-level pre-flight introspection exists; field-level mismatches are detected on first use of the tool. |
| C4   | P != D  | any        | any    | Incompatible      | The `manifest` call itself succeeds (it must, since it is how the plugin learns the daemon's `schema_version`). On observing the major mismatch, the plugin marks the session incompatible and returns `schema_incompatible` for every subsequent tool call. |

# 4. Definitions

- **Forward-compatible (C2).** Adding a field is minor-additive per
  REQ 7.3. A plugin built against schema 1.2.x reading a daemon at
  schema 1.5.x will see fields it does not know about. The plugin
  ignores unknown fields and surfaces only those it understands.
  This is the common case for a slow-rolling plugin fleet against
  faster-moving daemons.

- **Tool-level check (C3).** The plugin learns the daemon's
  enabled tool set from the `manifest` call (the `enabled_tools[]`
  field). The plugin does NOT have field-level introspection of
  the daemon's schema; field-level pre-flight checking would
  require the daemon to publish the per-tool field list, which the
  manifest does not do and which would duplicate the schema
  artefact. Two consequences:

  - A plugin tool whose underlying daemon tool is absent from the
    daemon's `enabled_tools[]` is treated as unavailable for the
    session; the plugin returns `tool_disabled` (a distinct error
    code, see `schema-draft.yaml` `ErrorEnvelope.error.code` enum)
    without making the call.
  - A plugin tool whose underlying daemon tool is present but
    whose emitted shape lacks a field the plugin requires is
    detected on first call: the plugin's response parser fails
    closed and surfaces `schema_incompatible` with a `message`
    naming the missing field. The plugin caches that outcome for
    the session.

  Plugin authors compensate by marking optional fields as optional
  in the plugin's MCP tool schema with sensible defaults. Required
  fields in the plugin schema must correspond to required fields
  in the daemon schema for the supported daemon major.

- **Incompatible (C4).** Removing or renaming a field is a major
  bump per REQ 7.3. Any major mismatch is hard-incompatible. The
  `manifest` call itself must succeed because that is how the
  plugin observes the daemon's `schema_version`; the daemon never
  refuses `manifest` based on the caller-side version. On
  observing the major mismatch, the plugin marks the session
  incompatible and returns `schema_incompatible` for every
  subsequent tool call. The plugin's MCP manifest declares the
  supported daemon major; an operator running daemon 2.x with
  plugin 1.x sees a clean error on the first tool call after
  manifest negotiation.

- **Patch differences** are never reasons for incompatibility. They
  exist for schema-doc clarifications and example updates that do
  not change wire shape.

# 5. Drift detection at build time

**Correction.** Earlier revisions of this section described a build
gate that compares a hash of "the schema file used by the daemon"
against "the schema file used by the plugin", failing the build when
they differ. No such gate was ever implemented, and it could not have
been: there is one schema document, `doc/schema-draft.yaml`, and
neither binary reads it. Both hand-code Go shapes that mirror it
(design §6), so there are no two files to compare. The section
described a control that did not exist, which is worse than
describing none.

What does run, from `build/build.sh` via `go test ./...` in the
linter module:

  - **`TestWireSchemaVersionIsDeclaredOnceInEffect`** compares the
    `SchemaVersion` constant in `daemon/internal/shared/schema/` with
    the one in `plugin/internal/schema/` and fails the build when they
    differ. The two exist separately because the plugin cannot import
    daemon internals; keeping them equal was previously a manual step
    at release time, and drift would have surfaced as a plugin
    refusing a daemon it is compatible with, or accepting one it is
    not.

What still is **not** checked mechanically, and is therefore a review
obligation:

  - that the Go shapes still match `doc/schema-draft.yaml`. Nothing
    validates one against the other. A field added to a response
    struct without a corresponding schema entry, or a type widened in
    one place and not the other, passes the build.
  - that `schema_version` was bumped when a response shape changed.
    The version is a constant a human edits.

# 6. Schema version history

| Schema version | Daemon release that landed it | Change                                                                                                       |
|----------------|-------------------------------|--------------------------------------------------------------------------------------------------------------|
| 0.6.0          | up to 1.14.x                  | Baseline at gate close.                                                                                      |
| 0.7.0          | 1.15.0                        | Additive minor (firewall + firewall_lookup tools and their data shapes).                                     |
| 0.8.0          | 1.19.1                        | `WorkloadNginxApache.server` enum gains `none` (was 1.18.0); `recent_4xx` / `recent_5xx` loosened from `integer` to `oneOf integer or null` and two new required fields `recent_window_minutes` / `recent_coverage` added (was 1.19.0). The `0.7.0` → `0.8.0` bump was deferred from those releases and lands cumulatively here. |
| 1.0.0          | 2.0.0                         | **First major bump — breaking.** `security.ssh_logins` renamed `accepted_since_boot` / `failed_since_boot` to `accepted_recent` / `failed_recent` (both nullable) and added the required `window` discriminator (`last_24h` / `since_log_rotation` / `unavailable`). The journal source is now bounded to the last 24h instead of walking since boot. A field rename is major per REQ 7.3; a `0.x` plugin fails closed against a `2.0.0` daemon per cell C4. Roll daemon and plugin together. |
| 1.1.0          | 2.2.0                         | Additive minor. Tool 4.2 `systemd_units` gains `pattern_units[]`, the result of the new manifest `whitelisted_unit_patterns` glob selector; `units[]` keeps the exact selector's results, unchanged in shape and content. (Correction: 2.2.0 and 2.2.1 also re-sorted `units[]` alphabetically, where it had previously been returned in manifest order; 2.2.2 restored that ordering. No unit was added, dropped, or changed in shape.) The `manifest` response gains a matching `whitelisted_unit_patterns` array. No field renamed or removed, so a `1.0.0` plugin keeps working against a `2.2.0` daemon and simply does not see the new arrays (cell C2). |
| 1.2.0          | 2.3.0                         | Additive minor. `MailData.queue_depth`, and all four `DiskEntry` measurements, loosened from `integer` to `oneOf integer or null`; `ListeningSocket` gains a required `connected` boolean; null means the depth was not measured (failed `postqueue` op, or an MTA whose queue this tool does not read), where the field previously reported `0` for both. No field renamed or removed, so a `1.1.0` plugin keeps working per cell C2 — but one decoding `queue_depth` as a plain `int` will fault on null and must move to a nullable type. |

`2.3.0` is an additive minor at the wire level (`1.2.0`), but it
changes a great deal that a client can observe without any field being
renamed or removed. An earlier revision of this section listed two of
these and called the release schema-neutral; the full list follows.
None is a rename or a removal, so REQ 7.3 keeps all of it out of a
major bump and no compatibility cell changes.

Three response shapes changed:

  1. **`mail.queue_depth` is nullable.** It was a non-nullable integer
     that reported `0` both when the queue was empty and when the
     depth had not been measured at all — a failed `postqueue` op, or
     a host running any MTA other than Postfix. Null now means "not
     measured"; `0` means an empty queue. A client decoding it as a
     plain `int` must move to a nullable type. **This is the field to
     re-check before upgrading**, because the old value fed exactly
     the alert that is supposed to fire when mail stops flowing, and
     the failure direction was silent.

  1a. **`system.disk[]` measurements are nullable, and every mount is
     listed again.** Network and userspace-backed filesystems (NFS,
     CIFS, virtiofs, FUSE) were dropped from the array entirely because
     `statfs(2)` on a dead server blocks uninterruptibly; a capacity
     panel for such a volume went to no-data with nothing naming what
     had vanished. They are now measured under a deadline and listed
     either way, with `size_b` / `used_b` / `inodes_total` /
     `inodes_used` null when the probe did not answer. A client
     decoding those four as plain integers must move to nullable types.

  1b. **`sockets.listening[]` gains `connected`, and connected UDP
     sockets are returned again.** Filtering UDP to state 07 removed
     genuine servers that `connect()` back to a client — ordinary for
     TFTP, some DNS forwarders and QUIC. Both kinds are returned and
     labelled; filter on `connected` rather than expecting the daemon
     to choose. The field is required, so a strict decoder that rejects
     unknown keys is unaffected but one validating against the 1.1.0
     schema will see an extra property.

Eight further changes are visible in HTTP status codes or in error
envelopes, with no field affected:

  2. A request to a path outside `/v1/` returns the JSON error
     envelope instead of `net/http`'s plain-text 404.
  3. The five pre-dispatch rejection paths are rate-limited, so any
     of them can return `429` where it previously returned `404` or
     `405`.
  4. The listener sets `ReadTimeout` (10 s), `WriteTimeout` (30 s),
     `IdleTimeout` (10 s) and `MaxHeaderBytes` (16 KiB). A client that
     trickles a request body, or holds an idle keep-alive connection
     longer than ten seconds, now has the connection closed.
  5. A tool with invocations that have not returned is refused with
     HTTP `503` and message `tool has invocations that have not
     returned`, under the existing `tool_failed` code. Previously the
     caller waited out the full timeout and received `504`.
  6. Helper ops run under a deadline, so a call that previously hung
     for the life of the process now returns a `deadline` error.
  7. `nginx_apache_status` validates its parameter against an
     allow-list, so a value that was previously accepted can now
     return `bad_argument`.
  8. An over-cap helper reply reports `output_truncated` rather than
     presenting as a generic failure.
  9. `CAP_SYS_ADMIN` is no longer granted to every host with a
     `storage` entry — it is gated on the declared `storage_backends[]`.
     A host running ZFS or btrfs without declaring it produces empty
     results from `zpool_status` and in-progress `btrfs_scrub`. The
     helper now logs this at first use, but the response itself is
     indistinguishable from a host with no pools. **Check
     `storage_backends[]` before upgrading.**

A client that keys on `error.code` rather than on the HTTP status is
unaffected by items 2-8. Item 1 requires a decoder change; item 9
requires a configuration check.

A plugin compiled against `0.7.0` that decoded `recent_4xx` /
`recent_5xx` as a plain `int` may surface a parse error on an
`0.8.0` daemon reporting `recent_coverage = unavailable`. The
operational mitigation per cell C2 is to decode those fields as
`*int` (nullable) and treat null as "unknown". A plugin compiled
against `0.8.0` and an `0.7.0` daemon falls under cell C2 in the
other direction — the new fields the plugin expects are absent
from the daemon's response. Plugin authors should treat the new
fields as optional during the rollout window.

# 7. Notes for the plugin author

- The plugin's MCP tool schema should mirror the daemon's data
  shape per tool, with every field marked optional unless the
  field is genuinely required for the tool to be useful to the
  caller.
- Required fields in the plugin's tool schema must correspond to
  REQ section 4 fields marked required in the corresponding tool.
  Optional fields in REQ section 4 must remain optional in the
  plugin's tool schema.
- When adding a new tool to the daemon, the plugin's schema bump
  is minor-additive; existing operators may upgrade either side
  first.
- When removing or renaming a field, both sides must coordinate a
  major bump; the plugin's MCP manifest must declare the new
  supported daemon major before the daemon ships it.
