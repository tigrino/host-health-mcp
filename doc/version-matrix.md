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

# 5. Drift detection in CI

The build script (`build/build.sh`) computes a hash of the schema
file used by the daemon and the schema file used by the plugin. The
build fails if the two hashes differ unless both `.deb` artefacts
declare the same `schema_version`. This catches the "plugin and
daemon shipped with mismatched schema files" case at build time,
not at first call.

# 6. Schema version history

| Schema version | Daemon release that landed it | Change                                                                                                       |
|----------------|-------------------------------|--------------------------------------------------------------------------------------------------------------|
| 0.6.0          | up to 1.14.x                  | Baseline at gate close.                                                                                      |
| 0.7.0          | 1.15.0                        | Additive minor (firewall + firewall_lookup tools and their data shapes).                                     |
| 0.8.0          | 1.19.1                        | `WorkloadNginxApache.server` enum gains `none` (was 1.18.0); `recent_4xx` / `recent_5xx` loosened from `integer` to `oneOf integer or null` and two new required fields `recent_window_minutes` / `recent_coverage` added (was 1.19.0). The `0.7.0` → `0.8.0` bump was deferred from those releases and lands cumulatively here. |
| 1.0.0          | 2.0.0                         | **First major bump — breaking.** `security.ssh_logins` renamed `accepted_since_boot` / `failed_since_boot` to `accepted_recent` / `failed_recent` (both nullable) and added the required `window` discriminator (`last_24h` / `since_log_rotation` / `unavailable`). The journal source is now bounded to the last 24h instead of walking since boot. A field rename is major per REQ 7.3; a `0.x` plugin fails closed against a `2.0.0` daemon per cell C4. Roll daemon and plugin together. |

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
