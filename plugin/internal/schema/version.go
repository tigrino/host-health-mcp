// Package schema carries the plugin's compile-time view of the
// daemon wire schema. version-matrix.md (cells C1-C4) defines what
// "compatible" means; the plugin compares its own SchemaVersion to
// the daemon's `schema_version` on first contact per session per host.
package schema

// SchemaVersion is the wire schema the plugin was compiled against.
// Kept in lockstep with daemon/internal/shared/schema.SchemaVersion at
// release time. A major-version mismatch is hard-incompatible (C4).
const SchemaVersion = "0.6.0"
