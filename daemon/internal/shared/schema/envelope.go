// Package schema defines the wire types the daemon emits to MCP plugins
// over its HTTP/JSON listener. The shapes here match doc/schema-draft.yaml.
package schema

import (
	"encoding/json"
	"time"
)

// SchemaVersion is the semver baked into the daemon at build. Bumped per
// REQ 7.3: minor on field-additive, major on field-removal or rename.
const SchemaVersion = "0.2.0"

// Envelope is the response shape for a successful tool call.
type Envelope struct {
	Host          string          `json:"host"`
	AsOf          time.Time       `json:"as_of"`
	CacheAgeS     int             `json:"cache_age_s"`
	SchemaVersion string          `json:"schema_version"`
	Data          json.RawMessage `json:"data"`
	Warnings      []string        `json:"warnings,omitempty"`
}

// ErrorEnvelope is the response shape for any non-2xx response. Both the
// HTTP status code and the body's Error.Code carry the failure reason;
// the body is the canonical source.
type ErrorEnvelope struct {
	Host          string    `json:"host"`
	AsOf          time.Time `json:"as_of"`
	SchemaVersion string    `json:"schema_version"`
	Error         Error     `json:"error"`
}

// Error is the structured error body. Code is one of the constants in
// this package; Message is bounded to 200 chars and drawn from a fixed
// catalogue compiled into the daemon.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
