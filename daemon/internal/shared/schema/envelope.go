// Package schema defines the wire types the daemon emits to MCP plugins
// over its HTTP/JSON listener. The shapes here match doc/schema-draft.yaml.
package schema

import (
	"encoding/json"
	"time"
	"unicode/utf8"
)

// SchemaVersion is the semver baked into the daemon at build. Bumped per
// REQ 7.3: minor on field-additive, major on field-removal or rename.
// 1.0.0 is the first major bump: security.ssh_logins renamed its two
// count fields (accepted_since_boot/failed_since_boot ->
// accepted_recent/failed_recent) and added the window discriminator.
const SchemaVersion = "1.2.0"

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
// this package; Message is bounded to MaxMessageLen and is normally
// drawn from the fixed catalogue in errors.go.
//
// "Normally" is doing work there. Several tools build a message from a
// decoder error so the caller learns which field was rejected, and the
// strict decoder embeds the offending field name — up to a full
// request body of caller-supplied bytes echoed back. That is
// self-reflection rather than disclosure, but the stated bound was
// simply not enforced. Route any constructed message through
// BoundMessage.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// MaxMessageLen is the cap the Error.Message contract states. Chosen
// to fit the catalogue strings plus a short constructed suffix.
const MaxMessageLen = 200

// BoundMessage truncates m to MaxMessageLen, marking it when it cuts
// so a reader can tell a short message from a clipped one. Truncation
// is on a rune boundary: a message can contain caller-supplied bytes,
// and slicing mid-rune would emit invalid UTF-8 in a JSON string.
func BoundMessage(m string) string {
	if len(m) <= MaxMessageLen {
		return m
	}
	const ellipsis = "…"
	cut := MaxMessageLen - len(ellipsis)
	for cut > 0 && !utf8.RuneStart(m[cut]) {
		cut--
	}
	return m[:cut] + ellipsis
}
