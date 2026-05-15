package schema

// HelperOpError is the structured per-source error block for a tool
// whose data source was a failed helper-op invocation. Returned in
// the tool's response data alongside (or in place of) the section's
// normal fields.
//
// The shape mirrors the per-device `storage.smart[].error` block
// that 1.7.0 introduced, generalised so every tool with a helper
// dependency can report failures in a structured field instead of
// stuffing argv/exit/stderr_prefix into the envelope's `warnings[]`
// strings. The warning strings now carry the section + op name plus
// a code; the structured fields carry the actionable diagnostics.
//
// Schema additive in 0.4.0 (version-matrix C2 forward-compatible
// with 0.3.0 clients).
type HelperOpError struct {
	// Op names the helper op that failed (e.g. "read_aide_summary").
	// Populated when the error appears in a tool-level errors[]
	// array; left empty when the error is the `error` field on a
	// per-source element whose op is implied by the surrounding
	// context (e.g. `storage.smart[N].error`).
	Op           string   `json:"op,omitempty"`
	Code         string   `json:"code"`
	Message      string   `json:"message"`
	Argv         []string `json:"argv,omitempty"`
	ExitCode     *int     `json:"exit_code,omitempty"`
	StderrSHA256 string   `json:"stderr_sha256,omitempty"`
	StderrPrefix string   `json:"stderr_prefix,omitempty"`
}
