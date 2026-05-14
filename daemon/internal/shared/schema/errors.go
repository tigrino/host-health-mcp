package schema

// Error codes per doc/schema-draft.yaml. Stable across minor versions;
// adding a code is a minor bump, renaming is a major bump.
const (
	ErrCodeAuthRequired       = "auth_required"
	ErrCodeAuthFailed         = "auth_failed"
	ErrCodeUnknownTool        = "unknown_tool"
	ErrCodeToolDisabled       = "tool_disabled"
	ErrCodeBadArgument        = "bad_argument"
	ErrCodeRateLimited        = "rate_limited"
	ErrCodeToolTimeout        = "tool_timeout"
	ErrCodeToolFailed         = "tool_failed"
	ErrCodeSchemaIncompatible = "schema_incompatible"
	ErrCodeInternalError      = "internal_error"
)

// Message catalogue. Free-form interpolation of subsystem strings is
// forbidden; tool implementations choose one of these templates.
const (
	MsgAuthRequired       = "client certificate required"
	MsgAuthFailed         = "client certificate verification failed"
	MsgUnknownTool        = "no such tool"
	MsgToolDisabled       = "tool not enabled in manifest"
	MsgBadArgument        = "argument failed validation"
	MsgRateLimited        = "request rate limit exceeded"
	MsgToolTimeout        = "tool exceeded its timeout"
	MsgToolFailed         = "tool failed to assemble its response"
	MsgSchemaIncompatible = "schema version not supported"
	MsgInternalError      = "internal error"
)
