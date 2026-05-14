package proto

// Helper-side error codes. The daemon maps these onto its own structured
// tool errors via internal/daemon/helperinvoke. See design §7.1.
const (
	CodeBadOp            = "bad_op"
	CodeBadParam         = "bad_param"
	CodeToolMissing      = "tool_missing"
	CodeToolFailed       = "tool_failed"
	CodeOutputTruncated  = "output_truncated"
	CodeDeadline         = "deadline"
	CodeInternal         = "internal"
)

// StatusOK and StatusErr are the two values Response.Status may take.
const (
	StatusOK  = "ok"
	StatusErr = "err"
)
