package ops

import (
	"context"

	"tigr.net/host-health-mcp/daemon/internal/helper/dispatch"
	"tigr.net/host-health-mcp/daemon/internal/shared/proto"
)

// AuditStatus is the typed result for op read_audit_status.
type AuditStatus struct {
	QueueDepth  int    `json:"queue_depth"`
	LostEvents  int    `json:"lost_events"`
	LastRotation string `json:"last_rotation,omitempty"`
}

// ReadAuditStatus queries the audit subsystem via NETLINK_AUDIT and
// returns queue depth + lost-event counters. Requires CAP_AUDIT_READ
// on the helper unit (templated in at install time from manifest.yml).
//
// Stub: returns a not-implemented error until the netlink dialog is
// written. Cleanest implementation is via golang.org/x/sys/unix with
// the AUDIT_GET netlink request type; deferred to a follow-up.
func ReadAuditStatus(ctx context.Context, _ string) (any, error) {
	return nil, &dispatch.Error{
		Code:    proto.CodeInternal,
		Message: "read_audit_status not yet implemented",
	}
}
