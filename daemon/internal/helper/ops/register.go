// Package ops contains the helper's per-op handlers. RegisterAll is the
// compile-time entry that populates a dispatch.Registry. Adding a new
// op means: write the handler in this package, then register it here.
// There is no runtime registration path.
package ops

import (
	"tigr.net/host-health-mcp/daemon/internal/helper/dispatch"
	"tigr.net/host-health-mcp/daemon/internal/shared/proto"
)

// RegisterAll registers every op the helper knows how to perform.
// Ops left out of this call are not available even if the
// corresponding token is in proto.AllOps.
func RegisterAll(r *dispatch.Registry) {
	r.Register(proto.OpReadAuditStatus, ReadAuditStatus)
	r.Register(proto.OpReadAideSummary, ReadAideSummary)
	r.Register(proto.OpReadRebootMarker, ReadRebootMarker)
	r.Register(proto.OpSmartSummary, SmartSummaryHandler)
	r.Register(proto.OpMdraidDetail, MdraidDetail)
	r.Register(proto.OpLvmReport, LvmReport)
	r.Register(proto.OpZpoolStatus, ZpoolStatus)
	r.Register(proto.OpBtrfsScrub, BtrfsScrub)
	r.Register(proto.OpPostqueue, Postqueue)
	r.Register(proto.OpWireguardShow, WireguardShow)
	r.Register(proto.OpAptPending, AptPending)
	r.Register(proto.OpNeedrestart, Needrestart)
	r.Register(proto.OpJournalQuery, JournalQuery)
}
