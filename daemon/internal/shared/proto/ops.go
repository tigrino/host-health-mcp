package proto

// Op tokens recognised by the helper. Both sides import this package and
// reference these constants; the closed compile-time enum (design §7.1)
// means the daemon cannot ask the helper to perform an operation that
// has not been compiled in.
const (
	OpReadAuditStatus  = "read_audit_status"
	OpReadAideSummary  = "read_aide_summary"
	OpReadRebootMarker = "read_reboot_marker"
	OpSmartSummary     = "smart_summary"
	OpMdraidDetail     = "mdraid_detail"
	OpLvmReport        = "lvm_report"
	OpZpoolStatus      = "zpool_status"
	OpBtrfsScrub       = "btrfs_scrub"
	OpPostqueue        = "postqueue"
	OpWireguardShow    = "wireguard_show"
	OpAptPending       = "apt_pending"
	OpNeedrestart      = "needrestart"
	OpJournalQuery     = "journal_query"
	OpNftTableCounts   = "nft_table_counts"
)

// AllOps lists every op token in a stable order. Used by the helper to
// validate manifest-derived configuration and by the daemon to detect
// missing helper support.
var AllOps = []string{
	OpReadAuditStatus,
	OpReadAideSummary,
	OpReadRebootMarker,
	OpSmartSummary,
	OpMdraidDetail,
	OpLvmReport,
	OpZpoolStatus,
	OpBtrfsScrub,
	OpPostqueue,
	OpWireguardShow,
	OpAptPending,
	OpNeedrestart,
	OpJournalQuery,
	OpNftTableCounts,
}

// IsKnownOp reports whether op is one of the recognised tokens.
func IsKnownOp(op string) bool {
	for _, k := range AllOps {
		if k == op {
			return true
		}
	}
	return false
}
