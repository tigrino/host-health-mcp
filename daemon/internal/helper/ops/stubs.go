package ops

import (
	"context"

	"tigr.net/host-health-mcp/daemon/internal/helper/dispatch"
	"tigr.net/host-health-mcp/daemon/internal/shared/proto"
)

// ReadAideSummary parses /var/lib/aide/aide.db's header. Stub: AIDE DB
// is a binary format that requires careful parsing; deferred to a
// follow-up.
func ReadAideSummary(ctx context.Context, _ string) (any, error) {
	return nil, &dispatch.Error{
		Code:    proto.CodeInternal,
		Message: "read_aide_summary not yet implemented",
	}
}

// ZpoolStatus invokes `zpool status -j`. Stub: deferred to a follow-up
// since ZFS may not be present in the canary environment.
func ZpoolStatus(ctx context.Context, _ string) (any, error) {
	return nil, &dispatch.Error{
		Code:    proto.CodeInternal,
		Message: "zpool_status not yet implemented",
	}
}

// BtrfsScrub invokes `btrfs scrub status -R <mountpoint>` after
// confirming the parameter passes the mountpoint whitelist regex AND
// statfs(2) reports f_type == BTRFS_SUPER_MAGIC. Stub: the statfs side
// is small but is deferred to keep the initial review-gate skeleton
// minimal.
func BtrfsScrub(ctx context.Context, _ string) (any, error) {
	return nil, &dispatch.Error{
		Code:    proto.CodeInternal,
		Message: "btrfs_scrub not yet implemented",
	}
}
