package ops

import (
	"bufio"
	"bytes"
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"host-health-mcp/daemon/internal/helper/dispatch"
	helperexec "host-health-mcp/daemon/internal/helper/exec"
	"host-health-mcp/daemon/internal/shared/proto"
)

// btrfsMountPathRE matches a tight subset of POSIX paths. The helper
// also verifies via statfs(2) that the target is actually a btrfs
// filesystem before invoking btrfs(8) (design §7.3, post-design
// elaboration: statfs(2) f_type == BTRFS_SUPER_MAGIC).
var btrfsMountPathRE = regexp.MustCompile(`^(/[A-Za-z0-9_-]+)+$`)

// BtrfsSuperMagic is the f_type for btrfs (uapi/linux/magic.h:
// 0x9123683E).
const BtrfsSuperMagic = 0x9123683E

// BtrfsScrubResult is the typed result for op btrfs_scrub.
type BtrfsScrubResult struct {
	Mountpoint       string     `json:"mountpoint"`
	LastScrubTS      *time.Time `json:"last_scrub_ts"`
	LastScrubStatus  *string    `json:"last_scrub_status"`
	ErrorsCount      int        `json:"errors_count"`
}

// BtrfsScrub invokes `btrfs scrub status -R <mountpoint>` and parses
// the key=value output. Refuses to run if statfs(2) on the parameter
// reports anything other than BTRFS_SUPER_MAGIC; this is independent
// validation that does not rely on the operator's mountpoint list.
func BtrfsScrub(ctx context.Context, param string) (any, error) {
	if !btrfsMountPathRE.MatchString(param) {
		return nil, &dispatch.Error{
			Code:    proto.CodeBadParam,
			Message: "mountpoint failed whitelist",
		}
	}
	// TOCTOU between statfs and exec is acknowledged; local-root attacker is out of scope per threat model.
	var st unix.Statfs_t
	if err := unix.Statfs(param, &st); err != nil {
		return nil, &dispatch.Error{
			Code:    proto.CodeBadParam,
			Message: "statfs failed: " + err.Error(),
		}
	}
	if st.Type != BtrfsSuperMagic {
		return nil, &dispatch.Error{
			Code:    proto.CodeBadParam,
			Message: "path is not a btrfs filesystem",
		}
	}

	stdout, err := helperexec.Run(ctx, "btrfs", "scrub", "status", "-R", param)
	if err != nil {
		return nil, err
	}

	out := BtrfsScrubResult{Mountpoint: param}
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "scrub started at"):
			// "scrub started at Mon Jan 2 15:04:05 2006, running for ..."
			rest := strings.TrimSpace(strings.TrimPrefix(line, "scrub started at"))
			// Some btrfs versions emit "scrub started at <ts>, ..."
			// others "scrub started at <ts>". Split on comma first.
			tsStr := rest
			if i := strings.Index(rest, ","); i >= 0 {
				tsStr = rest[:i]
			}
			if ts, err := time.Parse("Mon Jan _2 15:04:05 2006", tsStr); err == nil {
				ts = ts.UTC()
				out.LastScrubTS = &ts
			}
		case strings.HasPrefix(line, "status:"):
			s := strings.TrimSpace(strings.TrimPrefix(line, "status:"))
			out.LastScrubStatus = &s
		case strings.HasPrefix(line, "error_count:"):
			if v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "error_count:"))); err == nil {
				out.ErrorsCount = v
			}
		case strings.HasPrefix(line, "scrub_errors:"):
			if v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "scrub_errors:"))); err == nil {
				out.ErrorsCount = v
			}
		}
	}
	return out, nil
}
