// Package caps lets the helper see its own effective capability set.
//
// It exists to turn a silent degradation into a visible one. The
// capability drop-in is generated at install time from manifest.yml,
// and from 2.3.0 the dangerous capabilities are gated per storage
// backend. A host that runs ZFS or btrfs but does not declare it in
// storage_backends gets a helper without CAP_SYS_ADMIN, and the only
// symptom is that zpool_status and in-progress btrfs_scrub report
// nothing. Nothing errors. Nothing logs. The tool simply stops
// answering, which is the failure mode an operator is least likely to
// notice.
//
// Reading rather than asserting: the helper does not know which
// backends the operator declared (that is daemon-side config), so it
// cannot check at startup whether the grant matches the intent. What
// it can do is notice, at the moment an op needs a capability, that it
// does not have it, and say so once.
package caps

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Capability bit positions from <linux/capability.h>. Only the ones
// this project's ops can require are listed; an unknown name is a
// programming error, not a runtime condition.
var bits = map[string]uint{
	"CAP_CHOWN":           0,
	"CAP_DAC_READ_SEARCH": 2,
	"CAP_NET_ADMIN":       12,
	"CAP_SYS_RAWIO":       17,
	"CAP_SYS_ADMIN":       21,
	"CAP_AUDIT_CONTROL":   30,
	"CAP_AUDIT_READ":      37,
}

// statusPath is /proc/self/status; a var so tests can point at a
// fixture rather than requiring a particular ambient capability set.
var statusPath = "/proc/self/status"

// Set is a parsed effective-capability mask.
type Set struct {
	mask uint64
	// read reports whether the mask came from a successful read. When
	// false, Has answers true for everything: an unreadable
	// /proc/self/status must not be reported as "capability missing",
	// which would produce a false warning on every host it runs on.
	read bool
}

// Effective reads the calling process's effective capability set.
// A read failure is not an error the caller must handle — the
// returned Set fails open, which is correct for a diagnostic.
func Effective() Set {
	f, err := os.Open(statusPath)
	if err != nil {
		return Set{}
	}
	defer f.Close()
	return ParseStatus(f)
}

// ParseStatus reads a /proc/<pid>/status stream and returns its CapEff
// mask. Split out from Effective so callers that already hold the
// contents — and tests, which cannot choose their own ambient
// capabilities — do not have to go through the filesystem. A stream
// without a parseable CapEff line yields the fail-open zero Set.
func ParseStatus(r io.Reader) Set {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		v, ok := strings.CutPrefix(sc.Text(), "CapEff:")
		if !ok {
			continue
		}
		m, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
		if err != nil {
			return Set{}
		}
		return Set{mask: m, read: true}
	}
	return Set{}
}

// Has reports whether the named capability is in the effective set.
// Unknown names and unread masks answer true, so a caller using this
// to decide whether to warn does not warn on its own ignorance.
func (s Set) Has(name string) bool {
	if !s.read {
		return true
	}
	b, ok := bits[name]
	if !ok {
		return true
	}
	return s.mask&(1<<b) != 0
}

// Known reports whether Has can answer meaningfully for name.
func Known(name string) bool {
	_, ok := bits[name]
	return ok
}

// String renders the set as a sorted, human-readable list for the
// startup log line. Capabilities outside the table above are reported
// as their bit number so the line is never silently incomplete.
func (s Set) String() string {
	if !s.read {
		return "<unreadable>"
	}
	byBit := map[uint]string{}
	for n, b := range bits {
		byBit[b] = n
	}
	var out []string
	for b := uint(0); b < 64; b++ {
		if s.mask&(1<<b) == 0 {
			continue
		}
		if n, ok := byBit[b]; ok {
			out = append(out, n)
		} else {
			out = append(out, fmt.Sprintf("cap_%d", b))
		}
	}
	if len(out) == 0 {
		return "<none>"
	}
	return strings.Join(out, " ")
}
