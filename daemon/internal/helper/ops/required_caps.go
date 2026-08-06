package ops

// RequiredCap maps an op token to the capability it needs, for the ops
// where absence produces silence rather than an error.
//
// This mirrors the rules in daemon/internal/shared/capsplan, which
// decide the grant. The two are separate by necessity — one runs at
// install time in the capability generator, one at runtime in the
// helper — so a test pins them together rather than a comment asking
// nicely. Since 2.4.0 that test imports the rules and asks them what
// they can grant, instead of scraping the shell script they replaced.
//
// Only ops whose failure mode is a QUIET wrong answer are listed. An op
// that returns a hard error without its capability does not need this;
// the operator finds out. zpool_status and btrfs_scrub are the ones
// that matter: without CAP_SYS_ADMIN they report nothing, and "nothing"
// is indistinguishable from "this host has no pools".
var RequiredCap = map[string]string{
	"zpool_status":      "CAP_SYS_ADMIN",
	"btrfs_scrub":       "CAP_SYS_ADMIN",
	"smart_summary":     "CAP_SYS_RAWIO",
	"read_audit_status": "CAP_AUDIT_CONTROL",
	"wireguard_show":    "CAP_NET_ADMIN",
	"firewall_inspect":  "CAP_NET_ADMIN",
	"firewall_lookup":   "CAP_NET_ADMIN",
}
