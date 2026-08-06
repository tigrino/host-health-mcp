// Package capsplan decides which Linux capabilities the root helper
// needs, given what a host has declared in manifest.yml.
//
// It is a separate package from the generator command for two reasons.
// It is pure — no filesystem, no environment, no output — so the rules
// that decide what a root process is allowed to do are testable
// directly rather than through a drop-in file. And the generator
// command is a linter chokepoint, permitted to write files; the rules
// live outside that exemption so nothing computing a capability set is
// exempt from anything.
//
// It takes plain string slices rather than a config.Manifest so that
// shared code does not depend on daemon-only packages. The caller does
// the adaptation, which is three field accesses.
package capsplan

import (
	"fmt"
)

// The capability rules below mirror design 7.3 (Caps required column).
// Each grant is justified where it is not obvious from the op name:
//
//	read_audit_status  -> CAP_AUDIT_CONTROL
//	                       (AUDIT_GET shares audit_netlink_ok()'s
//	                       CAP_AUDIT_CONTROL gate with the rule-
//	                       modification opcodes; CAP_AUDIT_READ only
//	                       gates audit_bind() for multicast event
//	                       consumption.)
//	read_aide_summary  -> CAP_DAC_READ_SEARCH
//	smart_summary      -> CAP_SYS_RAWIO, CAP_DAC_READ_SEARCH
//	mdraid_detail      -> CAP_DAC_READ_SEARCH
//	lvm_report         -> CAP_DAC_READ_SEARCH
//	zpool_status       -> CAP_SYS_ADMIN
//	btrfs_scrub        -> CAP_SYS_ADMIN for a RUNNING scrub only:
//	                       `btrfs scrub status` reads
//	                       /var/lib/btrfs/scrub.status.<uuid> for a
//	                       FINISHED scrub but issues
//	                       BTRFS_IOC_SCRUB_PROGRESS for one in
//	                       progress, and that ioctl is
//	                       capable(CAP_SYS_ADMIN)-gated in
//	                       fs/btrfs/ioctl.c.
//	wireguard_show     -> CAP_NET_ADMIN
//	firewall*          -> CAP_NET_ADMIN
//	                       (nft list ruleset reads kernel nftables
//	                       state via netlink NFNL_SUBSYS_NFTABLES;
//	                       unprivileged callers cannot enumerate
//	                       tables/chains/sets on stock kernels.)
//	nginx_apache_status -> CAP_DAC_READ_SEARCH
//	                       (Debian-default access logs are
//	                       www-data:adm 0640; a uid=0 helper without
//	                       DAC_READ_SEARCH matches neither owner nor
//	                       group.)
//	dovecot_status     -> none. systemctl is-active uses dbus, and
//	                       doveadm connects to a root-owned socket the
//	                       uid=0 helper passes on owner-mode alone.

const (
	capChown          = "CAP_CHOWN"
	capDACReadSearch  = "CAP_DAC_READ_SEARCH"
	capNetAdmin       = "CAP_NET_ADMIN"
	capSysRawIO       = "CAP_SYS_RAWIO"
	capSysAdmin       = "CAP_SYS_ADMIN"
	capAuditControl   = "CAP_AUDIT_CONTROL"
	backendSmart      = "smart"
	backendZFS        = "zfs"
	backendBtrfs      = "btrfs"
	toolStorage       = "storage"
	toolSecurity      = "security"
	toolWorkload      = "workload"
	toolFirewall      = "firewall"
	toolFirewallLkup  = "firewall_lookup"
	pluginWireGuard   = "wireguard"
	pluginNginxApache = "nginx_apache"
)

// defaultBackends is what storage_backends falls back to when the key
// is absent or empty. Never "all": defaulting an allow-list to
// everything is how CAP_SYS_ADMIN ended up on every storage host in
// the first place. An operator who has not declared ZFS does not get
// CAP_SYS_ADMIN.
var DefaultBackends = []string{"smart", "lvm", "mdraid"}

var knownBackends = map[string]bool{
	"smart": true, "lvm": true, "mdraid": true, "zfs": true, "btrfs": true,
}

// knownTools mirrors the compiled-in tool surface (REQ 4.1-4.17 plus
// firewall and firewall_lookup). A name outside it means a typo in
// manifest.yml or a generator older than the daemon beside it.
var knownTools = map[string]bool{
	"manifest": true, "system": true, "pressure": true, "kernel": true,
	"sockets": true, "updates": true, "storage": true, "systemd_units": true,
	"dns": true, "mail": true, "certs": true, "backup": true,
	"sensors": true, "network": true, "security": true, "firewall": true,
	"firewall_lookup": true, "logs": true, "workload": true,
}

// knownPlugins mirrors build/workload-tags. TestKnownPluginsMatchTags
// keeps the two in step; a plugin added there and forgotten here would
// silently lose its capability grant.
var KnownPlugins = map[string]bool{
	"postfix": true, "nginx_apache": true, "wireguard": true, "dovecot": true,
}

// plan is the decided output of reading a manifest: the two capability
// sets, the backend list actually used, and everything the operator
// should be told about how it was arrived at.
type Plan struct {
	Bounding []string
	Ambient  []string
	Backends []string
	// Notes are statements of fact about what was decided (a
	// defaulted backend list). Warnings are things the operator
	// probably got wrong. Both go to stderr; the split exists so an
	// unattended-upgrade report can be read for the second kind.
	Notes    []string
	Warnings []string
}

// set preserves insertion order. The drop-in is regenerated on every
// configure and compared by eye across hosts, so a capability list
// that reshuffles between runs on identical input is a diff nobody can
// use.
type set struct {
	seen  map[string]bool
	order []string
}

func newSet() *set { return &set{seen: map[string]bool{}} }

func (s *set) add(v string) {
	if s.seen[v] {
		return
	}
	s.seen[v] = true
	s.order = append(s.order, v)
}

func (s *set) list() []string { return s.order }

func Has(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// planFor computes the capability sets from a manifest. Pure: it reads
// no files, writes nothing, and returns every message it wants emitted
// so the whole rule set is testable without a filesystem.
func For(tools, plugins, backends []string) Plan {
	var p Plan

	if len(backends) == 0 {
		backends = DefaultBackends
		// Only worth saying on a host that actually enables storage;
		// elsewhere none of these capabilities are granted either way
		// and the line is noise in an unattended-upgrade report.
		if Has(tools, toolStorage) {
			p.Notes = append(p.Notes, fmt.Sprintf(
				"storage_backends absent; defaulting to %q (declare 'zfs' to grant CAP_SYS_ADMIN)",
				joinSpace(DefaultBackends)))
		}
	}
	p.Backends = backends

	for _, b := range backends {
		if !knownBackends[b] {
			p.Warnings = append(p.Warnings, fmt.Sprintf("storage_backends contains unknown name %q", b))
		}
	}
	for _, n := range tools {
		if !knownTools[n] {
			p.Warnings = append(p.Warnings, fmt.Sprintf("enabled_tools contains unknown name %q", n))
		}
	}
	for _, n := range plugins {
		if !KnownPlugins[n] {
			p.Warnings = append(p.Warnings, fmt.Sprintf("workload_plugins contains unknown name %q", n))
		}
	}

	tool := func(name string) bool { return Has(tools, name) }
	plugin := func(name string) bool { return Has(plugins, name) }
	backend := func(name string) bool { return Has(backends, name) }

	caps := newSet()
	// CAP_CHOWN is required regardless of which ops are enabled: the
	// helper chowns its unix socket and runtime directory at startup so
	// the daemon can connect. Always in the union, never in ambient.
	caps.add(capChown)

	if tool(toolSecurity) {
		caps.add(capAuditControl)
		caps.add(capDACReadSearch)
	}
	// storage is one tool over five backends whose capability needs
	// differ. Granting CAP_SYS_ADMIN and CAP_SYS_RAWIO to every storage
	// operator also put them in the AMBIENT set, inherited across
	// execve by smartctl, lvs, mdadm and btrfs — so a memory-corruption
	// bug in any of those parsers escalated from "root under a narrow
	// bounding set" to full CAP_SYS_ADMIN.
	if tool(toolStorage) {
		caps.add(capDACReadSearch)
		if backend(backendSmart) {
			caps.add(capSysRawIO)
		}
		if backend(backendZFS) {
			caps.add(capSysAdmin)
		}
		if backend(backendBtrfs) {
			caps.add(capSysAdmin)
		}
	}
	if tool(toolWorkload) {
		if plugin(pluginWireGuard) {
			caps.add(capNetAdmin)
		}
		if plugin(pluginNginxApache) {
			caps.add(capDACReadSearch)
		}
	}
	if tool(toolFirewall) {
		caps.add(capNetAdmin)
	}
	if tool(toolFirewallLkup) {
		caps.add(capNetAdmin)
	}

	p.Bounding = caps.list()

	// Ambient carries the per-op capabilities minus CAP_CHOWN, which
	// only the helper process itself uses. Modern tools introspect
	// their effective set rather than trusting euid==0 (auditctl checks
	// CAP_AUDIT_READ explicitly), and under NoNewPrivileges=yes an
	// empty ambient set means they observe zero capabilities even
	// though their parent is root.
	ambient := newSet()
	for _, c := range p.Bounding {
		if c == capChown {
			continue
		}
		ambient.add(c)
	}
	p.Ambient = ambient.list()

	return p
}

func joinSpace(v []string) string {
	out := ""
	for i, s := range v {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}

// EveryGrantableCapability returns every capability these rules can
// put into a bounding set, derived by running them over every name
// they recognise rather than listed separately. A grant added above
// therefore cannot fail to appear here, which is what lets the
// helper's RequiredCap table be checked against the generator instead
// of against a copy of it.
func EveryGrantableCapability() []string {
	return For(keys(knownTools), keys(KnownPlugins), keys(knownBackends)).Bounding
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
