// Package config parses /etc/host-health-mcp/{daemon,manifest}.yml. The
// YAML decoder is set to strict so unknown keys fail at startup (REQ
// 8.1) rather than silently degrading.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Daemon is the typed shape of /etc/host-health-mcp/daemon.yml.
type Daemon struct {
	BindAddr                string                 `yaml:"bind_addr"`
	TLSCertPath             string                 `yaml:"tls_cert_path"`
	TLSKeyPath              string                 `yaml:"tls_key_path"`
	ClientCAPath            string                 `yaml:"client_ca_path"`
	ManifestPath            string                 `yaml:"manifest_path"`
	LogRedactionRules       string                 `yaml:"log_redaction_rules"`
	CacheTTLOverrides       map[string]int         `yaml:"cache_ttl_overrides"`
	TimeoutOverrides        map[string]int         `yaml:"timeout_overrides"`
	DNSProbeTargets         map[string]string      `yaml:"dns_probe_targets"`
	SensitiveDirs           []string               `yaml:"sensitive_dirs"`
	IPv4AllowlistRanges     []string               `yaml:"ipv4_allowlist_ranges"`
	IPv6AllowlistRanges     []string               `yaml:"ipv6_allowlist_ranges"`
	PublicBindAcknowledged  bool                   `yaml:"public_bind_acknowledged"`
	ExpensiveToolBuckets    map[string]BucketLimit `yaml:"expensive_tool_buckets"`
	MaxConcurrentHandshakes int                    `yaml:"max_concurrent_handshakes"`
	HelperSocketPath        string                 `yaml:"helper_socket_path"`
	// IPFilterAllow is consumed at install time by
	// host-health-mcp-caps-template, not by the daemon: it becomes the
	// IPAddressAllow= lines of a systemd drop-in, and the kernel does
	// the enforcing. It is declared here so the strict decoder accepts
	// the key and so garbage fails at startup rather than at the next
	// systemctl restart, when an invalid drop-in would stop the unit
	// from starting at all.
	//
	// systemd's IPAddressAllow=/IPAddressDeny= filter packets in BOTH
	// directions. The list must therefore name every network that has
	// to reach the listener as well as every egress destination, or
	// the daemon becomes unreachable. Empty means no drop-in is
	// generated and no IP filtering is applied.
	IPFilterAllow []string `yaml:"ip_filter_allow"`
}

// BucketLimit configures a token bucket per REQ 6.6. Enabled is a
// pointer so we can distinguish "absent" (default: enabled) from
// "explicitly false" (operator opt-out); without the pointer, a
// zero-value (0,0) bucket would conflict with the M-9 fail-closed
// load-time check.
type BucketLimit struct {
	SustainedPerMin int   `yaml:"sustained_per_min"`
	Burst           int   `yaml:"burst"`
	Enabled         *bool `yaml:"enabled,omitempty"`
}

// Manifest is the typed shape of /etc/host-health-mcp/manifest.yml.
type Manifest struct {
	EnabledTools     []string `yaml:"enabled_tools"`
	WhitelistedUnits []string `yaml:"whitelisted_units"`
	// WhitelistedUnitPatterns is the glob half of the tool 4.2
	// selector. Kept separate from WhitelistedUnits rather than
	// inferred from an entry's content because the two resolve
	// through different D-Bus calls with materially different
	// semantics — see ValidateUnitSelectors — so which one an
	// operator meant should be stated, not guessed. (An earlier
	// comment justified this by claiming a raw metacharacter is legal
	// in a unit name; it is not, systemd escapes them.)
	WhitelistedUnitPatterns []string `yaml:"whitelisted_unit_patterns"`

	// StorageBackends declares which storage backends this host runs.
	// Consumed by the install-time capability generator, not by the
	// daemon: it gates CAP_SYS_RAWIO (smart) and CAP_SYS_ADMIN (zfs)
	// individually instead of granting both to every storage operator.
	// Declared here so the strict decoder accepts the key.
	StorageBackends      []string                     `yaml:"storage_backends"`
	WorkloadPlugins      []string                     `yaml:"workload_plugins"`
	WorkloadPluginConfig map[string]map[string]string `yaml:"workload_plugin_config"`
	CertPaths            []string                     `yaml:"cert_paths"`
	CertRenewalUnits     []string                     `yaml:"cert_renewal_units"`
	BackupLogPath        string                       `yaml:"backup_log_path"`
	BackupBackend        string                       `yaml:"backup_backend"`
	BackupStatePath      string                       `yaml:"backup_state_path"`
	DebsumsLogPath       string                       `yaml:"debsums_log_path"`
	AideLogPath          string                       `yaml:"aide_log_path"`
	IPv6Policy           string                       `yaml:"ipv6_policy"`
	BtrfsMountpoints     []string                     `yaml:"btrfs_mountpoints"`
	Firewall             Firewall                     `yaml:"firewall"`
}

// Firewall is the manifest's host_firewall block. Empty (zero-value)
// means the tool returns an empty payload with a "firewall: disabled
// in manifest" warning. The two byte caps default to 2000 elements
// per set and 65536 bytes of rule text per chain to keep the helper
// reply comfortably under proto.MaxResponseFrame regardless of the
// host's ruleset size.
type Firewall struct {
	Enabled              bool             `yaml:"enabled"`
	BanSets              []FirewallBanSet `yaml:"ban_sets"`
	DetailModeAllowed    bool             `yaml:"detail_mode_allowed"`
	MaxSetElementsPerSet int              `yaml:"max_set_elements_per_set"`
	MaxRuleTextBytes     int              `yaml:"max_rule_text_bytes"`
}

// FirewallBanSet names one nftables set that carries the live ban
// list of a particular ban source. The daemon synthesizes
// data.bans.by_set from these entries by matching against the sets
// nft reports back.
type FirewallBanSet struct {
	Family string `yaml:"family"`
	Table  string `yaml:"table"`
	Name   string `yaml:"name"`
	Source string `yaml:"source"`
}

// LoadDaemon reads daemon.yml.
func LoadDaemon(path string) (Daemon, error) {
	cfg := defaultDaemon()
	if err := decodeYAMLStrict(path, &cfg); err != nil {
		return cfg, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// LoadManifest reads manifest.yml. Validation is part of the loader's
// contract, matching LoadDaemon, so no caller can obtain an unvalidated
// Manifest.
func LoadManifest(path string) (Manifest, error) {
	cfg := Manifest{}
	if err := decodeYAMLStrict(path, &cfg); err != nil {
		return cfg, err
	}
	if err := cfg.ValidateUnitSelectors(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// knownWorkloadPluginKeys enumerates the per-plugin config keys
// recognised by each compile-time workload plugin. Plugins absent
// from this map accept no keys today; an entry with an empty map
// means the plugin is known but accepts no keys. Used by
// CheckWorkloadPluginConfig to surface operator typos at startup
// without making them fatal (a strict yaml decode would not catch
// these because the outer schema is map[string]map[string]string).
var knownWorkloadPluginKeys = map[string]map[string]bool{
	"nginx_apache": {
		"access_log_path":           true,
		"access_log_window_minutes": true,
		"access_log_tail_bytes":     true,
	},
	"wireguard": {},
	"postfix":   {},
	"dovecot":   {},
}

// CheckWorkloadPluginConfig returns one warning per unrecognised key
// in WorkloadPluginConfig. Plugin names not listed in the known
// table are silently allowed (a plugin may be compiled in but not
// yet have a key registered here); only known plugins' key sets are
// enforced. The caller logs the returned warnings — the function
// itself has no side effects.
func (m Manifest) CheckWorkloadPluginConfig() []string {
	var warnings []string
	for plugin, kv := range m.WorkloadPluginConfig {
		allowed, known := knownWorkloadPluginKeys[plugin]
		if !known {
			continue
		}
		for k := range kv {
			if !allowed[k] {
				warnings = append(warnings, fmt.Sprintf("manifest: workload_plugin_config.%s: unknown key %q — ignored", plugin, k))
			}
		}
	}
	return warnings
}

// unitGlobMetachars are the fnmatch metacharacters systemd honours in
// a unit pattern.
const unitGlobMetachars = "*?["

// ValidateToolNames cross-checks every config key that names a tool
// against the set actually registered. Validate() cannot do this — it
// has no registry — so main calls this once the registry is built.
//
// A typo here used to be silent: `log:` for `logs:` dropped that tool
// to the global bucket with no diagnostic, while the same typo in
// enabled_tools is fatal and workload_plugin_config at least warns.
// Three neighbouring keys, three different behaviours, and the quiet
// one is the one that removes a rate limit.
func (d Daemon) ValidateToolNames(registered map[string]bool) error {
	var unknown []string
	for tool := range d.ExpensiveToolBuckets {
		if !registered[tool] {
			unknown = append(unknown, "expensive_tool_buckets."+tool)
		}
	}
	for tool := range d.TimeoutOverrides {
		if !registered[tool] {
			unknown = append(unknown, "timeout_overrides."+tool)
		}
	}
	for tool := range d.CacheTTLOverrides {
		if !registered[tool] {
			unknown = append(unknown, "cache_ttl_overrides."+tool)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("config: %s names no registered tool", strings.Join(unknown, ", "))
}

// ValidateUnitSelectors checks the tool 4.2 selector lists. Exact names
// carrying a metacharacter are rejected outright: passed to
// ListUnitsByNames they would match nothing and come back as a
// synthesised not-found row, which reads as "the unit is missing"
// rather than "you put a pattern in the wrong key".
func (m Manifest) ValidateUnitSelectors() error {
	for i, u := range m.WhitelistedUnits {
		if strings.TrimSpace(u) == "" {
			return fmt.Errorf("config: whitelisted_units[%d] is empty", i)
		}
		if strings.ContainsAny(u, unitGlobMetachars) {
			return fmt.Errorf("config: whitelisted_units[%d] %q contains a glob metacharacter; put patterns in whitelisted_unit_patterns", i, u)
		}
	}
	for i, p := range m.WhitelistedUnitPatterns {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("config: whitelisted_unit_patterns[%d] is empty", i)
		}
		if strings.Trim(p, unitGlobMetachars+"]") == "" {
			return fmt.Errorf("config: whitelisted_unit_patterns[%d] %q consists only of glob metacharacters; name something", i, p)
		}
	}
	return nil
}

func defaultDaemon() Daemon {
	return Daemon{
		ManifestPath:            "/etc/host-health-mcp/manifest.yml",
		MaxConcurrentHandshakes: 16,
		HelperSocketPath:        "/run/host-health-mcp/helper.sock",
	}
}

func decodeYAMLStrict(path string, into any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("config: %s: not present", path)
		}
		return fmt.Errorf("config: read %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("config: parse %s: %w", path, err)
	}
	return nil
}

// Validate runs after Load. Catches the small set of cross-field
// constraints that yaml.v3 cannot express on its own.
func (d Daemon) Validate() error {
	if d.BindAddr == "" {
		return errors.New("config: bind_addr is required")
	}
	if d.TLSCertPath == "" || d.TLSKeyPath == "" || d.ClientCAPath == "" {
		return errors.New("config: tls_cert_path, tls_key_path, client_ca_path are all required")
	}
	// An explicit 0 or a negative value left the listener UNCAPPED,
	// with no warning and no validation — the same fail-open class
	// already closed for the rate-limit buckets below, where an opt-out
	// must be spelled `enabled: false`. The cap is what bounds
	// concurrent TLS handshakes, so silently removing it is not a
	// setting anyone should reach by typing a zero.
	if d.MaxConcurrentHandshakes <= 0 {
		return fmt.Errorf("config: max_concurrent_handshakes must be positive, got %d; "+
			"there is no uncapped mode", d.MaxConcurrentHandshakes)
	}
	for tool, b := range d.ExpensiveToolBuckets {
		// REQ 6.6: an expensive_tool_bucket with sustained_per_min=0 AND
		// burst=0 silently disabled the per-tool limit pre-1.17. The
		// daemon now requires an explicit `enabled: false` for opt-out.
		disabled := b.Enabled != nil && !*b.Enabled
		if disabled {
			continue
		}
		if b.SustainedPerMin == 0 && b.Burst == 0 {
			return fmt.Errorf("config: rate limit for tool %q has sustained_per_min=0 and burst=0; set enabled: false to disable bucketing explicitly, or set positive values", tool)
		}
		// Each of these passed validation and produced a permanently
		// broken tool with no signal at startup. burst=0 means the
		// bucket can never hold a token, so the first call and every
		// call after it is refused; sustained=0 means it never refills,
		// so the tool works exactly burst times and is dead thereafter.
		if b.Burst <= 0 {
			return fmt.Errorf("config: rate limit for tool %q has burst=%d; the tool would refuse every call. Set a positive burst or enabled: false", tool, b.Burst)
		}
		if b.SustainedPerMin <= 0 {
			return fmt.Errorf("config: rate limit for tool %q has sustained_per_min=%d; the bucket never refills and the tool dies after %d calls. Set a positive rate or enabled: false", tool, b.SustainedPerMin, b.Burst)
		}
	}
	for i, r := range d.IPv4AllowlistRanges {
		if _, err := netip.ParsePrefix(r); err != nil {
			return fmt.Errorf("config: ipv4_allowlist_ranges[%d] %q: %w", i, r, err)
		}
	}
	for i, r := range d.IPv6AllowlistRanges {
		if _, err := netip.ParsePrefix(r); err != nil {
			return fmt.Errorf("config: ipv6_allowlist_ranges[%d] %q: %w", i, r, err)
		}
	}
	for i, e := range d.IPFilterAllow {
		if !validIPFilterEntry(e) {
			return fmt.Errorf("config: ip_filter_allow[%d] %q: want a CIDR, a bare address, or one of any/localhost/link-local/multicast", i, e)
		}
	}
	return nil
}

// systemdIPFilterKeywords are the symbolic names systemd accepts in an
// IPAddressAllow= line alongside literal addresses and prefixes.
var systemdIPFilterKeywords = map[string]bool{
	"any":        true,
	"localhost":  true,
	"link-local": true,
	"multicast":  true,
}

func validIPFilterEntry(e string) bool {
	if systemdIPFilterKeywords[e] {
		return true
	}
	if _, err := netip.ParsePrefix(e); err == nil {
		return true
	}
	_, err := netip.ParseAddr(e)
	return err == nil
}

// CacheTTL returns the configured TTL for a tool, or fallback if no
// override exists. Tools call this once per request.
func (d Daemon) CacheTTL(tool string, fallback time.Duration) time.Duration {
	if v, ok := d.CacheTTLOverrides[tool]; ok && v > 0 {
		return time.Duration(v) * time.Second
	}
	return fallback
}

// Timeout returns the configured per-tool timeout, or fallback. Capped
// at 10 s per REQ 5.1.
func (d Daemon) Timeout(tool string, fallback time.Duration) time.Duration {
	t := fallback
	if v, ok := d.TimeoutOverrides[tool]; ok && v > 0 {
		t = time.Duration(v) * time.Second
	}
	if t > 10*time.Second {
		t = 10 * time.Second
	}
	return t
}

// BindAddrIsPublic returns true when bind_addr looks publicly routable.
// A best-effort heuristic for the startup warning required by REQ 6.4;
// loopback and private/link-local ranges return false.
func (d Daemon) BindAddrIsPublic() bool {
	host, _, err := net.SplitHostPort(d.BindAddr)
	if err != nil {
		host = d.BindAddr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsPrivate() {
		return false
	}
	return true
}
