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
	"time"

	"gopkg.in/yaml.v3"
)

// Daemon is the typed shape of /etc/host-health-mcp/daemon.yml.
type Daemon struct {
	BindAddr                 string                   `yaml:"bind_addr"`
	TLSCertPath              string                   `yaml:"tls_cert_path"`
	TLSKeyPath               string                   `yaml:"tls_key_path"`
	ClientCAPath             string                   `yaml:"client_ca_path"`
	ManifestPath             string                   `yaml:"manifest_path"`
	LogRedactionRules        string                   `yaml:"log_redaction_rules"`
	CacheTTLOverrides        map[string]int           `yaml:"cache_ttl_overrides"`
	TimeoutOverrides         map[string]int           `yaml:"timeout_overrides"`
	DNSProbeTargets          map[string]string        `yaml:"dns_probe_targets"`
	SensitiveDirs            []string                 `yaml:"sensitive_dirs"`
	IPv4AllowlistRanges      []string                 `yaml:"ipv4_allowlist_ranges"`
	IPv6AllowlistRanges      []string                 `yaml:"ipv6_allowlist_ranges"`
	PublicBindAcknowledged   bool                     `yaml:"public_bind_acknowledged"`
	ExpensiveToolBuckets     map[string]BucketLimit   `yaml:"expensive_tool_buckets"`
	MaxConcurrentHandshakes  int                      `yaml:"max_concurrent_handshakes"`
	HelperSocketPath         string                   `yaml:"helper_socket_path"`
}

// BucketLimit configures a token bucket per REQ 6.6.
type BucketLimit struct {
	SustainedPerMin int `yaml:"sustained_per_min"`
	Burst           int `yaml:"burst"`
}

// Manifest is the typed shape of /etc/host-health-mcp/manifest.yml.
type Manifest struct {
	EnabledTools           []string `yaml:"enabled_tools"`
	WhitelistedUnits       []string `yaml:"whitelisted_units"`
	WorkloadPlugins        []string `yaml:"workload_plugins"`
	CertPaths              []string `yaml:"cert_paths"`
	CertRenewalUnits       []string `yaml:"cert_renewal_units"`
	BackupLogPath          string   `yaml:"backup_log_path"`
	BackupBackend          string   `yaml:"backup_backend"`
	BackupStatePath        string   `yaml:"backup_state_path"`
	DebsumsLogPath         string   `yaml:"debsums_log_path"`
	AideLogPath            string   `yaml:"aide_log_path"`
	IPv6Policy             string   `yaml:"ipv6_policy"`
	BtrfsMountpoints       []string `yaml:"btrfs_mountpoints"`
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

// LoadManifest reads manifest.yml.
func LoadManifest(path string) (Manifest, error) {
	cfg := Manifest{}
	if err := decodeYAMLStrict(path, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
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
	return nil
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
