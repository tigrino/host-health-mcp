// Command daemon is the network-facing side of host-health-mcp. It
// listens on an mTLS HTTPS endpoint, dispatches /v1/<tool> calls to
// registered tools, talks to the helper service over a unix socket
// for privileged reads, and emits one audit entry per call to
// journald (REQ 6.5).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"

	"net/netip"

	"host-health-mcp/daemon/internal/daemon/audit"
	"host-health-mcp/daemon/internal/daemon/cache"
	"host-health-mcp/daemon/internal/daemon/config"
	"host-health-mcp/daemon/internal/daemon/helperinvoke"
	"host-health-mcp/daemon/internal/daemon/httpserver"
	"host-health-mcp/daemon/internal/daemon/ratelimit"
	"host-health-mcp/daemon/internal/daemon/redact"
	"host-health-mcp/daemon/internal/daemon/tools"
	"host-health-mcp/daemon/internal/daemon/tools/backup"
	"host-health-mcp/daemon/internal/daemon/tools/certs"
	"host-health-mcp/daemon/internal/daemon/tools/dns"
	"host-health-mcp/daemon/internal/daemon/tools/firewall"
	firewall_lookup "host-health-mcp/daemon/internal/daemon/tools/firewall_lookup"
	"host-health-mcp/daemon/internal/daemon/tools/kernel"
	"host-health-mcp/daemon/internal/daemon/tools/logs"
	"host-health-mcp/daemon/internal/daemon/tools/mail"
	"host-health-mcp/daemon/internal/daemon/tools/manifest"
	"host-health-mcp/daemon/internal/daemon/tools/network"
	"host-health-mcp/daemon/internal/daemon/tools/pressure"
	"host-health-mcp/daemon/internal/daemon/tools/security"
	"host-health-mcp/daemon/internal/daemon/tools/sensors"
	"host-health-mcp/daemon/internal/daemon/tools/sockets"
	"host-health-mcp/daemon/internal/daemon/tools/storage"
	"host-health-mcp/daemon/internal/daemon/tools/system"
	systemdunits "host-health-mcp/daemon/internal/daemon/tools/systemd_units"
	"host-health-mcp/daemon/internal/daemon/tools/updates"
	"host-health-mcp/daemon/internal/daemon/tools/workload"
)

var buildID = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/host-health-mcp/daemon.yml", "daemon config file")
	versionFlag := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("host-health-mcp-daemon %s\n", buildID)
		return
	}

	cfg, err := config.LoadDaemon(*cfgPath)
	if err != nil {
		log.Fatalf("daemon: %v", err)
	}

	if cfg.BindAddrIsPublic() && !cfg.PublicBindAcknowledged {
		log.Fatalf("daemon: bind_addr %q is on a public interface; refusing to start. Set public_bind_acknowledged: true in daemon.yml to override.", cfg.BindAddr)
	}

	manifestCfg, err := config.LoadManifest(cfg.ManifestPath)
	if err != nil {
		log.Fatalf("daemon: manifest: %v", err)
	}

	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}

	// Build the redactor from operator-configured allowlists. Used by
	// the logs tool to scrub sample messages (REQ 6.3) and by the
	// helperinvoke layer to redact subprocess stderr_prefix before it
	// leaves the daemon (threat-model §6.7).
	rules := redact.Rules{SensitiveDirs: cfg.SensitiveDirs}
	for _, c := range cfg.IPv4AllowlistRanges {
		if p, err := netip.ParsePrefix(c); err == nil {
			rules.IPv4Allow = append(rules.IPv4Allow, p)
		}
	}
	for _, c := range cfg.IPv6AllowlistRanges {
		if p, err := netip.ParsePrefix(c); err == nil {
			rules.IPv6Allow = append(rules.IPv6Allow, p)
		}
	}
	redactor := redact.New(rules)

	// Helper client. The in-flight cap (8) matches design §7.4; the
	// per-tool fan-out caps inside each helper-invoking tool (e.g.
	// storage caps its per-call SMART fan-out at 8) bound parallelism
	// further.
	hc := helperinvoke.NewClient(cfg.HelperSocketPath, 8, redactor)

	// Tool registry. Local-only tools register without the helper
	// client; helper-invoking tools take it as a constructor arg.
	reg := tools.New()
	reg.Register(system.New())
	reg.Register(pressure.New())
	reg.Register(kernel.New())
	reg.Register(sockets.New())
	reg.Register(updates.New(hc))
	reg.Register(storage.New(hc, manifestCfg.BtrfsMountpoints))
	reg.Register(systemdunits.New(manifestCfg.WhitelistedUnits))
	reg.Register(dns.New(dns.Probes{
		ExternalProbe: cfg.DNSProbeTargets["external_probe"],
		FilterCanary:  cfg.DNSProbeTargets["filter_canary"],
	}))
	reg.Register(mail.New(hc))
	reg.Register(certs.New(manifestCfg.CertPaths, manifestCfg.CertRenewalUnits))
	reg.Register(backup.New(manifestCfg.BackupLogPath, manifestCfg.BackupBackend, manifestCfg.BackupStatePath))
	reg.Register(sensors.New())
	reg.Register(network.New(hc, manifestCfg.IPv6Policy))
	reg.Register(security.New(hc, manifestCfg.DebsumsLogPath, manifestCfg.AideLogPath))
	reg.Register(firewall.New(hc, manifestCfg.Firewall))
	reg.Register(firewall_lookup.New(hc, manifestCfg.Firewall))

	reg.Register(logs.New(hc, redactor))

	// Refuse to start if the manifest references a workload plugin
	// that was not compiled into this binary (REQ 8.2).
	compiled := map[string]bool{}
	for _, n := range workload.CompiledIn() {
		compiled[n] = true
	}
	for _, n := range manifestCfg.WorkloadPlugins {
		if !compiled[n] {
			log.Fatalf("daemon: manifest references workload plugin %q not compiled in (REQ 8.2). compiled-in set: %v", n, workload.CompiledIn())
		}
	}
	reg.Register(workload.New(hc, manifestCfg.WorkloadPlugins))

	// Resolve manifest.enabled_tools against the compiled-in registry
	// (REQ 8.2). The `manifest` tool itself is always reachable so
	// callers can introspect the deployment even when enabled_tools is
	// configured tightly.
	registered := map[string]bool{"manifest": true}
	for _, n := range reg.Names() {
		registered[n] = true
	}
	var enforcedTools []string
	enabledSet := map[string]bool{}
	if len(manifestCfg.EnabledTools) > 0 {
		var unknown []string
		for _, n := range manifestCfg.EnabledTools {
			if !registered[n] {
				unknown = append(unknown, n)
			} else {
				enabledSet[n] = true
				enforcedTools = append(enforcedTools, n)
			}
		}
		if len(unknown) > 0 {
			log.Fatalf("daemon: manifest.enabled_tools names %d tool(s) not compiled in: %v (REQ 8.2)", len(unknown), unknown)
		}
		// manifest tool is always exposed so introspection cannot be
		// turned off accidentally.
		if !enabledSet["manifest"] {
			enabledSet["manifest"] = true
			enforcedTools = append(enforcedTools, "manifest")
		}
	} else {
		log.Printf("daemon: WARNING manifest.enabled_tools is empty; exposing all %d compiled-in tools", len(registered))
		for n := range registered {
			enabledSet[n] = true
			enforcedTools = append(enforcedTools, n)
		}
	}

	reg.Register(manifest.New(manifest.Snapshot{
		DaemonVersion:          buildID,
		BuildID:                buildID,
		StartedAt:              time.Now().UTC(),
		EnabledTools:           enforcedTools,
		EnabledWorkloadPlugins: manifestCfg.WorkloadPlugins,
		WhitelistedUnits:       manifestCfg.WhitelistedUnits,
	}))

	cch := cache.New()

	global := ratelimit.BucketCfg{SustainedPerMin: 30, Burst: 10}
	perTool := map[string]ratelimit.BucketCfg{}
	for tool, bcfg := range cfg.ExpensiveToolBuckets {
		disabled := bcfg.Enabled != nil && !*bcfg.Enabled
		perTool[tool] = ratelimit.BucketCfg{
			SustainedPerMin: bcfg.SustainedPerMin,
			Burst:           bcfg.Burst,
			Disabled:        disabled,
		}
	}
	limiter := ratelimit.New(global, perTool)

	srv := httpserver.New(cfg, host, reg, enabledSet, cch, limiter, audit.New())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Cache sweeper: ctx-aware so it exits cleanly on shutdown
	// rather than leaking until process exit. The ratelimit sweeper
	// below already follows this pattern; symmetry matters because
	// future tests will want clean teardown.
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				cch.Sweep()
			}
		}
	}()

	go limiter.RunSweeper(ctx)

	if _, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		log.Printf("daemon: sd_notify ready: %v (continuing)", err)
	}

	// The unit declares Type=notify and WatchdogSec=. systemd kills
	// the process if WATCHDOG=1 is not received within the configured
	// window; ping at half the interval per the systemd recommendation.
	if interval, err := daemon.SdWatchdogEnabled(false); err == nil && interval > 0 {
		go runWatchdog(ctx, interval/2)
	}

	if err := srv.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("daemon: %v", err)
	}

	if _, err := daemon.SdNotify(false, daemon.SdNotifyStopping); err != nil {
		log.Printf("daemon: sd_notify stopping: %v", err)
	}
}

func runWatchdog(ctx context.Context, period time.Duration) {
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := daemon.SdNotify(false, daemon.SdNotifyWatchdog); err != nil {
				log.Printf("daemon: sd_notify watchdog: %v", err)
			}
		}
	}
}
