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

	"tigr.net/host-health-mcp/daemon/internal/daemon/audit"
	"tigr.net/host-health-mcp/daemon/internal/daemon/cache"
	"tigr.net/host-health-mcp/daemon/internal/daemon/config"
	"tigr.net/host-health-mcp/daemon/internal/daemon/helperinvoke"
	"tigr.net/host-health-mcp/daemon/internal/daemon/httpserver"
	"tigr.net/host-health-mcp/daemon/internal/daemon/ratelimit"
	"tigr.net/host-health-mcp/daemon/internal/daemon/redact"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/backup"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/certs"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/dns"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/kernel"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/logs"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/mail"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/manifest"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/network"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/pressure"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/security"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/sensors"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/sockets"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/storage"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/system"
	systemdunits "tigr.net/host-health-mcp/daemon/internal/daemon/tools/systemd_units"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/updates"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/workload"
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
		log.Printf("daemon: WARNING bind_addr %s appears public and public_bind_acknowledged is not set (REQ 6.4)", cfg.BindAddr)
	}

	manifestCfg, err := config.LoadManifest(cfg.ManifestPath)
	if err != nil {
		log.Fatalf("daemon: manifest: %v", err)
	}

	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}

	// Helper client. The in-flight cap (8) matches design §7.4; the
	// per-tool fan-out caps inside each helper-invoking tool (e.g.
	// storage caps its per-call SMART fan-out at 8) bound parallelism
	// further.
	hc := helperinvoke.NewClient(cfg.HelperSocketPath, 8)

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
	reg.Register(backup.New(manifestCfg.BackupLogPath, manifestCfg.BackupBackend))
	reg.Register(sensors.New())
	reg.Register(network.New(hc, manifestCfg.IPv6Policy))
	reg.Register(security.New(hc))

	// Build the redactor from operator-configured allowlists. Used by
	// the logs tool to scrub sample messages (REQ 6.3).
	rules := redact.Rules{}
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
	reg.Register(logs.New(hc, redact.New(rules)))

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

	reg.Register(manifest.New(manifest.Snapshot{
		DaemonVersion:          buildID,
		BuildID:                buildID,
		StartedAt:              time.Now().UTC(),
		EnabledTools:           reg.Names(),
		EnabledWorkloadPlugins: manifestCfg.WorkloadPlugins,
		WhitelistedUnits:       manifestCfg.WhitelistedUnits,
	}))

	cch := cache.New()
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for range t.C {
			cch.Sweep()
		}
	}()

	global := ratelimit.BucketCfg{SustainedPerMin: 30, Burst: 10}
	perTool := map[string]ratelimit.BucketCfg{}
	for tool, cfg := range cfg.ExpensiveToolBuckets {
		perTool[tool] = ratelimit.BucketCfg{
			SustainedPerMin: cfg.SustainedPerMin,
			Burst:           cfg.Burst,
		}
	}
	limiter := ratelimit.New(global, perTool)

	srv := httpserver.New(cfg, host, reg, cch, limiter, audit.New())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if _, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		log.Printf("daemon: sd_notify ready: %v (continuing)", err)
	}

	if err := srv.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("daemon: %v", err)
	}

	if _, err := daemon.SdNotify(false, daemon.SdNotifyStopping); err != nil {
		log.Printf("daemon: sd_notify stopping: %v", err)
	}
}
