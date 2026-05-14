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

	"tigr.net/host-health-mcp/daemon/internal/daemon/audit"
	"tigr.net/host-health-mcp/daemon/internal/daemon/cache"
	"tigr.net/host-health-mcp/daemon/internal/daemon/config"
	"tigr.net/host-health-mcp/daemon/internal/daemon/helperinvoke"
	"tigr.net/host-health-mcp/daemon/internal/daemon/httpserver"
	"tigr.net/host-health-mcp/daemon/internal/daemon/ratelimit"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/kernel"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/manifest"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/pressure"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/sockets"
	systemdunits "tigr.net/host-health-mcp/daemon/internal/daemon/tools/systemd_units"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/storage"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/system"
	"tigr.net/host-health-mcp/daemon/internal/daemon/tools/updates"
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
	reg.Register(storage.New(hc))
	reg.Register(systemdunits.New(manifestCfg.WhitelistedUnits))
	reg.Register(manifest.New(manifest.Snapshot{
		DaemonVersion:    buildID,
		BuildID:          buildID,
		StartedAt:        time.Now().UTC(),
		EnabledTools:     reg.Names(),
		WhitelistedUnits: manifestCfg.WhitelistedUnits,
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
