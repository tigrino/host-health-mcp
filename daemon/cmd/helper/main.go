// Command helper is the privileged side of host-health-mcp. It runs
// as root under its own systemd unit (host-health-mcp-helper.service)
// with a CapabilityBoundingSet templated from manifest.yml at install
// time. It listens on a unix socket; only the daemon's uid is allowed
// to connect (verified via SO_PEERCRED). The helper parses output
// from each underlying tool in its own process and returns typed
// fields; raw subprocess stdout never crosses the socket to the
// daemon (design §6.2, §7).
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

	"host-health-mcp/daemon/internal/helper/config"
	"host-health-mcp/daemon/internal/helper/dispatch"
	"host-health-mcp/daemon/internal/helper/ops"
	"host-health-mcp/daemon/internal/helper/server"
)

var buildID = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/host-health-mcp/helper.yml", "helper config file")
	versionFlag := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("host-health-mcp-helper %s\n", buildID)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("helper: %v", err)
	}

	uid, err := cfg.ResolveUID()
	if err != nil {
		log.Fatalf("helper: %v", err)
	}
	gid, err := cfg.ResolveGID()
	if err != nil {
		log.Fatalf("helper: %v", err)
	}

	reg := dispatch.New()
	ops.RegisterAll(reg)

	srv := server.New(server.Config{
		SocketPath: cfg.SocketPath,
		AllowedUID: uid,
		SocketGID:  gid,
		SocketMode: 0o660,
		Registry:   reg,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if _, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		log.Printf("helper: sd_notify ready: %v (continuing)", err)
	}
	if interval, err := daemon.SdWatchdogEnabled(false); err == nil && interval > 0 {
		go runWatchdog(ctx, interval/2)
	}

	if err := srv.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("helper: %v", err)
	}

	if _, err := daemon.SdNotify(false, daemon.SdNotifyStopping); err != nil {
		log.Printf("helper: sd_notify stopping: %v", err)
	}

	_ = os.Remove(cfg.SocketPath)
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
				log.Printf("helper: sd_notify watchdog: %v", err)
			}
		}
	}
}
