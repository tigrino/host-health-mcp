// Command plugin is the MCP server side of host-health-mcp. It
// exposes the daemon's tool surface to MCP-speaking clients over
// stdio. Configured via environment variables (REQ 9.4); the target
// host is supplied per call (REQ 7.2), with HOSTHEALTH_TARGET_HOST
// providing an optional default.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"host-health-mcp/plugin/internal/client"
	"host-health-mcp/plugin/internal/mcp"
)

var buildID = "dev"

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	versionFlag := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *versionFlag {
		fmt.Printf("host-health-mcp-plugin %s\n", buildID)
		return
	}

	defaultHost := os.Getenv("HOSTHEALTH_TARGET_HOST")
	portStr := envOr("HOSTHEALTH_TARGET_PORT", "8443")
	cert := envOr("HOSTHEALTH_TLS_CERT", "/etc/host-health-mcp/plugin/cert.pem")
	key := envOr("HOSTHEALTH_TLS_KEY", "/etc/host-health-mcp/plugin/key.pem")
	ca := envOr("HOSTHEALTH_TLS_CA", "")
	suffix := envOr("HOSTHEALTH_DNS_SUFFIX", "")
	prefix := envOr("HOSTHEALTH_TOOL_PREFIX", "host_")

	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("plugin: HOSTHEALTH_TARGET_PORT: %v", err)
	}

	cli, err := client.New(client.Config{
		Port:      port,
		CertPath:  cert,
		KeyPath:   key,
		CAPath:    ca,
		DNSSuffix: suffix,
	})
	if err != nil {
		log.Fatalf("plugin: %v", err)
	}

	tools := []mcp.Tool{
		{Name: prefix + "manifest", DaemonRPC: "manifest", Description: "host-health-mcp daemon self-description (read-only)", TimeoutS: 3},
		{Name: prefix + "system", DaemonRPC: "system", Description: "host uptime, load, memory, disk, kernel (read-only)", TimeoutS: 3},
		{Name: prefix + "systemd_units", DaemonRPC: "systemd_units", Description: "manifest-whitelisted systemd unit state (read-only)", TimeoutS: 3},
		{Name: prefix + "network", DaemonRPC: "network", Description: "interfaces, default routes, resolver (read-only)", TimeoutS: 3},
		{Name: prefix + "dns", DaemonRPC: "dns", Description: "DNS resolver and probe results (read-only)", TimeoutS: 5},
		{Name: prefix + "security", DaemonRPC: "security", Description: "AIDE/auditd/rkhunter/debsums/IPS/SSH posture (read-only)", TimeoutS: 5},
		{Name: prefix + "certs", DaemonRPC: "certs", Description: "manifest-declared certificate inventory (read-only)", TimeoutS: 3},
		{Name: prefix + "mail", DaemonRPC: "mail", Description: "MTA queue depth and recent send/fail state (read-only)", TimeoutS: 5},
		{Name: prefix + "backup", DaemonRPC: "backup", Description: "last backup run timestamps and backend (read-only)", TimeoutS: 3},
		{Name: prefix + "workload", DaemonRPC: "workload", Description: "compile-time-enabled workload plugin output (read-only)", TimeoutS: 5},
		{Name: prefix + "logs", DaemonRPC: "logs", Description: "journald or audit summary by severity/window/source (read-only)", TimeoutS: 8},
		{Name: prefix + "pressure", DaemonRPC: "pressure", Description: "PSI averages cpu/io/memory (read-only)", TimeoutS: 3},
		{Name: prefix + "kernel", DaemonRPC: "kernel", Description: "kernel taint, MCE/EDAC, OOM, cmdline keys (read-only)", TimeoutS: 3},
		{Name: prefix + "sockets", DaemonRPC: "sockets", Description: "listening socket inventory (read-only)", TimeoutS: 3},
		{Name: prefix + "updates", DaemonRPC: "updates", Description: "pending APT updates and needrestart services (read-only)", TimeoutS: 10},
		{Name: prefix + "storage", DaemonRPC: "storage", Description: "mdraid, LVM, SMART, btrfs, zfs (read-only)", TimeoutS: 10},
		{Name: prefix + "sensors", DaemonRPC: "sensors", Description: "hwmon temperatures, fans, voltages (read-only)", TimeoutS: 3},
	}

	srv := mcp.New(cli, tools, defaultHost, "host-health-mcp", buildID)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := srv.Serve(ctx, os.Stdin, os.Stdout); err != nil && err != context.Canceled {
		log.Fatalf("plugin: %v", err)
	}
}
