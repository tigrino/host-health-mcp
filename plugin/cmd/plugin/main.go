// Command plugin is the MCP server side of host-health-mcp. It
// exposes the daemon's tool surface to MCP-speaking clients over
// stdio. Configured via environment variables (REQ 9.4); the
// operator points it at a single daemon per process and provides
// mTLS material.
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

	"tigr.net/host-health-mcp/plugin/internal/client"
	"tigr.net/host-health-mcp/plugin/internal/mcp"
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

	host := envOr("HOSTHEALTH_TARGET_HOST", "localhost")
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
		Host:      host,
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
		{Name: prefix + "pressure", DaemonRPC: "pressure", Description: "PSI averages cpu/io/memory (read-only)", TimeoutS: 3},
		{Name: prefix + "kernel", DaemonRPC: "kernel", Description: "kernel taint, MCE/EDAC, OOM, cmdline keys (read-only)", TimeoutS: 3},
		{Name: prefix + "sockets", DaemonRPC: "sockets", Description: "listening socket inventory (read-only)", TimeoutS: 3},
	}

	srv := mcp.New(cli, tools)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := srv.Serve(ctx, os.Stdin, os.Stdout); err != nil && err != context.Canceled {
		log.Fatalf("plugin: %v", err)
	}
}
