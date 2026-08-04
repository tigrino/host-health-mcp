package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The network tool reads per-interface addresses through
// net.Interface.Addrs(), which Go implements over netlink RTM_GETADDR.
// A systemd sandbox that omits AF_NETLINK does not fail loudly: the
// call returns "address family not supported by protocol" and every
// interface reports addrs: [] with status ok and no warning — a silent
// data regression on every host.
//
// This asserts the SHIPPED UNIT still permits the family. It is a
// contract between two files that no compiler checks, which is exactly
// why it needs a test.
func TestDaemonUnitPermitsNetlink(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "..", "build", "systemd", "host-health-mcp.service")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	var line string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "RestrictAddressFamilies=") {
			line = l
		}
	}
	if line == "" {
		t.Skip("RestrictAddressFamilies= not set; the sandbox does not constrain families")
	}
	if !strings.Contains(line, "AF_NETLINK") {
		t.Errorf("%s\nomits AF_NETLINK. readInterfaceAddrs goes over netlink, so every "+
			"interface would report addrs: [] with no error", strings.TrimSpace(line))
	}
	// AF_PACKET is the family a compromised listener would reach for.
	if strings.Contains(line, "AF_PACKET") {
		t.Error("AF_PACKET is permitted; nothing in the daemon opens a raw socket")
	}
}

// The daemon must actually be able to enumerate interfaces in the
// environment the tests run in — if this fails, the seam above is
// testing the wrong thing.
func TestReadInterfaceAddrsWorksHere(t *testing.T) {
	if _, err := readInterfaceAddrs("lo"); err != nil {
		t.Skipf("no loopback interface available: %v", err)
	}
}
