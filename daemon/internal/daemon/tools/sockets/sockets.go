// Package sockets implements tool 4.16: listening-socket inventory.
// Reads /proc/net/{tcp,tcp6,udp,udp6} which expose listening sockets
// to any user; no PIDs or process info crosses out (REQ 4.16).
package sockets

import (
	"context"
	"fmt"
	"host-health-mcp/daemon/internal/shared/linescan"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Data is the response data for tool sockets.
type Data struct {
	Listening []ListeningSocket `json:"listening"`
}

// ListeningSocket is one row in /proc/net/<proto>.
type ListeningSocket struct {
	Proto  string `json:"proto"`
	Family string `json:"family"`
	Addr   string `json:"addr"`
	Port   int    `json:"port"`
}

// Tool is the registered tool.
type Tool struct{}

// New returns a new tool instance.
func New() *Tool { return &Tool{} }

// Name returns the tool name.
func (*Tool) Name() string { return "sockets" }

// DefaultTTL: listeners change infrequently.
func (*Tool) DefaultTTL() time.Duration { return 30 * time.Second }

// DefaultTimeout caps the per-call duration.
func (*Tool) DefaultTimeout() time.Duration { return 1 * time.Second }

// Handle reads all four files and returns the listeners.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	var warnings []string
	d := Data{Listening: []ListeningSocket{}}
	for _, src := range []struct {
		path, proto, family string
		listenState         string
	}{
		{"/proc/net/tcp", "tcp", "inet", "0A"},
		{"/proc/net/tcp6", "tcp", "inet6", "0A"},
		{"/proc/net/udp", "udp", "inet", "07"},
		{"/proc/net/udp6", "udp", "inet6", "07"},
	} {
		rows, err := readProcNet(src.path, src.proto, src.family, src.listenState)
		if err != nil {
			// Say so. Dropping the family silently turns "the read
			// failed" into "this host has no TCP listeners", which for
			// a security inventory is a materially misleading answer —
			// and worse than the partial list this replaced.
			warnings = append(warnings, "sockets: "+src.path+": "+err.Error()+
				"; listening[] is incomplete")
			continue
		}
		d.Listening = append(d.Listening, rows...)
	}
	return d, warnings, nil
}

// udpUnconnectedState is TCP_CLOSE (07) as reported in /proc/net/udp
// for a bound socket with no connected peer — the UDP equivalent of
// "listening".
const udpUnconnectedState = "07"

func readProcNet(path, proto, family, listenState string) ([]ListeningSocket, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []ListeningSocket
	scanner := linescan.New(f, path)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // header
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		localHex := fields[1]
		state := fields[3]
		// UDP was never filtered. The guard read `proto == "tcp" &&
		// state != listenState`, so every UDP row came back including
		// connected ephemeral client sockets — not the listening
		// inventory REQ 4.16 describes, and noisy enough to bury the
		// entries an operator is looking for.
		//
		// UDP has no LISTEN state: /proc/net/udp reports 07
		// (TCP_CLOSE) for an unconnected bound socket and 01
		// (TCP_ESTABLISHED) for one that has been connect()ed to a
		// peer. The bound-but-unconnected rows are the listeners.
		switch proto {
		case "tcp":
			if state != listenState {
				continue
			}
		case "udp":
			if state != udpUnconnectedState {
				continue
			}
		}
		addr, port, err := parseHexEndpoint(localHex, family)
		if err != nil {
			continue
		}
		out = append(out, ListeningSocket{
			Proto:  proto,
			Family: family,
			Addr:   addr,
			Port:   port,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// parseHexEndpoint converts /proc/net hex-encoded address:port into
// (addr, port) for inet/inet6.
func parseHexEndpoint(hex, family string) (string, int, error) {
	colon := strings.IndexByte(hex, ':')
	if colon < 0 {
		return "", 0, fmt.Errorf("no colon")
	}
	addrHex := hex[:colon]
	portHex := hex[colon+1:]
	port, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return "", 0, err
	}
	if family == "inet" {
		// 8 hex chars = 4 bytes, little-endian.
		if len(addrHex) != 8 {
			return "", 0, fmt.Errorf("bad inet length")
		}
		var b [4]byte
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(addrHex[2*i:2*i+2], 16, 8)
			if err != nil {
				return "", 0, err
			}
			b[3-i] = byte(v)
		}
		a := netip.AddrFrom4(b)
		return a.String(), int(port), nil
	}
	// inet6: 32 hex chars in network byte order with per-32-bit
	// little-endian word swap per /proc/net format.
	if len(addrHex) != 32 {
		return "", 0, fmt.Errorf("bad inet6 length")
	}
	var b [16]byte
	for w := 0; w < 4; w++ {
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(addrHex[w*8+2*i:w*8+2*i+2], 16, 8)
			if err != nil {
				return "", 0, err
			}
			b[w*4+3-i] = byte(v)
		}
	}
	a := netip.AddrFrom16(b)
	return a.String(), int(port), nil
}
