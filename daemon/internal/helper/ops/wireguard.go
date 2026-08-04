package ops

import (
	"bufio"
	"bytes"
	"context"
	"regexp"
	"strconv"
	"strings"

	"host-health-mcp/daemon/internal/helper/dispatch"
	helperexec "host-health-mcp/daemon/internal/helper/exec"
	"host-health-mcp/daemon/internal/shared/proto"
)

// wgPublicKeyRE validates a peer or interface public key. Base64 of 32
// bytes is 44 characters with one padding char; wg-show emits 43 chars
// with no padding. Anything that fails this pattern is treated as
// corrupt and the op fails entirely (design §7.3.1).
var wgPublicKeyRE = regexp.MustCompile(`^[A-Za-z0-9+/]{42,43}=?$`)

// WireguardShowResult is the typed result for op wireguard_show.
// Private and preshared keys are stripped inside the helper before any
// byte enters this structure (design §7.3.1).
type WireguardShowResult struct {
	Interfaces []WireguardInterface `json:"interfaces"`
}

// WireguardInterface mirrors a single interface section of
// `wg show all dump` with the private key removed.
type WireguardInterface struct {
	Name      string          `json:"name"`
	PublicKey string          `json:"public_key"`
	ListenPort int            `json:"listen_port"`
	Fwmark    string          `json:"fwmark,omitempty"`
	Peers     []WireguardPeer `json:"peers"`
}

// WireguardPeer mirrors a peer row with the preshared key removed.
type WireguardPeer struct {
	PublicKey       string `json:"public_key"`
	Endpoint        string `json:"endpoint,omitempty"`
	AllowedIPs      string `json:"allowed_ips,omitempty"`
	LatestHandshake int64  `json:"latest_handshake_unix,omitempty"`
	RxBytes         int64  `json:"rx_bytes"`
	TxBytes         int64  `json:"tx_bytes"`
	PersistentKA    int    `json:"persistent_keepalive,omitempty"`
}

// WireguardShow invokes `wg show all dump`. The dump format is one
// tab-separated row per line; the first row per interface carries the
// PRIVATE key (which is dropped) followed by public key, listen port,
// fwmark. Subsequent rows are peer rows whose third tab-separated
// field is the PRESHARED key (which is dropped). Requires
// CAP_NET_ADMIN on the helper unit; templated in at install time when
// the operator's manifest enables the wireguard workload plugin.
func WireguardShow(ctx context.Context, _ string) (any, error) {
	stdout, err := helperexec.Run(ctx, "wg", "show", "all", "dump")
	if err != nil {
		return nil, err
	}
	return parseWGDump(stdout)
}

// parseWGDump turns `wg show all dump` output into the typed result.
// Extracted from WireguardShow so the parser is unit-testable without
// invoking wg(8). The L-2 fix (fail on unexpected column count) lives
// here.
func parseWGDump(stdout []byte) (WireguardShowResult, error) {
	out := WireguardShowResult{Interfaces: []WireguardInterface{}}
	var current *WireguardInterface
	var currentName string

	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	// `wg show all dump` can emit long rows when a peer carries many
	// allowed_ips; raise the line cap so the default 64 KiB doesn't
	// silently truncate.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		// The first column on every row of `wg show all dump` is the
		// interface name. Differentiating interface header rows from
		// peer rows is by column count: 5 (incl. iface) for header
		// rows, 9 for peer rows.
		ifaceName := fields[0]
		if currentName != ifaceName {
			if current != nil {
				out.Interfaces = append(out.Interfaces, *current)
			}
			currentName = ifaceName
			current = &WireguardInterface{
				Name:  ifaceName,
				Peers: []WireguardPeer{},
			}
		}
		if len(fields) == 5 {
			// fields: iface, private-key, public-key, listen-port, fwmark
			//
			// fields[1] is the PRIVATE key. It is never read in this
			// branch, and zeroing it is belt-and-braces against a
			// future edit here — NOT the enforcement point. What
			// actually holds the §7.3.1 guarantee is the exact column
			// count: wgPublicKeyRE cannot tell a private key from a
			// public one (a base64 WireGuard private key is 43 chars
			// and matches it just as well), so if a future wg(8) added
			// columns to the interface row and this parser accepted a
			// range instead of exact counts, fields[1] would be read as
			// the peer public key and emitted as public_key — crossing
			// the socket to the MCP client unredacted, since workload
			// data does not route through the redactor.
			fields[1] = ""
			pub := fields[2]
			if !wgPublicKeyRE.MatchString(pub) {
				return out, &dispatch.Error{
					Code:    proto.CodeToolFailed,
					Message: "wg dump: interface public key failed pattern",
				}
			}
			current.PublicKey = pub
			if p, err := strconv.Atoi(fields[3]); err == nil {
				current.ListenPort = p
			}
			if fields[4] != "off" {
				current.Fwmark = fields[4]
			}
			continue
		}
		// Exactly 9, not ">= 8". wg(8) emits exactly 5 columns for an
		// interface row and exactly 9 for a peer row; anything else is
		// an output format this parser was not written against, and
		// guessing at it is how fields[1] changes meaning underneath
		// the key-stripping guarantee above. Fail closed instead.
		if len(fields) == 9 {
			// fields: iface, public-key, preshared-key, endpoint,
			//         allowed-ips, latest-handshake, rx, tx,
			//         persistent-keepalive
			pub := fields[1]
			if !wgPublicKeyRE.MatchString(pub) {
				return out, &dispatch.Error{
					Code:    proto.CodeToolFailed,
					Message: "wg dump: peer public key failed pattern",
				}
			}
			peer := WireguardPeer{PublicKey: pub}
			// fields[2] is the preshared key. Deliberately ignored.
			if fields[3] != "(none)" {
				peer.Endpoint = fields[3]
			}
			if fields[4] != "(none)" {
				peer.AllowedIPs = fields[4]
			}
			if v, err := strconv.ParseInt(fields[5], 10, 64); err == nil {
				peer.LatestHandshake = v
			}
			if v, err := strconv.ParseInt(fields[6], 10, 64); err == nil {
				peer.RxBytes = v
			}
			if v, err := strconv.ParseInt(fields[7], 10, 64); err == nil {
				peer.TxBytes = v
			}
			if fields[8] != "off" {
				if v, err := strconv.Atoi(fields[8]); err == nil {
					peer.PersistentKA = v
				}
			}
			current.Peers = append(current.Peers, peer)
			continue
		}
		// Any column count other than the two known shapes (5 for the
		// interface header, ≥8 for a peer row) means the upstream
		// `wg show all dump` format changed. Fail the op so a real
		// drift is loud rather than silently masking peer rows.
		return out, &dispatch.Error{
			Code:    proto.CodeToolFailed,
			Message: "wg dump: row has unexpected column count " + strconv.Itoa(len(fields)),
		}
	}
	if current != nil {
		out.Interfaces = append(out.Interfaces, *current)
	}
	if err := scanner.Err(); err != nil {
		return out, &dispatch.Error{
			Code:    proto.CodeToolFailed,
			Message: "wg dump scanner: " + err.Error(),
		}
	}
	return out, nil
}
