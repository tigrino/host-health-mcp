// Package network implements tool 4.3: interfaces, default routes,
// nft table+counter view, resolver-as-configured, IPv6-policy
// compliance. The daemon reads /sys/class/net for interface metadata,
// /proc/net/{route,ipv6_route} for default routes, and netlink
// (via net.Interface.Addrs) for per-interface v4+v6 addresses, all
// in its own process. Nft counts come from helper op
// `nft_table_counts` and are absent (empty map) when nft itself is
// not installed.
package network

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"host-health-mcp/daemon/internal/shared/linescan"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"host-health-mcp/daemon/internal/daemon/helperinvoke"
	"host-health-mcp/daemon/internal/shared/proto"
	"host-health-mcp/daemon/internal/shared/schema"
)

// Data is the response data for tool network. Mirrors NetworkData in
// doc/schema-draft.yaml.
type Data struct {
	Interfaces                []NetworkInterface     `json:"interfaces"`
	DefaultRoutes             []DefaultRoute         `json:"default_routes"`
	NftTableCounts            map[string]NftTable    `json:"nft_table_counts"`
	ResolvConfFirstNameserver *string                `json:"resolv_conf_first_nameserver"`
	IPv6PolicyCompliant       bool                   `json:"ipv6_policy_compliant"`
	Errors                    []schema.HelperOpError `json:"errors,omitempty"`
}

// NetworkInterface mirrors the schema.
type NetworkInterface struct {
	Name      string          `json:"name"`
	MAC       string          `json:"mac"`
	MTU       int             `json:"mtu"`
	OperState string          `json:"oper_state"`
	Carrier   bool            `json:"carrier"`
	Addrs     []InterfaceAddr `json:"addrs"`
}

// InterfaceAddr mirrors the schema.
type InterfaceAddr struct {
	Family    string `json:"family"`
	Addr      string `json:"addr"`
	PrefixLen int    `json:"prefixlen"`
}

// DefaultRoute mirrors the schema.
type DefaultRoute struct {
	Family  string `json:"family"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
	Metric  int    `json:"metric"`
}

// NftTable mirrors the schema's per-table block. HitCounters is
// populated by the helper's nft_table_counts op from the in-table
// named counters; empty when the table has no named counters or
// when nft is not installed.
type NftTable struct {
	RuleCount   int          `json:"rule_count"`
	HitCounters []NftCounter `json:"hit_counters,omitempty"`
}

// NftCounter mirrors the schema's per-counter row.
type NftCounter struct {
	Name    string `json:"name"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
}

// Tool is the registered tool.
type Tool struct {
	hc         *helperinvoke.Client
	ipv6Policy string // required-on, required-off, not-enforced
}

// New returns a new tool instance. ipv6Policy comes from manifest.yml.
func New(hc *helperinvoke.Client, ipv6Policy string) *Tool {
	if ipv6Policy == "" {
		ipv6Policy = "not-enforced"
	}
	return &Tool{hc: hc, ipv6Policy: ipv6Policy}
}

// Name returns the tool name.
func (*Tool) Name() string { return "network" }

// DefaultTTL: network state can move quickly under DHCP / link
// flap, but routine inspection at 30 s resolution is fine.
func (*Tool) DefaultTTL() time.Duration { return 30 * time.Second }

// DefaultTimeout caps the per-call duration.
func (*Tool) DefaultTimeout() time.Duration { return 2 * time.Second }

// Handle composes the network envelope.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	d := Data{
		Interfaces:     []NetworkInterface{},
		DefaultRoutes:  []DefaultRoute{},
		NftTableCounts: map[string]NftTable{},
	}
	var warnings []string

	// Keep what was read. readInterfaces now reports a per-interface
	// address lookup failure alongside a populated list, so discarding
	// on error would drop every interface because one of them could
	// not be queried.
	ifaces, err := readInterfaces()
	// Assign only what was actually read. readInterfaces returns
	// (nil, err) when /sys/class/net cannot be listed, and an
	// unconditional assignment overwrote the empty-slice initialiser
	// with nil — serialising as "interfaces": null, which the schema
	// declares required and typed array. Keeping partial results must
	// not mean publishing a shape no client is allowed to expect.
	if ifaces != nil {
		d.Interfaces = ifaces
	}
	if err != nil {
		warnings = append(warnings, "network: interface addresses: "+err.Error()+
			"; addrs[] may be incomplete")
	}

	if rs, err := readDefaultRoutes("/proc/net/route", "inet"); err == nil {
		d.DefaultRoutes = append(d.DefaultRoutes, rs...)
	} else {
		warnings = append(warnings, "network: ipv4 routes: "+err.Error())
	}
	if rs, err := readDefaultRoutes("/proc/net/ipv6_route", "inet6"); err == nil {
		d.DefaultRoutes = append(d.DefaultRoutes, rs...)
	} else if !os.IsNotExist(err) {
		warnings = append(warnings, "network: ipv6 routes: "+err.Error())
	}

	if ns := firstNameserver(); ns != "" {
		d.ResolvConfFirstNameserver = &ns
	}

	// Counters via the helper. Pull a typed result and copy into the
	// daemon's shape. The helper's keys are "family:table" pairs
	// matching the schema's "table-name" keying expectation.
	var nft struct {
		Tables map[string]struct {
			RuleCount   int          `json:"rule_count"`
			HitCounters []NftCounter `json:"hit_counters"`
		} `json:"tables"`
	}
	if err := t.hc.CallJSON(ctx, proto.OpNftTableCounts, "", &nft); err != nil {
		oe := helperinvoke.OpErrorFrom(err)
		oe.Op = proto.OpNftTableCounts
		d.Errors = append(d.Errors, *oe)
		warnings = append(warnings, "network: "+proto.OpNftTableCounts+": "+helperinvoke.CodeOf(err))
	} else {
		for k, v := range nft.Tables {
			d.NftTableCounts[k] = NftTable{
				RuleCount:   v.RuleCount,
				HitCounters: v.HitCounters,
			}
		}
	}

	d.IPv6PolicyCompliant = checkIPv6Policy(t.ipv6Policy, d.Interfaces)

	return d, warnings, nil
}

// readInterfaces walks /sys/class/net for non-loopback interfaces.
// sysClassNetPath is the interface enumeration root; a var so tests can
// point it at a fixture or at a path that cannot be read.
var sysClassNetPath = "/sys/class/net"

func readInterfaces() ([]NetworkInterface, error) {
	var firstAddrErr error
	entries, err := os.ReadDir(sysClassNetPath)
	if err != nil {
		return nil, err
	}
	var out []NetworkInterface
	for _, e := range entries {
		name := e.Name()
		dir := filepath.Join("/sys/class/net", name)
		mac := readTrim(filepath.Join(dir, "address"))
		mtuStr := readTrim(filepath.Join(dir, "mtu"))
		mtu, _ := strconv.Atoi(mtuStr)
		operState := readTrim(filepath.Join(dir, "operstate"))
		carrierStr := readTrim(filepath.Join(dir, "carrier"))
		carrier := carrierStr == "1"

		iface := NetworkInterface{
			Name: name, MAC: mac, MTU: mtu,
			OperState: operState, Carrier: carrier,
			Addrs: []InterfaceAddr{},
		}
		addrs, addrErr := readInterfaceAddrs(name)
		if addrErr != nil && firstAddrErr == nil {
			firstAddrErr = addrErr
		}
		iface.Addrs = addrs
		out = append(out, iface)
	}
	return out, firstAddrErr
}

// readInterfaceAddrs returns the configured addresses on iface for
// both v4 and v6. Uses net.Interface.Addrs() which is backed by
// netlink RTM_GETADDR — read-only, no os/exec, and one code path
// covers both families. Returns a non-nil empty slice when the
// interface has no addresses so the JSON serialises as `[]` rather
// than `null` (REQ 6.5 wire-shape contract).
// The error return matters more than it looks: both calls below go
// over netlink, and a sandbox that omits AF_NETLINK makes them fail
// while the tool happily emits addrs: []. That is indistinguishable
// from an interface with no addresses configured, on every interface,
// on every host. Surface it.
func readInterfaceAddrs(name string) ([]InterfaceAddr, error) {
	out := []InterfaceAddr{}
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return out, err
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return out, err
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		plen, _ := ipn.Mask.Size()
		family := "inet"
		ip := ipn.IP
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		} else {
			family = "inet6"
		}
		out = append(out, InterfaceAddr{
			Family: family, Addr: ip.String(), PrefixLen: plen,
		})
	}
	return out, nil
}

// readDefaultRoutes returns rows whose destination is the default
// (0.0.0.0/0 for IPv4 or ::/0 for IPv6). Format: /proc/net/route is
// IPv4, /proc/net/ipv6_route is IPv6; both are hex-encoded.
func readDefaultRoutes(path, family string) ([]DefaultRoute, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []DefaultRoute
	scanner := linescan.New(bytes.NewReader(b), path)
	first := true
	for scanner.Scan() {
		if family == "inet" && first {
			first = false
			continue // header
		}
		line := scanner.Text()
		fields := strings.Fields(line)
		if family == "inet" {
			// fields: Iface Dest Gateway Flags RefCnt Use Metric Mask MTU Win IRTT
			if len(fields) < 11 {
				continue
			}
			if fields[1] != "00000000" {
				continue
			}
			gw, err := parseHexIPv4LE(fields[2])
			if err != nil {
				continue
			}
			metric, _ := strconv.Atoi(fields[6])
			out = append(out, DefaultRoute{
				Family: "inet", Gateway: gw,
				Dev: fields[0], Metric: metric,
			})
		} else {
			// fields: Dest DestPrefix Source SourcePrefix NextHop Metric RefCnt Use Flags Iface
			if len(fields) < 10 {
				continue
			}
			if fields[1] != "00" {
				continue
			}
			if fields[0] != strings.Repeat("0", 32) {
				continue
			}
			gw := parseHexIPv6(fields[4])
			metric, _ := strconv.ParseInt(fields[5], 16, 32)
			out = append(out, DefaultRoute{
				Family: "inet6", Gateway: gw,
				Dev: fields[9], Metric: int(metric),
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseHexIPv4LE(h string) (string, error) {
	if len(h) != 8 {
		return "", fmt.Errorf("bad ipv4 length")
	}
	var b [4]byte
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(h[2*i:2*i+2], 16, 8)
		if err != nil {
			return "", err
		}
		b[3-i] = byte(v)
	}
	return netip.AddrFrom4(b).String(), nil
}

func parseHexIPv6(h string) string {
	if len(h) != 32 {
		return ""
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return ""
	}
	var arr [16]byte
	copy(arr[:], b)
	return netip.AddrFrom16(arr).String()
}

func firstNameserver() string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "nameserver ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "nameserver"))
		}
	}
	return ""
}

// checkIPv6Policy reports whether the configured ipv6_policy is
// satisfied by the host's current address state. required-off
// requires no interface to carry a global-scope IPv6 address;
// required-on requires at least one. not-enforced always returns true.
func checkIPv6Policy(policy string, ifaces []NetworkInterface) bool {
	has := false
	for _, ifc := range ifaces {
		for _, a := range ifc.Addrs {
			if a.Family != "inet6" {
				continue
			}
			addr, err := netip.ParseAddr(a.Addr)
			if err != nil {
				continue
			}
			if addr.IsGlobalUnicast() && !addr.IsLinkLocalUnicast() {
				has = true
			}
		}
	}
	switch policy {
	case "required-on":
		return has
	case "required-off":
		return !has
	default:
		return true
	}
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
