// Package firewall implements tool host_firewall: read-only
// inspection of the host's nftables ruleset, sets, and synthesised
// per-source ban counts. See doc/tools.md and the spec attached to
// the 1.13.0 changelog entry.
//
// All subprocess work is delegated to the helper op
// firewall_inspect; this package only owns the HTTP-side request
// parsing, manifest-driven argument validation, and structured-
// error attachment.
package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"host-health-mcp/daemon/internal/daemon/config"
	"host-health-mcp/daemon/internal/daemon/helperinvoke"
	"host-health-mcp/daemon/internal/daemon/tools"
	"host-health-mcp/daemon/internal/shared/proto"
	"host-health-mcp/daemon/internal/shared/schema"
)

// Request is the body the caller may POST. All fields are optional;
// zero values fall through to manifest defaults.
type Request struct {
	Mode               string `json:"mode,omitempty"`
	Table              string `json:"table,omitempty"`
	IncludeSetElements bool   `json:"include_set_elements,omitempty"`
}

// validModes is the closed set for Request.Mode. Empty means summary.
// Without this the helper's only test is `mode == "detail"`, so any
// other value — including a typo like "detial" — silently produced a
// summary response with no indication the argument was not understood.
var validModes = map[string]bool{"": true, "summary": true, "detail": true}

// validateRequest rejects caller arguments the helper would otherwise
// misread. Both checks fail closed: an unrecognised mode is an error
// rather than a silent downgrade, and an unparseable table filter is an
// error rather than a filter that matches everything.
func validateRequest(req *Request) *tools.Error {
	if !validModes[req.Mode] {
		return &tools.Error{
			Code:    schema.ErrCodeBadArgument,
			Message: "firewall: mode must be \"summary\" or \"detail\"",
		}
	}
	if req.Table == "" {
		return nil
	}
	family, name, ok := strings.Cut(req.Table, "/")
	if !ok || family == "" || name == "" {
		return &tools.Error{
			Code:    schema.ErrCodeBadArgument,
			Message: "firewall: table must be \"<family>/<name>\", e.g. \"inet/filter\"",
		}
	}
	return nil
}

// Data is the response data block. Mirrors the helper-side
// FirewallResult plus the structured per-op errors slice.
type Data struct {
	Backend           string                 `json:"backend"`
	NftVersion        string                 `json:"nft_version,omitempty"`
	RulesetHashSHA256 string                 `json:"ruleset_hash_sha256,omitempty"`
	Tables            []TableMeta            `json:"tables"`
	Chains            []Chain                `json:"chains"`
	Sets              []Set                  `json:"sets"`
	Bans              Bans                   `json:"bans"`
	Errors            []schema.HelperOpError `json:"errors,omitempty"`
}

// TableMeta mirrors the helper's FirewallTableMeta. Re-declared
// here so the daemon's schema is owned in one place; field tags
// match the helper's wire shape.
type TableMeta struct {
	Family     string `json:"family"`
	Name       string `json:"name"`
	ChainCount int    `json:"chain_count"`
	SetCount   int    `json:"set_count"`
	MapCount   int    `json:"map_count"`
	RuleCount  int    `json:"rule_count"`
}

// Chain mirrors the helper's FirewallChain.
type Chain struct {
	Family    string `json:"family"`
	Table     string `json:"table"`
	Name      string `json:"name"`
	Type      string `json:"type,omitempty"`
	Hook      string `json:"hook,omitempty"`
	Prio      *int   `json:"prio,omitempty"`
	Policy    string `json:"policy,omitempty"`
	RuleCount int    `json:"rule_count"`
	Rules     []Rule `json:"rules,omitempty"`
}

// Rule mirrors the helper's FirewallRule. Expr is the compact
// JSON encoding of nft's expression array; see the helper-side
// comment for why text rendering is not synthesised.
type Rule struct {
	Handle  int      `json:"handle"`
	Expr    string   `json:"expr"`
	Counter *Counter `json:"counter,omitempty"`
}

// Counter mirrors the helper's FirewallCounter.
type Counter struct {
	Packets int64 `json:"packets"`
	Bytes   int64 `json:"bytes"`
}

// Set mirrors the helper's FirewallSet.
type Set struct {
	Family            string    `json:"family"`
	Table             string    `json:"table"`
	Name              string    `json:"name"`
	Type              string    `json:"type"`
	Flags             []string  `json:"flags,omitempty"`
	SizeLimit         int       `json:"size_limit,omitempty"`
	ElementCount      int       `json:"element_count"`
	Elements          []SetElem `json:"elements,omitempty"`
	ElementsTruncated bool      `json:"elements_truncated,omitempty"`
	IsMap             bool      `json:"is_map,omitempty"`
}

// SetElem mirrors the helper's FirewallSetElem.
type SetElem struct {
	Key      string `json:"key"`
	ExpiresS *int64 `json:"expires_s,omitempty"`
	TimeoutS *int64 `json:"timeout_s,omitempty"`
}

// Bans mirrors the helper's FirewallBans.
type Bans struct {
	TotalActiveV4 int          `json:"total_active_v4"`
	TotalActiveV6 int          `json:"total_active_v6"`
	BySet         []BanSetStat `json:"by_set"`
}

// BanSetStat mirrors the helper's FirewallBanSetStat.
type BanSetStat struct {
	Set    string `json:"set"`
	Count  int    `json:"count"`
	Source string `json:"source"`
}

// Tool is the registered tool.
type Tool struct {
	hc *helperinvoke.Client
	mf config.Firewall
}

// New constructs the tool with a snapshot of the manifest's firewall
// block.
func New(hc *helperinvoke.Client, mf config.Firewall) *Tool {
	// Deep-copy ban_sets so a later manifest reload (if ever added)
	// cannot mutate state behind the tool.
	bs := make([]config.FirewallBanSet, len(mf.BanSets))
	copy(bs, mf.BanSets)
	mf.BanSets = bs
	return &Tool{hc: hc, mf: mf}
}

// Name returns the tool name. Short form matches the convention
// every other tool in the registry follows (`system`, `storage`,
// `network`, `mail`, …). Pre-1.15.0 builds used "host_firewall";
// the rename is the first breaking surface change since this tool
// was introduced and is called out in the 1.15.0 changelog.
func (*Tool) Name() string { return "firewall" }

// DefaultTTL: firewall state moves on operator action (ban
// propagation, rule pushes). 30 s aligns with the fleet's net-ban
// update cadence and keeps the per-call cost predictable.
func (*Tool) DefaultTTL() time.Duration { return 30 * time.Second }

// DefaultTimeout caps the per-call duration. nft -j list ruleset on
// a large host plus a per-ban-set element fetch fits comfortably in
// 6 s; the REQ 5.1 ceiling is 10 s.
func (*Tool) DefaultTimeout() time.Duration { return 6 * time.Second }

// AuditArgs returns the caller-supplied enum fields for inclusion in
// the audit Entry (REQ 6.5). Empty when the body is missing or no
// fields are set. Used by the httpserver.
func (*Tool) AuditArgs(body []byte) map[string]string {
	var r Request
	if len(body) > 0 {
		_ = json.Unmarshal(body, &r)
	}
	out := map[string]string{}
	if r.Mode != "" {
		out["mode"] = r.Mode
	}
	if r.Table != "" {
		out["table"] = r.Table
	}
	if r.IncludeSetElements {
		out["include_set_elements"] = "true"
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Handle composes the firewall envelope. Reads the manifest config
// snapshot for caps and ban_sets, parses the request body (which is
// optional), and forwards a single op call to the helper.
func (t *Tool) Handle(ctx context.Context, body []byte) (any, []string, error) {
	d := Data{
		Tables: []TableMeta{},
		Chains: []Chain{},
		Sets:   []Set{},
		Bans:   Bans{BySet: []BanSetStat{}},
	}
	var warnings []string

	if !t.mf.Enabled {
		warnings = append(warnings, "firewall: disabled in manifest")
		d.Backend = "none"
		return d, warnings, nil
	}

	var req Request
	if len(body) > 0 {
		// Tolerate empty body or "{}"; reject malformed JSON or unknown
		// fields (REQ 8 / schema additionalProperties:false).
		if err := schema.DecodeStrict(body, &req); err != nil {
			return nil, nil, &tools.Error{Code: schema.ErrCodeBadArgument, Message: "firewall: " + err.Error()}
		}
	}
	if terr := validateRequest(&req); terr != nil {
		return nil, nil, terr
	}

	helperReq := struct {
		Mode               string `json:"mode"`
		TableFilter        string `json:"table_filter"`
		IncludeSetElements bool   `json:"include_set_elements"`
		DetailModeAllowed  bool   `json:"detail_mode_allowed"`
		BanSets            []struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
			Source string `json:"source"`
		} `json:"ban_sets"`
		MaxSetElements   int `json:"max_set_elements"`
		MaxRuleTextBytes int `json:"max_rule_text_bytes"`
	}{
		Mode:               req.Mode,
		TableFilter:        req.Table,
		IncludeSetElements: req.IncludeSetElements,
		DetailModeAllowed:  t.mf.DetailModeAllowed,
		MaxSetElements:     t.mf.MaxSetElementsPerSet,
		MaxRuleTextBytes:   t.mf.MaxRuleTextBytes,
	}
	for _, bs := range t.mf.BanSets {
		helperReq.BanSets = append(helperReq.BanSets, struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
			Source string `json:"source"`
		}{bs.Family, bs.Table, bs.Name, bs.Source})
	}

	paramBytes, err := json.Marshal(helperReq)
	if err != nil {
		return nil, nil, fmt.Errorf("firewall: marshal request: %w", err)
	}

	// Single helper call. The helper performs all subprocess work
	// (nft -j list ruleset, optional per-set element fetches) and
	// returns the typed result. Per-op failures internal to the
	// helper come back as warnings on the result; only a wholesale
	// helper failure surfaces here as err.
	var raw json.RawMessage
	if err := t.hc.CallJSON(ctx, proto.OpFirewallInspect, string(paramBytes), &raw); err != nil {
		oe := helperinvoke.OpErrorFrom(err)
		oe.Op = proto.OpFirewallInspect
		d.Errors = append(d.Errors, *oe)
		warnings = append(warnings, "firewall: "+proto.OpFirewallInspect+": "+helperinvoke.CodeOf(err))
		d.Backend = "none"
		return d, warnings, nil
	}

	// Unmarshal into a local mirror struct, then translate. The
	// duplication keeps the daemon's wire schema authoritative
	// rather than re-exporting the helper's types.
	var helperRes struct {
		Backend           string      `json:"backend"`
		NftVersion        string      `json:"nft_version"`
		RulesetHashSHA256 string      `json:"ruleset_hash_sha256"`
		Tables            []TableMeta `json:"tables"`
		Chains            []Chain     `json:"chains"`
		Sets              []Set       `json:"sets"`
		Bans              Bans        `json:"bans"`
		Warnings          []string    `json:"warnings"`
	}
	if err := json.Unmarshal(raw, &helperRes); err != nil {
		return nil, nil, fmt.Errorf("firewall: parse helper result: %w", err)
	}

	d.Backend = helperRes.Backend
	d.NftVersion = helperRes.NftVersion
	d.RulesetHashSHA256 = helperRes.RulesetHashSHA256
	if helperRes.Tables != nil {
		d.Tables = helperRes.Tables
	}
	if helperRes.Chains != nil {
		d.Chains = helperRes.Chains
	}
	if helperRes.Sets != nil {
		d.Sets = helperRes.Sets
	}
	d.Bans = helperRes.Bans
	if d.Bans.BySet == nil {
		d.Bans.BySet = []BanSetStat{}
	}
	warnings = append(warnings, helperRes.Warnings...)

	return d, warnings, nil
}
