// Package firewall_lookup implements tool host_firewall_lookup:
// search the host's nftables ruleset and sets for any reference to
// a given IP address or CIDR. See doc/tools.md and the 1.14.0
// changelog entry.
//
// The tool is a thin wrapper around the helper's firewall_lookup
// op. The op handles all subprocess work and matching server-side
// so the tool's only job is request parsing, manifest gating, and
// structured-error attachment.
package firewall_lookup

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

// Request is the body the caller POSTs. Query is required; the
// other field is optional.
type Request struct {
	Query              string `json:"query"`
	IncludeSetElements bool   `json:"include_set_elements,omitempty"`
}

// Data is the response data block. Mirrors the helper-side
// FirewallLookupResult: matches[] carries rule hits, sets[]
// carries set/map element hits.
type Data struct {
	Query          string                 `json:"query"`
	QueryKind      string                 `json:"query_kind"`
	Matches        []Match                `json:"matches"`
	Sets           []SetHit               `json:"sets"`
	SearchedTables int                    `json:"searched_tables"`
	SearchedChains int                    `json:"searched_chains"`
	SearchedRules  int                    `json:"searched_rules"`
	SearchedSets   int                    `json:"searched_sets"`
	Errors         []schema.HelperOpError `json:"errors,omitempty"`
}

// Match mirrors the helper-side FirewallRuleMatch. See
// doc/tools.md for the match_kind taxonomy.
type Match struct {
	MatchKind    string `json:"match_kind"`
	Family       string `json:"family"`
	Table        string `json:"table"`
	Chain        string `json:"chain"`
	RuleHandle   int    `json:"rule_handle"`
	RuleText     string `json:"rule_text"`
	Operator     string `json:"operator,omitempty"`
	MatchedValue string `json:"matched_value,omitempty"`
	SetName      string `json:"set_name,omitempty"`
}

// SetHit mirrors the helper-side FirewallSetHit. One entry per
// matching set/map element.
type SetHit struct {
	MatchKind  string `json:"match_kind"`
	Family     string `json:"family"`
	Table      string `json:"table"`
	Set        string `json:"set"`
	ElementKey string `json:"element_key"`
	ExpiresS   *int64 `json:"expires_s,omitempty"`
	TimeoutS   *int64 `json:"timeout_s,omitempty"`
}

// Tool is the registered tool.
type Tool struct {
	hc *helperinvoke.Client
	mf config.Firewall
}

// New constructs the tool.
func New(hc *helperinvoke.Client, mf config.Firewall) *Tool {
	return &Tool{hc: hc, mf: mf}
}

// Name returns the tool name. Short form matches the convention
// every other tool in the registry follows. Pre-1.15.0 builds
// used "host_firewall_lookup"; the rename is documented in the
// 1.15.0 changelog.
func (*Tool) Name() string { return "firewall_lookup" }

// DefaultTTL: matches host_firewall's 30 s. Cache key is the full
// request body so different queries don't collide.
func (*Tool) DefaultTTL() time.Duration { return 30 * time.Second }

// DefaultTimeout caps the per-call duration. The lookup parses the
// same ruleset host_firewall does plus runs O(rules + set_elems)
// match logic in Go; 6 s is generous on realistic fleet sizes.
func (*Tool) DefaultTimeout() time.Duration { return 6 * time.Second }

// AuditArgs returns the caller-supplied query, rune-truncated to
// 64 characters so an attacker cannot pad the audit line. Empty
// when the body is missing or the query is blank. Used by the
// httpserver to populate audit Entry.Args (REQ 6.5).
func (*Tool) AuditArgs(body []byte) map[string]string {
	var r Request
	if len(body) > 0 {
		_ = json.Unmarshal(body, &r)
	}
	q := truncateRunes(strings.TrimSpace(r.Query), 64)
	if q == "" {
		return nil
	}
	return map[string]string{"query": q}
}

func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	n := 0
	for i := range s {
		if n == max {
			return s[:i]
		}
		n++
	}
	return s
}

// Handle parses the request body, validates the query, and forwards
// a single helper call. The manifest's firewall.enabled flag gates
// access — operators who don't want firewall introspection at all
// can disable the whole block in one place.
func (t *Tool) Handle(ctx context.Context, body []byte) (any, []string, error) {
	d := Data{Matches: []Match{}, Sets: []SetHit{}}
	var warnings []string

	if !t.mf.Enabled {
		warnings = append(warnings, "firewall: disabled in manifest")
		return d, warnings, nil
	}

	var req Request
	if len(body) > 0 {
		if err := schema.DecodeStrict(body, &req); err != nil {
			return nil, nil, &tools.Error{Code: schema.ErrCodeBadArgument, Message: schema.BoundMessage("firewall_lookup: " + err.Error())}
		}
	}
	if strings.TrimSpace(req.Query) == "" {
		return nil, nil, &tools.Error{Code: schema.ErrCodeBadArgument, Message: "firewall_lookup: query is required"}
	}

	param, err := json.Marshal(struct {
		Query              string `json:"query"`
		IncludeSetElements bool   `json:"include_set_elements"`
	}{
		Query:              req.Query,
		IncludeSetElements: req.IncludeSetElements,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("firewall_lookup: marshal request: %w", err)
	}

	var raw json.RawMessage
	if err := t.hc.CallJSON(ctx, proto.OpFirewallLookup, string(param), &raw); err != nil {
		oe := helperinvoke.OpErrorFrom(err)
		oe.Op = proto.OpFirewallLookup
		d.Errors = append(d.Errors, *oe)
		warnings = append(warnings, "firewall: "+proto.OpFirewallLookup+": "+helperinvoke.CodeOf(err))
		return d, warnings, nil
	}

	var helperRes struct {
		Query          string   `json:"query"`
		QueryKind      string   `json:"query_kind"`
		Matches        []Match  `json:"matches"`
		Sets           []SetHit `json:"sets"`
		SearchedTables int      `json:"searched_tables"`
		SearchedChains int      `json:"searched_chains"`
		SearchedRules  int      `json:"searched_rules"`
		SearchedSets   int      `json:"searched_sets"`
		Warnings       []string `json:"warnings"`
	}
	if err := json.Unmarshal(raw, &helperRes); err != nil {
		return nil, nil, fmt.Errorf("firewall_lookup: parse helper result: %w", err)
	}

	d.Query = helperRes.Query
	d.QueryKind = helperRes.QueryKind
	if helperRes.Matches != nil {
		d.Matches = helperRes.Matches
	}
	if helperRes.Sets != nil {
		d.Sets = helperRes.Sets
	}
	d.SearchedTables = helperRes.SearchedTables
	d.SearchedChains = helperRes.SearchedChains
	d.SearchedRules = helperRes.SearchedRules
	d.SearchedSets = helperRes.SearchedSets
	warnings = append(warnings, helperRes.Warnings...)

	return d, warnings, nil
}
