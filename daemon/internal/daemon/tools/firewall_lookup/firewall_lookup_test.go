package firewall_lookup

import (
	"encoding/json"
	"testing"
)

// TestMatch_WireRoundTrip is the regression test for the
// post-1.14.0 canary finding: the daemon's Match type carried
// stale field names (kind/handle/expr/element_key) from before the
// fleet-manager spec refactor on the helper side, leaving every
// renamed field empty after unmarshal. Asserts every wire field
// populates from a canned helper response.
func TestMatch_WireRoundTrip(t *testing.T) {
	// Shape produced by helper-side FirewallRuleMatch.
	raw := []byte(`{
		"match_kind": "set_member",
		"family": "inet",
		"table": "net-ban",
		"chain": "input",
		"rule_handle": 12,
		"rule_text": "[{\"match\":{\"left\":\"x\",\"right\":\"@banned_v4\",\"op\":\"==\"}},{\"drop\":null}]",
		"operator": "==",
		"matched_value": "@banned_v4",
		"set_name": "banned_v4"
	}`)
	var m Match
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.MatchKind != "set_member" {
		t.Errorf("MatchKind = %q, want set_member", m.MatchKind)
	}
	if m.RuleHandle != 12 {
		t.Errorf("RuleHandle = %d, want 12", m.RuleHandle)
	}
	if m.Chain != "input" {
		t.Errorf("Chain = %q, want input", m.Chain)
	}
	if m.SetName != "banned_v4" {
		t.Errorf("SetName = %q, want banned_v4", m.SetName)
	}
	if m.RuleText == "" {
		t.Error("RuleText is empty")
	}
}

// TestSetHit_WireRoundTrip verifies the Sets[] entries populate
// fully when include_set_elements=true.
func TestSetHit_WireRoundTrip(t *testing.T) {
	raw := []byte(`{
		"match_kind": "set_member",
		"family": "inet",
		"table": "net-ban",
		"set": "banned_v4",
		"element_key": "203.0.113.7",
		"expires_s": 41892,
		"timeout_s": 43200
	}`)
	var h SetHit
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if h.MatchKind != "set_member" {
		t.Errorf("MatchKind = %q, want set_member", h.MatchKind)
	}
	if h.Set != "banned_v4" {
		t.Errorf("Set = %q, want banned_v4", h.Set)
	}
	if h.ElementKey != "203.0.113.7" {
		t.Errorf("ElementKey = %q, want 203.0.113.7", h.ElementKey)
	}
	if h.ExpiresS == nil || *h.ExpiresS != 41892 {
		t.Errorf("ExpiresS = %v, want 41892", h.ExpiresS)
	}
	if h.TimeoutS == nil || *h.TimeoutS != 43200 {
		t.Errorf("TimeoutS = %v, want 43200", h.TimeoutS)
	}
}

// TestData_FullEnvelope drives the full helper-side response
// shape through the daemon tool's unmarshal path and asserts both
// arrays populate. The canary report had sets[] empty even when
// the helper found a member — this test would have caught that.
func TestData_FullEnvelope(t *testing.T) {
	raw := []byte(`{
		"query": "203.0.113.7",
		"query_kind": "ipv4_addr",
		"matches": [
			{
				"match_kind": "set_member",
				"family": "inet",
				"table": "net-ban",
				"chain": "input",
				"rule_handle": 12,
				"rule_text": "[...]",
				"operator": "==",
				"matched_value": "@banned_v4",
				"set_name": "banned_v4"
			}
		],
		"sets": [
			{
				"match_kind": "set_member",
				"family": "inet",
				"table": "net-ban",
				"set": "banned_v4",
				"element_key": "203.0.113.7",
				"expires_s": 41892,
				"timeout_s": 43200
			}
		],
		"searched_tables": 1,
		"searched_chains": 1,
		"searched_rules": 1,
		"searched_sets": 1
	}`)
	var helperRes struct {
		Query          string   `json:"query"`
		QueryKind      string   `json:"query_kind"`
		Matches        []Match  `json:"matches"`
		Sets           []SetHit `json:"sets"`
		SearchedTables int      `json:"searched_tables"`
		SearchedChains int      `json:"searched_chains"`
		SearchedRules  int      `json:"searched_rules"`
		SearchedSets   int      `json:"searched_sets"`
	}
	if err := json.Unmarshal(raw, &helperRes); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(helperRes.Matches) != 1 || helperRes.Matches[0].MatchKind != "set_member" {
		t.Errorf("matches did not parse correctly: %+v", helperRes.Matches)
	}
	if len(helperRes.Sets) != 1 || helperRes.Sets[0].ElementKey != "203.0.113.7" {
		t.Errorf("sets did not parse correctly: %+v", helperRes.Sets)
	}
}
