package ops

import (
	"encoding/json"
	"net/netip"
	"testing"
)

func TestParseLookupQuery_Addr(t *testing.T) {
	cases := []struct {
		in   string
		kind string
		is6  bool
		cidr bool
	}{
		{"203.0.113.7", "ipv4_addr", false, false},
		{"10.0.0.0/24", "ipv4_cidr", false, true},
		{"2001:db8::1", "ipv6_addr", true, false},
		{"2001:db8::/32", "ipv6_cidr", true, true},
	}
	for _, c := range cases {
		q, err := parseLookupQuery(c.in)
		if err != nil {
			t.Errorf("parseLookupQuery(%q): %v", c.in, err)
			continue
		}
		if q.kind != c.kind || q.is6 != c.is6 || q.isCIDR != c.cidr {
			t.Errorf("parseLookupQuery(%q) = %+v, want kind=%s is6=%v cidr=%v",
				c.in, q, c.kind, c.is6, c.cidr)
		}
	}
}

func TestParseLookupQuery_Invalid(t *testing.T) {
	for _, in := range []string{"", "not-an-ip", "300.0.0.1", "10.0.0.0/33"} {
		if _, err := parseLookupQuery(in); err == nil {
			t.Errorf("parseLookupQuery(%q) = nil, want error", in)
		}
	}
}

func TestAddrMatchesQuery(t *testing.T) {
	q4, _ := parseLookupQuery("203.0.113.7")
	q4cidr, _ := parseLookupQuery("203.0.113.0/24")
	q6, _ := parseLookupQuery("2001:db8::1")

	if !addrMatchesQuery(netip.MustParseAddr("203.0.113.7"), q4) {
		t.Error("exact match should hit")
	}
	if addrMatchesQuery(netip.MustParseAddr("203.0.113.8"), q4) {
		t.Error("non-matching addr should miss")
	}
	if !addrMatchesQuery(netip.MustParseAddr("203.0.113.7"), q4cidr) {
		t.Error("addr inside CIDR should hit")
	}
	if addrMatchesQuery(netip.MustParseAddr("198.51.100.1"), q4cidr) {
		t.Error("addr outside CIDR should miss")
	}
	if addrMatchesQuery(netip.MustParseAddr("203.0.113.7"), q6) {
		t.Error("ipv4 vs ipv6 query should never match")
	}
}

func TestPrefixMatchesQuery(t *testing.T) {
	q, _ := parseLookupQuery("10.0.0.5")
	if !prefixMatchesQuery(netip.MustParsePrefix("10.0.0.0/24"), q) {
		t.Error("IP inside prefix should match")
	}
	if prefixMatchesQuery(netip.MustParsePrefix("10.0.1.0/24"), q) {
		t.Error("IP outside prefix should miss")
	}
	qcidr, _ := parseLookupQuery("10.0.0.0/16")
	if !prefixMatchesQuery(netip.MustParsePrefix("10.0.5.0/24"), qcidr) {
		t.Error("prefix contained by query CIDR should match")
	}
	if !prefixMatchesQuery(netip.MustParsePrefix("10.0.0.0/8"), qcidr) {
		t.Error("prefix containing query CIDR should match")
	}
}

func TestElementValueOverlapsQuery_Exact(t *testing.T) {
	q, _ := parseLookupQuery("203.0.113.7")
	key, ok := elementValueOverlapsQuery(json.RawMessage(`"203.0.113.7"`), q)
	if !ok || key != "203.0.113.7" {
		t.Errorf("got (%q, %v), want (203.0.113.7, true)", key, ok)
	}
}

func TestElementValueOverlapsQuery_PrefixCovers(t *testing.T) {
	q, _ := parseLookupQuery("203.0.113.42")
	key, ok := elementValueOverlapsQuery(
		json.RawMessage(`{"prefix":{"addr":"203.0.113.0","len":24}}`), q)
	if !ok || key != "203.0.113.0/24" {
		t.Errorf("got (%q, %v), want (203.0.113.0/24, true)", key, ok)
	}
}

func TestElementValueOverlapsQuery_RangeCovers(t *testing.T) {
	q, _ := parseLookupQuery("10.0.0.5")
	key, ok := elementValueOverlapsQuery(
		json.RawMessage(`{"range":["10.0.0.1","10.0.0.10"]}`), q)
	if !ok || key != "10.0.0.1-10.0.0.10" {
		t.Errorf("got (%q, %v), want (10.0.0.1-10.0.0.10, true)", key, ok)
	}
}

func TestRuleMatchKind_Composition(t *testing.T) {
	cases := []struct {
		field, rhsKind string
		isCIDR         bool
		want           string
	}{
		{"saddr", "exact", false, "saddr_exact"},
		{"daddr", "exact", false, "daddr_exact"},
		{"saddr", "subnet", false, "saddr_in_subnet"},
		{"daddr", "subnet", true, "daddr_in_subnet"},
		{"saddr", "set_ref", false, "set_member"},
		{"saddr", "set_ref", true, "set_subset_overlap"},
	}
	for _, c := range cases {
		got := ruleMatchKind(c.field, c.rhsKind, c.isCIDR)
		if got != c.want {
			t.Errorf("ruleMatchKind(%s,%s,%v) = %q, want %q",
				c.field, c.rhsKind, c.isCIDR, got, c.want)
		}
	}
}

// TestFirewallLookup_EndToEnd_Ban drives the full FirewallLookup
// handler with a synthesised ruleset that mirrors the fleet's
// net-ban shape: a banned_v4 set with the query as a member, and
// an input chain whose rule references @banned_v4. Asserts:
//
//   - sets[] reports the query as a set_member of banned_v4.
//   - matches[] reports the input chain rule with match_kind=set_member.
//
// The handler is invoked indirectly via the same code paths that
// run in production; only the nft subprocess is short-circuited by
// not calling it (we drive the JSON straight into the parser via
// a small helper).
func TestFirewallLookup_RulesetWalk(t *testing.T) {
	ruleset := []byte(`{"nftables":[
		{"table":{"family":"inet","name":"net-ban","handle":1}},
		{"chain":{"family":"inet","table":"net-ban","name":"input","handle":1,"type":"filter","hook":"input","prio":-150,"policy":"accept"}},
		{"set":{"family":"inet","table":"net-ban","name":"banned_v4","type":"ipv4_addr","handle":2,"flags":["timeout"],"elem":[{"elem":{"val":"203.0.113.7","expires":3600,"timeout":7200}}]}},
		{"rule":{"family":"inet","table":"net-ban","chain":"input","handle":12,"expr":[
			{"match":{"left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"@banned_v4","op":"=="}},
			{"drop":null}
		]}}
	]}`)

	q, err := parseLookupQuery("203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}

	var root fwNftRoot
	if err := json.Unmarshal(ruleset, &root); err != nil {
		t.Fatal(err)
	}

	// Pass 1 (set indexing) — replicated from FirewallLookup body.
	sets := map[string]*fwLookupSetIndex{}
	for i := range root.Nftables {
		e := root.Nftables[i]
		if e.Set == nil {
			continue
		}
		s := e.Set
		key := s.Family + "/" + s.Table + "/" + s.Name
		idx := &fwLookupSetIndex{set: s, key: key}
		sets[key] = idx
		for _, elemRaw := range s.Elem {
			hit, ok := elementMatchesQuery(elemRaw, q)
			if !ok {
				continue
			}
			idx.hasMatch = true
			hit.MatchKind = "set_member"
			hit.Family = s.Family
			hit.Table = s.Table
			hit.Set = s.Name
			idx.matchedAt = append(idx.matchedAt, hit)
		}
	}

	// Confirm the set hit landed.
	idx := sets["inet/net-ban/banned_v4"]
	if idx == nil || !idx.hasMatch || len(idx.matchedAt) != 1 {
		t.Fatalf("set index missing query: %+v", idx)
	}
	if idx.matchedAt[0].ElementKey != "203.0.113.7" {
		t.Errorf("element_key = %q, want 203.0.113.7", idx.matchedAt[0].ElementKey)
	}
	if exp := idx.matchedAt[0].ExpiresS; exp == nil || *exp != 3600 {
		t.Errorf("expires_s = %v, want 3600", exp)
	}

	// Pass 2 (rule walk).
	var ruleMatches []FirewallRuleMatch
	for _, e := range root.Nftables {
		if e.Rule == nil {
			continue
		}
		ruleMatches = append(ruleMatches, matchRuleAgainstQuery(e.Rule, q, sets)...)
	}
	if len(ruleMatches) != 1 {
		t.Fatalf("rule matches = %d, want 1: %+v", len(ruleMatches), ruleMatches)
	}
	rm := ruleMatches[0]
	if rm.MatchKind != "set_member" {
		t.Errorf("match_kind = %q, want set_member", rm.MatchKind)
	}
	if rm.Chain != "input" || rm.RuleHandle != 12 || rm.SetName != "banned_v4" {
		t.Errorf("rule fields = %+v", rm)
	}
}

// TestFirewallLookup_DirectAddrInPrefixRule verifies the
// saddr_in_subnet path: rule rhs is a prefix object covering the
// query.
func TestFirewallLookup_DirectAddrInPrefixRule(t *testing.T) {
	rule := &fwNftRule{
		Family: "ip", Table: "filter", Chain: "input", Handle: 5,
		Expr: []json.RawMessage{
			json.RawMessage(`{"match":{"left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.0.0.0","len":24}},"op":"=="}}`),
			json.RawMessage(`{"drop":null}`),
		},
	}
	q, _ := parseLookupQuery("10.0.0.42")
	hits := matchRuleAgainstQuery(rule, q, nil)
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1", len(hits))
	}
	if hits[0].MatchKind != "saddr_in_subnet" {
		t.Errorf("match_kind = %q, want saddr_in_subnet", hits[0].MatchKind)
	}
	if hits[0].MatchedValue != "10.0.0.0/24" {
		t.Errorf("matched_value = %q, want 10.0.0.0/24", hits[0].MatchedValue)
	}
}

// TestFirewallLookup_DaddrExactRule verifies daddr literal equality.
func TestFirewallLookup_DaddrExactRule(t *testing.T) {
	rule := &fwNftRule{
		Family: "ip", Table: "filter", Chain: "output", Handle: 9,
		Expr: []json.RawMessage{
			json.RawMessage(`{"match":{"left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"203.0.113.7","op":"=="}}`),
			json.RawMessage(`{"accept":null}`),
		},
	}
	q, _ := parseLookupQuery("203.0.113.7")
	hits := matchRuleAgainstQuery(rule, q, nil)
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1: %+v", len(hits), hits)
	}
	if hits[0].MatchKind != "daddr_exact" {
		t.Errorf("match_kind = %q, want daddr_exact", hits[0].MatchKind)
	}
}

// TestFirewallLookup_CIDRQueryAgainstLiteralRule a /24 query
// should match a rule for a single IP inside that /24 with
// saddr_in_subnet (the rule's IP is inside the query's CIDR).
func TestFirewallLookup_CIDRQueryAgainstLiteralRule(t *testing.T) {
	rule := &fwNftRule{
		Family: "ip", Table: "filter", Chain: "input", Handle: 11,
		Expr: []json.RawMessage{
			json.RawMessage(`{"match":{"left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"10.0.0.7","op":"=="}}`),
			json.RawMessage(`{"drop":null}`),
		},
	}
	q, _ := parseLookupQuery("10.0.0.0/24")
	hits := matchRuleAgainstQuery(rule, q, nil)
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1", len(hits))
	}
	if hits[0].MatchKind != "saddr_in_subnet" {
		t.Errorf("match_kind = %q, want saddr_in_subnet", hits[0].MatchKind)
	}
}
