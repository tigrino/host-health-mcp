package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"host-health-mcp/daemon/internal/helper/dispatch"
	helperexec "host-health-mcp/daemon/internal/helper/exec"
	"host-health-mcp/daemon/internal/shared/proto"
)

// FirewallLookupReq is the JSON the daemon serialises as the helper
// op param for OpFirewallLookup.
type FirewallLookupReq struct {
	Query              string `json:"query"`
	IncludeSetElements bool   `json:"include_set_elements"`
}

// FirewallLookupResult is the helper-to-daemon payload for the
// lookup op. matches[] carries rule hits; sets[] carries set/map
// element hits — keeping them parallel matches the fleet-manager
// usage pattern of "show me the rules" vs. "show me which set
// contains it." The searched_* counters distinguish "no matches
// because nothing matched" from "no matches because the ruleset
// was empty."
type FirewallLookupResult struct {
	Query          string               `json:"query"`
	QueryKind      string               `json:"query_kind"`
	Matches        []FirewallRuleMatch  `json:"matches"`
	Sets           []FirewallSetHit     `json:"sets"`
	SearchedTables int                  `json:"searched_tables"`
	SearchedChains int                  `json:"searched_chains"`
	SearchedRules  int                  `json:"searched_rules"`
	SearchedSets   int                  `json:"searched_sets"`
	Warnings       []string             `json:"warnings,omitempty"`
}

// FirewallRuleMatch is one rule hit. MatchKind is the discriminated
// enum:
//
//   - saddr_exact / daddr_exact: rule literal IP test, query equals
//     the literal.
//   - saddr_in_subnet / daddr_in_subnet: rule tests against a
//     prefix or anonymous-set member that contains the query (for
//     an IP query) or overlaps it (for a CIDR query).
//   - set_member: rule references @setname and the query is a
//     single-address member.
//   - set_subset_overlap: rule references @setname and the query
//     (a CIDR) overlaps one or more members of the set.
//
// rule_text is the compact JSON encoding of nftables' expression
// array — see the host_firewall tool docs for why nft's text form
// is not synthesised.
type FirewallRuleMatch struct {
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

// FirewallSetHit is one set/map element hit. MatchKind is one of:
//
//   - set_member: query is a single-address match for an element.
//   - set_subset_overlap: query (a CIDR) overlaps with a prefix /
//     range element.
type FirewallSetHit struct {
	MatchKind  string `json:"match_kind"`
	Family     string `json:"family"`
	Table      string `json:"table"`
	Set        string `json:"set"`
	ElementKey string `json:"element_key"`
	ExpiresS   *int64 `json:"expires_s,omitempty"`
	TimeoutS   *int64 `json:"timeout_s,omitempty"`
}

// FirewallLookup is the helper handler. The caller passes a query
// (either an IP or a CIDR) and the op scans the full nftables
// ruleset to find:
//
//   1. Set elements that match (the query is contained by a member
//      address/prefix, or vice versa for CIDR queries).
//   2. Rules whose `match` expression on ip{,6} saddr/daddr names a
//      value (IP, prefix, or anonymous set) that contains/is
//      contained by the query.
//   3. Rules referencing a named set via @setname where the query is
//      a member of that set.
//
// Matching is bidirectional for CIDR queries: a /24 query matches a
// rule for 203.0.113.7 and vice versa. The intent is "show me
// every place in the firewall where this address could be evaluated."
func FirewallLookup(ctx context.Context, paramJSON string) (any, error) {
	var req FirewallLookupReq
	if paramJSON != "" {
		if err := json.Unmarshal([]byte(paramJSON), &req); err != nil {
			return nil, &dispatch.Error{
				Code:    proto.CodeBadParam,
				Message: "firewall_lookup: param: " + err.Error(),
			}
		}
	}
	if strings.TrimSpace(req.Query) == "" {
		return nil, &dispatch.Error{
			Code:    proto.CodeBadParam,
			Message: "firewall_lookup: empty query",
		}
	}

	q, err := parseLookupQuery(req.Query)
	if err != nil {
		return nil, &dispatch.Error{
			Code:    proto.CodeBadParam,
			Message: "firewall_lookup: " + err.Error(),
		}
	}

	res := FirewallLookupResult{
		Query:     req.Query,
		QueryKind: q.kind,
		Matches:   []FirewallRuleMatch{},
		Sets:      []FirewallSetHit{},
	}

	raw, truncated, err := helperexec.RunCapped(ctx, firewallRulesetCap, "nft", "-j", "list", "ruleset")
	if err != nil {
		var de *dispatch.Error
		if errors.As(err, &de) && de.Code == proto.CodeToolMissing {
			res.Warnings = append(res.Warnings, "firewall: nft not installed")
			return res, nil
		}
		return nil, err
	}
	if truncated {
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("firewall: nft list ruleset exceeded %d bytes; lookup scanned the prefix only", firewallRulesetCap))
	}

	var root fwNftRoot
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, &dispatch.Error{
			Code:    proto.CodeToolFailed,
			Message: "firewall_lookup: parse nft -j: " + err.Error(),
			Argv:    []string{"nft", "-j", "list", "ruleset"},
		}
	}

	// Pass 1: index sets and which of them contain the query.
	// Tracks: setKey -> set metadata + matched element entries to
	// emit (if include_set_elements) and a hasMatch flag the rule
	// walker reads to decide @setname references.
	sets := map[string]*fwLookupSetIndex{}
	for i := range root.Nftables {
		e := root.Nftables[i]
		var s *fwNftSet
		if e.Set != nil {
			s = e.Set
		} else if e.Map != nil {
			s = e.Map
		}
		if s == nil {
			continue
		}
		key := s.Family + "/" + s.Table + "/" + s.Name
		typeStr := stringifyType(s.Type)
		idx := &fwLookupSetIndex{set: s, key: key}
		sets[key] = idx
		res.SearchedSets++

		// Address-family pre-filter: skip sets whose element family
		// doesn't match the query's. ipv6_addr sets never hit an
		// ipv4 query, and vice versa.
		if !setTypeMatchesQuery(typeStr, q) {
			continue
		}

		for _, elemRaw := range s.Elem {
			hit, ok := elementMatchesQuery(elemRaw, q)
			if !ok {
				continue
			}
			idx.hasMatch = true
			// Distinguish single-address match vs CIDR-overlap.
			// element_key carries '/', '-', or neither — for a
			// non-CIDR query, only single-addr keys produce
			// set_member; for a CIDR query, anything that
			// overlaps produces set_subset_overlap (we
			// can't claim "exact" with a CIDR query against a
			// set element).
			if q.isCIDR {
				hit.MatchKind = "set_subset_overlap"
			} else if strings.ContainsAny(hit.ElementKey, "/-") {
				hit.MatchKind = "set_subset_overlap"
			} else {
				hit.MatchKind = "set_member"
			}
			hit.Family = s.Family
			hit.Table = s.Table
			hit.Set = s.Name
			if req.IncludeSetElements {
				idx.matchedAt = append(idx.matchedAt, hit)
			}
		}
	}

	// Emit set-element hits if requested. Done before rule
	// matches so the consumer can render the sets[] view first.
	if req.IncludeSetElements {
		keys := make([]string, 0, len(sets))
		for k := range sets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			res.Sets = append(res.Sets, sets[k].matchedAt...)
		}
	}

	// Pass 2: walk rules. For each rule, look at match expressions
	// against ip{,6} saddr/daddr. Direct hits and set-reference
	// hits both produce rule matches.
	tableSeen := map[string]bool{}
	chainSeen := map[string]bool{}
	for _, e := range root.Nftables {
		if e.Table != nil {
			tableSeen[e.Table.Family+"/"+e.Table.Name] = true
			continue
		}
		if e.Chain != nil {
			chainSeen[e.Chain.Family+"/"+e.Chain.Table+"/"+e.Chain.Name] = true
			continue
		}
		if e.Rule == nil {
			continue
		}
		r := e.Rule
		res.SearchedRules++
		ruleMatches := matchRuleAgainstQuery(r, q, sets)
		res.Matches = append(res.Matches, ruleMatches...)
	}
	res.SearchedTables = len(tableSeen)
	res.SearchedChains = len(chainSeen)

	return res, nil
}

// lookupQuery is the parsed form of the caller's input. Either Addr
// or Prefix is set, never both.
type lookupQuery struct {
	kind   string // "ipv4_addr" | "ipv6_addr" | "ipv4_cidr" | "ipv6_cidr"
	addr   netip.Addr
	prefix netip.Prefix
	is6    bool
	isCIDR bool
}

func parseLookupQuery(s string) (lookupQuery, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return lookupQuery{}, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		p = p.Masked()
		kind := "ipv4_cidr"
		if p.Addr().Is6() {
			kind = "ipv6_cidr"
		}
		return lookupQuery{kind: kind, prefix: p, is6: p.Addr().Is6(), isCIDR: true}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return lookupQuery{}, fmt.Errorf("invalid address %q: %w", s, err)
	}
	kind := "ipv4_addr"
	if a.Is6() {
		kind = "ipv6_addr"
	}
	return lookupQuery{kind: kind, addr: a, is6: a.Is6()}, nil
}

// setTypeMatchesQuery returns true when the set's element family
// can plausibly contain matches for the query. Concat types are
// matched on the first component; mixed-family sets are skipped.
func setTypeMatchesQuery(setType string, q lookupQuery) bool {
	if setType == "" {
		return false
	}
	first := setType
	if i := strings.Index(setType, "."); i > 0 {
		first = setType[:i]
	}
	switch first {
	case "ipv4_addr":
		return !q.is6
	case "ipv6_addr":
		return q.is6
	}
	return false
}

// elementMatchesQuery tests one set element value against the query.
// Returns the hit metadata (ElementKey, ExpiresS, TimeoutS) and
// whether a match was found. The caller sets MatchKind. Element
// values can be:
//
//   - bare string (single addr)
//   - {prefix: {addr, len}}
//   - {range: [lo, hi]}
//   - {elem: {val, expires, timeout}} wrapping any of the above
func elementMatchesQuery(raw json.RawMessage, q lookupQuery) (FirewallSetHit, bool) {
	val, expires, timeout := unwrapElem(raw)
	keyStr, ok := elementValueOverlapsQuery(val, q)
	if !ok {
		return FirewallSetHit{}, false
	}
	hit := FirewallSetHit{ElementKey: keyStr}
	if expires != nil {
		hit.ExpiresS = expires
	}
	if timeout != nil {
		hit.TimeoutS = timeout
	}
	return hit, true
}

// unwrapElem peels the optional {"elem": {...}} wrapper.
func unwrapElem(raw json.RawMessage) (val json.RawMessage, expires *int64, timeout *int64) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return raw, nil, nil
	}
	inner, ok := obj["elem"]
	if !ok {
		return raw, nil, nil
	}
	var in struct {
		Val     json.RawMessage `json:"val"`
		Expires *int64          `json:"expires"`
		Timeout *int64          `json:"timeout"`
	}
	if err := json.Unmarshal(inner, &in); err != nil {
		return inner, nil, nil
	}
	return in.Val, in.Expires, in.Timeout
}

// elementValueOverlapsQuery checks whether the element value covers
// the query (or vice versa for CIDR queries). Returns the human-
// readable key and a match flag.
func elementValueOverlapsQuery(val json.RawMessage, q lookupQuery) (string, bool) {
	if len(val) == 0 {
		return "", false
	}
	// Single address.
	var asString string
	if err := json.Unmarshal(val, &asString); err == nil {
		a, err := netip.ParseAddr(asString)
		if err != nil {
			return "", false
		}
		if addrMatchesQuery(a, q) {
			return asString, true
		}
		return "", false
	}
	var asObj map[string]json.RawMessage
	if err := json.Unmarshal(val, &asObj); err != nil {
		return "", false
	}
	if p, ok := asObj["prefix"]; ok {
		var pf struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		}
		if err := json.Unmarshal(p, &pf); err == nil {
			pre, err := netip.ParsePrefix(pf.Addr + "/" + fmt.Sprint(pf.Len))
			if err == nil && prefixMatchesQuery(pre, q) {
				return fmt.Sprintf("%s/%d", pf.Addr, pf.Len), true
			}
		}
	}
	if r, ok := asObj["range"]; ok {
		var rng []string
		if err := json.Unmarshal(r, &rng); err == nil && len(rng) == 2 {
			lo, errLo := netip.ParseAddr(rng[0])
			hi, errHi := netip.ParseAddr(rng[1])
			if errLo == nil && errHi == nil && rangeMatchesQuery(lo, hi, q) {
				return rng[0] + "-" + rng[1], true
			}
		}
	}
	return "", false
}

// addrMatchesQuery: does a single address overlap with the query?
func addrMatchesQuery(a netip.Addr, q lookupQuery) bool {
	if a.Is6() != q.is6 {
		return false
	}
	if q.isCIDR {
		return q.prefix.Contains(a)
	}
	return a == q.addr
}

// prefixMatchesQuery: does a prefix overlap with the query? For an
// IP query, "contains the IP". For a CIDR query, "either covers the
// other or they overlap" — formally, the two prefixes share at
// least one address.
func prefixMatchesQuery(p netip.Prefix, q lookupQuery) bool {
	if p.Addr().Is6() != q.is6 {
		return false
	}
	p = p.Masked()
	if q.isCIDR {
		qp := q.prefix
		// They overlap iff one contains the other's network addr.
		return p.Contains(qp.Addr()) || qp.Contains(p.Addr())
	}
	return p.Contains(q.addr)
}

// rangeMatchesQuery: does the range [lo, hi] overlap with the query?
// netip.Addr supports Compare for ordering.
func rangeMatchesQuery(lo, hi netip.Addr, q lookupQuery) bool {
	if lo.Is6() != q.is6 || hi.Is6() != q.is6 {
		return false
	}
	if q.isCIDR {
		// Range overlaps prefix iff range's hi >= prefix's first
		// addr AND range's lo <= prefix's last addr. We approximate
		// "last addr of prefix" by checking whether the range
		// contains either endpoint of the prefix OR the prefix
		// contains either endpoint of the range.
		if q.prefix.Contains(lo) || q.prefix.Contains(hi) {
			return true
		}
		// And the inverse: query inside range.
		return q.prefix.Addr().Compare(lo) >= 0 && q.prefix.Addr().Compare(hi) <= 0
	}
	return q.addr.Compare(lo) >= 0 && q.addr.Compare(hi) <= 0
}

// fwLookupSetIndex tracks per-set lookup state during a single
// FirewallLookup invocation. Package-scoped so the rule walker
// helpers (matchRuleAgainstQuery, evaluateRightSide) can reference
// it across files / functions.
type fwLookupSetIndex struct {
	set       *fwNftSet
	key       string // "family/table/name"
	matchedAt []FirewallSetHit
	hasMatch  bool
}

// matchRuleAgainstQuery walks one rule's expressions and emits
// FirewallRuleMatch entries for every saddr/daddr test that
// references (or covers, via a set membership) the query.
// Multiple matches per rule are possible — e.g. saddr and daddr
// both match — each becomes its own entry.
func matchRuleAgainstQuery(r *fwNftRule, q lookupQuery, sets map[string]*fwLookupSetIndex) []FirewallRuleMatch {
	exprBytes, _ := json.Marshal(r.Expr)
	exprStr := string(exprBytes)
	var matches []FirewallRuleMatch
	for _, raw := range r.Expr {
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(raw, &probe); err != nil {
			continue
		}
		matchRaw, ok := probe["match"]
		if !ok {
			continue
		}
		var m struct {
			Left  json.RawMessage `json:"left"`
			Right json.RawMessage `json:"right"`
			Op    string          `json:"op"`
		}
		if err := json.Unmarshal(matchRaw, &m); err != nil {
			continue
		}
		field := ipPayloadField(m.Left)
		if field != "saddr" && field != "daddr" {
			continue
		}
		hits := evaluateRightSide(m.Right, q, r.Family, r.Table, sets)
		for _, hit := range hits {
			hit.MatchKind = ruleMatchKind(field, hit.kind, q.isCIDR)
			hit.Family = r.Family
			hit.Table = r.Table
			hit.Chain = r.Chain
			hit.RuleHandle = r.Handle
			hit.RuleText = exprStr
			hit.Operator = m.Op
			matches = append(matches, hit.FirewallRuleMatch)
		}
	}
	return matches
}

// ruleMatchKind composes the discriminated match_kind enum from
// (field, rhs kind, isCIDR).
func ruleMatchKind(field, rhsKind string, queryIsCIDR bool) string {
	switch rhsKind {
	case "set_ref":
		if queryIsCIDR {
			return "set_subset_overlap"
		}
		return "set_member"
	case "exact":
		if field == "saddr" {
			return "saddr_exact"
		}
		return "daddr_exact"
	case "subnet":
		if field == "saddr" {
			return "saddr_in_subnet"
		}
		return "daddr_in_subnet"
	}
	return rhsKind
}

// ipPayloadField returns "saddr" or "daddr" if left is a payload
// expression on ip / ip6 source/destination, else "".
func ipPayloadField(left json.RawMessage) string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(left, &obj); err != nil {
		return ""
	}
	p, ok := obj["payload"]
	if !ok {
		return ""
	}
	var pl struct {
		Protocol string `json:"protocol"`
		Field    string `json:"field"`
	}
	if err := json.Unmarshal(p, &pl); err != nil {
		return ""
	}
	if pl.Protocol != "ip" && pl.Protocol != "ip6" {
		return ""
	}
	return pl.Field
}

// ruleHit is the partial form evaluateRightSide returns; the
// caller (matchRuleAgainstQuery) fills in family/table/chain/handle
// and translates `kind` into the wire-level MatchKind via
// ruleMatchKind. kind is one of: "exact", "subnet", "set_ref".
type ruleHit struct {
	FirewallRuleMatch
	kind string
}

// evaluateRightSide tests every shape the right-hand side of a
// match can take: a literal address, a prefix object, a range, a
// named-set reference (@setname), or an anonymous set
// ({"set":[...elements...]}). Returns one or more partial hits;
// the caller composes the final MatchKind from (field, rhs kind,
// query type).
func evaluateRightSide(right json.RawMessage, q lookupQuery, family, table string, sets map[string]*fwLookupSetIndex) []ruleHit {
	if len(right) == 0 {
		return nil
	}
	// String: either a literal IP or a "@setname" reference.
	var asString string
	if err := json.Unmarshal(right, &asString); err == nil {
		if strings.HasPrefix(asString, "@") {
			setName := asString[1:]
			key := family + "/" + table + "/" + setName
			if idx, ok := sets[key]; ok && idx.hasMatch {
				return []ruleHit{{
					FirewallRuleMatch: FirewallRuleMatch{
						SetName:      setName,
						MatchedValue: asString,
					},
					kind: "set_ref",
				}}
			}
			return nil
		}
		if a, err := netip.ParseAddr(asString); err == nil && addrMatchesQuery(a, q) {
			// Literal IP equality (or contained-by, for a CIDR
			// query against a single-addr rhs). A CIDR query
			// containing a single rhs IP is an "in_subnet"
			// match — the rule's IP falls within our query.
			k := "exact"
			if q.isCIDR {
				k = "subnet"
			}
			return []ruleHit{{
				FirewallRuleMatch: FirewallRuleMatch{MatchedValue: asString},
				kind:              k,
			}}
		}
		return nil
	}
	// Object: prefix or anonymous set or range.
	var asObj map[string]json.RawMessage
	if err := json.Unmarshal(right, &asObj); err == nil {
		if p, ok := asObj["prefix"]; ok {
			var pf struct {
				Addr string `json:"addr"`
				Len  int    `json:"len"`
			}
			if err := json.Unmarshal(p, &pf); err == nil {
				pre, perr := netip.ParsePrefix(pf.Addr + "/" + fmt.Sprint(pf.Len))
				if perr == nil && prefixMatchesQuery(pre, q) {
					return []ruleHit{{
						FirewallRuleMatch: FirewallRuleMatch{
							MatchedValue: fmt.Sprintf("%s/%d", pf.Addr, pf.Len),
						},
						kind: "subnet",
					}}
				}
			}
		}
		if setArr, ok := asObj["set"]; ok {
			var members []json.RawMessage
			if err := json.Unmarshal(setArr, &members); err == nil {
				for _, mv := range members {
					if keyStr, hit := elementValueOverlapsQuery(mv, q); hit {
						k := "exact"
						if strings.ContainsAny(keyStr, "/-") || q.isCIDR {
							k = "subnet"
						}
						return []ruleHit{{
							FirewallRuleMatch: FirewallRuleMatch{MatchedValue: keyStr},
							kind:              k,
						}}
					}
				}
			}
		}
		if r, ok := asObj["range"]; ok {
			var rng []string
			if err := json.Unmarshal(r, &rng); err == nil && len(rng) == 2 {
				lo, errLo := netip.ParseAddr(rng[0])
				hi, errHi := netip.ParseAddr(rng[1])
				if errLo == nil && errHi == nil && rangeMatchesQuery(lo, hi, q) {
					return []ruleHit{{
						FirewallRuleMatch: FirewallRuleMatch{MatchedValue: rng[0] + "-" + rng[1]},
						kind:              "subnet",
					}}
				}
			}
		}
	}
	return nil
}
