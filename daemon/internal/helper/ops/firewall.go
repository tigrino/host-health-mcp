package ops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"host-health-mcp/daemon/internal/helper/dispatch"
	helperexec "host-health-mcp/daemon/internal/helper/exec"
	"host-health-mcp/daemon/internal/shared/proto"
)

// firewallRulesetCap bounds the bytes the helper will accumulate
// from `nft -j list ruleset`. Modern nft userspace prints the
// whole document as one JSON line, so RunStreaming's line scanner
// (MaxLineLength = 64 KiB) cannot read it — we use RunCapped
// instead. Sized for fleets with 70k-element ban sets:
//
//	70 000 elements * ~110 bytes (val + timeout + expires) ≈ 7.7 MiB
//
// 32 MiB gives well over an order-of-magnitude headroom. Helper
// is root, called at 30 s TTL, infrequent — the memory cost is
// bounded per call and trivial in absolute terms.
const firewallRulesetCap = 32 * 1024 * 1024

// firewallSetListCap bounds the per-set `nft -j list set` output.
// Even a single 69k-entry set fits well under 16 MiB.
const firewallSetListCap = 16 * 1024 * 1024

// firewallHardElemCap is the absolute ceiling on set elements the
// helper returns INLINE per set, regardless of the manifest's
// max_set_elements_per_set. Bounded so a misconfigured manifest
// cannot push the helper→daemon response over MaxResponseFrame
// (4 MiB in schema 0.5.0). 40 000 ipv4_addr entries with
// timeout/expires ≈ 90 bytes each ≈ 3.6 MiB; leaves room for
// metadata of every other table/chain/set.
const firewallHardElemCap = 40000

// firewallElemBudget is the total inline elements (across every
// reported set) the helper will include. Beyond this, sets get
// elements_truncated=true and only counts remain. Sized so the
// serialised response stays under MaxResponseFrame on pathological
// inputs (an operator naming 10 ban_sets all with full inclusion
// would otherwise sum past the frame cap).
const firewallElemBudget = 40000

// firewallHardRuleTextCap is the absolute ceiling on the per-chain rule
// text budget, regardless of the manifest's max_rule_text_bytes. That
// key had a floor (<= 0 becomes 65536) but no ceiling, so an operator
// setting it arbitrarily high removed the only bound on inline rules
// per chain and could push the response past MaxResponseFrame — which
// the helper reports as a dropped connection with no diagnostic. 1 MiB
// is 16x the default and still leaves frame headroom.
const firewallHardRuleTextCap = 1024 * 1024

// FirewallReq mirrors the daemon's encoded request param.
type FirewallReq struct {
	Mode               string           `json:"mode"`
	TableFilter        string           `json:"table_filter"`
	IncludeSetElements bool             `json:"include_set_elements"`
	DetailModeAllowed  bool             `json:"detail_mode_allowed"`
	BanSets            []FirewallBanSet `json:"ban_sets"`
	MaxSetElements     int              `json:"max_set_elements"`
	MaxRuleTextBytes   int              `json:"max_rule_text_bytes"`
}

// FirewallBanSet names one nftables set surfaced as a ban source.
type FirewallBanSet struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Source string `json:"source"`
}

// FirewallResult is the helper-to-daemon payload. Mirrors the daemon
// tool's response data block; the daemon attaches structured errors
// and rate-limiter accounting on top.
type FirewallResult struct {
	Backend           string                 `json:"backend"`
	NftVersion        string                 `json:"nft_version,omitempty"`
	RulesetHashSHA256 string                 `json:"ruleset_hash_sha256,omitempty"`
	Tables            []FirewallTableMeta    `json:"tables"`
	Chains            []FirewallChain        `json:"chains"`
	Sets              []FirewallSet          `json:"sets"`
	Bans              FirewallBans           `json:"bans"`
	Warnings          []string               `json:"warnings,omitempty"`
}

// FirewallTableMeta is one entry in result.tables.
type FirewallTableMeta struct {
	Family     string `json:"family"`
	Name       string `json:"name"`
	ChainCount int    `json:"chain_count"`
	SetCount   int    `json:"set_count"`
	MapCount   int    `json:"map_count"`
	RuleCount  int    `json:"rule_count"`
}

// FirewallChain is one chain. Rules is populated only in detail mode.
type FirewallChain struct {
	Family    string         `json:"family"`
	Table     string         `json:"table"`
	Name      string         `json:"name"`
	Type      string         `json:"type,omitempty"`
	Hook      string         `json:"hook,omitempty"`
	Prio      *int           `json:"prio,omitempty"`
	Policy    string         `json:"policy,omitempty"`
	RuleCount int            `json:"rule_count"`
	Rules     []FirewallRule `json:"rules,omitempty"`
}

// FirewallRule renders one rule. Expr is the compact JSON encoding
// of nftables' expression array; the helper does not attempt to
// reconstruct nft's text rendering (that would require a parser
// re-implementing the userspace nft printer). Plugins / clients
// that want a human form can either decode the JSON or call `nft
// list ruleset` directly on the host.
type FirewallRule struct {
	Handle  int              `json:"handle"`
	Expr    string           `json:"expr"`
	Counter *FirewallCounter `json:"counter,omitempty"`
}

// FirewallCounter is the counter expression pulled out of expr[].
type FirewallCounter struct {
	Packets int64 `json:"packets"`
	Bytes   int64 `json:"bytes"`
}

// FirewallSet is one set or map.
type FirewallSet struct {
	Family            string            `json:"family"`
	Table             string            `json:"table"`
	Name              string            `json:"name"`
	Type              string            `json:"type"`
	Flags             []string          `json:"flags,omitempty"`
	SizeLimit         int               `json:"size_limit,omitempty"`
	ElementCount      int               `json:"element_count"`
	Elements          []FirewallSetElem `json:"elements,omitempty"`
	ElementsTruncated bool              `json:"elements_truncated,omitempty"`
	IsMap             bool              `json:"is_map,omitempty"`
}

// FirewallSetElem is one element of a set. Key is the rendered
// member ("203.0.113.7", "203.0.113.0/24", "10.0.0.1-10.0.0.10").
// expires_s and timeout_s are present only on timeout-flagged sets.
type FirewallSetElem struct {
	Key      string `json:"key"`
	ExpiresS *int64 `json:"expires_s,omitempty"`
	TimeoutS *int64 `json:"timeout_s,omitempty"`
}

// FirewallBans is the synthesized convenience view that maps the
// manifest's ban_sets onto the live set counts.
type FirewallBans struct {
	TotalActiveV4 int                  `json:"total_active_v4"`
	TotalActiveV6 int                  `json:"total_active_v6"`
	BySet         []FirewallBanSetStat `json:"by_set"`
}

// FirewallBanSetStat is one row of bans.by_set.
type FirewallBanSetStat struct {
	Set    string `json:"set"`
	Count  int    `json:"count"`
	Source string `json:"source"`
}

// FirewallInspect is the helper op handler for op firewall_inspect.
// The daemon's param is the JSON-encoded FirewallReq above.
//
// The op runs `nft -j list ruleset` to extract structured metadata
// (tables, chains, sets, rule counts). The raw bytes are sha256-
// hashed for fleet-diff use. Rule bodies are populated only in
// detail mode and only when the manifest permits it. Set elements
// are populated only when explicitly requested.
//
// Backend detection: nftables is the primary path. If nft is not
// installed or returns no tables, the op returns
// backend="none" rather than fabricating iptables enumeration —
// the fleet's policy is nftables-only and an iptables-legacy
// fallback is intentionally deferred. Any future iptables backend
// must arrive as its own op, not as a quiet branch here.
func FirewallInspect(ctx context.Context, paramJSON string) (any, error) {
	var req FirewallReq
	if paramJSON != "" {
		if err := json.Unmarshal([]byte(paramJSON), &req); err != nil {
			return nil, &dispatch.Error{
				Code:    proto.CodeBadParam,
				Message: "firewall_inspect: param: " + err.Error(),
			}
		}
	}
	if req.MaxSetElements <= 0 {
		req.MaxSetElements = 2000
	}
	if req.MaxRuleTextBytes <= 0 {
		req.MaxRuleTextBytes = 65536
	}
	if req.MaxSetElements > firewallHardElemCap {
		req.MaxSetElements = firewallHardElemCap
	}
	if req.MaxRuleTextBytes > firewallHardRuleTextCap {
		req.MaxRuleTextBytes = firewallHardRuleTextCap
	}

	res := FirewallResult{
		Tables:   []FirewallTableMeta{},
		Chains:   []FirewallChain{},
		Sets:     []FirewallSet{},
		Bans:     FirewallBans{BySet: []FirewallBanSetStat{}},
	}

	rawBytes, truncated, err := runNftListRuleset(ctx)
	if err != nil {
		var de *dispatch.Error
		if errors.As(err, &de) && de.Code == proto.CodeToolMissing {
			res.Backend = "none"
			res.Warnings = append(res.Warnings, "firewall: nft not installed")
			return res, nil
		}
		return nil, err
	}
	if truncated {
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("firewall: nft list ruleset output exceeded %d bytes; parsing the prefix only", firewallRulesetCap))
	}

	// Hash the raw nft -j bytes (the truncation flag is reflected in
	// the warning). Operators verifying drift across hosts must use
	// the JSON form of the command, not `nft list ruleset` — that
	// distinction is documented in tools.md.
	sum := sha256.Sum256(rawBytes)
	res.RulesetHashSHA256 = hex.EncodeToString(sum[:])

	if v, vErr := runNftVersion(ctx); vErr == nil {
		res.NftVersion = v
	}

	tableMeta := map[string]*FirewallTableMeta{} // key = family/name
	chainsByTable := map[string]map[string]*FirewallChain{}
	sets := map[string]*FirewallSet{} // key = family/table/name

	type tableFilter struct {
		family, name string
	}
	var filter *tableFilter
	if req.TableFilter != "" {
		// Fail closed. Leaving filter nil on an unparseable value made
		// keep() return true for everything, so a malformed filter
		// widened the response to the entire ruleset instead of
		// narrowing it. The daemon validates this too; this is the
		// second layer.
		family, name, ok := strings.Cut(req.TableFilter, "/")
		if !ok || family == "" || name == "" {
			return FirewallResult{}, &dispatch.Error{
				Code:    proto.CodeBadParam,
				Message: "firewall_inspect: table_filter must be \"<family>/<name>\"",
			}
		}
		filter = &tableFilter{family: family, name: name}
	}

	keep := func(family, name string) bool {
		if filter == nil {
			return true
		}
		return filter.family == family && filter.name == name
	}

	detail := req.Mode == "detail" && req.DetailModeAllowed
	if req.Mode == "detail" && !req.DetailModeAllowed {
		res.Warnings = append(res.Warnings, "firewall: detail mode disabled in manifest; returning summary metadata only")
	}

	if err := walkNftRuleset(rawBytes, func(entry fwNftEntry) {
		switch {
		case entry.Table != nil:
			t := entry.Table
			if !keep(t.Family, t.Name) {
				return
			}
			key := t.Family + "/" + t.Name
			tableMeta[key] = &FirewallTableMeta{Family: t.Family, Name: t.Name}
		case entry.Chain != nil:
			c := entry.Chain
			if !keep(c.Family, c.Table) {
				return
			}
			key := c.Family + "/" + c.Table
			if _, ok := chainsByTable[key]; !ok {
				chainsByTable[key] = map[string]*FirewallChain{}
			}
			chain := &FirewallChain{
				Family: c.Family, Table: c.Table, Name: c.Name,
				Type: c.Type, Hook: c.Hook, Policy: c.Policy,
			}
			if c.Prio != nil {
				p := *c.Prio
				chain.Prio = &p
			}
			chainsByTable[key][c.Name] = chain
			if tm := tableMeta[key]; tm != nil {
				tm.ChainCount++
			}
		case entry.Rule != nil:
			r := entry.Rule
			if !keep(r.Family, r.Table) {
				return
			}
			key := r.Family + "/" + r.Table
			tm := tableMeta[key]
			if tm != nil {
				tm.RuleCount++
			}
			if chains, ok := chainsByTable[key]; ok {
				if chain, ok := chains[r.Chain]; ok {
					chain.RuleCount++
					if detail && len(chain.Rules)*128 < req.MaxRuleTextBytes {
						chain.Rules = append(chain.Rules, renderRule(r))
					}
				}
			}
		case entry.Set != nil, entry.Map != nil:
			s := entry.Set
			isMap := false
			if s == nil {
				s = entry.Map
				isMap = true
			}
			if !keep(s.Family, s.Table) {
				return
			}
			key := s.Family + "/" + s.Table
			setKey := key + "/" + s.Name
			meta := &FirewallSet{
				Family: s.Family, Table: s.Table, Name: s.Name,
				Type: stringifyType(s.Type), Flags: s.Flags,
				SizeLimit: s.Size, IsMap: isMap,
			}
			if len(s.Elem) > 0 {
				meta.ElementCount = len(s.Elem)
			}
			sets[setKey] = meta
			if tm := tableMeta[key]; tm != nil {
				if isMap {
					tm.MapCount++
				} else {
					tm.SetCount++
				}
			}
		}
	}); err != nil {
		return nil, &dispatch.Error{
			Code:    proto.CodeToolFailed,
			Message: "firewall_inspect: parse nft -j: " + err.Error(),
			Argv:    []string{"nft", "-j", "list", "ruleset"},
		}
	}

	// Determine backend before bailing out on empty.
	if len(tableMeta) == 0 {
		res.Backend = "none"
	} else {
		res.Backend = "nftables"
	}

	// Populate ban-set rows in the manifest order. Sets the operator
	// names but nft hasn't reported are emitted with count=0; the
	// warning makes the drift visible.
	banSetKeys := map[string]string{} // key → source
	for _, bs := range req.BanSets {
		k := bs.Family + "/" + bs.Table + "/" + bs.Name
		banSetKeys[k] = bs.Source
		stat := FirewallBanSetStat{Set: k, Source: bs.Source}
		if meta, ok := sets[k]; ok {
			stat.Count = meta.ElementCount
			if isV4Set(meta.Type) {
				res.Bans.TotalActiveV4 += meta.ElementCount
			}
			if isV6Set(meta.Type) {
				res.Bans.TotalActiveV6 += meta.ElementCount
			}
		} else {
			res.Warnings = append(res.Warnings,
				"firewall: ban_set "+k+" not present in live ruleset")
		}
		res.Bans.BySet = append(res.Bans.BySet, stat)
	}

	// Fetch set elements only when requested. Iterate the manifest's
	// ban_sets first (operator's stated interest), then any remaining
	// sets in detail mode. Honour the global element budget.
	if req.IncludeSetElements {
		remaining := firewallElemBudget
		order := orderSetKeys(sets, req.BanSets)
		for _, k := range order {
			meta := sets[k]
			if meta == nil {
				continue
			}
			cap := req.MaxSetElements
			if cap > remaining {
				cap = remaining
			}
			if cap <= 0 {
				meta.ElementsTruncated = true
				continue
			}
			elems, total, err := runNftListSet(ctx, meta.Family, meta.Table, meta.Name, cap)
			if err != nil {
				res.Warnings = append(res.Warnings,
					"firewall: list set "+k+": "+errorCodeOf(err))
				continue
			}
			meta.Elements = elems
			meta.ElementCount = total
			if total > len(elems) {
				meta.ElementsTruncated = true
			}
			remaining -= len(elems)
			if remaining <= 0 {
				remaining = 0
			}
		}
	}

	// Stable, deterministic ordering of slices.
	for _, tm := range tableMeta {
		res.Tables = append(res.Tables, *tm)
	}
	sort.Slice(res.Tables, func(i, j int) bool {
		if res.Tables[i].Family != res.Tables[j].Family {
			return res.Tables[i].Family < res.Tables[j].Family
		}
		return res.Tables[i].Name < res.Tables[j].Name
	})
	for _, chains := range chainsByTable {
		for _, c := range chains {
			res.Chains = append(res.Chains, *c)
		}
	}
	sort.Slice(res.Chains, func(i, j int) bool {
		if res.Chains[i].Family != res.Chains[j].Family {
			return res.Chains[i].Family < res.Chains[j].Family
		}
		if res.Chains[i].Table != res.Chains[j].Table {
			return res.Chains[i].Table < res.Chains[j].Table
		}
		return res.Chains[i].Name < res.Chains[j].Name
	})
	for _, s := range sets {
		res.Sets = append(res.Sets, *s)
	}
	sort.Slice(res.Sets, func(i, j int) bool {
		if res.Sets[i].Family != res.Sets[j].Family {
			return res.Sets[i].Family < res.Sets[j].Family
		}
		if res.Sets[i].Table != res.Sets[j].Table {
			return res.Sets[i].Table < res.Sets[j].Table
		}
		return res.Sets[i].Name < res.Sets[j].Name
	})

	return res, nil
}

// runNftListRuleset captures the full output of `nft -j list ruleset`
// up to firewallRulesetCap. Uses helperexec.RunCapped because
// modern nft -j prints the entire document on a single line that
// can run to many megabytes; RunStreaming's line scanner would
// reject it as "token too long".
func runNftListRuleset(ctx context.Context) (raw []byte, truncated bool, err error) {
	return helperexec.RunCapped(ctx, firewallRulesetCap, "nft", "-j", "list", "ruleset")
}

// runNftVersion is best-effort. Failure is silent: the version
// field is omitted, not surfaced as a warning.
func runNftVersion(ctx context.Context) (string, error) {
	out, err := helperexec.Run(ctx, "nft", "--version")
	if err != nil {
		return "", err
	}
	// Output: "nftables v1.0.9 (Old Doc Yak)". Take the v-prefixed
	// token; fall through to the trimmed first line otherwise.
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	for _, f := range strings.Fields(line) {
		if strings.HasPrefix(f, "v") && len(f) > 1 {
			return strings.TrimPrefix(f, "v"), nil
		}
	}
	return line, nil
}

// runNftListSet fetches up to `cap` elements from one set. Returns
// the parsed elements and the total element count seen in the JSON
// (which may exceed cap).
func runNftListSet(ctx context.Context, family, table, name string, cap int) ([]FirewallSetElem, int, error) {
	out, _, err := helperexec.RunCapped(ctx, firewallSetListCap, "nft", "-j", "list", "set", family, table, name)
	if err != nil {
		return nil, 0, err
	}
	var parsed fwNftRoot
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, 0, fmt.Errorf("parse nft set: %w", err)
	}
	for _, e := range parsed.Nftables {
		if e.Set != nil {
			elems := renderElements(e.Set.Elem, cap)
			return elems, len(e.Set.Elem), nil
		}
		if e.Map != nil {
			elems := renderElements(e.Map.Elem, cap)
			return elems, len(e.Map.Elem), nil
		}
	}
	return nil, 0, nil
}

// fwNftRoot is the wrapping shape of `nft -j …` output.
type fwNftRoot struct {
	Nftables []fwNftEntry `json:"nftables"`
}

// fwNftEntry holds one nft JSON object. Every object in
// `nftables[]` is `{"<kind>": {…}}`; the kind keys are mutually
// exclusive in practice, so json.Unmarshal populates exactly one
// of these pointers per entry.
type fwNftEntry struct {
	Metainfo *json.RawMessage `json:"metainfo,omitempty"`
	Table    *fwNftTable        `json:"table,omitempty"`
	Chain    *fwNftChain        `json:"chain,omitempty"`
	Rule     *fwNftRule         `json:"rule,omitempty"`
	Set      *fwNftSet          `json:"set,omitempty"`
	Map      *fwNftSet          `json:"map,omitempty"`
}

type fwNftTable struct {
	Family string `json:"family"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
}

type fwNftChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	Prio   *int   `json:"prio"`
	Policy string `json:"policy"`
}

type fwNftRule struct {
	Family string            `json:"family"`
	Table  string            `json:"table"`
	Chain  string            `json:"chain"`
	Handle int               `json:"handle"`
	Expr   []json.RawMessage `json:"expr"`
}

type fwNftSet struct {
	Family string            `json:"family"`
	Table  string            `json:"table"`
	Name   string            `json:"name"`
	Handle int               `json:"handle"`
	Type   json.RawMessage   `json:"type"`
	Flags  []string          `json:"flags"`
	Size   int               `json:"size"`
	Elem   []json.RawMessage `json:"elem"`
}

// walkNftRuleset streams entries through visit. Unmarshals the
// whole document then iterates; nft -j does not produce a
// streaming-friendly format and the 4 MiB cap above bounds the
// in-memory size.
func walkNftRuleset(raw []byte, visit func(fwNftEntry)) error {
	if len(raw) == 0 {
		return nil
	}
	var root fwNftRoot
	if err := json.Unmarshal(raw, &root); err != nil {
		return err
	}
	for _, e := range root.Nftables {
		visit(e)
	}
	return nil
}

// renderRule extracts the counter (if any) and serialises the
// expression array as compact JSON for the Expr field.
func renderRule(r *fwNftRule) FirewallRule {
	out := FirewallRule{Handle: r.Handle}
	exprBytes, err := json.Marshal(r.Expr)
	if err == nil {
		out.Expr = string(exprBytes)
	}
	// Look for a counter sub-expression. Counters appear as
	// {"counter":{"packets":N,"bytes":N}}.
	for _, raw := range r.Expr {
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(raw, &probe); err != nil {
			continue
		}
		if c, ok := probe["counter"]; ok {
			var ctr FirewallCounter
			if err := json.Unmarshal(c, &ctr); err == nil {
				out.Counter = &ctr
			}
		}
	}
	return out
}

// stringifyType collapses nft's set/map type field into a string.
// Simple sets carry `"ipv4_addr"`; concatenated sets carry an array
// like `["ipv4_addr","inet_service"]`; we join with `.` to match
// nft's textual rendering of concat types.
func stringifyType(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return strings.Join(arr, ".")
	}
	return string(raw)
}

// renderElements turns nft's set-element JSON into FirewallSetElem
// rows. The shape is either:
//
//	"203.0.113.7"                              (simple key, no metadata)
//
// or
//
//	{"elem":{"val":"203.0.113.7","expires":41892,"timeout":43200}}
//
// where val itself can be a string, a prefix object, or a range
// array. Anything we can't interpret becomes the raw JSON of val.
func renderElements(elems []json.RawMessage, cap int) []FirewallSetElem {
	if cap <= 0 {
		return nil
	}
	out := make([]FirewallSetElem, 0, len(elems))
	for i, raw := range elems {
		if i >= cap {
			break
		}
		out = append(out, renderOneElement(raw))
	}
	return out
}

func renderOneElement(raw json.RawMessage) FirewallSetElem {
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return FirewallSetElem{Key: asString}
	}
	var asObj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &asObj); err != nil {
		return FirewallSetElem{Key: string(raw)}
	}
	inner, ok := asObj["elem"]
	if !ok {
		return FirewallSetElem{Key: renderElementVal(raw)}
	}
	var inObj struct {
		Val     json.RawMessage `json:"val"`
		Expires *int64          `json:"expires"`
		Timeout *int64          `json:"timeout"`
	}
	if err := json.Unmarshal(inner, &inObj); err != nil {
		return FirewallSetElem{Key: string(inner)}
	}
	return FirewallSetElem{
		Key:      renderElementVal(inObj.Val),
		ExpiresS: inObj.Expires,
		TimeoutS: inObj.Timeout,
	}
}

// renderElementVal turns a set/map element value into its text form.
//
//	"203.0.113.7"                          → "203.0.113.7"
//	{"prefix":{"addr":"203.0.113.0","len":24}} → "203.0.113.0/24"
//	{"range":["203.0.113.0","203.0.113.255"]}  → "203.0.113.0-203.0.113.255"
//
// Anything else falls through to the raw JSON; downstream operators
// can decode the unusual shape themselves.
func renderElementVal(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return asString
	}
	var asObj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &asObj); err == nil {
		if p, ok := asObj["prefix"]; ok {
			var pf struct {
				Addr string `json:"addr"`
				Len  int    `json:"len"`
			}
			if err := json.Unmarshal(p, &pf); err == nil {
				return pf.Addr + "/" + strconv.Itoa(pf.Len)
			}
		}
		if r, ok := asObj["range"]; ok {
			var rng []string
			if err := json.Unmarshal(r, &rng); err == nil && len(rng) == 2 {
				return rng[0] + "-" + rng[1]
			}
		}
	}
	return string(raw)
}

// orderSetKeys returns set keys with ban-set entries first (in
// manifest order), then any remaining sets in stable order.
func orderSetKeys(sets map[string]*FirewallSet, banSets []FirewallBanSet) []string {
	seen := map[string]bool{}
	var out []string
	for _, bs := range banSets {
		k := bs.Family + "/" + bs.Table + "/" + bs.Name
		if _, ok := sets[k]; ok && !seen[k] {
			out = append(out, k)
			seen[k] = true
		}
	}
	var rest []string
	for k := range sets {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// isV4Set reports whether a set's element type carries IPv4
// addresses (either alone or as the first element of a concat type).
func isV4Set(t string) bool {
	if t == "" {
		return false
	}
	for _, part := range strings.Split(t, ".") {
		if part == "ipv4_addr" {
			return true
		}
	}
	return false
}

// isV6Set is the IPv6 sibling of isV4Set.
func isV6Set(t string) bool {
	if t == "" {
		return false
	}
	for _, part := range strings.Split(t, ".") {
		if part == "ipv6_addr" {
			return true
		}
	}
	return false
}

// errorCodeOf returns the dispatch.Error code if err is one, or
// "tool_failed" otherwise. Used to keep warning strings short.
func errorCodeOf(err error) string {
	var de *dispatch.Error
	if errors.As(err, &de) {
		return de.Code
	}
	return proto.CodeToolFailed
}
