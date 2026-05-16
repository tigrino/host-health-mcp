package ops

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRenderElementVal_Shapes covers the three element value shapes
// nftables emits in -j output: bare string, prefix object, range
// array. The renderer must produce a stable text key suitable for
// the wire schema.
func TestRenderElementVal_Shapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ipv4_addr", `"203.0.113.7"`, "203.0.113.7"},
		{"prefix", `{"prefix":{"addr":"203.0.113.0","len":24}}`, "203.0.113.0/24"},
		{"range", `{"range":["10.0.0.1","10.0.0.5"]}`, "10.0.0.1-10.0.0.5"},
		{"ipv6", `"2001:db8::1"`, "2001:db8::1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := renderElementVal(json.RawMessage(c.in))
			if got != c.want {
				t.Errorf("renderElementVal(%s) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestRenderOneElement_WithMetadata verifies elements carrying
// timeout/expires unmarshal into the schema correctly.
func TestRenderOneElement_WithMetadata(t *testing.T) {
	in := json.RawMessage(`{"elem":{"val":"203.0.113.7","expires":41892,"timeout":43200}}`)
	got := renderOneElement(in)
	if got.Key != "203.0.113.7" {
		t.Errorf("Key = %q, want 203.0.113.7", got.Key)
	}
	if got.ExpiresS == nil || *got.ExpiresS != 41892 {
		t.Errorf("ExpiresS = %v, want 41892", got.ExpiresS)
	}
	if got.TimeoutS == nil || *got.TimeoutS != 43200 {
		t.Errorf("TimeoutS = %v, want 43200", got.TimeoutS)
	}
}

// TestRenderOneElement_PlainString covers the no-metadata case
// (sets without timeout flag).
func TestRenderOneElement_PlainString(t *testing.T) {
	got := renderOneElement(json.RawMessage(`"10.0.0.1"`))
	if got.Key != "10.0.0.1" {
		t.Errorf("Key = %q, want 10.0.0.1", got.Key)
	}
	if got.ExpiresS != nil || got.TimeoutS != nil {
		t.Errorf("expected no metadata fields, got expires=%v timeout=%v", got.ExpiresS, got.TimeoutS)
	}
}

// TestWalkNftRuleset_TypicalShape parses a realistic small ruleset
// and asserts that table / chain / rule / set counters land where
// expected.
func TestWalkNftRuleset_TypicalShape(t *testing.T) {
	raw := []byte(`{"nftables":[
		{"metainfo":{"version":"1.0.9","release_name":"Old Doc Yak","json_schema_version":1}},
		{"table":{"family":"inet","name":"net-ban","handle":1}},
		{"chain":{"family":"inet","table":"net-ban","name":"input","handle":1,"type":"filter","hook":"input","prio":-150,"policy":"accept"}},
		{"rule":{"family":"inet","table":"net-ban","chain":"input","handle":12,"expr":[{"match":{"left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"@banned_v4","op":"=="}},{"counter":{"packets":142,"bytes":8804}},{"drop":null}]}},
		{"set":{"family":"inet","table":"net-ban","name":"banned_v4","type":"ipv4_addr","handle":2,"flags":["timeout","interval"],"size":65535,"elem":["203.0.113.7","203.0.113.8"]}}
	]}`)
	tables := 0
	chains := 0
	rules := 0
	sets := 0
	err := walkNftRuleset(raw, func(e fwNftEntry) {
		switch {
		case e.Table != nil:
			tables++
		case e.Chain != nil:
			chains++
		case e.Rule != nil:
			rules++
		case e.Set != nil:
			sets++
		}
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if tables != 1 || chains != 1 || rules != 1 || sets != 1 {
		t.Errorf("counts = (t=%d c=%d r=%d s=%d), want all 1", tables, chains, rules, sets)
	}
}

// TestRenderRule_ExtractsCounter walks the expr array, picks out the
// counter sub-expression, and serialises the rest as a compact
// JSON string in Expr. Critical for fleet-side rule diffing.
func TestRenderRule_ExtractsCounter(t *testing.T) {
	r := &fwNftRule{
		Handle: 12,
		Expr: []json.RawMessage{
			json.RawMessage(`{"match":{"left":"x","right":"@banned","op":"=="}}`),
			json.RawMessage(`{"counter":{"packets":142,"bytes":8804}}`),
			json.RawMessage(`{"drop":null}`),
		},
	}
	got := renderRule(r)
	if got.Handle != 12 {
		t.Errorf("Handle = %d, want 12", got.Handle)
	}
	if got.Counter == nil || got.Counter.Packets != 142 || got.Counter.Bytes != 8804 {
		t.Errorf("Counter = %+v, want {142,8804}", got.Counter)
	}
	if !strings.Contains(got.Expr, "match") || !strings.Contains(got.Expr, "drop") {
		t.Errorf("Expr did not preserve expressions: %s", got.Expr)
	}
}

// TestRenderElements_RespectsCap is the load-bearing big-list test:
// a 69 000-entry set must not OOM, must not exceed the cap, and
// must return exactly cap rows.
func TestRenderElements_RespectsCap(t *testing.T) {
	const total = 69000
	const cap = 1500
	elems := make([]json.RawMessage, total)
	for i := 0; i < total; i++ {
		elems[i] = json.RawMessage(`{"elem":{"val":"10.0.0.1","expires":3600,"timeout":7200}}`)
	}
	out := renderElements(elems, cap)
	if len(out) != cap {
		t.Errorf("len(out) = %d, want %d", len(out), cap)
	}
	if out[0].Key != "10.0.0.1" {
		t.Errorf("first key = %q, want 10.0.0.1", out[0].Key)
	}
}

// TestIsV4V6Set covers the type-discrimination helper used to
// populate Bans.TotalActiveV4 / V6 from set metadata.
func TestIsV4V6Set(t *testing.T) {
	cases := []struct {
		t      string
		isV4   bool
		isV6   bool
	}{
		{"ipv4_addr", true, false},
		{"ipv6_addr", false, true},
		{"ipv4_addr.inet_service", true, false},
		{"ether_addr", false, false},
		{"", false, false},
	}
	for _, c := range cases {
		if got := isV4Set(c.t); got != c.isV4 {
			t.Errorf("isV4Set(%q) = %v, want %v", c.t, got, c.isV4)
		}
		if got := isV6Set(c.t); got != c.isV6 {
			t.Errorf("isV6Set(%q) = %v, want %v", c.t, got, c.isV6)
		}
	}
}

// TestStringifyType handles simple-type and concat-type variants.
func TestStringifyType(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`"ipv4_addr"`, "ipv4_addr"},
		{`["ipv4_addr","inet_service"]`, "ipv4_addr.inet_service"},
		{`null`, ""},
	}
	for _, c := range cases {
		got := stringifyType(json.RawMessage(c.in))
		if got != c.want {
			t.Errorf("stringifyType(%s) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestOrderSetKeys_BanSetsFirst confirms the ban_set ordering rule:
// manifest-named sets appear in manifest order, remaining sets in
// stable alphabetical order behind them.
func TestOrderSetKeys_BanSetsFirst(t *testing.T) {
	sets := map[string]*FirewallSet{
		"inet/net-ban/banned_v4":           {},
		"inet/net-ban/banned_v6":           {},
		"inet/crowdsec/crowdsec-blacklists": {},
		"inet/filter/temp_set":              {},
	}
	banSets := []FirewallBanSet{
		{Family: "inet", Table: "crowdsec", Name: "crowdsec-blacklists", Source: "crowdsec"},
		{Family: "inet", Table: "net-ban", Name: "banned_v4", Source: "net-ban"},
	}
	got := orderSetKeys(sets, banSets)
	want := []string{
		"inet/crowdsec/crowdsec-blacklists",
		"inet/net-ban/banned_v4",
		// remainder, alpha order
		"inet/filter/temp_set",
		"inet/net-ban/banned_v6",
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
