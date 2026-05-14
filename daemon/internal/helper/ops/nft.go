package ops

import (
	"context"
	"encoding/json"
	"errors"

	"tigr.net/host-health-mcp/daemon/internal/helper/dispatch"
	helperexec "tigr.net/host-health-mcp/daemon/internal/helper/exec"
	"tigr.net/host-health-mcp/daemon/internal/shared/proto"
)

// NftTableCountsResult is the typed result for op nft_table_counts.
// Mirrors the daemon-side network tool's NftTableCounts map shape.
type NftTableCountsResult struct {
	Tables map[string]NftTable `json:"tables"`
}

// NftTable is one entry in the result map.
type NftTable struct {
	RuleCount   int          `json:"rule_count"`
	HitCounters []NftCounter `json:"hit_counters"`
}

// NftCounter mirrors one counter row.
type NftCounter struct {
	Name    string `json:"name"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
}

// nftEnvelope is the shape `nft -j list ruleset` returns.
type nftEnvelope struct {
	Nftables []nftEntry `json:"nftables"`
}

type nftEntry struct {
	Counter *struct {
		Family string `json:"family"`
		Name   string `json:"name"`
		Table  string `json:"table"`
		Packets int64 `json:"packets"`
		Bytes   int64 `json:"bytes"`
	} `json:"counter"`
	Rule *struct {
		Family string `json:"family"`
		Table  string `json:"table"`
	} `json:"rule"`
}

// NftTableCounts invokes `nft -j list ruleset` and groups the output
// by table. Per-table rule counts and per-counter hit values are
// returned. Requires CAP_NET_ADMIN on the helper unit when the
// operator enables it; the cap is templated in only when the network
// tool is enabled in the manifest.
func NftTableCounts(ctx context.Context, _ string) (any, error) {
	stdout, err := helperexec.Run(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		// nft genuinely absent (binary not installed): return empty
		// rather than failing, so the daemon's network tool can
		// proceed. Any other error - permission denied, kernel
		// module missing, malformed output - is surfaced upward so
		// the operator sees a real diagnostic instead of a
		// misleading empty-table report.
		var de *dispatch.Error
		if errors.As(err, &de) && de.Code == proto.CodeToolMissing {
			return NftTableCountsResult{Tables: map[string]NftTable{}}, nil
		}
		return nil, err
	}

	var env nftEnvelope
	if err := json.Unmarshal(stdout, &env); err != nil {
		return nil, &dispatch.Error{
			Code:    proto.CodeToolFailed,
			Message: "nft JSON parse: " + err.Error(),
		}
	}

	out := NftTableCountsResult{Tables: map[string]NftTable{}}
	for _, entry := range env.Nftables {
		if entry.Rule != nil {
			key := entry.Rule.Family + ":" + entry.Rule.Table
			t := out.Tables[key]
			t.RuleCount++
			out.Tables[key] = t
		}
		if entry.Counter != nil {
			key := entry.Counter.Family + ":" + entry.Counter.Table
			t := out.Tables[key]
			t.HitCounters = append(t.HitCounters, NftCounter{
				Name:    entry.Counter.Name,
				Packets: entry.Counter.Packets,
				Bytes:   entry.Counter.Bytes,
			})
			out.Tables[key] = t
		}
	}
	return out, nil
}
