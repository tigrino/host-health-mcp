// Package logs implements tool 4.10: severity+window+source filtered
// summary of journald or audit entries. The helper does the
// journalctl invocation and parse; the daemon applies the redaction
// filter (REQ 6.3) to each sample message before returning.
package logs

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"host-health-mcp/daemon/internal/daemon/helperinvoke"
	"host-health-mcp/daemon/internal/daemon/redact"
	"host-health-mcp/daemon/internal/shared/proto"
)

// Request is the typed argument shape for tool logs.
type Request struct {
	Severity string `json:"severity"`
	Window   string `json:"window"`
	Source   string `json:"source"`
}

// Data is the response data for tool logs. Mirrors LogsData in
// doc/schema-draft.yaml.
type Data struct {
	TotalCount int            `json:"total_count"`
	ByUnit     map[string]int `json:"by_unit"`
	Samples    []Sample       `json:"samples"`
}

// Sample is one redacted journal entry.
type Sample struct {
	TS      time.Time `json:"ts"`
	Unit    string    `json:"unit"`
	Message string    `json:"message"`
}

// validSeverity enumerates the REQ 4.10 severity values.
var validSeverity = map[string]bool{
	"emerg":   true,
	"alert":   true,
	"crit":    true,
	"err":     true,
	"warning": true,
}

// validWindow enumerates the REQ 4.10 window values.
var validWindow = map[string]bool{
	"15m": true, "1h": true, "6h": true, "24h": true,
}

// validSource enumerates the REQ 4.10 source values.
var validSource = map[string]bool{
	"journal": true, "audit": true,
}

// Tool is the registered tool.
type Tool struct {
	hc       *helperinvoke.Client
	redactor *redact.Filter
}

// New returns a new tool instance.
func New(hc *helperinvoke.Client, r *redact.Filter) *Tool {
	return &Tool{hc: hc, redactor: r}
}

// Name returns the tool name.
func (*Tool) Name() string { return "logs" }

// DefaultTTL: log volume changes quickly under incidents; keep cache
// short.
func (*Tool) DefaultTTL() time.Duration { return 15 * time.Second }

// DefaultTimeout caps the per-call duration. The helper's journalctl
// invocation is the slow part; 5 s is a sane default with the helper-
// side bound subtracting 500 ms.
func (*Tool) DefaultTimeout() time.Duration { return 5 * time.Second }

// helperResult mirrors the helper's JournalQueryResult.
type helperResult struct {
	TotalCount int               `json:"total_count"`
	ByUnit     map[string]int    `json:"by_unit"`
	Samples    []helperSample    `json:"samples"`
}

type helperSample struct {
	TS      string `json:"ts"`
	Unit    string `json:"unit"`
	Message string `json:"message"`
}

// applyDefaults fills in zero-value fields with their documented
// defaults. The MCP plugin's tool inputSchema only exposes `host`
// and forwards `{}` as the body, so without defaults every MCP-
// routed call would arrive with an empty Request and fail
// validation before reaching the helper. Direct HTTP callers can
// still override any field explicitly.
func (r *Request) applyDefaults() {
	if r.Severity == "" {
		r.Severity = "warning"
	}
	if r.Window == "" {
		r.Window = "1h"
	}
	if r.Source == "" {
		r.Source = "journal"
	}
}

// validate enforces the REQ 4.10 enum tables. Called after
// applyDefaults so empty-body MCP calls succeed on the default
// triple (warning / 1h / journal).
func (r *Request) validate() error {
	if !validSeverity[r.Severity] {
		return fmt.Errorf("logs: severity must be one of emerg/alert/crit/err/warning")
	}
	if !validWindow[r.Window] {
		return fmt.Errorf("logs: window must be one of 15m/1h/6h/24h")
	}
	if !validSource[r.Source] {
		return fmt.Errorf("logs: source must be one of journal/audit")
	}
	return nil
}

// Handle validates the request, calls the helper, applies the
// redactor to every sample's message.
func (t *Tool) Handle(ctx context.Context, body []byte) (any, []string, error) {
	var req Request
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return nil, nil, fmt.Errorf("logs: parse request: %w", err)
		}
	}
	req.applyDefaults()
	if err := req.validate(); err != nil {
		return nil, nil, err
	}

	param := fmt.Sprintf("severity=%s window=%s source=%s",
		req.Severity, req.Window, req.Source)

	var hr helperResult
	if err := t.hc.CallJSON(ctx, proto.OpJournalQuery, param, &hr); err != nil {
		return nil, nil, err
	}

	d := Data{
		TotalCount: hr.TotalCount,
		ByUnit:     hr.ByUnit,
		Samples:    make([]Sample, 0, len(hr.Samples)),
	}
	for _, s := range hr.Samples {
		ts, _ := time.Parse(time.RFC3339Nano, s.TS)
		d.Samples = append(d.Samples, Sample{
			TS:      ts.UTC(),
			Unit:    s.Unit,
			Message: t.redactor.Redact(s.Message),
		})
	}
	return d, nil, nil
}
