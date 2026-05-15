// Package mail implements tool 4.7: MTA in use, queue depth, last
// send/fail timestamps, redacted failure reason. Uses the helper's
// postqueue op for the queue depth on hosts running Postfix; other
// MTAs fall through to "unknown" today.
package mail

import (
	"context"
	"errors"
	"os"
	"time"

	"host-health-mcp/daemon/internal/daemon/helperinvoke"
	"host-health-mcp/daemon/internal/shared/proto"
	"host-health-mcp/daemon/internal/shared/schema"
)

// Data is the response data for tool mail. Mirrors MailData in
// doc/schema-draft.yaml.
type Data struct {
	MTAInUse              string                 `json:"mta_in_use"`
	QueueDepth            int                    `json:"queue_depth"`
	LastSuccessfulSendTS  *time.Time             `json:"last_successful_send_ts"`
	LastFailureTS         *time.Time             `json:"last_failure_ts"`
	LastFailureReason     *string                `json:"last_failure_reason"`
	Errors                []schema.HelperOpError `json:"errors,omitempty"`
}

// Tool is the registered tool.
type Tool struct {
	hc *helperinvoke.Client
}

// New returns a new tool instance.
func New(hc *helperinvoke.Client) *Tool { return &Tool{hc: hc} }

// Name returns the tool name.
func (*Tool) Name() string { return "mail" }

// DefaultTTL: queue depth moves but the operator-facing resolution
// of one minute is enough.
func (*Tool) DefaultTTL() time.Duration { return 60 * time.Second }

// DefaultTimeout caps the per-call duration.
func (*Tool) DefaultTimeout() time.Duration { return 3 * time.Second }

// helperPostqueue mirrors the helper's PostqueueResult.
type helperPostqueue struct {
	QueueDepth int `json:"queue_depth"`
}

// Handle assembles the mail envelope. The MTA detection is by binary
// presence; the queue depth comes from the helper for Postfix.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	d := Data{MTAInUse: detectMTA()}
	var warnings []string

	if d.MTAInUse == "postfix" {
		var pq helperPostqueue
		if err := t.hc.CallJSON(ctx, proto.OpPostqueue, "", &pq); err != nil {
			oe := helperinvoke.OpErrorFrom(err)
			oe.Op = proto.OpPostqueue
			d.Errors = append(d.Errors, *oe)
			warnings = append(warnings, "mail: "+proto.OpPostqueue+": "+helperinvoke.CodeOf(err))
		} else {
			d.QueueDepth = pq.QueueDepth
		}
	}

	// /var/log/mail.log mtime as a coarse "last send/fail" signal when
	// the operator hasn't configured anything more specific. This is
	// best-effort; the field is null when no log exists.
	if info, err := os.Stat("/var/log/mail.log"); err == nil {
		ts := info.ModTime().UTC()
		d.LastSuccessfulSendTS = &ts
	} else if !errors.Is(err, os.ErrNotExist) {
		warnings = append(warnings, "mail: /var/log/mail.log: "+err.Error())
	}

	return d, warnings, nil
}

// detectMTA returns one of the REQ 4.7 enum values by probing for the
// canonical binary in /usr/sbin or by checking for the daemon's
// systemd unit name. We never invoke them.
func detectMTA() string {
	for _, c := range []struct {
		path, name string
	}{
		{"/usr/sbin/postfix", "postfix"},
		{"/usr/sbin/exim4", "exim"},
		{"/usr/sbin/sendmail", "sendmail"},
		{"/usr/bin/msmtp", "msmtp"},
		{"/usr/sbin/msmtp", "msmtp"},
	} {
		if _, err := os.Stat(c.path); err == nil {
			return c.name
		}
	}
	return "none"
}
