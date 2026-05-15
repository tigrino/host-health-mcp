package ops

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"host-health-mcp/daemon/internal/helper/dispatch"
	helperexec "host-health-mcp/daemon/internal/helper/exec"
	"host-health-mcp/daemon/internal/shared/proto"
)

// SystemdTimerLastTriggerResult is the typed result for op
// systemd_timer_last_trigger.
type SystemdTimerLastTriggerResult struct {
	Present   bool       `json:"present"`
	LastTrigger *time.Time `json:"last_trigger"`
}

// SystemdTimerLastTrigger queries `systemctl show <unit>
// --property=LastTriggerUSec --value` and returns the parsed
// timestamp. The unit name is the op parameter; the helper validates
// that it is a non-empty timer unit ending in `.timer` to keep the
// surface small. systemctl talks to systemd over dbus internally;
// going through systemctl rather than linking go-systemd's dbus
// client keeps the helper static (REQ 5.4) at the cost of one extra
// process.
// timerUnitRE is a positive whitelist for systemd timer unit names.
// First char must be alphanumeric (rejects '-foo.timer' which
// systemctl would parse as a flag); the rest is the conservative
// systemd unit-name character set; must end in ".timer". Negative
// filters (ContainsAny) leave too much surface — a positive regex
// makes the accepted set explicit.
var timerUnitRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]*\.timer$`)

func SystemdTimerLastTrigger(ctx context.Context, param string) (any, error) {
	out := SystemdTimerLastTriggerResult{}

	unit := strings.TrimSpace(param)
	if !timerUnitRE.MatchString(unit) {
		return nil, &dispatch.Error{
			Code:    proto.CodeToolFailed,
			Message: "systemd_timer_last_trigger: param must match " + timerUnitRE.String(),
		}
	}

	stdout, err := helperexec.Run(ctx,
		"systemctl", "show", unit,
		"--property=LastTriggerUSec",
		"--value",
	)
	if err != nil {
		var de *dispatch.Error
		if errors.As(err, &de) && de.Code == proto.CodeToolMissing {
			return out, nil
		}
		return nil, err
	}

	v := strings.TrimSpace(string(bytes.TrimSuffix(stdout, []byte{'\n'})))
	// LastTriggerUSec for a never-triggered timer is "0", or
	// equivalently "n/a" on older systemd. Treat both as not-yet-run.
	if v == "" || v == "0" || strings.EqualFold(v, "n/a") {
		out.Present = true
		return out, nil
	}
	usec, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return nil, &dispatch.Error{
			Code:    proto.CodeToolFailed,
			Message: "systemd_timer_last_trigger: parse LastTriggerUSec: " + err.Error(),
		}
	}
	ts := time.UnixMicro(usec).UTC()
	out.Present = true
	out.LastTrigger = &ts
	return out, nil
}
