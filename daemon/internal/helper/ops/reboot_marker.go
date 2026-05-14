package ops

import (
	"context"
	"errors"
	"io/fs"
	"os"
)

const rebootMarkerPath = "/var/run/reboot-required"

// RebootMarker is the typed result for op read_reboot_marker.
type RebootMarker struct {
	Present bool `json:"present"`
	Bytes   int  `json:"bytes"`
}

// ReadRebootMarker reports presence and byte-length of
// /var/run/reboot-required. World-readable on Debian/Ubuntu so the
// helper needs no capability for this op; the call goes through the
// helper anyway to keep the privileged-read surface uniform.
func ReadRebootMarker(ctx context.Context, _ string) (any, error) {
	info, err := os.Stat(rebootMarkerPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return RebootMarker{}, nil
		}
		return nil, err
	}
	return RebootMarker{Present: true, Bytes: int(info.Size())}, nil
}
