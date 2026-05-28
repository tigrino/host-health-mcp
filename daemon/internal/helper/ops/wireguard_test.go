package ops

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"host-health-mcp/daemon/internal/helper/dispatch"
	"host-health-mcp/daemon/internal/shared/proto"
)

// fakeWGOutput mirrors the `wg show all dump` shape. The interface row
// puts the private key first; the peer row puts the preshared key in
// column index 2. The test must demonstrate that neither value
// appears in the parsed result.
const fakeWGOutput = "" +
	"wg0\t" + privKeyFake + "\t" + ifacePubKey + "\t51820\toff\n" +
	"wg0\t" + peerPubKey + "\t" + pskFake + "\t198.51.100.1:51820\t10.0.0.0/24\t1700000000\t1024\t2048\toff\n"

const (
	privKeyFake = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	pskFake     = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	ifacePubKey = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	peerPubKey  = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
)

func TestWireGuardParserStripsSecrets(t *testing.T) {
	result, err := parseWGDump([]byte(fakeWGOutput))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	raw, _ := json.Marshal(result)
	body := string(raw)
	for name, secret := range map[string]string{
		"private key":   privKeyFake,
		"preshared key": pskFake,
	} {
		if strings.Contains(body, secret) {
			t.Errorf("%s leaked into the parsed result: %s", name, body)
		}
	}
	if !strings.Contains(body, ifacePubKey) {
		t.Errorf("interface public key not preserved: %s", body)
	}
	if !strings.Contains(body, peerPubKey) {
		t.Errorf("peer public key not preserved: %s", body)
	}
}

// TestWireGuardRejectsUnexpectedColumnCount covers L-2: a 6-column row
// (neither header-shape nor peer-shape) must fail the op rather than
// be silently dropped.
func TestWireGuardRejectsUnexpectedColumnCount(t *testing.T) {
	// 6 tab-separated fields: deliberately neither 5 nor ≥8.
	bad := "wg0\ta\tb\tc\td\te\n"
	_, err := parseWGDump([]byte(bad))
	if err == nil {
		t.Fatal("parser accepted 6-column row; expected failure")
	}
	var de *dispatch.Error
	if !errors.As(err, &de) {
		t.Fatalf("error is not *dispatch.Error: %T (%v)", err, err)
	}
	if de.Code != proto.CodeToolFailed {
		t.Errorf("code = %q, want %q", de.Code, proto.CodeToolFailed)
	}
}
