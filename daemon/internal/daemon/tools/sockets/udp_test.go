package sockets

import "testing"

// C-7: the guard was `proto == "tcp" && state != listenState`, so UDP
// was never filtered and every row came back — including connected
// ephemeral client sockets, which is not the listening inventory REQ
// 4.16 describes.
//
// UDP has no LISTEN state: /proc/net/udp reports 07 (TCP_CLOSE) for a
// bound socket with no peer and 01 for one that has been connect()ed.
func TestUDPUnconnectedStateConstant(t *testing.T) {
	if udpUnconnectedState != "07" {
		t.Errorf("udpUnconnectedState = %q, want 07 (TCP_CLOSE)", udpUnconnectedState)
	}
	// TCP's LISTEN is 0A; UDP never reports it, which is why the
	// original single-branch guard let every UDP row through.
	if udpUnconnectedState == "0A" {
		t.Error("UDP must not reuse the TCP LISTEN state; no UDP socket ever reports it")
	}
}
