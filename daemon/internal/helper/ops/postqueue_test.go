package ops

import "testing"

func TestParsePostqueueOutput_Empty(t *testing.T) {
	in := []byte("Mail queue is empty\n")
	got, err := parsePostqueueOutput(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.QueueDepth != 0 || got.DeferredCount != 0 {
		t.Fatalf("empty queue: got %+v want zero values", got)
	}
}

func TestParsePostqueueOutput_DeferredOnly(t *testing.T) {
	in := []byte(`-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
ABCDEF1234     1234 Mon Jun  1 12:00:00  sender@example.com
                                         rcpt@example.com

GHIJKL5678     2345 Mon Jun  1 12:01:00  sender@example.com
                                         rcpt@example.com

-- 3 Kbytes in 2 Requests.
`)
	got, err := parsePostqueueOutput(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.QueueDepth != 2 {
		t.Fatalf("queue_depth: got %d want 2", got.QueueDepth)
	}
	if got.DeferredCount != 2 {
		t.Fatalf("deferred_count: got %d want 2", got.DeferredCount)
	}
}

func TestParsePostqueueOutput_Mixed(t *testing.T) {
	// Three messages: one active ('*'), one hold ('!'), one deferred.
	in := []byte(`-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
ABCDEF1234*    1234 Mon Jun  1 12:00:00  s@example.com
                                         r@example.com

GHIJKL5678!     567 Mon Jun  1 12:01:00  s@example.com
                                         r@example.com

MNOPQR9012     8910 Mon Jun  1 12:02:00  s@example.com
                                         r@example.com

-- 11 Kbytes in 3 Requests.
`)
	got, err := parsePostqueueOutput(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.QueueDepth != 3 {
		t.Fatalf("queue_depth: got %d want 3", got.QueueDepth)
	}
	if got.DeferredCount != 1 {
		t.Fatalf("deferred_count: got %d want 1", got.DeferredCount)
	}
}

func TestParsePostqueueOutput_SkipsContinuationAndHeader(t *testing.T) {
	in := []byte(`-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
ABCDEFGHIJKL     42 Mon Jun  1 12:00:00  s@example.com
                                         r@example.com
-- 0 Kbytes in 1 Requests.
`)
	got, err := parsePostqueueOutput(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.QueueDepth != 1 {
		t.Fatalf("queue_depth: got %d want 1", got.QueueDepth)
	}
	if got.DeferredCount != 1 {
		t.Fatalf("deferred_count: got %d want 1", got.DeferredCount)
	}
}
