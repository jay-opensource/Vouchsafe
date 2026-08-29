package ceremony

import (
	"errors"
	"testing"
	"time"
)

func newTestChallengeStore() *ChallengeStore {
	s := NewChallengeStore()
	s.now = func() time.Time { return fixedNow }
	return s
}

var fixedNow = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

func TestIssueAndConsume_Success(t *testing.T) {
	s := newTestChallengeStore()
	ch, err := s.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(ch) != ChallengeLength {
		t.Fatalf("challenge length = %d, want %d", len(ch), ChallengeLength)
	}
	if err := s.Consume("alice", PurposeRegister, ch); err != nil {
		t.Fatalf("Consume: %v", err)
	}
}

func TestConsume_WrongChallengeIsSingleUse(t *testing.T) {
	s := newTestChallengeStore()
	ch, err := s.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	altered := append([]byte(nil), ch...)
	altered[0] ^= 0xff

	if err := s.Consume("alice", PurposeRegister, altered); !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("got %v, want ErrChallengeMismatch", err)
	}

	// A failed verification must not leave the challenge usable for a
	// second try — the correct challenge must now also be rejected.
	if err := s.Consume("alice", PurposeRegister, ch); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("replay after failed attempt: got %v, want ErrChallengeNotFound", err)
	}
}

func TestConsume_ReplayOfSuccessfulAttempt(t *testing.T) {
	s := newTestChallengeStore()
	ch, err := s.Issue("alice", PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Consume("alice", PurposeLogin, ch); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if err := s.Consume("alice", PurposeLogin, ch); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("replay: got %v, want ErrChallengeNotFound", err)
	}
}

func TestConsume_NeverIssued(t *testing.T) {
	s := newTestChallengeStore()
	if err := s.Consume("alice", PurposeRegister, make([]byte, ChallengeLength)); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("got %v, want ErrChallengeNotFound", err)
	}
}

func TestConsume_WrongUsername(t *testing.T) {
	s := newTestChallengeStore()
	ch, err := s.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Consume("bob", PurposeRegister, ch); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("got %v, want ErrChallengeNotFound", err)
	}
}

func TestConsume_WrongPurpose(t *testing.T) {
	s := newTestChallengeStore()
	ch, err := s.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Consume("alice", PurposeLogin, ch); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("got %v, want ErrChallengeNotFound", err)
	}
}

func TestConsume_Expired(t *testing.T) {
	s := newTestChallengeStore()
	current := fixedNow
	s.now = func() time.Time { return current }

	ch, err := s.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	current = current.Add(ChallengeTTL + time.Second)
	if err := s.Consume("alice", PurposeRegister, ch); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("got %v, want ErrChallengeExpired", err)
	}

	// Expired challenges are still single-use: a retry must not succeed
	// even if it somehow arrived before another expiry check.
	if err := s.Consume("alice", PurposeRegister, ch); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("retry after expiry: got %v, want ErrChallengeNotFound", err)
	}
}

func TestConsume_JustUnderTTLSucceeds(t *testing.T) {
	s := newTestChallengeStore()
	current := fixedNow
	s.now = func() time.Time { return current }

	ch, err := s.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	current = current.Add(ChallengeTTL - time.Second)
	if err := s.Consume("alice", PurposeRegister, ch); err != nil {
		t.Fatalf("Consume just under TTL: %v", err)
	}
}

func TestIssue_OverwritesPriorPendingForSameKey(t *testing.T) {
	s := newTestChallengeStore()
	first, err := s.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue (1): %v", err)
	}
	second, err := s.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue (2): %v", err)
	}

	if err := s.Consume("alice", PurposeRegister, first); !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("consuming the superseded challenge: got %v, want ErrChallengeMismatch", err)
	}
	// The failed attempt above deleted the (only) pending entry for this
	// key, so even the correct current challenge is now gone too — this
	// is the single-use property, not a second bug.
	if err := s.Consume("alice", PurposeRegister, second); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("got %v, want ErrChallengeNotFound", err)
	}
}

func TestPurgeExpiredOnIssue(t *testing.T) {
	s := newTestChallengeStore()
	current := fixedNow
	s.now = func() time.Time { return current }

	if _, err := s.Issue("alice", PurposeRegister); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if got := len(s.pending); got != 1 {
		t.Fatalf("pending = %d, want 1", got)
	}

	current = current.Add(ChallengeTTL + time.Second)
	if _, err := s.Issue("bob", PurposeRegister); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if got := len(s.pending); got != 1 {
		t.Fatalf("pending = %d after purge, want 1 (only bob's fresh entry)", got)
	}
	if _, ok := s.pending[pendingKey{Username: "alice", Purpose: PurposeRegister}]; ok {
		t.Fatalf("alice's expired entry was not purged")
	}
}

func TestIssue_GeneratesDistinctChallenges(t *testing.T) {
	s := newTestChallengeStore()
	a, err := s.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	b, err := s.Issue("bob", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if string(a) == string(b) {
		t.Fatalf("two issued challenges were identical")
	}
}
