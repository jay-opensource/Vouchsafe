// Package ceremony implements the WebAuthn registration and
// authentication ceremonies: challenge issuance, attestation and
// assertion verification, and every security check §7.1 of the spec
// requires — challenge freshness, origin binding, replay detection, and
// identity resolution.
package ceremony

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	// ChallengeLength is the size of a freshly issued challenge, per
	// WebAuthn's recommendation of at least 16 bytes of entropy.
	ChallengeLength = 32
	// ChallengeTTL is how long an issued challenge remains valid.
	ChallengeTTL = 120 * time.Second
)

var (
	ErrChallengeNotFound = errors.New("ceremony: no matching pending challenge")
	ErrChallengeExpired  = errors.New("ceremony: challenge expired")
	ErrChallengeMismatch = errors.New("ceremony: challenge does not match the one issued")
)

// Purpose distinguishes a registration challenge from a login challenge,
// so a user with both ceremonies in flight at once doesn't have issuing
// one silently invalidate the other.
type Purpose string

const (
	PurposeRegister Purpose = "register"
	PurposeLogin    Purpose = "login"
)

type pendingKey struct {
	Username string
	Purpose  Purpose
}

type pendingChallenge struct {
	challenge []byte
	issuedAt  time.Time
}

// ChallengeStore issues and consumes single-use, expiring challenges.
// It never accepts a challenge the server did not itself issue for that
// exact username and purpose, and it deletes a challenge on the first
// verification attempt regardless of outcome — a failed verification
// must not leave a challenge usable for a second try.
type ChallengeStore struct {
	mu      sync.Mutex
	pending map[pendingKey]pendingChallenge
	now     func() time.Time
	ttl     time.Duration
}

// NewChallengeStore creates an empty challenge store with the default
// 120-second expiry.
func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{
		pending: make(map[pendingKey]pendingChallenge),
		now:     time.Now,
		ttl:     ChallengeTTL,
	}
}

// Issue generates a fresh challenge for username/purpose and records it
// as pending, replacing any challenge previously issued for the same
// username and purpose. Also opportunistically sweeps expired entries
// for other keys, bounding the store's memory under normal operation
// without a background goroutine.
func (s *ChallengeStore) Issue(username string, purpose Purpose) ([]byte, error) {
	buf := make([]byte, ChallengeLength)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("ceremony: generate challenge: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked()
	s.pending[pendingKey{Username: username, Purpose: purpose}] = pendingChallenge{
		challenge: buf,
		issuedAt:  s.now(),
	}
	return buf, nil
}

// Consume verifies that got was issued by this store for username and
// purpose, has not already been consumed, and has not expired — then
// removes it either way, so it can never be used a second time. The
// comparison against the stored challenge is constant-time; only the
// username/purpose pair is used to locate the pending entry.
func (s *ChallengeStore) Consume(username string, purpose Purpose, got []byte) error {
	key := pendingKey{Username: username, Purpose: purpose}

	s.mu.Lock()
	pc, ok := s.pending[key]
	if ok {
		delete(s.pending, key)
	}
	s.mu.Unlock()

	if !ok {
		return ErrChallengeNotFound
	}
	if subtle.ConstantTimeCompare(pc.challenge, got) != 1 {
		return ErrChallengeMismatch
	}
	if s.now().Sub(pc.issuedAt) > s.ttl {
		return ErrChallengeExpired
	}
	return nil
}

// SetClock overrides the store's time source. Production code never
// calls this — the zero value already uses time.Now — but a caller
// outside this package (the negative-test suite, for one) has no other
// way to exercise the 120-second expiry without a real sleep.
func (s *ChallengeStore) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

func (s *ChallengeStore) purgeExpiredLocked() {
	now := s.now()
	for k, pc := range s.pending {
		if now.Sub(pc.issuedAt) > s.ttl {
			delete(s.pending, k)
		}
	}
}
