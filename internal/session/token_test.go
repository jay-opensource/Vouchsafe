package session

import (
	"errors"
	"testing"
	"time"
)

func testKey() []byte {
	return []byte("01234567890123456789012345678901") // 33 bytes
}

func TestIssueAndVerify_Success(t *testing.T) {
	s, err := NewSigner(testKey(), time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tok, err := s.Issue("alice", true)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims, err := s.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Username != "alice" || !claims.UVPerformed {
		t.Fatalf("got %+v", claims)
	}
}

func TestNewSigner_RejectsShortKey(t *testing.T) {
	if _, err := NewSigner([]byte("too-short"), time.Hour); err == nil {
		t.Fatalf("expected an error for a key under 32 bytes")
	}
}

func TestVerify_TamperedPayload(t *testing.T) {
	s, err := NewSigner(testKey(), time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tok, err := s.Issue("alice", false)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	tampered := tok[:5] + "X" + tok[6:]
	if _, err := s.Verify(tampered); err == nil {
		t.Fatalf("expected an error for a tampered payload")
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	s, err := NewSigner(testKey(), time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tok, err := s.Issue("alice", false)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	tampered := tok + "X"
	if _, err := s.Verify(tampered); !errors.Is(err, ErrInvalidSignature) && !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("got %v, want ErrInvalidSignature or ErrMalformedToken", err)
	}
}

func TestVerify_MalformedNoDot(t *testing.T) {
	s, err := NewSigner(testKey(), time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if _, err := s.Verify("not-a-token"); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("got %v, want ErrMalformedToken", err)
	}
}

func TestVerify_MalformedBadBase64(t *testing.T) {
	s, err := NewSigner(testKey(), time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if _, err := s.Verify("!!!.!!!"); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("got %v, want ErrMalformedToken", err)
	}
}

func TestVerify_Expired(t *testing.T) {
	s, err := NewSigner(testKey(), time.Minute)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	current := time.Now()
	s.now = func() time.Time { return current }

	tok, err := s.Issue("alice", false)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	current = current.Add(2 * time.Minute)
	if _, err := s.Verify(tok); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}

func TestVerify_JustBeforeExpirySucceeds(t *testing.T) {
	s, err := NewSigner(testKey(), time.Minute)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	current := time.Now()
	s.now = func() time.Time { return current }

	tok, err := s.Issue("alice", false)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	current = current.Add(59 * time.Second)
	if _, err := s.Verify(tok); err != nil {
		t.Fatalf("Verify just before expiry: %v", err)
	}
}

func TestVerify_WrongKeyRejected(t *testing.T) {
	s1, err := NewSigner(testKey(), time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	s2, err := NewSigner([]byte("99999999999999999999999999999999"), time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tok, err := s1.Issue("alice", false)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s2.Verify(tok); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("got %v, want ErrInvalidSignature", err)
	}
}
