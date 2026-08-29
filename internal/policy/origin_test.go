package policy

import (
	"crypto/sha256"
	"errors"
	"testing"
)

func TestCheckOrigin_ExactMatch(t *testing.T) {
	a := NewOriginAllowlist("https://example.com")
	if err := a.CheckOrigin("https://example.com"); err != nil {
		t.Fatalf("CheckOrigin: %v", err)
	}
}

func TestCheckOrigin_RejectsSuffixAttack(t *testing.T) {
	// The canonical origin-check bug: a naive suffix/contains match
	// would wrongly accept this.
	a := NewOriginAllowlist("https://example.com")
	if err := a.CheckOrigin("https://example.com.attacker.net"); !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("got %v, want ErrOriginNotAllowed", err)
	}
}

func TestCheckOrigin_RejectsPrefixAttack(t *testing.T) {
	a := NewOriginAllowlist("https://example.com")
	if err := a.CheckOrigin("https://evilexample.com"); !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("got %v, want ErrOriginNotAllowed", err)
	}
}

func TestCheckOrigin_RejectsSchemeMismatch(t *testing.T) {
	a := NewOriginAllowlist("https://example.com")
	if err := a.CheckOrigin("http://example.com"); !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("got %v, want ErrOriginNotAllowed", err)
	}
}

func TestCheckOrigin_RejectsPortMismatch(t *testing.T) {
	a := NewOriginAllowlist("http://localhost:8080")
	if err := a.CheckOrigin("http://localhost:8081"); !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("got %v, want ErrOriginNotAllowed", err)
	}
}

func TestCheckOrigin_MultipleAllowedOrigins(t *testing.T) {
	a := NewOriginAllowlist("https://example.com", "http://localhost:8080")
	if err := a.CheckOrigin("https://example.com"); err != nil {
		t.Fatalf("first origin: %v", err)
	}
	if err := a.CheckOrigin("http://localhost:8080"); err != nil {
		t.Fatalf("second origin: %v", err)
	}
	if err := a.CheckOrigin("https://third.example"); !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("unlisted origin: got %v, want ErrOriginNotAllowed", err)
	}
}

func TestCheckOrigin_EmptyAllowlistRejectsEverything(t *testing.T) {
	a := NewOriginAllowlist()
	if err := a.CheckOrigin("https://example.com"); !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("got %v, want ErrOriginNotAllowed", err)
	}
}

func TestCheckRPIDHash_Match(t *testing.T) {
	hash := sha256.Sum256([]byte("example.com"))
	if err := CheckRPIDHash("example.com", hash); err != nil {
		t.Fatalf("CheckRPIDHash: %v", err)
	}
}

func TestCheckRPIDHash_Mismatch(t *testing.T) {
	var bogus [32]byte
	if err := CheckRPIDHash("example.com", bogus); !errors.Is(err, ErrRPIDHashMismatch) {
		t.Fatalf("got %v, want ErrRPIDHashMismatch", err)
	}
}

func TestCheckRPIDHash_HashFromDifferentRPID(t *testing.T) {
	hashOfAttackerDomain := sha256.Sum256([]byte("attacker.net"))
	if err := CheckRPIDHash("example.com", hashOfAttackerDomain); !errors.Is(err, ErrRPIDHashMismatch) {
		t.Fatalf("got %v, want ErrRPIDHashMismatch", err)
	}
}
