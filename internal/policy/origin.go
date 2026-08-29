// Package policy implements the WebAuthn security checks that don't
// belong to any single ceremony step: origin binding, rpIdHash
// validation, and user-presence/verification flag enforcement.
package policy

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

var (
	ErrOriginNotAllowed = errors.New("policy: origin not allowed")
	ErrRPIDHashMismatch = errors.New("policy: rpIdHash does not match rpID")
)

// OriginAllowlist is a fixed set of origins a ceremony's clientDataJSON
// "origin" field may exactly equal. Passkeys' phishing resistance over
// passwords comes entirely from this check and CheckRPIDHash below —
// skip either and a credential works on the wrong site.
//
// Membership is checked by exact string equality only, never a prefix,
// suffix, or substring match — that's how origin checks are usually
// broken in practice. A naive strings.HasSuffix or strings.Contains
// against "https://example.com" would wrongly accept
// "https://example.com.attacker.net".
type OriginAllowlist struct {
	allowed map[string]struct{}
}

// NewOriginAllowlist builds an allowlist from one or more exact origin
// strings (e.g. "https://example.com", "http://localhost:8080").
func NewOriginAllowlist(origins ...string) *OriginAllowlist {
	m := make(map[string]struct{}, len(origins))
	for _, o := range origins {
		m[o] = struct{}{}
	}
	return &OriginAllowlist{allowed: m}
}

// CheckOrigin reports whether origin exactly matches an allowed entry.
func (a *OriginAllowlist) CheckOrigin(origin string) error {
	if _, ok := a.allowed[origin]; !ok {
		return fmt.Errorf("%w: %q", ErrOriginNotAllowed, origin)
	}
	return nil
}

// CheckRPIDHash recomputes SHA-256(rpID) and compares it against the
// rpIdHash an authenticator reported in authenticatorData, rather than
// trusting whatever the client claims.
func CheckRPIDHash(rpID string, gotHash [32]byte) error {
	if sha256.Sum256([]byte(rpID)) != gotHash {
		return ErrRPIDHashMismatch
	}
	return nil
}
