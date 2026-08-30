// Package session issues and verifies session tokens with
// crypto/hmac + crypto/sha256 — deliberately not a JWT: no algorithm
// field for a verifier to be confused about, no library, no "alg: none"
// class of bug to inherit.
package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrMalformedToken  = errors.New("session: malformed token")
	ErrInvalidSignature = errors.New("session: invalid signature")
	ErrExpired          = errors.New("session: token expired")
)

// Claims is the payload carried inside a session token.
type Claims struct {
	Username    string    `json:"username"`
	UVPerformed bool      `json:"uv"`
	IssuedAt    time.Time `json:"iat"`
	ExpiresAt   time.Time `json:"exp"`
}

// Signer issues and verifies tokens of the form
// base64url(JSON claims) + "." + base64url(HMAC-SHA256 over the first part).
type Signer struct {
	key []byte
	now func() time.Time
	ttl time.Duration
}

// NewSigner creates a Signer. key must be at least 32 bytes.
func NewSigner(key []byte, ttl time.Duration) (*Signer, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("session: key must be at least 32 bytes, got %d", len(key))
	}
	return &Signer{key: key, now: time.Now, ttl: ttl}, nil
}

// Issue creates a signed token for username, valid for the Signer's TTL.
func (s *Signer) Issue(username string, uvPerformed bool) (string, error) {
	now := s.now()
	claims := Claims{
		Username:    username,
		UVPerformed: uvPerformed,
		IssuedAt:    now,
		ExpiresAt:   now.Add(s.ttl),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("session: encode claims: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	mac := s.sign(payloadB64)
	return payloadB64 + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

// Verify checks a token's signature and expiry and returns its claims.
func (s *Signer) Verify(token string) (Claims, error) {
	dot := strings.LastIndexByte(token, '.')
	if dot < 0 {
		return Claims{}, ErrMalformedToken
	}
	payloadB64, macB64 := token[:dot], token[dot+1:]

	gotMAC, err := base64.RawURLEncoding.DecodeString(macB64)
	if err != nil {
		return Claims{}, ErrMalformedToken
	}
	wantMAC := s.sign(payloadB64)
	if subtle.ConstantTimeCompare(gotMAC, wantMAC) != 1 {
		return Claims{}, ErrInvalidSignature
	}

	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return Claims{}, ErrMalformedToken
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, ErrMalformedToken
	}
	if s.now().After(claims.ExpiresAt) {
		return Claims{}, ErrExpired
	}
	return claims, nil
}

func (s *Signer) sign(payloadB64 string) []byte {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(payloadB64))
	return mac.Sum(nil)
}
