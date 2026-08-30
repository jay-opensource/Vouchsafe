package ceremony

import (
	"crypto/sha256"
	"testing"

	"github.com/jay-opensource/Vouchsafe/internal/cose"
	"github.com/jay-opensource/Vouchsafe/internal/webauthntest"
)

// BenchmarkLogin_* measures end-to-end authentication-ceremony
// verification latency per algorithm: challenge/origin/rpID checks,
// signature verification, and counter bookkeeping — everything Login
// does, not just the raw crypto primitive. Setup (issuing a fresh
// single-use challenge and producing a new signed assertion) happens
// outside the timed portion of each iteration, since a real deployment
// pays that cost once per login attempt, not per benchmark sample.
//
// Run with: go test -bench=. -benchmem ./internal/ceremony/
func benchmarkLogin(b *testing.B, alg int64) {
	reg, auth := newTestServer(b)
	va, credID := registerTestUser(b, reg, "alice", alg)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		challenge, err := auth.Challenges.Issue("alice", PurposeLogin)
		if err != nil {
			b.Fatalf("Issue: %v", err)
		}
		assertion, err := va.Authenticate(rTestRPID, rTestOrigin, challenge, credID)
		if err != nil {
			b.Fatalf("Authenticate: %v", err)
		}
		b.StartTimer()

		if _, err := auth.Login(AssertionRequest{
			Username:          "alice",
			CredentialID:      credID,
			ClientDataJSON:    assertion.ClientDataJSON,
			AuthenticatorData: assertion.AuthenticatorData,
			Signature:         assertion.Signature,
		}); err != nil {
			b.Fatalf("Login: %v", err)
		}
	}
}

func BenchmarkLogin_ES256(b *testing.B) { benchmarkLogin(b, cose.AlgES256) }
func BenchmarkLogin_RS256(b *testing.B) { benchmarkLogin(b, cose.AlgRS256) }
func BenchmarkLogin_EdDSA(b *testing.B) { benchmarkLogin(b, cose.AlgEdDSA) }

// benchmarkVerifySignatureOnly isolates the raw cryptographic
// verification cost, with no store I/O in the loop — Login's own
// benchmark above is dominated by the durable fsync write
// UpdateSignCount performs on every call, not by cryptography. Both
// numbers are published deliberately: the honest latency picture is
// "verification itself is fast; durability is what costs."
func benchmarkVerifySignatureOnly(b *testing.B, alg int64) {
	va, err := webauthntest.New(alg)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	assertion, err := va.Authenticate(rTestRPID, rTestOrigin, make([]byte, 32), []byte{0x01})
	if err != nil {
		b.Fatalf("Authenticate: %v", err)
	}
	cdHash := sha256.Sum256(assertion.ClientDataJSON)
	signedOver := append(append([]byte(nil), assertion.AuthenticatorData...), cdHash[:]...)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := verifySignature(alg, va.PublicKey(), signedOver, assertion.Signature); err != nil {
			b.Fatalf("verifySignature: %v", err)
		}
	}
}

func BenchmarkVerifySignatureOnly_ES256(b *testing.B) { benchmarkVerifySignatureOnly(b, cose.AlgES256) }
func BenchmarkVerifySignatureOnly_RS256(b *testing.B) { benchmarkVerifySignatureOnly(b, cose.AlgRS256) }
func BenchmarkVerifySignatureOnly_EdDSA(b *testing.B) { benchmarkVerifySignatureOnly(b, cose.AlgEdDSA) }
