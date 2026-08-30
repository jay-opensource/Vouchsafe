// Package negative is the spec's §9.3 negative-test suite: one
// deliberate mutation per named defect, each asserting the specific
// rejection. This is the deliverable, not polish — a working demo does
// not reveal any of these on its own.
package negative

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay-opensource/Vouchsafe/internal/cbortest"
	"github.com/jay-opensource/Vouchsafe/internal/ceremony"
	"github.com/jay-opensource/Vouchsafe/internal/cose"
	"github.com/jay-opensource/Vouchsafe/internal/policy"
	"github.com/jay-opensource/Vouchsafe/internal/store"
	"github.com/jay-opensource/Vouchsafe/internal/webauthntest"
)

const (
	rpID   = "example.com"
	origin = "https://example.com"
)

type server struct {
	Registrar     *ceremony.Registrar
	Authenticator *ceremony.Authenticator
	Challenges    *ceremony.ChallengeStore
}

func newServer(t *testing.T) *server {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "vouchsafe.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	challenges := ceremony.NewChallengeStore()
	origins := policy.NewOriginAllowlist(origin)
	return &server{
		Registrar:     &ceremony.Registrar{Challenges: challenges, Origins: origins, Store: s, RPID: rpID, UVPolicy: policy.UVPreferred},
		Authenticator: &ceremony.Authenticator{Challenges: challenges, Origins: origins, Store: s, RPID: rpID, UVPolicy: policy.UVPreferred},
		Challenges:    challenges,
	}
}

func (s *server) register(t *testing.T, username string, alg int64) (*webauthntest.VirtualAuthenticator, []byte) {
	t.Helper()
	va, err := webauthntest.New(alg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("rand: %v", err)
	}
	challenge, err := s.Challenges.Issue(username, ceremony.PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	reg, err := va.Register(rpID, origin, challenge, credID)
	if err != nil {
		t.Fatalf("harness Register: %v", err)
	}
	if err := s.Registrar.Register(ceremony.RegistrationRequest{
		Username: username, CredentialID: credID,
		ClientDataJSON: reg.ClientDataJSON, AttestationObject: reg.AttestationObject,
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return va, credID
}

func clientData(typ, challengeB64, origin string) []byte {
	return []byte(`{"type":"` + typ + `","challenge":"` + challengeB64 + `","origin":"` + origin + `"}`)
}

// 1. Challenge altered by one byte -> not the issued challenge (W5)
func TestChallengeAlteredByOneByte_Rejected(t *testing.T) {
	s := newServer(t)
	va, credID := s.register(t, "alice", cose.AlgES256)
	challenge, err := s.Challenges.Issue("alice", ceremony.PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	altered := append([]byte(nil), challenge...)
	altered[0] ^= 0xff
	assertion, err := va.Authenticate(rpID, origin, altered, credID)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	_, err = s.Authenticator.Login(ceremony.AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: assertion.AuthenticatorData, Signature: assertion.Signature,
	})
	if !errors.Is(err, ceremony.ErrChallengeMismatch) {
		t.Fatalf("got %v, want ErrChallengeMismatch", err)
	}
}

// 2. Valid ceremony replayed verbatim -> challenge already consumed (W5)
func TestValidCeremonyReplayedVerbatim_Rejected(t *testing.T) {
	s := newServer(t)
	va, credID := s.register(t, "alice", cose.AlgES256)
	challenge, err := s.Challenges.Issue("alice", ceremony.PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rpID, origin, challenge, credID)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	req := ceremony.AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: assertion.AuthenticatorData, Signature: assertion.Signature,
	}
	if _, err := s.Authenticator.Login(req); err != nil {
		t.Fatalf("first login: %v", err)
	}
	if _, err := s.Authenticator.Login(req); !errors.Is(err, ceremony.ErrChallengeNotFound) {
		t.Fatalf("replay: got %v, want ErrChallengeNotFound", err)
	}
}

// 3. Challenge older than 120s -> expired (W5)
func TestChallengeOlderThan120s_Rejected(t *testing.T) {
	s := newServer(t)
	current := time.Now()
	s.Challenges.SetClock(func() time.Time { return current })

	va, credID := s.register(t, "alice", cose.AlgES256)
	challenge, err := s.Challenges.Issue("alice", ceremony.PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	current = current.Add(ceremony.ChallengeTTL + time.Second)

	assertion, err := va.Authenticate(rpID, origin, challenge, credID)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	_, err = s.Authenticator.Login(ceremony.AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: assertion.AuthenticatorData, Signature: assertion.Signature,
	})
	if !errors.Is(err, ceremony.ErrChallengeExpired) {
		t.Fatalf("got %v, want ErrChallengeExpired", err)
	}
}

// 4. Origin http://localhost:8080.attacker.net -> not an exact match (W6)
func TestOriginSuffixAttack_Rejected(t *testing.T) {
	s := newServer(t)
	va, credID := s.register(t, "alice", cose.AlgES256)
	challenge, err := s.Challenges.Issue("alice", ceremony.PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rpID, origin+".attacker.net", challenge, credID)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	_, err = s.Authenticator.Login(ceremony.AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: assertion.AuthenticatorData, Signature: assertion.Signature,
	})
	if !errors.Is(err, policy.ErrOriginNotAllowed) {
		t.Fatalf("got %v, want ErrOriginNotAllowed", err)
	}
}

// 5. rpIdHash from a different domain -> hash mismatch (W6)
func TestRPIDHashFromDifferentDomain_Rejected(t *testing.T) {
	s := newServer(t)
	va, credID := s.register(t, "alice", cose.AlgES256)
	s.Authenticator.RPID = "different.example"

	challenge, err := s.Challenges.Issue("alice", ceremony.PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rpID, origin, challenge, credID)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	_, err = s.Authenticator.Login(ceremony.AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: assertion.AuthenticatorData, Signature: assertion.Signature,
	})
	if !errors.Is(err, policy.ErrRPIDHashMismatch) {
		t.Fatalf("got %v, want ErrRPIDHashMismatch", err)
	}
}

// 6. UP flag cleared -> no user presence (W10)
func TestUPFlagCleared_Rejected(t *testing.T) {
	s := newServer(t)
	va, credID := s.register(t, "alice", cose.AlgES256)
	challenge, err := s.Challenges.Issue("alice", ceremony.PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rpID, origin, challenge, credID)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	corrupted := append([]byte(nil), assertion.AuthenticatorData...)
	corrupted[32] &^= 0x01
	_, err = s.Authenticator.Login(ceremony.AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: corrupted, Signature: assertion.Signature,
	})
	if !errors.Is(err, policy.ErrUserNotPresent) {
		t.Fatalf("got %v, want ErrUserNotPresent", err)
	}
}

// 7. UV cleared under uv=required -> policy violation (W10)
func TestUVClearedUnderRequiredPolicy_Rejected(t *testing.T) {
	s := newServer(t)
	s.Authenticator.UVPolicy = policy.UVRequired
	va, credID := s.register(t, "alice", cose.AlgES256)
	challenge, err := s.Challenges.Issue("alice", ceremony.PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rpID, origin, challenge, credID)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	corrupted := append([]byte(nil), assertion.AuthenticatorData...)
	corrupted[32] &^= 0x04 // clear UV, leave UP set
	_, err = s.Authenticator.Login(ceremony.AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: corrupted, Signature: assertion.Signature,
	})
	if !errors.Is(err, policy.ErrUserNotVerified) {
		t.Fatalf("got %v, want ErrUserNotVerified", err)
	}
}

// 8. signCount decremented -> suspected cloned authenticator (W7)
func TestSignCountDecremented_RejectedAsClone(t *testing.T) {
	s := newServer(t)
	va, credID := s.register(t, "alice", cose.AlgES256)

	challenge1, err := s.Challenges.Issue("alice", ceremony.PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	a1, err := va.Authenticate(rpID, origin, challenge1, credID)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, err := s.Authenticator.Login(ceremony.AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: a1.ClientDataJSON, AuthenticatorData: a1.AuthenticatorData, Signature: a1.Signature,
	}); err != nil {
		t.Fatalf("first login: %v", err)
	}

	va.SetSignCount(0)
	challenge2, err := s.Challenges.Issue("alice", ceremony.PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	a2, err := va.Authenticate(rpID, origin, challenge2, credID)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	_, err = s.Authenticator.Login(ceremony.AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: a2.ClientDataJSON, AuthenticatorData: a2.AuthenticatorData, Signature: a2.Signature,
	})
	if !errors.Is(err, ceremony.ErrCounterRegression) {
		t.Fatalf("got %v, want ErrCounterRegression", err)
	}
}

// 9. signCount zero on both sides -> must be ACCEPTED, counter unsupported (W7)
func TestSignCountZeroBothSides_MustBeAccepted(t *testing.T) {
	s := newServer(t)
	va, err := webauthntest.New(cose.AlgES256, webauthntest.WithZeroCounter())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("rand: %v", err)
	}
	challenge, err := s.Challenges.Issue("alice", ceremony.PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	reg, err := va.Register(rpID, origin, challenge, credID)
	if err != nil {
		t.Fatalf("harness Register: %v", err)
	}
	if err := s.Registrar.Register(ceremony.RegistrationRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: reg.ClientDataJSON, AttestationObject: reg.AttestationObject,
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	loginChallenge, err := s.Challenges.Issue("alice", ceremony.PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rpID, origin, loginChallenge, credID)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, err := s.Authenticator.Login(ceremony.AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: assertion.AuthenticatorData, Signature: assertion.Signature,
	}); err != nil {
		t.Fatalf("expected a zero-counter login to be accepted, got: %v", err)
	}
}

// 10. One byte of authData flipped -> signature no longer verifies (§7.1)
func TestOneByteOfAuthDataFlipped_SignatureFails(t *testing.T) {
	s := newServer(t)
	va, credID := s.register(t, "alice", cose.AlgES256)
	challenge, err := s.Challenges.Issue("alice", ceremony.PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rpID, origin, challenge, credID)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	corrupted := append([]byte(nil), assertion.AuthenticatorData...)
	corrupted[33] ^= 0xff // inside signCount — not flags/rpIdHash, so this isolates signature failure
	_, err = s.Authenticator.Login(ceremony.AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: corrupted, Signature: assertion.Signature,
	})
	if !errors.Is(err, ceremony.ErrSignatureVerification) {
		t.Fatalf("got %v, want ErrSignatureVerification", err)
	}
}

// 11. Assertion re-signed under another algorithm -> algorithm is pinned
// at registration, not taken from the request (W9)
func TestAssertionResignedUnderAnotherAlgorithm_Rejected(t *testing.T) {
	s := newServer(t)
	_, credID := s.register(t, "alice", cose.AlgES256)

	challenge, err := s.Challenges.Issue("alice", ceremony.PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cd := clientData("webauthn.get", base64.RawURLEncoding.EncodeToString(challenge), origin)

	forgePriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate forging key: %v", err)
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 37)
	copy(authData[0:32], rpIDHash[:])
	authData[32] = 0x01 | 0x04

	cdHash := sha256.Sum256(cd)
	signedOver := append(append([]byte(nil), authData...), cdHash[:]...)
	digest := sha256.Sum256(signedOver)
	sig, err := rsa.SignPKCS1v15(rand.Reader, forgePriv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	_, err = s.Authenticator.Login(ceremony.AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: cd, AuthenticatorData: authData, Signature: sig,
	})
	if !errors.Is(err, ceremony.ErrSignatureVerification) {
		t.Fatalf("got %v, want ErrSignatureVerification", err)
	}
}

// 12. User A's assertion + username "B" -> session must be issued for A (W8)
func TestUserAAssertionWithUsernameB_SessionIssuedForA(t *testing.T) {
	s := newServer(t)
	vaAlice, credAlice := s.register(t, "alice", cose.AlgES256)
	s.register(t, "bob", cose.AlgES256)

	challengeForBob, err := s.Challenges.Issue("bob", ceremony.PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := vaAlice.Authenticate(rpID, origin, challengeForBob, credAlice)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	result, err := s.Authenticator.Login(ceremony.AssertionRequest{
		Username: "bob", CredentialID: credAlice,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: assertion.AuthenticatorData, Signature: assertion.Signature,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.Username != "alice" {
		t.Fatalf("Username = %q, want alice", result.Username)
	}
}

// 13. Non-canonical CBOR (indefinite length) -> CTAP2 canonical form required (W3)
func TestNonCanonicalCBOR_Rejected(t *testing.T) {
	s := newServer(t)
	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("rand: %v", err)
	}
	challenge, err := s.Challenges.Issue("alice", ceremony.PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cd := clientData("webauthn.create", base64.RawURLEncoding.EncodeToString(challenge), origin)

	malformed := []byte{0xbf} // indefinite-length map: CTAP2 canonical form forbids this
	err = s.Registrar.Register(ceremony.RegistrationRequest{
		Username: "alice", CredentialID: credID, ClientDataJSON: cd, AttestationObject: malformed,
	})
	if !errors.Is(err, ceremony.ErrMalformedAttestationObject) {
		t.Fatalf("got %v, want ErrMalformedAttestationObject", err)
	}
}

// 14. CBOR nested 200 deep -> depth cap (W1)
func TestCBORNested200Deep_Rejected(t *testing.T) {
	s := newServer(t)
	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("rand: %v", err)
	}
	challenge, err := s.Challenges.Issue("alice", ceremony.PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cd := clientData("webauthn.create", base64.RawURLEncoding.EncodeToString(challenge), origin)

	deep := cbortest.Uint(0)
	for range 200 {
		deep = cbortest.Array(deep)
	}

	err = s.Registrar.Register(ceremony.RegistrationRequest{
		Username: "alice", CredentialID: credID, ClientDataJSON: cd, AttestationObject: deep,
	})
	if !errors.Is(err, ceremony.ErrMalformedAttestationObject) {
		t.Fatalf("got %v, want ErrMalformedAttestationObject", err)
	}
}

// 15. Truncated attestationObject -> bounds check, clean error, no panic (W1)
func TestTruncatedAttestationObject_CleanError(t *testing.T) {
	s := newServer(t)
	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("rand: %v", err)
	}
	challenge, err := s.Challenges.Issue("alice", ceremony.PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cd := clientData("webauthn.create", base64.RawURLEncoding.EncodeToString(challenge), origin)

	truncated := []byte{0xa3, 0x63, 'f', 'm'} // major5 map, 3 pairs claimed; cut off mid text-string
	err = s.Registrar.Register(ceremony.RegistrationRequest{
		Username: "alice", CredentialID: credID, ClientDataJSON: cd, AttestationObject: truncated,
	})
	if !errors.Is(err, ceremony.ErrMalformedAttestationObject) {
		t.Fatalf("got %v, want ErrMalformedAttestationObject (no panic — reaching this line proves that)", err)
	}
}

// 16. Unsupported attestation format -> named refusal, not silent acceptance (W11)
func TestUnsupportedAttestationFormat_NamedRefusal(t *testing.T) {
	s := newServer(t)
	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("rand: %v", err)
	}
	challenge, err := s.Challenges.Issue("alice", ceremony.PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cd := clientData("webauthn.create", base64.RawURLEncoding.EncodeToString(challenge), origin)
	attObj := cbortest.Map(
		cbortest.Entry{Key: cbortest.Text("fmt"), Val: cbortest.Text("tpm")},
		cbortest.Entry{Key: cbortest.Text("attStmt"), Val: cbortest.Map()},
		cbortest.Entry{Key: cbortest.Text("authData"), Val: cbortest.Bytes([]byte{0x00})},
	)
	err = s.Registrar.Register(ceremony.RegistrationRequest{
		Username: "alice", CredentialID: credID, ClientDataJSON: cd, AttestationObject: attObj,
	})
	if !errors.Is(err, ceremony.ErrAttestationFormat) {
		t.Fatalf("got %v, want ErrAttestationFormat", err)
	}
}
