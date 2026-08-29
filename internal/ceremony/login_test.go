package ceremony

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jay-opensource/Vouchsafe/internal/cose"
	"github.com/jay-opensource/Vouchsafe/internal/policy"
	"github.com/jay-opensource/Vouchsafe/internal/store"
	"github.com/jay-opensource/Vouchsafe/internal/webauthntest"
)

func encodeB64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signWithForgedRSAKey produces a real signature over the exact bytes
// WebAuthn defines as signed, using a key that was never registered —
// used to prove algorithm-confusion attempts fail rather than to
// exercise a normal success path.
func signWithForgedRSAKey(t *testing.T, priv *rsa.PrivateKey, clientDataJSON, authData []byte) []byte {
	t.Helper()
	cdHash := sha256.Sum256(clientDataJSON)
	signedOver := append(append([]byte(nil), authData...), cdHash[:]...)
	digest := sha256.Sum256(signedOver)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

// newTestServer builds a Registrar and an Authenticator sharing one
// ChallengeStore, one origin allowlist, and one credential store, as if
// they were the two ceremony handlers of a single running vouchsafe.
func newTestServer(t *testing.T) (*Registrar, *Authenticator) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "vouchsafe.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	challenges := NewChallengeStore()
	origins := policy.NewOriginAllowlist(rTestOrigin)

	reg := &Registrar{Challenges: challenges, Origins: origins, Store: s, RPID: rTestRPID, UVPolicy: policy.UVPreferred}
	auth := &Authenticator{Challenges: challenges, Origins: origins, Store: s, RPID: rTestRPID, UVPolicy: policy.UVPreferred}
	return reg, auth
}

// registerTestUser runs a full registration through the harness and the
// real Registrar, returning the authenticator and credential ID for
// subsequent login tests.
func registerTestUser(t *testing.T, reg *Registrar, username string, alg int64) (*webauthntest.VirtualAuthenticator, []byte) {
	t.Helper()
	va, err := webauthntest.New(alg)
	if err != nil {
		t.Fatalf("New authenticator: %v", err)
	}
	credID := randomCredentialID(t)
	challenge, err := reg.Challenges.Issue(username, PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	regResult, err := va.Register(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness Register: %v", err)
	}
	if err := reg.Register(RegistrationRequest{
		Username:          username,
		CredentialID:      credID,
		ClientDataJSON:    regResult.ClientDataJSON,
		AttestationObject: regResult.AttestationObject,
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return va, credID
}

func testLoginSuccess(t *testing.T, alg int64) {
	t.Helper()
	reg, auth := newTestServer(t)
	va, credID := registerTestUser(t, reg, "alice", alg)

	challenge, err := auth.Challenges.Issue("alice", PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness Authenticate: %v", err)
	}

	result, err := auth.Login(AssertionRequest{
		Username:          "alice",
		CredentialID:      credID,
		ClientDataJSON:    assertion.ClientDataJSON,
		AuthenticatorData: assertion.AuthenticatorData,
		Signature:         assertion.Signature,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.Username != "alice" {
		t.Fatalf("Username = %q, want alice", result.Username)
	}
	if !result.UVPerformed {
		t.Fatalf("UVPerformed = false, want true (harness always sets UV)")
	}
}

func TestLogin_Success_ES256(t *testing.T) { testLoginSuccess(t, cose.AlgES256) }
func TestLogin_Success_RS256(t *testing.T) { testLoginSuccess(t, cose.AlgRS256) }

func TestLogin_ChallengeNeverIssued(t *testing.T) {
	reg, auth := newTestServer(t)
	va, credID := registerTestUser(t, reg, "alice", cose.AlgES256)

	assertion, err := va.Authenticate(rTestRPID, rTestOrigin, make([]byte, 32), credID)
	if err != nil {
		t.Fatalf("harness Authenticate: %v", err)
	}
	_, err = auth.Login(AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: assertion.AuthenticatorData, Signature: assertion.Signature,
	})
	if !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("got %v, want ErrChallengeNotFound", err)
	}
}

func TestLogin_WrongChallenge(t *testing.T) {
	reg, auth := newTestServer(t)
	va, credID := registerTestUser(t, reg, "alice", cose.AlgES256)

	if _, err := auth.Challenges.Issue("alice", PurposeLogin); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	wrong := make([]byte, 32)
	if _, err := rand.Read(wrong); err != nil {
		t.Fatalf("rand: %v", err)
	}
	assertion, err := va.Authenticate(rTestRPID, rTestOrigin, wrong, credID)
	if err != nil {
		t.Fatalf("harness Authenticate: %v", err)
	}
	_, err = auth.Login(AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: assertion.AuthenticatorData, Signature: assertion.Signature,
	})
	if !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("got %v, want ErrChallengeMismatch", err)
	}
}

func TestLogin_WrongOrigin(t *testing.T) {
	reg, auth := newTestServer(t)
	va, credID := registerTestUser(t, reg, "alice", cose.AlgES256)

	challenge, err := auth.Challenges.Issue("alice", PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rTestRPID, "https://evil.example", challenge, credID)
	if err != nil {
		t.Fatalf("harness Authenticate: %v", err)
	}
	_, err = auth.Login(AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: assertion.AuthenticatorData, Signature: assertion.Signature,
	})
	if !errors.Is(err, policy.ErrOriginNotAllowed) {
		t.Fatalf("got %v, want ErrOriginNotAllowed", err)
	}
}

func TestLogin_WrongRPID(t *testing.T) {
	reg, auth := newTestServer(t)
	va, credID := registerTestUser(t, reg, "alice", cose.AlgES256)
	auth.RPID = "different.example"

	challenge, err := auth.Challenges.Issue("alice", PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness Authenticate: %v", err)
	}
	_, err = auth.Login(AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: assertion.AuthenticatorData, Signature: assertion.Signature,
	})
	if !errors.Is(err, policy.ErrRPIDHashMismatch) {
		t.Fatalf("got %v, want ErrRPIDHashMismatch", err)
	}
}

func TestLogin_WrongClientDataType(t *testing.T) {
	reg, auth := newTestServer(t)
	va, credID := registerTestUser(t, reg, "alice", cose.AlgES256)

	challenge, err := auth.Challenges.Issue("alice", PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness Authenticate: %v", err)
	}
	badClientData := clientDataJSON("webauthn.create", encodeB64URL(challenge), rTestOrigin)

	_, err = auth.Login(AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: badClientData, AuthenticatorData: assertion.AuthenticatorData, Signature: assertion.Signature,
	})
	if !errors.Is(err, ErrClientDataType) {
		t.Fatalf("got %v, want ErrClientDataType", err)
	}
}

func TestLogin_CredentialNotFound(t *testing.T) {
	_, auth := newTestServer(t)
	va, err := webauthntest.New(cose.AlgES256)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	unregisteredCredID := randomCredentialID(t)

	challenge, err := auth.Challenges.Issue("alice", PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rTestRPID, rTestOrigin, challenge, unregisteredCredID)
	if err != nil {
		t.Fatalf("harness Authenticate: %v", err)
	}
	_, err = auth.Login(AssertionRequest{
		Username: "alice", CredentialID: unregisteredCredID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: assertion.AuthenticatorData, Signature: assertion.Signature,
	})
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("got %v, want ErrCredentialNotFound", err)
	}
}

func TestLogin_SignatureDoesNotVerify(t *testing.T) {
	reg, auth := newTestServer(t)
	va, credID := registerTestUser(t, reg, "alice", cose.AlgES256)

	challenge, err := auth.Challenges.Issue("alice", PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness Authenticate: %v", err)
	}
	corrupted := append([]byte(nil), assertion.Signature...)
	corrupted[0] ^= 0xff

	_, err = auth.Login(AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: assertion.AuthenticatorData, Signature: corrupted,
	})
	if !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("got %v, want ErrSignatureVerification", err)
	}
}

// TestLogin_AlgorithmConfusionAttemptFails proves an attacker can't get
// a different algorithm's verification path to run just by presenting a
// signature made under it — AssertionRequest carries no algorithm field
// at all, so the choice of ecdsa.VerifyASN1 vs rsa.VerifyPKCS1v15 comes
// only from the algorithm pinned on the stored credential (W9).
func TestLogin_AlgorithmConfusionAttemptFails(t *testing.T) {
	reg, auth := newTestServer(t)
	_, credID := registerTestUser(t, reg, "alice", cose.AlgES256) // registered as ES256

	challenge, err := auth.Challenges.Issue("alice", PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cd := clientDataJSON("webauthn.get", encodeB64URL(challenge), rTestOrigin)

	// A signature genuinely produced by an entirely different (and
	// unregistered) RSA key over the exact bytes WebAuthn defines as
	// signed — an attacker substituting this can only hope the verifier
	// picks its algorithm from somewhere other than storage.
	forgePriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate forging key: %v", err)
	}
	rpIDHash := sha256.Sum256([]byte(rTestRPID))
	authData := make([]byte, 37) // well-formed fixed header, correct rpIdHash, UP+UV set
	copy(authData[0:32], rpIDHash[:])
	authData[32] = 0x01 | 0x04
	sig := signWithForgedRSAKey(t, forgePriv, cd, authData)

	_, err = auth.Login(AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: cd, AuthenticatorData: authData, Signature: sig,
	})
	if !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("got %v, want ErrSignatureVerification (a forged signature under a different algorithm must not verify)", err)
	}
}

func TestLogin_UPNotSet(t *testing.T) {
	reg, auth := newTestServer(t)
	va, credID := registerTestUser(t, reg, "alice", cose.AlgES256)

	challenge, err := auth.Challenges.Issue("alice", PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness Authenticate: %v", err)
	}
	corrupted := append([]byte(nil), assertion.AuthenticatorData...)
	corrupted[32] &^= 0x01 // clear UP; signature check is never reached since CheckFlags runs first

	_, err = auth.Login(AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: corrupted, Signature: assertion.Signature,
	})
	if !errors.Is(err, policy.ErrUserNotPresent) {
		t.Fatalf("got %v, want ErrUserNotPresent", err)
	}
}

func TestLogin_UpdatesStoredSignCount(t *testing.T) {
	reg, auth := newTestServer(t)
	va, credID := registerTestUser(t, reg, "alice", cose.AlgES256)

	before, ok, err := auth.Store.FindByID(credID)
	if err != nil || !ok {
		t.Fatalf("FindByID before login: ok=%v err=%v", ok, err)
	}

	challenge, err := auth.Challenges.Issue("alice", PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness Authenticate: %v", err)
	}
	if _, err := auth.Login(AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: assertion.AuthenticatorData, Signature: assertion.Signature,
	}); err != nil {
		t.Fatalf("Login: %v", err)
	}

	after, ok, err := auth.Store.FindByID(credID)
	if err != nil || !ok {
		t.Fatalf("FindByID after login: ok=%v err=%v", ok, err)
	}
	if after.SignCount <= before.SignCount {
		t.Fatalf("SignCount did not advance: before=%d after=%d", before.SignCount, after.SignCount)
	}
}
