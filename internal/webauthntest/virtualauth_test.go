package webauthntest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/jay-opensource/Vouchsafe/internal/authdata"
	"github.com/jay-opensource/Vouchsafe/internal/cbor"
	"github.com/jay-opensource/Vouchsafe/internal/cose"
)

// These are the Tier-1 checkpoint: a full round trip of harness output
// through every parser built so far (cbor -> authdata -> cose), and a
// real signature verified with a key that came out the other end of
// that pipeline — the equivalent of the spec's "hour-24 real-browser
// registration" gate, since no real browser is available here.

const (
	testRPID   = "example.com"
	testOrigin = "https://example.com"
)

func decodeAttestationObject(t *testing.T, attObj []byte) (fmtStr string, authData []byte) {
	t.Helper()
	v, n, err := cbor.Decode(attObj)
	if err != nil {
		t.Fatalf("decode attestationObject: %v", err)
	}
	if n != len(attObj) {
		t.Fatalf("attestationObject: consumed %d of %d bytes", n, len(attObj))
	}
	fmtVal, ok := v.MapGetText("fmt")
	if !ok || fmtVal.Type != cbor.TypeText {
		t.Fatalf("attestationObject missing fmt")
	}
	adVal, ok := v.MapGetText("authData")
	if !ok || adVal.Type != cbor.TypeBytes {
		t.Fatalf("attestationObject missing authData")
	}
	if _, ok := v.MapGetText("attStmt"); !ok {
		t.Fatalf("attestationObject missing attStmt")
	}
	return fmtVal.Text, adVal.Bytes
}

func decodeClientData(t *testing.T, cd []byte, wantType, wantOrigin string, wantChallenge []byte) {
	t.Helper()
	var parsed struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(cd, &parsed); err != nil {
		t.Fatalf("clientDataJSON: %v", err)
	}
	if parsed.Type != wantType {
		t.Fatalf("type = %q, want %q", parsed.Type, wantType)
	}
	if parsed.Origin != wantOrigin {
		t.Fatalf("origin = %q, want %q", parsed.Origin, wantOrigin)
	}
	got, err := base64.RawURLEncoding.DecodeString(parsed.Challenge)
	if err != nil {
		t.Fatalf("challenge not valid base64url: %v", err)
	}
	if !bytes.Equal(got, wantChallenge) {
		t.Fatalf("challenge = %x, want %x", got, wantChallenge)
	}
}

func testRegisterRoundTrip(t *testing.T, alg int64) {
	t.Helper()
	v, err := New(alg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	credentialID := []byte{0x01, 0x02, 0x03, 0x04}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		t.Fatalf("challenge: %v", err)
	}

	reg, err := v.Register(testRPID, testOrigin, challenge, credentialID)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	decodeClientData(t, reg.ClientDataJSON, "webauthn.create", testOrigin, challenge)

	fmtStr, rawAuthData := decodeAttestationObject(t, reg.AttestationObject)
	if fmtStr != "none" {
		t.Fatalf("fmt = %q, want none", fmtStr)
	}

	ad, err := authdata.Parse(rawAuthData)
	if err != nil {
		t.Fatalf("authdata.Parse: %v", err)
	}
	if !ad.UP || !ad.UV || !ad.AT {
		t.Fatalf("expected UP+UV+AT set, got UP=%v UV=%v AT=%v", ad.UP, ad.UV, ad.AT)
	}
	if ad.Attested == nil {
		t.Fatalf("Attested is nil")
	}
	if ad.Attested.AAGUID != v.AAGUID {
		t.Fatalf("AAGUID mismatch: got %x, want %x", ad.Attested.AAGUID, v.AAGUID)
	}
	if !bytes.Equal(ad.Attested.CredentialID, credentialID) {
		t.Fatalf("CredentialID mismatch")
	}

	key, err := cose.Parse(ad.Attested.CredentialPublicKey)
	if err != nil {
		t.Fatalf("cose.Parse: %v", err)
	}
	if key.Alg != alg {
		t.Fatalf("Alg = %d, want %d", key.Alg, alg)
	}

	switch alg {
	case cose.AlgES256:
		pub, ok := key.Public.(*ecdsa.PublicKey)
		if !ok || !pub.Equal(v.PublicKey()) {
			t.Fatalf("parsed EC2 key does not match the harness's own key")
		}
	case cose.AlgRS256:
		pub, ok := key.Public.(*rsa.PublicKey)
		if !ok || !pub.Equal(v.PublicKey()) {
			t.Fatalf("parsed RSA key does not match the harness's own key")
		}
	case cose.AlgEdDSA:
		pub, ok := key.Public.(ed25519.PublicKey)
		if !ok || !pub.Equal(v.PublicKey()) {
			t.Fatalf("parsed Ed25519 key does not match the harness's own key")
		}
	}
}

func TestRegisterRoundTrip_ES256(t *testing.T) { testRegisterRoundTrip(t, cose.AlgES256) }
func TestRegisterRoundTrip_RS256(t *testing.T) { testRegisterRoundTrip(t, cose.AlgRS256) }
func TestRegisterRoundTrip_EdDSA(t *testing.T) { testRegisterRoundTrip(t, cose.AlgEdDSA) }

// testAuthenticateRoundTrip is the strongest checkpoint: it verifies a
// signature using a key that traveled through the entire Register ->
// attestationObject -> cbor.Decode -> authdata.Parse -> cose.Parse
// pipeline, not the harness's private key struct directly — proving the
// whole chain agrees on what the credential's public key actually is.
func testAuthenticateRoundTrip(t *testing.T, alg int64) {
	t.Helper()
	v, err := New(alg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	credentialID := []byte{0xaa, 0xbb}
	regChallenge := make([]byte, 32)
	rand.Read(regChallenge)
	reg, err := v.Register(testRPID, testOrigin, regChallenge, credentialID)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	_, rawAuthData := decodeAttestationObject(t, reg.AttestationObject)
	regAD, err := authdata.Parse(rawAuthData)
	if err != nil {
		t.Fatalf("authdata.Parse (registration): %v", err)
	}
	key, err := cose.Parse(regAD.Attested.CredentialPublicKey)
	if err != nil {
		t.Fatalf("cose.Parse: %v", err)
	}

	loginChallenge := make([]byte, 32)
	rand.Read(loginChallenge)
	assertion, err := v.Authenticate(testRPID, testOrigin, loginChallenge, credentialID)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	decodeClientData(t, assertion.ClientDataJSON, "webauthn.get", testOrigin, loginChallenge)

	ad, err := authdata.Parse(assertion.AuthenticatorData)
	if err != nil {
		t.Fatalf("authdata.Parse (assertion): %v", err)
	}
	if ad.AT {
		t.Fatalf("assertion authenticatorData must not carry attestedCredentialData")
	}
	if ad.SignCount != 2 { // registration used signCount 1, this call increments to 2
		t.Fatalf("SignCount = %d, want 2", ad.SignCount)
	}

	// Recompute the signed-over bytes exactly as WebAuthn defines them and
	// verify with the key that came out of the parser pipeline, not the
	// harness's own private key struct. ES256/RS256 verify against a
	// SHA-256 digest of these bytes; EdDSA verifies the bytes directly.
	cdHash := sha256.Sum256(assertion.ClientDataJSON)
	signedOver := append(append([]byte(nil), assertion.AuthenticatorData...), cdHash[:]...)
	digest := sha256.Sum256(signedOver)

	switch alg {
	case cose.AlgES256:
		pub := key.Public.(*ecdsa.PublicKey)
		if !ecdsa.VerifyASN1(pub, digest[:], assertion.Signature) {
			t.Fatalf("ES256 signature did not verify against the parsed public key")
		}
	case cose.AlgRS256:
		pub := key.Public.(*rsa.PublicKey)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], assertion.Signature); err != nil {
			t.Fatalf("RS256 signature did not verify against the parsed public key: %v", err)
		}
	case cose.AlgEdDSA:
		pub := key.Public.(ed25519.PublicKey)
		if !ed25519.Verify(pub, signedOver, assertion.Signature) {
			t.Fatalf("EdDSA signature did not verify against the parsed public key")
		}
	}
}

func TestAuthenticateRoundTrip_ES256(t *testing.T) { testAuthenticateRoundTrip(t, cose.AlgES256) }
func TestAuthenticateRoundTrip_RS256(t *testing.T) { testAuthenticateRoundTrip(t, cose.AlgRS256) }
func TestAuthenticateRoundTrip_EdDSA(t *testing.T) { testAuthenticateRoundTrip(t, cose.AlgEdDSA) }

func TestWithZeroCounter(t *testing.T) {
	v, err := New(cose.AlgES256, WithZeroCounter())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	credentialID := []byte{0x01}
	challenge := make([]byte, 32)

	reg, err := v.Register(testRPID, testOrigin, challenge, credentialID)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	_, rawAuthData := decodeAttestationObject(t, reg.AttestationObject)
	regAD, err := authdata.Parse(rawAuthData)
	if err != nil {
		t.Fatalf("authdata.Parse: %v", err)
	}
	if regAD.SignCount != 0 {
		t.Fatalf("registration SignCount = %d, want 0", regAD.SignCount)
	}

	for i := range 3 {
		assertion, err := v.Authenticate(testRPID, testOrigin, challenge, credentialID)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		ad, err := authdata.Parse(assertion.AuthenticatorData)
		if err != nil {
			t.Fatalf("authdata.Parse: %v", err)
		}
		if ad.SignCount != 0 {
			t.Fatalf("call %d: SignCount = %d, want 0 (zero-counter authenticator)", i, ad.SignCount)
		}
	}
}

func TestSetSignCount(t *testing.T) {
	v, err := New(cose.AlgES256)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	credentialID := []byte{0x01}
	challenge := make([]byte, 32)

	v.SetSignCount(41)
	assertion, err := v.Authenticate(testRPID, testOrigin, challenge, credentialID)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	ad, err := authdata.Parse(assertion.AuthenticatorData)
	if err != nil {
		t.Fatalf("authdata.Parse: %v", err)
	}
	if ad.SignCount != 42 { // SetSignCount doesn't bypass the normal increment
		t.Fatalf("SignCount = %d, want 42", ad.SignCount)
	}
}

func TestNew_RejectsUnsupportedAlgorithm(t *testing.T) {
	if _, err := New(-999); err == nil {
		t.Fatalf("expected an error for an unsupported algorithm")
	}
}
