package ceremony

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/jay-opensource/Vouchsafe/internal/cbor"
	"github.com/jay-opensource/Vouchsafe/internal/cbortest"
	"github.com/jay-opensource/Vouchsafe/internal/cose"
	"github.com/jay-opensource/Vouchsafe/internal/webauthntest"
)

func TestRegister_PackedSelfAttestation_Success(t *testing.T) {
	r := newTestRegistrar(t)
	va, err := webauthntest.New(cose.AlgES256)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	credID := randomCredentialID(t)
	challenge, err := r.Challenges.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	reg, err := va.RegisterPackedSelf(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness RegisterPackedSelf: %v", err)
	}

	if err := r.Register(RegistrationRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: reg.ClientDataJSON, AttestationObject: reg.AttestationObject,
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	stored, ok, err := r.Store.FindByID(credID)
	if err != nil || !ok {
		t.Fatalf("FindByID: ok=%v err=%v", ok, err)
	}
	if stored.Algorithm != cose.AlgES256 {
		t.Fatalf("Algorithm = %d, want %d", stored.Algorithm, cose.AlgES256)
	}
}

func TestRegister_PackedFullAttestation_Success(t *testing.T) {
	r := newTestRegistrar(t)
	va, err := webauthntest.New(cose.AlgES256)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	credID := randomCredentialID(t)
	challenge, err := r.Challenges.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	reg, err := va.RegisterPackedFull(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness RegisterPackedFull: %v", err)
	}

	if err := r.Register(RegistrationRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: reg.ClientDataJSON, AttestationObject: reg.AttestationObject,
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// The stored credential key must be the credential's own key, not
	// the throwaway attestation-certificate key that signed the
	// statement — attestation authenticates the credential, it isn't
	// the credential.
	stored, ok, err := r.Store.FindByID(credID)
	if err != nil || !ok {
		t.Fatalf("FindByID: ok=%v err=%v", ok, err)
	}
	keyVal, n, err := cbor.Decode(stored.PublicKey)
	if err != nil || n != len(stored.PublicKey) {
		t.Fatalf("decode stored key: n=%d err=%v", n, err)
	}
	key, err := cose.Parse(keyVal)
	if err != nil {
		t.Fatalf("cose.Parse: %v", err)
	}
	if key.Alg != cose.AlgES256 {
		t.Fatalf("stored key Alg = %d, want %d", key.Alg, cose.AlgES256)
	}
}

func TestRegister_PackedSelfAttestation_BadSignatureRejected(t *testing.T) {
	r := newTestRegistrar(t)
	va, err := webauthntest.New(cose.AlgES256)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	credID := randomCredentialID(t)
	challenge, err := r.Challenges.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	reg, err := va.RegisterPackedSelf(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness RegisterPackedSelf: %v", err)
	}

	_, attStmt, rawAuthData, err := decodeAttestationObject(reg.AttestationObject)
	if err != nil {
		t.Fatalf("decodeAttestationObject: %v", err)
	}
	sigVal, ok := attStmt.MapGetText("sig")
	if !ok {
		t.Fatalf("attStmt missing sig")
	}
	corruptedSig := append([]byte(nil), sigVal.Bytes...)
	corruptedSig[0] ^= 0xff

	algVal, _ := attStmt.MapGetText("alg")
	rebuilt := cbortest.Map(
		cbortest.Entry{Key: cbortest.Text("fmt"), Val: cbortest.Text("packed")},
		cbortest.Entry{Key: cbortest.Text("attStmt"), Val: cbortest.Map(
			cbortest.Entry{Key: cbortest.Text("alg"), Val: cbortest.NegInt(algVal.Int)},
			cbortest.Entry{Key: cbortest.Text("sig"), Val: cbortest.Bytes(corruptedSig)},
		)},
		cbortest.Entry{Key: cbortest.Text("authData"), Val: cbortest.Bytes(rawAuthData)},
	)

	err = r.Register(RegistrationRequest{Username: "alice", CredentialID: credID, ClientDataJSON: reg.ClientDataJSON, AttestationObject: rebuilt})
	if !errors.Is(err, ErrAttestationStatement) {
		t.Fatalf("got %v, want ErrAttestationStatement", err)
	}
}

func TestRegister_PackedFullAttestation_MalformedCertRejected(t *testing.T) {
	r := newTestRegistrar(t)
	credID := randomCredentialID(t)
	challenge, err := r.Challenges.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cd := clientDataJSON("webauthn.create", base64.RawURLEncoding.EncodeToString(challenge), rTestOrigin)
	authData := validAttestedAuthData(t, rTestRPID, credID)

	attObj := cbortest.Map(
		cbortest.Entry{Key: cbortest.Text("fmt"), Val: cbortest.Text("packed")},
		cbortest.Entry{Key: cbortest.Text("attStmt"), Val: cbortest.Map(
			cbortest.Entry{Key: cbortest.Text("alg"), Val: cbortest.NegInt(cose.AlgES256)},
			cbortest.Entry{Key: cbortest.Text("sig"), Val: cbortest.Bytes([]byte{0x01, 0x02})},
			cbortest.Entry{Key: cbortest.Text("x5c"), Val: cbortest.Array(cbortest.Bytes([]byte{0xff, 0xff, 0xff}))}, // not a real cert
		)},
		cbortest.Entry{Key: cbortest.Text("authData"), Val: cbortest.Bytes(authData)},
	)

	err = r.Register(RegistrationRequest{Username: "alice", CredentialID: credID, ClientDataJSON: cd, AttestationObject: attObj})
	if !errors.Is(err, ErrAttestationStatement) {
		t.Fatalf("got %v, want ErrAttestationStatement", err)
	}
}

func TestRegister_PackedAttestation_MissingSigRejected(t *testing.T) {
	r := newTestRegistrar(t)
	credID := randomCredentialID(t)
	challenge, err := r.Challenges.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cd := clientDataJSON("webauthn.create", base64.RawURLEncoding.EncodeToString(challenge), rTestOrigin)
	authData := validAttestedAuthData(t, rTestRPID, credID)

	attObj := cbortest.Map(
		cbortest.Entry{Key: cbortest.Text("fmt"), Val: cbortest.Text("packed")},
		cbortest.Entry{Key: cbortest.Text("attStmt"), Val: cbortest.Map(
			cbortest.Entry{Key: cbortest.Text("alg"), Val: cbortest.NegInt(cose.AlgES256)},
		)},
		cbortest.Entry{Key: cbortest.Text("authData"), Val: cbortest.Bytes(authData)},
	)

	err = r.Register(RegistrationRequest{Username: "alice", CredentialID: credID, ClientDataJSON: cd, AttestationObject: attObj})
	if !errors.Is(err, ErrAttestationStatement) {
		t.Fatalf("got %v, want ErrAttestationStatement", err)
	}
}

func TestRegister_PackedSelfAttestation_AlgMismatchRejected(t *testing.T) {
	r := newTestRegistrar(t)
	va, err := webauthntest.New(cose.AlgES256)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	credID := randomCredentialID(t)
	challenge, err := r.Challenges.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	reg, err := va.RegisterPackedSelf(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness RegisterPackedSelf: %v", err)
	}

	_, attStmt, rawAuthData, err := decodeAttestationObject(reg.AttestationObject)
	if err != nil {
		t.Fatalf("decodeAttestationObject: %v", err)
	}
	sigVal, _ := attStmt.MapGetText("sig")

	// Claim RS256 in the attestation statement while the credential (and
	// the real signature) is ES256 — must be rejected, not silently
	// re-verified under whatever alg the statement happens to claim.
	rebuilt := cbortest.Map(
		cbortest.Entry{Key: cbortest.Text("fmt"), Val: cbortest.Text("packed")},
		cbortest.Entry{Key: cbortest.Text("attStmt"), Val: cbortest.Map(
			cbortest.Entry{Key: cbortest.Text("alg"), Val: cbortest.NegInt(cose.AlgRS256)},
			cbortest.Entry{Key: cbortest.Text("sig"), Val: cbortest.Bytes(sigVal.Bytes)},
		)},
		cbortest.Entry{Key: cbortest.Text("authData"), Val: cbortest.Bytes(rawAuthData)},
	)

	err = r.Register(RegistrationRequest{Username: "alice", CredentialID: credID, ClientDataJSON: reg.ClientDataJSON, AttestationObject: rebuilt})
	if !errors.Is(err, ErrAttestationStatement) {
		t.Fatalf("got %v, want ErrAttestationStatement", err)
	}
}
