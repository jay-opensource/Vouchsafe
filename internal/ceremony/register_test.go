package ceremony

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jay-opensource/Vouchsafe/internal/cbor"
	"github.com/jay-opensource/Vouchsafe/internal/cbortest"
	"github.com/jay-opensource/Vouchsafe/internal/cose"
	"github.com/jay-opensource/Vouchsafe/internal/policy"
	"github.com/jay-opensource/Vouchsafe/internal/store"
	"github.com/jay-opensource/Vouchsafe/internal/webauthntest"
)

const (
	rTestRPID   = "example.com"
	rTestOrigin = "https://example.com"
)

func newTestRegistrar(t *testing.T) *Registrar {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "vouchsafe.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	return &Registrar{
		Challenges: NewChallengeStore(),
		Origins:    policy.NewOriginAllowlist(rTestOrigin),
		Store:      s,
		RPID:       rTestRPID,
		UVPolicy:   policy.UVPreferred,
	}
}

func randomCredentialID(t *testing.T) []byte {
	t.Helper()
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return id
}

func clientDataJSON(typ, challengeB64, origin string) []byte {
	return []byte(`{"type":"` + typ + `","challenge":"` + challengeB64 + `","origin":"` + origin + `"}`)
}

func TestRegister_Success(t *testing.T) {
	r := newTestRegistrar(t)
	va, err := webauthntest.New(cose.AlgES256)
	if err != nil {
		t.Fatalf("New authenticator: %v", err)
	}
	credID := randomCredentialID(t)
	challenge, err := r.Challenges.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	reg, err := va.Register(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness Register: %v", err)
	}

	if err := r.Register(RegistrationRequest{
		Username:          "alice",
		CredentialID:      credID,
		ClientDataJSON:    reg.ClientDataJSON,
		AttestationObject: reg.AttestationObject,
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	stored, ok, err := r.Store.FindByID(credID)
	if err != nil || !ok {
		t.Fatalf("FindByID: ok=%v err=%v", ok, err)
	}
	if stored.Username != "alice" {
		t.Fatalf("Username = %q, want alice", stored.Username)
	}
	if stored.Algorithm != cose.AlgES256 {
		t.Fatalf("Algorithm = %d, want %d", stored.Algorithm, cose.AlgES256)
	}
	if stored.SignCount != 1 {
		t.Fatalf("SignCount = %d, want 1", stored.SignCount)
	}
	if !bytes.Equal(stored.AAGUID, va.AAGUID[:]) {
		t.Fatalf("AAGUID mismatch")
	}

	keyVal, n, err := cbor.Decode(stored.PublicKey)
	if err != nil || n != len(stored.PublicKey) {
		t.Fatalf("decode stored PublicKey: n=%d err=%v", n, err)
	}
	key, err := cose.Parse(keyVal)
	if err != nil {
		t.Fatalf("cose.Parse stored PublicKey: %v", err)
	}
	pub, ok := key.Public.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(va.PublicKey()) {
		t.Fatalf("stored public key does not match the authenticator's key")
	}
}

func TestRegister_ChallengeNeverIssued(t *testing.T) {
	r := newTestRegistrar(t)
	va, err := webauthntest.New(cose.AlgES256)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	credID := randomCredentialID(t)
	reg, err := va.Register(rTestRPID, rTestOrigin, make([]byte, 32), credID)
	if err != nil {
		t.Fatalf("harness Register: %v", err)
	}
	err = r.Register(RegistrationRequest{Username: "alice", CredentialID: credID, ClientDataJSON: reg.ClientDataJSON, AttestationObject: reg.AttestationObject})
	if !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("got %v, want ErrChallengeNotFound", err)
	}
}

func TestRegister_WrongChallenge(t *testing.T) {
	r := newTestRegistrar(t)
	va, err := webauthntest.New(cose.AlgES256)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	credID := randomCredentialID(t)
	if _, err := r.Challenges.Issue("alice", PurposeRegister); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	wrongChallenge := make([]byte, 32)
	if _, err := rand.Read(wrongChallenge); err != nil {
		t.Fatalf("rand: %v", err)
	}
	reg, err := va.Register(rTestRPID, rTestOrigin, wrongChallenge, credID)
	if err != nil {
		t.Fatalf("harness Register: %v", err)
	}
	err = r.Register(RegistrationRequest{Username: "alice", CredentialID: credID, ClientDataJSON: reg.ClientDataJSON, AttestationObject: reg.AttestationObject})
	if !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("got %v, want ErrChallengeMismatch", err)
	}
}

func TestRegister_WrongOrigin(t *testing.T) {
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
	reg, err := va.Register(rTestRPID, "https://evil.example", challenge, credID)
	if err != nil {
		t.Fatalf("harness Register: %v", err)
	}
	err = r.Register(RegistrationRequest{Username: "alice", CredentialID: credID, ClientDataJSON: reg.ClientDataJSON, AttestationObject: reg.AttestationObject})
	if !errors.Is(err, policy.ErrOriginNotAllowed) {
		t.Fatalf("got %v, want ErrOriginNotAllowed", err)
	}
}

func TestRegister_WrongRPID(t *testing.T) {
	r := newTestRegistrar(t)
	r.RPID = "different.example" // configured RP differs from what the authenticator hashed against
	va, err := webauthntest.New(cose.AlgES256)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	credID := randomCredentialID(t)
	challenge, err := r.Challenges.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	reg, err := va.Register(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness Register: %v", err)
	}
	err = r.Register(RegistrationRequest{Username: "alice", CredentialID: credID, ClientDataJSON: reg.ClientDataJSON, AttestationObject: reg.AttestationObject})
	if !errors.Is(err, policy.ErrRPIDHashMismatch) {
		t.Fatalf("got %v, want ErrRPIDHashMismatch", err)
	}
}

func TestRegister_WrongClientDataType(t *testing.T) {
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
	reg, err := va.Register(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness Register: %v", err)
	}
	badClientData := clientDataJSON("webauthn.get", base64.RawURLEncoding.EncodeToString(challenge), rTestOrigin)

	err = r.Register(RegistrationRequest{Username: "alice", CredentialID: credID, ClientDataJSON: badClientData, AttestationObject: reg.AttestationObject})
	if !errors.Is(err, ErrClientDataType) {
		t.Fatalf("got %v, want ErrClientDataType", err)
	}
}

func TestRegister_UPNotSet(t *testing.T) {
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
	reg, err := va.Register(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness Register: %v", err)
	}

	_, _, rawAuthData, err := decodeAttestationObject(reg.AttestationObject)
	if err != nil {
		t.Fatalf("decodeAttestationObject: %v", err)
	}
	corrupted := append([]byte(nil), rawAuthData...)
	corrupted[32] &^= 0x01 // clear UP

	rebuilt := cbortest.Map(
		cbortest.Entry{Key: cbortest.Text("fmt"), Val: cbortest.Text("none")},
		cbortest.Entry{Key: cbortest.Text("attStmt"), Val: cbortest.Map()},
		cbortest.Entry{Key: cbortest.Text("authData"), Val: cbortest.Bytes(corrupted)},
	)

	err = r.Register(RegistrationRequest{Username: "alice", CredentialID: credID, ClientDataJSON: reg.ClientDataJSON, AttestationObject: rebuilt})
	if !errors.Is(err, policy.ErrUserNotPresent) {
		t.Fatalf("got %v, want ErrUserNotPresent", err)
	}
}

func TestRegister_NonNoneAttestationFormatRejected(t *testing.T) {
	r := newTestRegistrar(t)
	credID := randomCredentialID(t)
	challenge, err := r.Challenges.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cd := clientDataJSON("webauthn.create", base64.RawURLEncoding.EncodeToString(challenge), rTestOrigin)
	attObj := cbortest.Map(
		cbortest.Entry{Key: cbortest.Text("fmt"), Val: cbortest.Text("packed")},
		cbortest.Entry{Key: cbortest.Text("attStmt"), Val: cbortest.Map()},
		cbortest.Entry{Key: cbortest.Text("authData"), Val: cbortest.Bytes([]byte{0x00})},
	)

	err = r.Register(RegistrationRequest{Username: "alice", CredentialID: credID, ClientDataJSON: cd, AttestationObject: attObj})
	if !errors.Is(err, ErrAttestationFormat) {
		t.Fatalf("got %v, want ErrAttestationFormat", err)
	}
}

func TestRegister_MissingAttestedCredentialData(t *testing.T) {
	r := newTestRegistrar(t)
	credID := randomCredentialID(t)
	challenge, err := r.Challenges.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cd := clientDataJSON("webauthn.create", base64.RawURLEncoding.EncodeToString(challenge), rTestOrigin)

	rpIDHash := sha256.Sum256([]byte(rTestRPID))
	authData := make([]byte, 0, 37)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, 0x01|0x04) // UP+UV, no AT
	authData = append(authData, 0x00, 0x00, 0x00, 0x01)

	attObj := cbortest.Map(
		cbortest.Entry{Key: cbortest.Text("fmt"), Val: cbortest.Text("none")},
		cbortest.Entry{Key: cbortest.Text("attStmt"), Val: cbortest.Map()},
		cbortest.Entry{Key: cbortest.Text("authData"), Val: cbortest.Bytes(authData)},
	)

	err = r.Register(RegistrationRequest{Username: "alice", CredentialID: credID, ClientDataJSON: cd, AttestationObject: attObj})
	if !errors.Is(err, ErrMissingAttestedData) {
		t.Fatalf("got %v, want ErrMissingAttestedData", err)
	}
}

func TestRegister_DuplicateCredentialIDRejected(t *testing.T) {
	r := newTestRegistrar(t)
	va, err := webauthntest.New(cose.AlgES256)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	credID := randomCredentialID(t)

	challenge1, err := r.Challenges.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue (1): %v", err)
	}
	reg1, err := va.Register(rTestRPID, rTestOrigin, challenge1, credID)
	if err != nil {
		t.Fatalf("harness Register (1): %v", err)
	}
	if err := r.Register(RegistrationRequest{Username: "alice", CredentialID: credID, ClientDataJSON: reg1.ClientDataJSON, AttestationObject: reg1.AttestationObject}); err != nil {
		t.Fatalf("first Register: %v", err)
	}

	challenge2, err := r.Challenges.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue (2): %v", err)
	}
	reg2, err := va.Register(rTestRPID, rTestOrigin, challenge2, credID) // same credential ID again
	if err != nil {
		t.Fatalf("harness Register (2): %v", err)
	}
	if err := r.Register(RegistrationRequest{Username: "alice", CredentialID: credID, ClientDataJSON: reg2.ClientDataJSON, AttestationObject: reg2.AttestationObject}); err == nil {
		t.Fatalf("expected an error registering a duplicate credential ID")
	}
}
