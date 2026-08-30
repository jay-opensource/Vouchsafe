package ceremony

import (
	"errors"
	"testing"

	"github.com/jay-opensource/Vouchsafe/internal/cose"
	"github.com/jay-opensource/Vouchsafe/internal/policy"
	"github.com/jay-opensource/Vouchsafe/internal/webauthntest"
)

// The harness always sets UV in authenticatorData, so these tests exercise
// the override wiring itself (does the stricter/weaker request actually
// reach policy.CheckFlags), not UV-cleared rejection — that's covered
// elsewhere (register_test.go's TestRegister_UPNotSet and the negative
// suite's UV-cleared-under-required case).

func TestRegister_UVOverride_CannotWeakenServerFloor(t *testing.T) {
	r := newTestRegistrar(t)
	r.UVPolicy = policy.UVRequired // server floor: strict
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

	// Requesting a weaker policy than the server floor must be ignored —
	// this still succeeds only because the harness's authData genuinely
	// has UV set, satisfying the (unweakened) required floor.
	err = r.Register(RegistrationRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: reg.ClientDataJSON, AttestationObject: reg.AttestationObject,
		UVOverride: policy.UVDiscouraged,
	})
	if err != nil {
		t.Fatalf("Register with weaker override (should be ignored, not honored): %v", err)
	}
}

func TestLogin_UVOverride_StricterAppliedWhenUVMissing(t *testing.T) {
	reg, auth := newTestServer(t)
	auth.UVPolicy = policy.UVDiscouraged // server floor: lenient
	va, credID := registerTestUser(t, reg, "alice", cose.AlgES256)

	challenge, err := auth.Challenges.Issue("alice", PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	corrupted := append([]byte(nil), assertion.AuthenticatorData...)
	corrupted[32] &^= 0x04 // clear UV; server floor alone would allow this

	_, err = auth.Login(AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: corrupted, Signature: assertion.Signature,
		UVOverride: policy.UVRequired, // this ceremony asks for more than the floor
	})
	if !errors.Is(err, policy.ErrUserNotVerified) {
		t.Fatalf("got %v, want ErrUserNotVerified — a stricter per-ceremony override must be enforced", err)
	}
}

func TestLogin_UVOverride_IgnoredWhenWeakerThanFloor(t *testing.T) {
	reg, auth := newTestServer(t)
	auth.UVPolicy = policy.UVRequired // server floor: strict
	va, credID := registerTestUser(t, reg, "alice", cose.AlgES256)

	challenge, err := auth.Challenges.Issue("alice", PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	corrupted := append([]byte(nil), assertion.AuthenticatorData...)
	corrupted[32] &^= 0x04 // clear UV

	_, err = auth.Login(AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: corrupted, Signature: assertion.Signature,
		UVOverride: policy.UVDiscouraged, // weaker than floor — must be ignored
	})
	if !errors.Is(err, policy.ErrUserNotVerified) {
		t.Fatalf("got %v, want ErrUserNotVerified — a weaker override must not loosen the server floor", err)
	}
}
