package ceremony

import (
	"errors"
	"testing"

	"github.com/jay-opensource/Vouchsafe/internal/cose"
	"github.com/jay-opensource/Vouchsafe/internal/webauthntest"
)

func loginOnce(t *testing.T, auth *Authenticator, va *webauthntest.VirtualAuthenticator, username string, credID []byte) error {
	t.Helper()
	challenge, err := auth.Challenges.Issue(username, PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness Authenticate: %v", err)
	}
	_, err = auth.Login(AssertionRequest{
		Username:          username,
		CredentialID:      credID,
		ClientDataJSON:    assertion.ClientDataJSON,
		AuthenticatorData: assertion.AuthenticatorData,
		Signature:         assertion.Signature,
	})
	return err
}

func TestLogin_RepeatedLoginsSucceed(t *testing.T) {
	reg, auth := newTestServer(t)
	va, credID := registerTestUser(t, reg, "alice", cose.AlgES256)

	for i := range 3 {
		if err := loginOnce(t, auth, va, "alice", credID); err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
	}

	cred, ok, err := auth.Store.FindByID(credID)
	if err != nil || !ok {
		t.Fatalf("FindByID: ok=%v err=%v", ok, err)
	}
	if cred.SignCount != 4 { // registration leaves it at 1, three logins each +1
		t.Fatalf("SignCount = %d, want 4", cred.SignCount)
	}
}

func TestLogin_CounterRegressionRejected(t *testing.T) {
	reg, auth := newTestServer(t)
	va, credID := registerTestUser(t, reg, "alice", cose.AlgES256) // stored SignCount starts at 1

	if err := loginOnce(t, auth, va, "alice", credID); err != nil {
		t.Fatalf("first login: %v", err) // advances stored SignCount to 2
	}

	// Force the next assertion to report a lower counter than what's
	// already stored — the signal a real cloned authenticator would give.
	va.SetSignCount(0)
	challenge, err := auth.Challenges.Issue("alice", PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := va.Authenticate(rTestRPID, rTestOrigin, challenge, credID) // reports 1, stored is 2
	if err != nil {
		t.Fatalf("harness Authenticate: %v", err)
	}
	_, err = auth.Login(AssertionRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: assertion.ClientDataJSON, AuthenticatorData: assertion.AuthenticatorData, Signature: assertion.Signature,
	})
	if !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("got %v, want ErrCounterRegression", err)
	}

	// A rejected login must not have overwritten the stored counter.
	cred, ok, err := auth.Store.FindByID(credID)
	if err != nil || !ok {
		t.Fatalf("FindByID: ok=%v err=%v", ok, err)
	}
	if cred.SignCount != 2 {
		t.Fatalf("SignCount after rejected login = %d, want 2 (unchanged)", cred.SignCount)
	}
}

func TestLogin_ZeroCounterNeverRejectedAsRegression(t *testing.T) {
	reg, auth := newTestServer(t)
	s, err := webauthntest.New(cose.AlgES256, webauthntest.WithZeroCounter())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	credID := randomCredentialID(t)
	challenge, err := reg.Challenges.Issue("alice", PurposeRegister)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	regResult, err := s.Register(rTestRPID, rTestOrigin, challenge, credID)
	if err != nil {
		t.Fatalf("harness Register: %v", err)
	}
	if err := reg.Register(RegistrationRequest{
		Username: "alice", CredentialID: credID,
		ClientDataJSON: regResult.ClientDataJSON, AttestationObject: regResult.AttestationObject,
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	for i := range 3 {
		if err := loginOnce(t, auth, s, "alice", credID); err != nil {
			t.Fatalf("zero-counter login %d rejected: %v", i, err)
		}
	}

	cred, ok, err := auth.Store.FindByID(credID)
	if err != nil || !ok {
		t.Fatalf("FindByID: ok=%v err=%v", ok, err)
	}
	if cred.SignCount != 0 {
		t.Fatalf("SignCount = %d, want 0 (counter-unsupported authenticator)", cred.SignCount)
	}
}
