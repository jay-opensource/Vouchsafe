package ceremony

import (
	"testing"

	"github.com/jay-opensource/Vouchsafe/internal/cose"
)

// TestLogin_ResolvesIdentityFromCredentialNotRequestUsername is the
// spec's own adversarial case (§9.3): "User A's assertion + username
// 'B' -> session must be issued for A." Login()'s only use of
// AssertionRequest.Username is to locate the pending challenge (see the
// Username field's doc comment on AssertionRequest and W8 in login.go);
// the identity a successful login resolves to must come from whichever
// credential the signature actually verifies against.
//
// The scenario: a challenge is issued for bob's login attempt, but it's
// alice's authenticator that ends up signing it — modeling a client
// tricked into completing the wrong pending ceremony (races between
// tabs, a confused-deputy redirect, and similar are the realistic shape
// of this) — and the request claims alice's real credential ID together
// with bob's username. If the server ever returned "bob" here, an
// attacker who could arrange for someone else's device to sign their
// pending challenge would get to choose who they're logged in as.
func TestLogin_ResolvesIdentityFromCredentialNotRequestUsername(t *testing.T) {
	reg, auth := newTestServer(t)
	vaAlice, credAlice := registerTestUser(t, reg, "alice", cose.AlgES256)
	_, credBob := registerTestUser(t, reg, "bob", cose.AlgES256)

	challengeForBob, err := auth.Challenges.Issue("bob", PurposeLogin)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	assertion, err := vaAlice.Authenticate(rTestRPID, rTestOrigin, challengeForBob, credAlice)
	if err != nil {
		t.Fatalf("harness Authenticate: %v", err)
	}

	result, err := auth.Login(AssertionRequest{
		Username:          "bob", // the claim in the request
		CredentialID:      credAlice,
		ClientDataJSON:    assertion.ClientDataJSON,
		AuthenticatorData: assertion.AuthenticatorData,
		Signature:         assertion.Signature,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.Username != "alice" {
		t.Fatalf(`Username = %q, want "alice" — a session must never be issued for the username claimed in the request`, result.Username)
	}

	// bob's own credential and pending state are untouched by this.
	bobCred, ok, err := auth.Store.FindByID(credBob)
	if err != nil || !ok {
		t.Fatalf("FindByID(credBob): ok=%v err=%v", ok, err)
	}
	if bobCred.Username != "bob" {
		t.Fatalf("bob's stored credential was mutated: Username = %q", bobCred.Username)
	}
}
