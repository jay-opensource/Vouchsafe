package ceremony

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jay-opensource/Vouchsafe/internal/authdata"
	"github.com/jay-opensource/Vouchsafe/internal/cbor"
	"github.com/jay-opensource/Vouchsafe/internal/cose"
	"github.com/jay-opensource/Vouchsafe/internal/policy"
	"github.com/jay-opensource/Vouchsafe/internal/store"
)

var (
	ErrCredentialNotFound    = errors.New("ceremony: credential not found")
	ErrSignatureVerification = errors.New("ceremony: signature verification failed")
	ErrUnsupportedAlgorithm  = errors.New("ceremony: unsupported algorithm")
	ErrCorruptStoredKey      = errors.New("ceremony: stored public key is corrupt")
	ErrCounterRegression     = errors.New("ceremony: signature counter went backwards — suspected cloned authenticator")
)

// Authenticator verifies authentication (login) ceremonies.
type Authenticator struct {
	Challenges *ChallengeStore
	Origins    *policy.OriginAllowlist
	Store      *store.Store
	RPID       string
	UVPolicy   policy.UVPolicy
}

// AssertionRequest is what the HTTP layer hands in after decoding a
// browser's navigator.credentials.get() response.
type AssertionRequest struct {
	// Username is a hint used only to locate the pending challenge this
	// ceremony began with (see ChallengeStore) — it plays no part in
	// deciding who this ceremony authenticates as. See LoginResult.
	Username string

	CredentialID      []byte
	ClientDataJSON    []byte
	AuthenticatorData []byte
	Signature         []byte
}

// LoginResult is the outcome of a successful authentication ceremony.
type LoginResult struct {
	// Username is resolved from the credential the signature actually
	// verifies against — never from AssertionRequest.Username. That
	// field only routes to the right pending challenge; the identity
	// this ceremony authenticates as is whoever registered
	// AssertionRequest.CredentialID (W8).
	Username    string
	UVPerformed bool
}

// Login verifies an authentication ceremony end to end and returns the
// identity it resolved.
func (a *Authenticator) Login(req AssertionRequest) (LoginResult, error) {
	var cd clientDataFields
	if err := json.Unmarshal(req.ClientDataJSON, &cd); err != nil {
		return LoginResult{}, fmt.Errorf("%w: %v", ErrMalformedClientData, err)
	}
	if cd.Type != "webauthn.get" {
		return LoginResult{}, fmt.Errorf("%w: %q", ErrClientDataType, cd.Type)
	}

	challenge, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil {
		return LoginResult{}, fmt.Errorf("%w: challenge: %v", ErrMalformedClientData, err)
	}
	if err := a.Challenges.Consume(req.Username, PurposeLogin, challenge); err != nil {
		return LoginResult{}, err
	}

	if err := a.Origins.CheckOrigin(cd.Origin); err != nil {
		return LoginResult{}, err
	}

	// Everything from here on is resolved from the credential the
	// signature was made with — req.Username has already done its only
	// job, locating the challenge above (W8).
	cred, ok, err := a.Store.FindByID(req.CredentialID)
	if err != nil {
		return LoginResult{}, err
	}
	if !ok {
		return LoginResult{}, ErrCredentialNotFound
	}

	ad, err := authdata.Parse(req.AuthenticatorData)
	if err != nil {
		return LoginResult{}, err
	}
	if err := policy.CheckRPIDHash(a.RPID, ad.RPIDHash); err != nil {
		return LoginResult{}, err
	}
	uvPerformed, err := policy.CheckFlags(a.UVPolicy, ad.UP, ad.UV)
	if err != nil {
		return LoginResult{}, err
	}

	keyVal, n, err := cbor.Decode(cred.PublicKey)
	if err != nil || n != len(cred.PublicKey) {
		return LoginResult{}, ErrCorruptStoredKey
	}
	key, err := cose.Parse(keyVal)
	if err != nil {
		return LoginResult{}, err
	}
	// Belt-and-suspenders consistency check: both key.Alg and
	// cred.Algorithm were populated from the same cose.Parse call at
	// registration, so they should never disagree short of storage
	// corruption. The actual W9 guarantee is structural, not this check
	// — AssertionRequest has no algorithm field at all, so nothing in
	// this request can influence which verification function runs below;
	// that choice comes only from cred.Algorithm, read from storage.
	if key.Alg != cred.Algorithm {
		return LoginResult{}, ErrCorruptStoredKey
	}

	cdHash := sha256.Sum256(req.ClientDataJSON)
	signedOver := append(append([]byte(nil), req.AuthenticatorData...), cdHash[:]...)
	digest := sha256.Sum256(signedOver)

	if err := verifySignature(cred.Algorithm, key.Public, digest[:], req.Signature); err != nil {
		return LoginResult{}, err
	}

	// Counter regression is checked only now, after the signature has
	// verified — branching on ad.SignCount before that would react to
	// attacker-controlled data from someone who hasn't proven possession
	// of the private key yet. A zero on either side means the
	// authenticator doesn't implement the counter (the common case for
	// modern platform authenticators, which report it as always 0) —
	// that is "unsupported," not evidence of cloning, and must not be
	// rejected; getting that case wrong locks out real devices.
	if cred.SignCount != 0 && ad.SignCount != 0 && ad.SignCount <= cred.SignCount {
		return LoginResult{}, fmt.Errorf("%w: stored=%d received=%d", ErrCounterRegression, cred.SignCount, ad.SignCount)
	}

	if err := a.Store.UpdateSignCount(req.CredentialID, ad.SignCount); err != nil {
		return LoginResult{}, err
	}

	return LoginResult{Username: cred.Username, UVPerformed: uvPerformed}, nil
}

func verifySignature(alg int64, pub crypto.PublicKey, digest, sig []byte) error {
	switch alg {
	case cose.AlgES256:
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: expected an EC2 key for ES256", ErrUnsupportedAlgorithm)
		}
		if !ecdsa.VerifyASN1(ecPub, digest, sig) {
			return ErrSignatureVerification
		}
		return nil
	case cose.AlgRS256:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: expected an RSA key for RS256", ErrUnsupportedAlgorithm)
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest, sig); err != nil {
			return ErrSignatureVerification
		}
		return nil
	default:
		return fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, alg)
	}
}
