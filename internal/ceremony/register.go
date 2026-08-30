package ceremony

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jay-opensource/Vouchsafe/internal/authdata"
	"github.com/jay-opensource/Vouchsafe/internal/cbor"
	"github.com/jay-opensource/Vouchsafe/internal/cose"
	"github.com/jay-opensource/Vouchsafe/internal/policy"
	"github.com/jay-opensource/Vouchsafe/internal/store"
)

var (
	ErrClientDataType             = errors.New("ceremony: unexpected clientDataJSON type")
	ErrMalformedClientData        = errors.New("ceremony: malformed clientDataJSON")
	ErrMalformedAttestationObject = errors.New("ceremony: malformed attestationObject")
	ErrAttestationFormat          = errors.New("ceremony: unsupported attestation format")
	ErrAttestationStatement       = errors.New("ceremony: malformed attestation statement")
	ErrMissingAttestedData        = errors.New("ceremony: attestedCredentialData missing")
)

// Registrar verifies and stores registration ceremonies.
type Registrar struct {
	Challenges *ChallengeStore
	Origins    *policy.OriginAllowlist
	Store      *store.Store
	RPID       string
	UVPolicy   policy.UVPolicy
}

// RegistrationRequest is what the HTTP layer hands in after decoding a
// browser's navigator.credentials.create() response (base64url-decoded
// already — this package works in raw bytes, not wire encoding).
type RegistrationRequest struct {
	Username          string
	CredentialID      []byte
	ClientDataJSON    []byte
	AttestationObject []byte
}

type clientDataFields struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// Register verifies a registration ceremony end to end — clientDataJSON
// type and challenge, origin, rpIdHash, UP/UV flags, attestation format
// — and, only if every check passes, stores the new credential.
func (r *Registrar) Register(req RegistrationRequest) error {
	var cd clientDataFields
	if err := json.Unmarshal(req.ClientDataJSON, &cd); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedClientData, err)
	}
	if cd.Type != "webauthn.create" {
		return fmt.Errorf("%w: %q", ErrClientDataType, cd.Type)
	}

	challenge, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil {
		return fmt.Errorf("%w: challenge: %v", ErrMalformedClientData, err)
	}
	if err := r.Challenges.Consume(req.Username, PurposeRegister, challenge); err != nil {
		return err
	}

	if err := r.Origins.CheckOrigin(cd.Origin); err != nil {
		return err
	}

	fmtStr, attStmt, rawAuthData, err := decodeAttestationObject(req.AttestationObject)
	if err != nil {
		return err
	}

	ad, err := authdata.Parse(rawAuthData)
	if err != nil {
		return err
	}
	if err := policy.CheckRPIDHash(r.RPID, ad.RPIDHash); err != nil {
		return err
	}
	if _, err := policy.CheckFlags(r.UVPolicy, ad.UP, ad.UV); err != nil {
		return err
	}
	if !ad.AT || ad.Attested == nil {
		return ErrMissingAttestedData
	}

	key, err := cose.Parse(ad.Attested.CredentialPublicKey)
	if err != nil {
		return err
	}

	// Attestation is verified last, once the credential's own key is
	// available — packed self-attestation needs it, and every format
	// needs clientDataJSON for the signed-over digest.
	if err := verifyAttestation(fmtStr, attStmt, rawAuthData, req.ClientDataJSON, key); err != nil {
		return err
	}

	return r.Store.AddCredential(store.Credential{
		ID:        ad.Attested.CredentialID,
		Username:  req.Username,
		PublicKey: ad.Attested.CredentialPublicKeyRaw,
		Algorithm: key.Alg,
		SignCount: ad.SignCount,
		AAGUID:    append([]byte(nil), ad.Attested.AAGUID[:]...),
		CreatedAt: time.Now().UTC(),
	})
}

// decodeAttestationObject decodes the CBOR attestationObject map and
// extracts its three required fields.
func decodeAttestationObject(raw []byte) (fmtStr string, attStmt cbor.Value, authData []byte, err error) {
	v, n, err := cbor.Decode(raw)
	if err != nil {
		return "", cbor.Value{}, nil, fmt.Errorf("%w: %v", ErrMalformedAttestationObject, err)
	}
	if n != len(raw) {
		return "", cbor.Value{}, nil, fmt.Errorf("%w: %d trailing bytes", ErrMalformedAttestationObject, len(raw)-n)
	}
	if v.Type != cbor.TypeMap {
		return "", cbor.Value{}, nil, fmt.Errorf("%w: not a CBOR map", ErrMalformedAttestationObject)
	}

	fmtVal, ok := v.MapGetText("fmt")
	if !ok || fmtVal.Type != cbor.TypeText {
		return "", cbor.Value{}, nil, fmt.Errorf("%w: missing fmt", ErrMalformedAttestationObject)
	}
	attStmtVal, ok := v.MapGetText("attStmt")
	if !ok || attStmtVal.Type != cbor.TypeMap {
		return "", cbor.Value{}, nil, fmt.Errorf("%w: missing or malformed attStmt", ErrMalformedAttestationObject)
	}
	authDataVal, ok := v.MapGetText("authData")
	if !ok || authDataVal.Type != cbor.TypeBytes {
		return "", cbor.Value{}, nil, fmt.Errorf("%w: missing authData", ErrMalformedAttestationObject)
	}

	return fmtVal.Text, attStmtVal, authDataVal.Bytes, nil
}
