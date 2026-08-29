// Package webauthntest is a synthetic FIDO2 authenticator: real
// ECDSA/RSA keypairs, real signatures, real CBOR/attestationObject/
// authenticatorData bytes, built without any actual hardware or
// browser. No real Touch ID / Windows Hello / security-key access is
// available in this build environment, so this stands in for the
// spec's real-browser fixtures (§9.2) — the same "writer exists for
// tests only" pattern tracewright uses for its own synthetic pcap
// fixtures. Never imported by cmd/vouchsafe.
package webauthntest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/jay-opensource/Vouchsafe/internal/cbortest"
	"github.com/jay-opensource/Vouchsafe/internal/cose"
)

const (
	flagUP = 1 << 0
	flagUV = 1 << 2
	flagAT = 1 << 6
)

// VirtualAuthenticator is a synthetic authenticator: a real keypair, a
// real AAGUID, and a monotonic (or fixed-zero) signature counter, used to
// build genuine, correctly-signed WebAuthn ceremony payloads for testing.
type VirtualAuthenticator struct {
	AAGUID [16]byte
	Alg    int64

	ecPriv  *ecdsa.PrivateKey
	rsaPriv *rsa.PrivateKey

	signCount   uint32
	zeroCounter bool
}

// Option configures a VirtualAuthenticator at construction.
type Option func(*VirtualAuthenticator)

// WithZeroCounter makes the authenticator always report signCount 0,
// matching real hardware that doesn't implement the signature counter —
// a case the login ceremony must treat as "unsupported," not a clone.
func WithZeroCounter() Option {
	return func(v *VirtualAuthenticator) { v.zeroCounter = true }
}

// New creates a virtual authenticator with a freshly generated keypair
// for the given COSE algorithm (cose.AlgES256 or cose.AlgRS256).
func New(alg int64, opts ...Option) (*VirtualAuthenticator, error) {
	v := &VirtualAuthenticator{Alg: alg, signCount: 1}
	if _, err := rand.Read(v.AAGUID[:]); err != nil {
		return nil, fmt.Errorf("webauthntest: aaguid: %w", err)
	}

	switch alg {
	case cose.AlgES256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("webauthntest: generate EC key: %w", err)
		}
		v.ecPriv = priv
	case cose.AlgRS256:
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("webauthntest: generate RSA key: %w", err)
		}
		v.rsaPriv = priv
	default:
		return nil, fmt.Errorf("webauthntest: unsupported algorithm %d", alg)
	}

	for _, opt := range opts {
		opt(v)
	}
	if v.zeroCounter {
		v.signCount = 0
	}
	return v, nil
}

// SetSignCount forces this authenticator's internal counter to n. The
// next Authenticate call still applies its normal (possibly disabled)
// increment on top of it. A real authenticator's counter only ever
// advances; this exists so tests can construct the regression scenario
// a real one wouldn't produce on its own.
func (v *VirtualAuthenticator) SetSignCount(n uint32) {
	v.signCount = n
}

// PublicKey returns the authenticator's public key.
func (v *VirtualAuthenticator) PublicKey() crypto.PublicKey {
	if v.ecPriv != nil {
		return &v.ecPriv.PublicKey
	}
	return &v.rsaPriv.PublicKey
}

// RegistrationResult is what a real browser's PublicKeyCredential
// response carries back for navigator.credentials.create().
type RegistrationResult struct {
	CredentialID      []byte
	ClientDataJSON    []byte
	AttestationObject []byte
}

// Register builds a genuine registration ceremony payload: a real
// keypair-backed attestationObject (fmt=none) plus matching
// clientDataJSON, as if a browser had just called
// navigator.credentials.create() and the user touched the sensor.
func (v *VirtualAuthenticator) Register(rpID, origin string, challenge, credentialID []byte) (RegistrationResult, error) {
	cd, err := buildClientDataJSON("webauthn.create", origin, challenge)
	if err != nil {
		return RegistrationResult{}, err
	}
	authData := v.buildAuthDataRegistration(rpID, credentialID)
	attObj := buildAttestationObjectNone(authData)
	return RegistrationResult{
		CredentialID:      credentialID,
		ClientDataJSON:    cd,
		AttestationObject: attObj,
	}, nil
}

// AssertionResult is what a real browser's PublicKeyCredential response
// carries back for navigator.credentials.get().
type AssertionResult struct {
	CredentialID      []byte
	ClientDataJSON    []byte
	AuthenticatorData []byte
	Signature         []byte
}

// Authenticate builds a genuine authentication ceremony payload: real
// authenticatorData plus a real signature over
// authenticatorData || SHA256(clientDataJSON), computed with the same
// keypair Register used. Each call advances the signature counter
// (unless the authenticator was built WithZeroCounter).
func (v *VirtualAuthenticator) Authenticate(rpID, origin string, challenge, credentialID []byte) (AssertionResult, error) {
	cd, err := buildClientDataJSON("webauthn.get", origin, challenge)
	if err != nil {
		return AssertionResult{}, err
	}
	authData := v.buildAuthDataAssertion(rpID)

	cdHash := sha256.Sum256(cd)
	signedOver := append(append([]byte(nil), authData...), cdHash[:]...)
	digest := sha256.Sum256(signedOver)

	sig, err := v.sign(digest[:])
	if err != nil {
		return AssertionResult{}, err
	}

	return AssertionResult{
		CredentialID:      credentialID,
		ClientDataJSON:    cd,
		AuthenticatorData: authData,
		Signature:         sig,
	}, nil
}

func (v *VirtualAuthenticator) sign(digest []byte) ([]byte, error) {
	switch v.Alg {
	case cose.AlgES256:
		return ecdsa.SignASN1(rand.Reader, v.ecPriv, digest)
	case cose.AlgRS256:
		return rsa.SignPKCS1v15(rand.Reader, v.rsaPriv, crypto.SHA256, digest)
	default:
		return nil, fmt.Errorf("webauthntest: unsupported algorithm %d", v.Alg)
	}
}

func (v *VirtualAuthenticator) buildAuthDataRegistration(rpID string, credentialID []byte) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))

	buf := make([]byte, 0, 128)
	buf = append(buf, rpIDHash[:]...)
	buf = append(buf, flagUP|flagUV|flagAT)
	buf = appendUint32(buf, v.signCount)
	buf = append(buf, v.AAGUID[:]...)
	buf = appendUint16(buf, uint16(len(credentialID)))
	buf = append(buf, credentialID...)
	buf = append(buf, v.encodePublicKey()...)
	return buf
}

// buildAuthDataAssertion advances the counter (unless fixed at zero) and
// builds authenticatorData for an authentication ceremony — no
// attestedCredentialData, matching a real authenticatorGetAssertion.
func (v *VirtualAuthenticator) buildAuthDataAssertion(rpID string) []byte {
	if !v.zeroCounter {
		v.signCount++
	}
	rpIDHash := sha256.Sum256([]byte(rpID))

	buf := make([]byte, 0, 37)
	buf = append(buf, rpIDHash[:]...)
	buf = append(buf, flagUP|flagUV)
	buf = appendUint32(buf, v.signCount)
	return buf
}

func (v *VirtualAuthenticator) encodePublicKey() []byte {
	if v.ecPriv != nil {
		return encodeCOSEKeyEC2(&v.ecPriv.PublicKey, v.Alg)
	}
	return encodeCOSEKeyRSA(&v.rsaPriv.PublicKey, v.Alg)
}

// encodeCOSEKeyEC2 and encodeCOSEKeyRSA are the encoder counterparts to
// internal/cose.Parse. Production code only ever decodes a COSE_Key (an
// attacker-facing browser sends it, the server never emits one), so
// this encoding logic lives here, in test-only code, rather than in
// internal/cose.
func encodeCOSEKeyEC2(pub *ecdsa.PublicKey, alg int64) []byte {
	coordLen := (pub.Curve.Params().BitSize + 7) / 8
	return cbortest.Map(
		cbortest.Entry{Key: cbortest.Uint(1), Val: cbortest.Uint(2)}, // kty: EC2
		cbortest.Entry{Key: cbortest.Uint(3), Val: cbortest.NegInt(alg)},
		cbortest.Entry{Key: cbortest.NegInt(-1), Val: cbortest.Uint(1)}, // crv: P-256
		cbortest.Entry{Key: cbortest.NegInt(-2), Val: cbortest.Bytes(padBigInt(pub.X, coordLen))},
		cbortest.Entry{Key: cbortest.NegInt(-3), Val: cbortest.Bytes(padBigInt(pub.Y, coordLen))},
	)
}

func encodeCOSEKeyRSA(pub *rsa.PublicKey, alg int64) []byte {
	return cbortest.Map(
		cbortest.Entry{Key: cbortest.Uint(1), Val: cbortest.Uint(3)}, // kty: RSA
		cbortest.Entry{Key: cbortest.Uint(3), Val: cbortest.NegInt(alg)},
		cbortest.Entry{Key: cbortest.NegInt(-1), Val: cbortest.Bytes(pub.N.Bytes())},
		cbortest.Entry{Key: cbortest.NegInt(-2), Val: cbortest.Bytes(big.NewInt(int64(pub.E)).Bytes())},
	)
}

// buildAttestationObjectNone builds a "fmt": "none" attestationObject.
// Map entries are listed in the canonical order the real CBOR decoder
// requires: shorter-encoded-key-first, so "fmt" (encodes to 4 bytes)
// sorts before "attStmt" (8 bytes) before "authData" (9 bytes) — NOT
// alphabetical order.
func buildAttestationObjectNone(authData []byte) []byte {
	return cbortest.Map(
		cbortest.Entry{Key: cbortest.Text("fmt"), Val: cbortest.Text("none")},
		cbortest.Entry{Key: cbortest.Text("attStmt"), Val: cbortest.Map()},
		cbortest.Entry{Key: cbortest.Text("authData"), Val: cbortest.Bytes(authData)},
	)
}

type clientDataFields struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func buildClientDataJSON(typ, origin string, challenge []byte) ([]byte, error) {
	cd := clientDataFields{
		Type:      typ,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Origin:    origin,
	}
	b, err := json.Marshal(cd)
	if err != nil {
		return nil, fmt.Errorf("webauthntest: clientDataJSON: %w", err)
	}
	return b, nil
}

func padBigInt(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b[len(b)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func appendUint16(buf []byte, v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return append(buf, b...)
}

func appendUint32(buf []byte, v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return append(buf, b...)
}
