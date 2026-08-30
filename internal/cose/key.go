// Package cose parses COSE_Key (RFC 9053) public keys — the format
// WebAuthn embeds in authenticatorData — into Go public keys, and pins
// the algorithm each key declared. Algorithm confusion (verifying under
// an algorithm the request claims rather than the one recorded at
// registration) is a named WebAuthn defect class; carrying Alg alongside
// the key is what lets a caller pin it and reject anything else.
package cose

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/jay-opensource/Vouchsafe/internal/cbor"
)

// COSE_Key common parameter labels (RFC 9052 §7.1), key-type-specific
// labels (RFC 9053 §7.1.1 EC2, §7.1.3 RSA), and the algorithm/curve
// identifiers WebAuthn actually uses (RFC 9053 §2, IANA COSE registries).
const (
	labelKty = 1
	labelAlg = 3

	ktyOKP = 1
	ktyEC2 = 2
	ktyRSA = 3

	labelEC2Crv = -1
	labelEC2X   = -2
	labelEC2Y   = -3

	labelRSAN = -1
	labelRSAE = -2

	curveP256    = 1
	curveP384    = 2
	curveP521    = 3
	curveEd25519 = 6

	labelOKPCrv = -1
	labelOKPX   = -2

	AlgES256 = -7
	AlgEdDSA = -8
	AlgRS256 = -257
)

// minRSAModulusBits rejects registrations of implausibly weak RSA keys.
// Not part of the COSE/WebAuthn spec — a defensive addition, since a
// working demo would not reveal that a 512-bit key was ever accepted.
const minRSAModulusBits = 2048

var (
	ErrUnsupportedKeyType = errors.New("cose: unsupported key type")
	ErrUnsupportedCurve   = errors.New("cose: unsupported curve")
	ErrMalformedKey       = errors.New("cose: malformed key")
)

// Key is a decoded COSE_Key: a public key together with the COSE
// algorithm identifier it declared. Callers must store Alg with the
// credential at registration and reject any later assertion that does
// not verify under that exact algorithm.
type Key struct {
	Public crypto.PublicKey
	Alg    int64
}

// Parse decodes a COSE_Key CBOR map into a Go public key. Supports EC2
// (ES256/P-256, plus P-384/P-521), RSA (RS256), and OKP/Ed25519 (EdDSA).
func Parse(v cbor.Value) (Key, error) {
	if v.Type != cbor.TypeMap {
		return Key{}, fmt.Errorf("%w: not a CBOR map", ErrMalformedKey)
	}
	kty, ok := v.MapGetInt(labelKty)
	if !ok || (kty.Type != cbor.TypeUint && kty.Type != cbor.TypeNegInt) {
		return Key{}, fmt.Errorf("%w: missing or malformed kty", ErrMalformedKey)
	}
	alg, ok := v.MapGetInt(labelAlg)
	if !ok || (alg.Type != cbor.TypeUint && alg.Type != cbor.TypeNegInt) {
		return Key{}, fmt.Errorf("%w: missing or malformed alg", ErrMalformedKey)
	}

	switch kty.Int {
	case ktyEC2:
		pub, err := parseEC2(v)
		if err != nil {
			return Key{}, err
		}
		return Key{Public: pub, Alg: alg.Int}, nil
	case ktyRSA:
		pub, err := parseRSA(v)
		if err != nil {
			return Key{}, err
		}
		return Key{Public: pub, Alg: alg.Int}, nil
	case ktyOKP:
		pub, err := parseOKP(v)
		if err != nil {
			return Key{}, err
		}
		return Key{Public: pub, Alg: alg.Int}, nil
	default:
		return Key{}, fmt.Errorf("%w: kty %d", ErrUnsupportedKeyType, kty.Int)
	}
}

func parseEC2(v cbor.Value) (*ecdsa.PublicKey, error) {
	crv, ok := v.MapGetInt(labelEC2Crv)
	if !ok {
		return nil, fmt.Errorf("%w: missing crv", ErrMalformedKey)
	}
	xVal, ok := v.MapGetInt(labelEC2X)
	if !ok || xVal.Type != cbor.TypeBytes {
		return nil, fmt.Errorf("%w: missing or malformed x", ErrMalformedKey)
	}
	yVal, ok := v.MapGetInt(labelEC2Y)
	if !ok || yVal.Type != cbor.TypeBytes {
		return nil, fmt.Errorf("%w: missing or malformed y", ErrMalformedKey)
	}

	var ecdhCurve ecdh.Curve
	var stdCurve elliptic.Curve
	switch crv.Int {
	case curveP256:
		ecdhCurve, stdCurve = ecdh.P256(), elliptic.P256()
	case curveP384:
		ecdhCurve, stdCurve = ecdh.P384(), elliptic.P384()
	case curveP521:
		ecdhCurve, stdCurve = ecdh.P521(), elliptic.P521()
	default:
		return nil, fmt.Errorf("%w: crv %d", ErrUnsupportedCurve, crv.Int)
	}

	coordLen := (stdCurve.Params().BitSize + 7) / 8
	if len(xVal.Bytes) != coordLen || len(yVal.Bytes) != coordLen {
		return nil, fmt.Errorf("%w: coordinate length does not match curve", ErrMalformedKey)
	}

	// Validate the point the safe way. crypto/elliptic's own IsOnCurve is
	// deprecated as a "low-level unsafe API"; crypto/ecdh's NewPublicKey
	// decodes the same uncompressed SEC1 point encoding and rejects
	// anything not genuinely on the curve, including the point at
	// infinity and compressed encodings — exactly the validation an
	// attacker-supplied public key needs before it is trusted for
	// anything.
	uncompressed := make([]byte, 0, 1+2*coordLen)
	uncompressed = append(uncompressed, 0x04)
	uncompressed = append(uncompressed, xVal.Bytes...)
	uncompressed = append(uncompressed, yVal.Bytes...)
	if _, err := ecdhCurve.NewPublicKey(uncompressed); err != nil {
		return nil, fmt.Errorf("%w: point not on curve: %v", ErrMalformedKey, err)
	}

	return &ecdsa.PublicKey{
		Curve: stdCurve,
		X:     new(big.Int).SetBytes(xVal.Bytes),
		Y:     new(big.Int).SetBytes(yVal.Bytes),
	}, nil
}

func parseOKP(v cbor.Value) (ed25519.PublicKey, error) {
	crv, ok := v.MapGetInt(labelOKPCrv)
	if !ok {
		return nil, fmt.Errorf("%w: missing crv", ErrMalformedKey)
	}
	if crv.Int != curveEd25519 {
		return nil, fmt.Errorf("%w: crv %d", ErrUnsupportedCurve, crv.Int)
	}
	xVal, ok := v.MapGetInt(labelOKPX)
	if !ok || xVal.Type != cbor.TypeBytes {
		return nil, fmt.Errorf("%w: missing or malformed x", ErrMalformedKey)
	}
	if len(xVal.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: x has wrong length for Ed25519", ErrMalformedKey)
	}
	return ed25519.PublicKey(append([]byte(nil), xVal.Bytes...)), nil
}

func parseRSA(v cbor.Value) (*rsa.PublicKey, error) {
	nVal, ok := v.MapGetInt(labelRSAN)
	if !ok || nVal.Type != cbor.TypeBytes {
		return nil, fmt.Errorf("%w: missing or malformed n", ErrMalformedKey)
	}
	eVal, ok := v.MapGetInt(labelRSAE)
	if !ok || eVal.Type != cbor.TypeBytes {
		return nil, fmt.Errorf("%w: missing or malformed e", ErrMalformedKey)
	}

	n := new(big.Int).SetBytes(nVal.Bytes)
	if n.Sign() <= 0 {
		return nil, fmt.Errorf("%w: non-positive modulus", ErrMalformedKey)
	}
	if n.BitLen() < minRSAModulusBits {
		return nil, fmt.Errorf("%w: modulus below %d bits", ErrMalformedKey, minRSAModulusBits)
	}

	e := new(big.Int).SetBytes(eVal.Bytes)
	if !e.IsInt64() {
		return nil, fmt.Errorf("%w: exponent too large", ErrMalformedKey)
	}
	const maxRSAExponent = 1<<31 - 1
	eInt := e.Int64()
	if eInt <= 0 || eInt > maxRSAExponent {
		return nil, fmt.Errorf("%w: exponent out of range", ErrMalformedKey)
	}

	return &rsa.PublicKey{N: n, E: int(eInt)}, nil
}
