package ceremony

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	"github.com/jay-opensource/Vouchsafe/internal/cbor"
	"github.com/jay-opensource/Vouchsafe/internal/cose"
)

// verifyAttestation checks the attestation statement for a supported
// format. Anything outside the frozen set (none, packed) is a named
// refusal — ErrAttestationFormat — never a silent pass.
func verifyAttestation(fmtStr string, attStmt cbor.Value, rawAuthData, clientDataJSON []byte, credentialKey cose.Key) error {
	switch fmtStr {
	case "none":
		if attStmt.Type != cbor.TypeMap || len(attStmt.Map) != 0 {
			return fmt.Errorf("%w: fmt=none requires an empty attStmt", ErrAttestationStatement)
		}
		return nil
	case "packed":
		return verifyPackedAttestation(attStmt, rawAuthData, clientDataJSON, credentialKey)
	default:
		return fmt.Errorf("%w: %q", ErrAttestationFormat, fmtStr)
	}
}

type packedAttStmt struct {
	Alg int64
	Sig []byte
	X5C [][]byte // DER certs, leaf first; nil for self-attestation
}

func decodePackedAttStmt(attStmt cbor.Value) (packedAttStmt, error) {
	if attStmt.Type != cbor.TypeMap {
		return packedAttStmt{}, fmt.Errorf("%w: packed attStmt must be a CBOR map", ErrAttestationStatement)
	}
	algVal, ok := attStmt.MapGetText("alg")
	if !ok || (algVal.Type != cbor.TypeUint && algVal.Type != cbor.TypeNegInt) {
		return packedAttStmt{}, fmt.Errorf("%w: packed attStmt missing alg", ErrAttestationStatement)
	}
	sigVal, ok := attStmt.MapGetText("sig")
	if !ok || sigVal.Type != cbor.TypeBytes {
		return packedAttStmt{}, fmt.Errorf("%w: packed attStmt missing sig", ErrAttestationStatement)
	}
	stmt := packedAttStmt{Alg: algVal.Int, Sig: sigVal.Bytes}

	if x5cVal, ok := attStmt.MapGetText("x5c"); ok {
		if x5cVal.Type != cbor.TypeArray || len(x5cVal.Array) == 0 {
			return packedAttStmt{}, fmt.Errorf("%w: packed attStmt x5c must be a non-empty array", ErrAttestationStatement)
		}
		for _, item := range x5cVal.Array {
			if item.Type != cbor.TypeBytes {
				return packedAttStmt{}, fmt.Errorf("%w: packed attStmt x5c entries must be byte strings", ErrAttestationStatement)
			}
			stmt.X5C = append(stmt.X5C, item.Bytes)
		}
	}
	return stmt, nil
}

// verifyPackedAttestation implements the two packed cases WebAuthn
// defines. Full attestation (x5c present) is verified against the leaf
// certificate's own key — deliberately not chained to a trust anchor,
// since that needs the FIDO Metadata Service, a remote lookup that is
// permanently out of scope (README "Limits"). Self attestation (no x5c)
// is verified against the credential's own key, and requires its
// algorithm to match what was pinned at credential creation.
func verifyPackedAttestation(attStmt cbor.Value, rawAuthData, clientDataJSON []byte, credentialKey cose.Key) error {
	stmt, err := decodePackedAttStmt(attStmt)
	if err != nil {
		return err
	}

	cdHash := sha256.Sum256(clientDataJSON)
	signedOver := append(append([]byte(nil), rawAuthData...), cdHash[:]...)

	if len(stmt.X5C) == 0 {
		if stmt.Alg != credentialKey.Alg {
			return fmt.Errorf("%w: packed self-attestation alg does not match the credential's own algorithm", ErrAttestationStatement)
		}
		if err := verifySignature(stmt.Alg, credentialKey.Public, signedOver, stmt.Sig); err != nil {
			return fmt.Errorf("%w: packed self-attestation signature does not verify", ErrAttestationStatement)
		}
		return nil
	}

	cert, err := x509.ParseCertificate(stmt.X5C[0])
	if err != nil {
		return fmt.Errorf("%w: packed attestation certificate: %v", ErrAttestationStatement, err)
	}
	if err := verifySignature(stmt.Alg, cert.PublicKey, signedOver, stmt.Sig); err != nil {
		return fmt.Errorf("%w: packed full-attestation signature does not verify", ErrAttestationStatement)
	}
	return nil
}
