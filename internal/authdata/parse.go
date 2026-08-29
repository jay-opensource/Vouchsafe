// Package authdata parses the WebAuthn authenticatorData structure
// (§6.1 of the spec) strictly by its flag bits. attestedCredentialData
// and extensions are each present only if their flag says so, and the
// credential public key's own length is never stated directly — it is
// found by decoding the CBOR item itself, never assumed.
package authdata

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jay-opensource/Vouchsafe/internal/cbor"
)

const (
	flagUP = 1 << 0
	flagUV = 1 << 2
	flagBE = 1 << 3
	flagBS = 1 << 4
	flagAT = 1 << 6
	flagED = 1 << 7

	rpIDHashLen    = 32
	flagsLen       = 1
	signCountLen   = 4
	fixedHeaderLen = rpIDHashLen + flagsLen + signCountLen // 37

	aaguidLen    = 16
	credIDLenLen = 2
)

var (
	ErrTruncated = errors.New("authdata: truncated input")
	ErrMalformed = errors.New("authdata: malformed input")
)

// AttestedCredentialData holds the credential identity and public key
// present when the AT flag is set (registration ceremonies).
type AttestedCredentialData struct {
	AAGUID              [16]byte
	CredentialID        []byte
	CredentialPublicKey cbor.Value // decoded COSE_Key map; internal/cose parses it into a crypto.PublicKey

	// CredentialPublicKeyRaw is the exact CBOR-encoded bytes of the
	// COSE_Key, for callers that need to persist it (production code
	// never re-encodes CBOR, so this is the only way to store what was
	// received without inventing a second key serialization format).
	CredentialPublicKeyRaw []byte
}

// Data is a parsed authenticatorData structure (WebAuthn §6.1).
type Data struct {
	RPIDHash  [32]byte
	SignCount uint32

	UP bool // user present
	UV bool // user verified
	BE bool // backup eligible
	BS bool // backup state
	AT bool // attestedCredentialData present
	ED bool // extensions present

	Attested   *AttestedCredentialData // nil unless AT is set
	Extensions cbor.Value              // zero Value unless ED is set
}

// Parse reads an authenticatorData structure. buf must be exactly the
// authenticatorData bytes (the caller already knows its length from the
// enclosing CBOR byte string) — any bytes left over after the fields the
// flags declare present is treated as malformed input, not ignored.
func Parse(buf []byte) (Data, error) {
	if len(buf) < fixedHeaderLen {
		return Data{}, fmt.Errorf("%w: need at least %d bytes, have %d", ErrTruncated, fixedHeaderLen, len(buf))
	}

	var d Data
	copy(d.RPIDHash[:], buf[0:32])
	flags := buf[32]
	d.SignCount = binary.BigEndian.Uint32(buf[33:37])

	d.UP = flags&flagUP != 0
	d.UV = flags&flagUV != 0
	d.BE = flags&flagBE != 0
	d.BS = flags&flagBS != 0
	d.AT = flags&flagAT != 0
	d.ED = flags&flagED != 0

	pos := fixedHeaderLen

	if d.AT {
		attested, next, err := parseAttestedCredentialData(buf, pos)
		if err != nil {
			return Data{}, err
		}
		d.Attested = attested
		pos = next
	}

	if d.ED {
		ext, n, err := cbor.Decode(buf[pos:])
		if err != nil {
			return Data{}, fmt.Errorf("%w: extensions: %v", ErrMalformed, err)
		}
		if ext.Type != cbor.TypeMap {
			return Data{}, fmt.Errorf("%w: extensions must be a CBOR map", ErrMalformed)
		}
		d.Extensions = ext
		pos += n
	}

	if pos != len(buf) {
		return Data{}, fmt.Errorf("%w: %d trailing bytes", ErrMalformed, len(buf)-pos)
	}

	return d, nil
}

func parseAttestedCredentialData(buf []byte, pos int) (*AttestedCredentialData, int, error) {
	if len(buf) < pos+aaguidLen+credIDLenLen {
		return nil, 0, fmt.Errorf("%w: attestedCredentialData header", ErrTruncated)
	}
	var a AttestedCredentialData
	copy(a.AAGUID[:], buf[pos:pos+aaguidLen])
	pos += aaguidLen

	credIDLen := int(binary.BigEndian.Uint16(buf[pos : pos+credIDLenLen]))
	pos += credIDLenLen

	if len(buf) < pos+credIDLen {
		return nil, 0, fmt.Errorf("%w: credentialId", ErrTruncated)
	}
	a.CredentialID = append([]byte(nil), buf[pos:pos+credIDLen]...)
	pos += credIDLen

	pubKeyStart := pos
	pubKey, n, err := cbor.Decode(buf[pos:])
	if err != nil {
		return nil, 0, fmt.Errorf("%w: credentialPublicKey: %v", ErrMalformed, err)
	}
	if pubKey.Type != cbor.TypeMap {
		return nil, 0, fmt.Errorf("%w: credentialPublicKey must be a CBOR map", ErrMalformed)
	}
	a.CredentialPublicKey = pubKey
	a.CredentialPublicKeyRaw = append([]byte(nil), buf[pubKeyStart:pubKeyStart+n]...)
	pos += n

	return &a, pos, nil
}
