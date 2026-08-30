package authdata

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/jay-opensource/Vouchsafe/internal/cbortest"
)

func fixedHeader(flags byte, signCount uint32) []byte {
	buf := make([]byte, fixedHeaderLen)
	for i := range buf[:32] {
		buf[i] = byte(i + 1)
	}
	buf[32] = flags
	binary.BigEndian.PutUint32(buf[33:37], signCount)
	return buf
}

// a placeholder COSE_Key-shaped CBOR map. authdata doesn't validate key
// content, only that it decodes as a map — internal/cose owns validity.
func fakeCOSEKey() []byte {
	return cbortest.Map(
		cbortest.Entry{Key: cbortest.Uint(1), Val: cbortest.Uint(2)},
		cbortest.Entry{Key: cbortest.Uint(3), Val: cbortest.NegInt(-7)},
	)
}

func TestParse_NoFlags(t *testing.T) {
	buf := fixedHeader(0, 42)
	d, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !bytes.Equal(d.RPIDHash[:], buf[0:32]) {
		t.Fatalf("RPIDHash mismatch")
	}
	if d.SignCount != 42 {
		t.Fatalf("SignCount = %d, want 42", d.SignCount)
	}
	if d.UP || d.UV || d.BE || d.BS || d.AT || d.ED {
		t.Fatalf("expected all flags false, got %+v", d)
	}
	if d.Attested != nil {
		t.Fatalf("Attested should be nil when AT is unset")
	}
}

func TestParse_FlagBits(t *testing.T) {
	cases := []struct {
		name           string
		flags          byte
		up, uv, be, bs bool
	}{
		{"UP only", flagUP, true, false, false, false},
		{"UV only", flagUV, false, true, false, false},
		{"BE only", flagBE, false, false, true, false},
		{"BS only", flagBS, false, false, false, true},
		{"UP+UV+BE+BS", flagUP | flagUV | flagBE | flagBS, true, true, true, true},
		{"reserved bits ignored", 0x22, false, false, false, false}, // bits 1 and 5
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := Parse(fixedHeader(c.flags, 0))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if d.UP != c.up || d.UV != c.uv || d.BE != c.be || d.BS != c.bs {
				t.Fatalf("got UP=%v UV=%v BE=%v BS=%v, want UP=%v UV=%v BE=%v BS=%v",
					d.UP, d.UV, d.BE, d.BS, c.up, c.uv, c.be, c.bs)
			}
		})
	}
}

func TestParse_AttestedCredentialData(t *testing.T) {
	buf := fixedHeader(flagAT, 1)
	aaguid := bytes.Repeat([]byte{0xaa}, 16)
	credID := []byte{0x01, 0x02, 0x03, 0x04}
	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(credID)))
	key := fakeCOSEKey()

	buf = append(buf, aaguid...)
	buf = append(buf, credIDLen...)
	buf = append(buf, credID...)
	buf = append(buf, key...)

	d, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if d.Attested == nil {
		t.Fatalf("Attested is nil, want populated")
	}
	if !bytes.Equal(d.Attested.AAGUID[:], aaguid) {
		t.Fatalf("AAGUID mismatch")
	}
	if !bytes.Equal(d.Attested.CredentialID, credID) {
		t.Fatalf("CredentialID mismatch")
	}
	if kty, ok := d.Attested.CredentialPublicKey.MapGetInt(1); !ok || kty.Int != 2 {
		t.Fatalf("CredentialPublicKey kty: got %+v ok=%v", kty, ok)
	}
	if !bytes.Equal(d.Attested.CredentialPublicKeyRaw, key) {
		t.Fatalf("CredentialPublicKeyRaw = %x, want %x", d.Attested.CredentialPublicKeyRaw, key)
	}
}

func TestParse_AttestedPlusExtensions(t *testing.T) {
	buf := fixedHeader(flagAT|flagED, 1)
	aaguid := bytes.Repeat([]byte{0xbb}, 16)
	credID := []byte{0x01}
	credIDLen := []byte{0x00, 0x01}
	key := fakeCOSEKey()
	ext := cbortest.Map(cbortest.Entry{Key: cbortest.Text("x"), Val: cbortest.Bool(true)})

	buf = append(buf, aaguid...)
	buf = append(buf, credIDLen...)
	buf = append(buf, credID...)
	buf = append(buf, key...)
	buf = append(buf, ext...)

	d, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if d.Attested == nil {
		t.Fatalf("Attested is nil")
	}
	if !d.ED {
		t.Fatalf("ED flag not reflected")
	}
	if v, ok := d.Extensions.MapGetText("x"); !ok || !v.Bool {
		t.Fatalf("Extensions: got %+v ok=%v", v, ok)
	}
}

func TestParse_TooShort(t *testing.T) {
	if _, err := Parse(make([]byte, fixedHeaderLen-1)); !errors.Is(err, ErrTruncated) {
		t.Fatalf("got %v, want ErrTruncated", err)
	}
}

func TestParse_ATSetButTruncatedAAGUID(t *testing.T) {
	buf := fixedHeader(flagAT, 0)
	buf = append(buf, 0x00, 0x01, 0x02) // only 3 of the 18 required header bytes
	if _, err := Parse(buf); !errors.Is(err, ErrTruncated) {
		t.Fatalf("got %v, want ErrTruncated", err)
	}
}

func TestParse_CredentialIDLengthExceedsBuffer(t *testing.T) {
	buf := fixedHeader(flagAT, 0)
	buf = append(buf, bytes.Repeat([]byte{0}, 16)...) // aaguid
	buf = append(buf, 0x00, 0xff)                     // claims 255-byte credentialId
	buf = append(buf, 0x01, 0x02)                     // only 2 bytes actually present
	if _, err := Parse(buf); !errors.Is(err, ErrTruncated) {
		t.Fatalf("got %v, want ErrTruncated", err)
	}
}

func TestParse_MalformedPublicKeyCBOR(t *testing.T) {
	buf := fixedHeader(flagAT, 0)
	buf = append(buf, bytes.Repeat([]byte{0}, 16)...) // aaguid
	buf = append(buf, 0x00, 0x00)                     // credentialId length 0
	buf = append(buf, 0x18)                           // truncated CBOR header — no argument byte
	if _, err := Parse(buf); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

func TestParse_PublicKeyMustBeMap(t *testing.T) {
	buf := fixedHeader(flagAT, 0)
	buf = append(buf, bytes.Repeat([]byte{0}, 16)...) // aaguid
	buf = append(buf, 0x00, 0x00)                     // credentialId length 0
	buf = append(buf, cbortest.Uint(1)...)            // a bare uint, not a map
	if _, err := Parse(buf); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

func TestParse_ExtensionsMustBeMap(t *testing.T) {
	buf := fixedHeader(flagED, 0)
	buf = append(buf, cbortest.Uint(1)...) // a bare uint, not a map
	if _, err := Parse(buf); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

func TestParse_RejectsTrailingBytes(t *testing.T) {
	buf := fixedHeader(0, 0)
	buf = append(buf, 0xff) // one byte nothing accounts for
	if _, err := Parse(buf); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}
