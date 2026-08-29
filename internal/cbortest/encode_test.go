package cbortest

import (
	"bytes"
	"testing"

	"github.com/jay-opensource/Vouchsafe/internal/cbor"
)

// These are round-trip sanity checks: every fixture built by every other
// test in this module depends on this encoder producing bytes the real
// decoder accepts and reads back correctly.

func TestRoundTripScalars(t *testing.T) {
	cases := []struct {
		name string
		enc  []byte
		want cbor.Value
	}{
		{"uint 0", Uint(0), cbor.Value{Type: cbor.TypeUint, Int: 0}},
		{"uint 65536", Uint(65536), cbor.Value{Type: cbor.TypeUint, Int: 65536}},
		{"negint -7", NegInt(-7), cbor.Value{Type: cbor.TypeNegInt, Int: -7}},
		{"bool true", Bool(true), cbor.Value{Type: cbor.TypeBool, Bool: true}},
		{"bool false", Bool(false), cbor.Value{Type: cbor.TypeBool, Bool: false}},
		{"null", Null(), cbor.Value{Type: cbor.TypeNull}},
		{"text", Text("webauthn.create"), cbor.Value{Type: cbor.TypeText, Text: "webauthn.create"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, n, err := cbor.Decode(c.enc)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if n != len(c.enc) {
				t.Fatalf("consumed %d, want %d", n, len(c.enc))
			}
			if v.Type != c.want.Type || v.Int != c.want.Int || v.Bool != c.want.Bool || v.Text != c.want.Text {
				t.Fatalf("got %+v, want %+v", v, c.want)
			}
		})
	}
}

func TestRoundTripBytes(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	enc := Bytes(payload)
	v, n, err := cbor.Decode(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n != len(enc) || !bytes.Equal(v.Bytes, payload) {
		t.Fatalf("got Bytes=%x n=%d, want %x n=%d", v.Bytes, n, payload, len(enc))
	}
}

func TestRoundTripMapCanonicalOrder(t *testing.T) {
	// {1: 2, 3: -7, -1: 1} — a COSE_Key-shaped map, entries given in the
	// canonical order the real decoder requires (shorter key encoding
	// first; among equal-length keys, bytewise-lexicographic).
	enc := Map(
		Entry{Key: Uint(1), Val: Uint(2)},
		Entry{Key: Uint(3), Val: NegInt(-7)},
		Entry{Key: NegInt(-1), Val: Uint(1)},
	)
	v, n, err := cbor.Decode(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n != len(enc) {
		t.Fatalf("consumed %d, want %d", n, len(enc))
	}
	if kty, ok := v.MapGetInt(1); !ok || kty.Int != 2 {
		t.Fatalf("kty: got %+v ok=%v", kty, ok)
	}
	if alg, ok := v.MapGetInt(3); !ok || alg.Int != -7 {
		t.Fatalf("alg: got %+v ok=%v", alg, ok)
	}
	if crv, ok := v.MapGetInt(-1); !ok || crv.Int != 1 {
		t.Fatalf("crv: got %+v ok=%v", crv, ok)
	}
}

func TestRoundTripArray(t *testing.T) {
	enc := Array(Uint(1), Uint(2), Uint(3))
	v, n, err := cbor.Decode(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n != len(enc) || len(v.Array) != 3 {
		t.Fatalf("got %+v n=%d", v, n)
	}
}
