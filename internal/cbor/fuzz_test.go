package cbor

import (
	"reflect"
	"testing"
)

// FuzzDecode exercises the decoder against attacker-controlled bytes: an
// attestationObject comes from whatever is on the other end of the
// browser, so the parser sitting in front of every WebAuthn security
// check must never panic and must never read out of bounds, no matter
// how the input is malformed.
func FuzzDecode(f *testing.F) {
	seeds := [][]byte{
		// well-formed values from the unit-test corpus
		{0x00}, {0x01}, {0x17},
		{0x18, 0x18}, {0x18, 0xff},
		{0x19, 0x01, 0x00}, {0x19, 0xff, 0xff},
		{0x1a, 0x00, 0x01, 0x00, 0x00},
		{0x20}, {0x26}, // negints, including COSE alg ES256 (-7)
		{0x43, 0x01, 0x02, 0x03},
		{0x65, 'h', 'e', 'l', 'l', 'o'},
		{0x83, 0x01, 0x02, 0x03},
		{0xa2, 0x01, 0x00, 0x02, 0x00},
		{0xf4}, {0xf5}, {0xf6},

		// a COSE_Key-shaped map: {1: 2, 3: -7, -1: 1}
		{0xa3, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01},
		// an attestationObject-shaped map: {"fmt": "none", "attStmt": {}}
		{
			0xa2,
			0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e',
			0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0,
		},

		// malformed / rejected inputs — the corpus the fuzzer should
		// mutate away from panicking on
		{},
		{0x18},                   // truncated argument
		{0x43, 0x01, 0x02},       // bstr length exceeds remaining input
		{0x18, 0x17},             // non-canonical 1-byte form
		{0x19, 0x00, 0xff},       // non-canonical 2-byte form
		{0xa2, 0x02, 0x00, 0x01, 0x00}, // map keys out of canonical order
		{0xa2, 0x01, 0x00, 0x01, 0x00}, // duplicate map key
		{0xc0, 0x00},             // tag
		{0x5f}, {0x9f}, {0xbf},   // indefinite length
		{0xf9, 0x00, 0x00}, {0xfa, 0, 0, 0, 0}, {0xfb, 0, 0, 0, 0, 0, 0, 0, 0}, // floats
		nestedArray(MaxDepth+1, []byte{0x00}), // over the depth cap
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		v, n, err := Decode(data)
		if err != nil {
			return
		}
		if n < 0 || n > len(data) {
			t.Fatalf("consumed %d bytes, out of range for input of length %d", n, len(data))
		}
		// A successful decode must be idempotent on the exact prefix it
		// reported consuming — this is the property authenticatorData
		// parsing relies on to locate an embedded COSE_Key correctly.
		v2, n2, err2 := Decode(data[:n])
		if err2 != nil {
			t.Fatalf("decode not idempotent on its own consumed prefix: %v", err2)
		}
		if n2 != n {
			t.Fatalf("decode not idempotent: first pass consumed %d, second pass %d", n, n2)
		}
		if !reflect.DeepEqual(v, v2) {
			t.Fatalf("decode not deterministic on its own consumed prefix: %+v != %+v", v, v2)
		}
	})
}
