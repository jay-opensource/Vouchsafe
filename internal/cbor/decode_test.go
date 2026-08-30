package cbor

import (
	"bytes"
	"errors"
	"testing"
)

func TestDecodeUint(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want int64
	}{
		{"direct 0", []byte{0x00}, 0},
		{"direct 1", []byte{0x01}, 1},
		{"direct max 23", []byte{0x17}, 23},
		{"1-byte form 24", []byte{0x18, 0x18}, 24},
		{"1-byte form 255", []byte{0x18, 0xff}, 255},
		{"2-byte form 256", []byte{0x19, 0x01, 0x00}, 256},
		{"2-byte form 65535", []byte{0x19, 0xff, 0xff}, 65535},
		{"4-byte form 65536", []byte{0x1a, 0x00, 0x01, 0x00, 0x00}, 65536},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, n, err := Decode(c.in)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if v.Type != TypeUint || v.Int != c.want {
				t.Fatalf("got Type=%v Int=%d, want Uint(%d)", v.Type, v.Int, c.want)
			}
			if n != len(c.in) {
				t.Fatalf("consumed %d bytes, want %d", n, len(c.in))
			}
		})
	}
}

func TestDecodeUintRejectsNonCanonical(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"1-byte form encodes 23", []byte{0x18, 0x17}},
		{"2-byte form encodes 255", []byte{0x19, 0x00, 0xff}},
		{"4-byte form encodes 65535", []byte{0x1a, 0x00, 0x00, 0xff, 0xff}},
		{"8-byte form encodes 4294967295", []byte{0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := Decode(c.in)
			if !errors.Is(err, ErrNonCanonical) {
				t.Fatalf("got %v, want ErrNonCanonical", err)
			}
		})
	}
}

func TestDecodeNegInt(t *testing.T) {
	// -7 is the COSE algorithm identifier for ES256, and is the case this
	// decoder exists to get right.
	v, n, err := Decode([]byte{0x26})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if v.Type != TypeNegInt || v.Int != -7 {
		t.Fatalf("got Type=%v Int=%d, want NegInt(-7)", v.Type, v.Int)
	}
	if n != 1 {
		t.Fatalf("consumed %d bytes, want 1", n)
	}

	v, _, err = Decode([]byte{0x20})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if v.Int != -1 {
		t.Fatalf("got Int=%d, want -1", v.Int)
	}
}

func TestDecodeBytesAndText(t *testing.T) {
	v, n, err := Decode([]byte{0x43, 0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if v.Type != TypeBytes || !bytes.Equal(v.Bytes, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("got %+v, want Bytes([1 2 3])", v)
	}
	if n != 4 {
		t.Fatalf("consumed %d, want 4", n)
	}

	v, n, err = Decode([]byte{0x65, 'h', 'e', 'l', 'l', 'o'})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if v.Type != TypeText || v.Text != "hello" {
		t.Fatalf("got %+v, want Text(hello)", v)
	}
	if n != 6 {
		t.Fatalf("consumed %d, want 6", n)
	}
}

func TestDecodeTruncated(t *testing.T) {
	cases := [][]byte{
		{},
		{0x43, 0x01, 0x02}, // bstr claims 3 bytes, only 2 present
		{0x18},             // 1-byte form header with no argument byte
	}
	for _, in := range cases {
		_, _, err := Decode(in)
		if !errors.Is(err, ErrTruncated) {
			t.Fatalf("Decode(%x): got %v, want ErrTruncated", in, err)
		}
	}
}

func TestDecodeBoolNull(t *testing.T) {
	v, _, err := Decode([]byte{0xf4})
	if err != nil || v.Type != TypeBool || v.Bool != false {
		t.Fatalf("false: got %+v, err=%v", v, err)
	}
	v, _, err = Decode([]byte{0xf5})
	if err != nil || v.Type != TypeBool || v.Bool != true {
		t.Fatalf("true: got %+v, err=%v", v, err)
	}
	v, _, err = Decode([]byte{0xf6})
	if err != nil || v.Type != TypeNull {
		t.Fatalf("null: got %+v, err=%v", v, err)
	}
}

func TestDecodeRejectsFloat(t *testing.T) {
	cases := [][]byte{
		{0xf9, 0x00, 0x00},             // float16
		{0xfa, 0x00, 0x00, 0x00, 0x00}, // float32
		{0xfb, 0, 0, 0, 0, 0, 0, 0, 0}, // float64
	}
	for _, in := range cases {
		_, _, err := Decode(in)
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Decode(%x): got %v, want ErrUnsupported", in, err)
		}
	}
}

func TestDecodeRejectsTags(t *testing.T) {
	_, _, err := Decode([]byte{0xc0, 0x00})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v, want ErrUnsupported", err)
	}
}

func TestDecodeRejectsIndefiniteLength(t *testing.T) {
	cases := [][]byte{
		{0x5f}, // indefinite byte string
		{0x9f}, // indefinite array
		{0xbf}, // indefinite map
	}
	for _, in := range cases {
		_, _, err := Decode(in)
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Decode(%x): got %v, want ErrUnsupported", in, err)
		}
	}
}

func TestDecodeArrayNested(t *testing.T) {
	// [1, 2, 3]
	v, n, err := Decode([]byte{0x83, 0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if v.Type != TypeArray || len(v.Array) != 3 {
		t.Fatalf("got %+v", v)
	}
	if n != 4 {
		t.Fatalf("consumed %d, want 4", n)
	}
}

func TestDecodeDepthLimit(t *testing.T) {
	// exactly MaxDepth (8) levels of single-element array wrapping a uint — must succeed.
	ok := nestedArray(MaxDepth, []byte{0x00})
	if _, _, err := Decode(ok); err != nil {
		t.Fatalf("depth %d: got %v, want success", MaxDepth, err)
	}

	// MaxDepth+1 levels must fail.
	tooDeep := nestedArray(MaxDepth+1, []byte{0x00})
	if _, _, err := Decode(tooDeep); !errors.Is(err, ErrDepth) {
		t.Fatalf("depth %d: got %v, want ErrDepth", MaxDepth+1, err)
	}
}

func nestedArray(depth int, leaf []byte) []byte {
	out := leaf
	for range depth {
		out = append([]byte{0x81}, out...) // array of 1 item
	}
	return out
}

func TestDecodeMapCanonicalOrder(t *testing.T) {
	// {1: 0, 2: 0} — correct canonical order.
	if _, _, err := Decode([]byte{0xa2, 0x01, 0x00, 0x02, 0x00}); err != nil {
		t.Fatalf("valid order: got %v", err)
	}

	// {2: 0, 1: 0} — keys out of order.
	if _, _, err := Decode([]byte{0xa2, 0x02, 0x00, 0x01, 0x00}); !errors.Is(err, ErrMapOrder) {
		t.Fatalf("swapped order: got %v, want ErrMapOrder", err)
	}

	// {1: 0, 1: 0} — duplicate key.
	if _, _, err := Decode([]byte{0xa2, 0x01, 0x00, 0x01, 0x00}); !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("duplicate key: got %v, want ErrDuplicateKey", err)
	}
}

func TestDecodeMapGetInt(t *testing.T) {
	// COSE_Key-shaped map: {1: 2, 3: -7, -1: 1} (kty=EC2, alg=ES256, crv=P-256)
	v, _, err := Decode([]byte{
		0xa3,
		0x01, 0x02, // kty: 2
		0x03, 0x26, // alg: -7
		0x20, 0x01, // crv (-1): 1
	})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if kty, ok := v.MapGetInt(1); !ok || kty.Int != 2 {
		t.Fatalf("kty: got %+v, ok=%v", kty, ok)
	}
	if alg, ok := v.MapGetInt(3); !ok || alg.Int != -7 {
		t.Fatalf("alg: got %+v, ok=%v", alg, ok)
	}
	if crv, ok := v.MapGetInt(-1); !ok || crv.Int != 1 {
		t.Fatalf("crv: got %+v, ok=%v", crv, ok)
	}
	if _, ok := v.MapGetInt(99); ok {
		t.Fatalf("missing key 99 reported present")
	}
}

func TestDecodeMapGetText(t *testing.T) {
	// {"fmt": "none"}
	v, _, err := Decode([]byte{0xa1, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e'})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	fmtVal, ok := v.MapGetText("fmt")
	if !ok || fmtVal.Text != "none" {
		t.Fatalf("got %+v, ok=%v", fmtVal, ok)
	}
}

func TestDecodeIgnoresTrailingBytes(t *testing.T) {
	// A single uint(1) followed by two bytes of garbage — Decode must
	// report the item ends after 1 byte, not consume or error on the rest.
	// This is the property authenticatorData parsing depends on to find
	// where an embedded COSE_Key CBOR item ends.
	v, n, err := Decode([]byte{0x01, 0xff, 0xff})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if v.Int != 1 || n != 1 {
		t.Fatalf("got Int=%d n=%d, want Int=1 n=1", v.Int, n)
	}
}

func TestDecodeMaxElements(t *testing.T) {
	// An array header claiming MaxElements+1 single-byte uint(0) elements.
	n := MaxElements + 1
	buf := make([]byte, 0, 3+n)
	buf = append(buf, 0x99, byte(n>>8), byte(n)) // ai=25, 2-byte length
	for range n {
		buf = append(buf, 0x00)
	}
	if _, _, err := Decode(buf); !errors.Is(err, ErrTooManyElements) {
		t.Fatalf("got %v, want ErrTooManyElements", err)
	}
}

func TestDecodeMaxInputSize(t *testing.T) {
	buf := make([]byte, MaxInputSize+1)
	if _, _, err := Decode(buf); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("got %v, want ErrInputTooLarge", err)
	}
}
