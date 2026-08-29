// Package cbor implements a decoder for the CTAP2 canonical subset of CBOR
// (RFC 8949) used by WebAuthn attestation objects and authenticator data.
package cbor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// MajorType identifies the decoded shape of a Value.
type MajorType uint8

const (
	TypeUint MajorType = iota
	TypeNegInt
	TypeBytes
	TypeText
	TypeArray
	TypeMap
	TypeBool
	TypeNull
)

const (
	// MaxDepth bounds array/map nesting so a crafted input cannot cause
	// unbounded recursion.
	MaxDepth = 8
	// MaxElements bounds the total number of items decoded from a single
	// input so a crafted length field cannot cause quadratic blowup.
	MaxElements = 10000
	// MaxInputSize bounds the buffer handed to Decode. WebAuthn
	// attestationObject/authenticatorData payloads are a few KB at most.
	MaxInputSize = 1 << 20
)

var (
	ErrTruncated       = errors.New("cbor: truncated input")
	ErrNonCanonical    = errors.New("cbor: non-canonical encoding")
	ErrUnsupported     = errors.New("cbor: unsupported CBOR feature")
	ErrDepth           = errors.New("cbor: nesting depth exceeded")
	ErrTooManyElements = errors.New("cbor: too many elements")
	ErrInputTooLarge   = errors.New("cbor: input too large")
	ErrMapOrder        = errors.New("cbor: map keys not in canonical order")
	ErrDuplicateKey    = errors.New("cbor: duplicate map key")
)

// Value is a decoded CBOR item. Only the fields matching Type are valid.
type Value struct {
	Type  MajorType
	Int   int64
	Bytes []byte
	Text  string
	Array []Value
	Map   []MapEntry
	Bool  bool
}

// MapEntry is one key/value pair of a decoded CBOR map, in canonical order.
type MapEntry struct {
	Key Value
	Val Value
}

// MapGetInt looks up a map value by an integer key, as used by COSE_Key
// labels (small positive or negative integers).
func (v Value) MapGetInt(key int64) (Value, bool) {
	for _, e := range v.Map {
		if (e.Key.Type == TypeUint || e.Key.Type == TypeNegInt) && e.Key.Int == key {
			return e.Val, true
		}
	}
	return Value{}, false
}

// MapGetText looks up a map value by a text-string key, as used by
// attestationObject's "fmt" / "authData" / "attStmt".
func (v Value) MapGetText(key string) (Value, bool) {
	for _, e := range v.Map {
		if e.Key.Type == TypeText && e.Key.Text == key {
			return e.Val, true
		}
	}
	return Value{}, false
}

type decoder struct {
	buf   []byte
	pos   int
	depth int
	elems int
}

// Decode reads exactly one top-level CBOR item from buf and returns it
// along with the number of bytes it consumed. Trailing bytes are not an
// error and are not consumed — callers that need to find where a nested
// CBOR item ends (a COSE_Key embedded in authenticatorData, for example)
// rely on this instead of guessing a length.
func Decode(buf []byte) (Value, int, error) {
	if len(buf) > MaxInputSize {
		return Value{}, 0, fmt.Errorf("%w: %d bytes", ErrInputTooLarge, len(buf))
	}
	d := &decoder{buf: buf}
	v, err := d.decodeValue()
	if err != nil {
		return Value{}, 0, err
	}
	return v, d.pos, nil
}

func (d *decoder) readByte() (byte, error) {
	if d.pos >= len(d.buf) {
		return 0, ErrTruncated
	}
	b := d.buf[d.pos]
	d.pos++
	return b, nil
}

func (d *decoder) readN(n int) ([]byte, error) {
	if n < 0 || d.pos+n > len(d.buf) {
		return nil, ErrTruncated
	}
	b := d.buf[d.pos : d.pos+n]
	d.pos += n
	return b, nil
}

// readInitialByte reads one CBOR initial byte and splits it into major
// type and additional-information field.
func (d *decoder) readInitialByte() (major, ai byte, start int, err error) {
	start = d.pos
	b, err := d.readByte()
	if err != nil {
		return 0, 0, start, err
	}
	return b >> 5, b & 0x1f, start, nil
}

// readArgument reads the length/value argument for major types 0 through
// 6, enforcing shortest-form encoding per RFC 8949 §4.2 deterministic
// encoding. Major type 7's additional-information field encodes distinct
// semantics (booleans, null, float width) rather than a length or integer
// value, so it is handled separately in decodeSimple and never reaches here.
func (d *decoder) readArgument(ai byte, start int) (uint64, error) {
	switch {
	case ai < 24:
		return uint64(ai), nil
	case ai == 24:
		bs, err := d.readN(1)
		if err != nil {
			return 0, err
		}
		v := uint64(bs[0])
		if v < 24 {
			return 0, fmt.Errorf("%w: 1-byte argument %d at offset %d", ErrNonCanonical, v, start)
		}
		return v, nil
	case ai == 25:
		bs, err := d.readN(2)
		if err != nil {
			return 0, err
		}
		v := uint64(binary.BigEndian.Uint16(bs))
		if v <= 0xff {
			return 0, fmt.Errorf("%w: 2-byte argument %d at offset %d", ErrNonCanonical, v, start)
		}
		return v, nil
	case ai == 26:
		bs, err := d.readN(4)
		if err != nil {
			return 0, err
		}
		v := uint64(binary.BigEndian.Uint32(bs))
		if v <= 0xffff {
			return 0, fmt.Errorf("%w: 4-byte argument %d at offset %d", ErrNonCanonical, v, start)
		}
		return v, nil
	case ai == 27:
		bs, err := d.readN(8)
		if err != nil {
			return 0, err
		}
		v := binary.BigEndian.Uint64(bs)
		if v <= 0xffffffff {
			return 0, fmt.Errorf("%w: 8-byte argument %d at offset %d", ErrNonCanonical, v, start)
		}
		return v, nil
	case ai == 31:
		return 0, fmt.Errorf("%w: indefinite length at offset %d", ErrUnsupported, start)
	default: // 28, 29, 30 reserved
		return 0, fmt.Errorf("%w: reserved additional info %d at offset %d", ErrUnsupported, ai, start)
	}
}

// decodeSimple handles major type 7: booleans, null, and the
// (unsupported) simple-value and float encodings. Unlike major types 0-6,
// additional-information values 25/26/27 here mean "2/4/8 raw bytes
// follow" (a float16/32/64 bit pattern), not a shortest-form integer
// argument, so no canonical-form check applies to them.
func (d *decoder) decodeSimple(ai byte, start int) (Value, error) {
	switch ai {
	case 20:
		return Value{Type: TypeBool, Bool: false}, nil
	case 21:
		return Value{Type: TypeBool, Bool: true}, nil
	case 22:
		return Value{Type: TypeNull}, nil
	case 24:
		if _, err := d.readN(1); err != nil {
			return Value{}, err
		}
		return Value{}, fmt.Errorf("%w: simple value extension at offset %d", ErrUnsupported, start)
	case 25:
		if _, err := d.readN(2); err != nil {
			return Value{}, err
		}
		return Value{}, fmt.Errorf("%w: float16 at offset %d", ErrUnsupported, start)
	case 26:
		if _, err := d.readN(4); err != nil {
			return Value{}, err
		}
		return Value{}, fmt.Errorf("%w: float32 at offset %d", ErrUnsupported, start)
	case 27:
		if _, err := d.readN(8); err != nil {
			return Value{}, err
		}
		return Value{}, fmt.Errorf("%w: float64 at offset %d", ErrUnsupported, start)
	case 31:
		return Value{}, fmt.Errorf("%w: indefinite-length break at offset %d", ErrUnsupported, start)
	default:
		return Value{}, fmt.Errorf("%w: simple value %d at offset %d", ErrUnsupported, ai, start)
	}
}

func (d *decoder) decodeValue() (Value, error) {
	d.elems++
	if d.elems > MaxElements {
		return Value{}, ErrTooManyElements
	}
	major, ai, start, err := d.readInitialByte()
	if err != nil {
		return Value{}, err
	}
	if major == 7 {
		return d.decodeSimple(ai, start)
	}
	arg, err := d.readArgument(ai, start)
	if err != nil {
		return Value{}, err
	}

	switch major {
	case 0:
		if arg > math.MaxInt64 {
			return Value{}, fmt.Errorf("%w: uint overflow at offset %d", ErrUnsupported, start)
		}
		return Value{Type: TypeUint, Int: int64(arg)}, nil

	case 1:
		if arg > math.MaxInt64 {
			return Value{}, fmt.Errorf("%w: negint overflow at offset %d", ErrUnsupported, start)
		}
		return Value{Type: TypeNegInt, Int: -1 - int64(arg)}, nil

	case 2:
		if arg > uint64(len(d.buf)-d.pos) {
			return Value{}, fmt.Errorf("%w: byte string length %d at offset %d", ErrTruncated, arg, start)
		}
		b, err := d.readN(int(arg))
		if err != nil {
			return Value{}, err
		}
		return Value{Type: TypeBytes, Bytes: append([]byte(nil), b...)}, nil

	case 3:
		if arg > uint64(len(d.buf)-d.pos) {
			return Value{}, fmt.Errorf("%w: text string length %d at offset %d", ErrTruncated, arg, start)
		}
		b, err := d.readN(int(arg))
		if err != nil {
			return Value{}, err
		}
		return Value{Type: TypeText, Text: string(b)}, nil

	case 4:
		return d.decodeArray(arg, start)

	case 5:
		return d.decodeMap(arg, start)

	case 6:
		return Value{}, fmt.Errorf("%w: tags at offset %d", ErrUnsupported, start)

	default:
		return Value{}, fmt.Errorf("%w: major type %d at offset %d", ErrUnsupported, major, start)
	}
}

func (d *decoder) decodeArray(n uint64, start int) (Value, error) {
	if d.depth >= MaxDepth {
		return Value{}, fmt.Errorf("%w: at offset %d", ErrDepth, start)
	}
	d.depth++
	items := make([]Value, 0, min(n, 64))
	for range n {
		v, err := d.decodeValue()
		if err != nil {
			return Value{}, err
		}
		items = append(items, v)
	}
	d.depth--
	return Value{Type: TypeArray, Array: items}, nil
}

func (d *decoder) decodeMap(n uint64, start int) (Value, error) {
	if d.depth >= MaxDepth {
		return Value{}, fmt.Errorf("%w: at offset %d", ErrDepth, start)
	}
	d.depth++
	entries := make([]MapEntry, 0, min(n, 64))
	keySpans := make([][]byte, 0, min(n, 64))
	for range n {
		keyStart := d.pos
		k, err := d.decodeValue()
		if err != nil {
			return Value{}, err
		}
		keySpan := append([]byte(nil), d.buf[keyStart:d.pos]...)
		v, err := d.decodeValue()
		if err != nil {
			return Value{}, err
		}
		entries = append(entries, MapEntry{Key: k, Val: v})
		keySpans = append(keySpans, keySpan)
	}
	d.depth--

	for i := 1; i < len(keySpans); i++ {
		switch canonicalCompare(keySpans[i-1], keySpans[i]) {
		case 0:
			return Value{}, fmt.Errorf("%w: at offset %d", ErrDuplicateKey, start)
		case 1:
			return Value{}, fmt.Errorf("%w: at offset %d", ErrMapOrder, start)
		}
	}
	return Value{Type: TypeMap, Map: entries}, nil
}

// canonicalCompare orders two encoded CBOR keys per RFC 8949 §4.2.1: the
// item with the shorter encoding sorts first; equal-length encodings sort
// bytewise lexicographically. Returns -1, 0, or 1.
func canonicalCompare(a, b []byte) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return bytes.Compare(a, b)
}
