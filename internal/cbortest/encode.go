// Package cbortest provides minimal canonical CBOR encoding for building
// test fixtures. It exists only so tests can construct well-formed
// COSE_Key, authenticatorData, and attestationObject byte sequences
// without a hand-maintained byte literal for every case. It is never
// imported by cmd/vouchsafe: the shipped binary only ever decodes CBOR
// (per the hackathon's zero-dependency rules and the honest-scope
// argument in STDLIB.md), and this package is not part of that surface.
package cbortest

import "encoding/binary"

// Uint encodes a CBOR unsigned integer (major type 0) in canonical
// shortest form.
func Uint(n uint64) []byte { return encodeHeader(0, n) }

// NegInt encodes a CBOR negative integer (major type 1) representing the
// signed value v, which must be negative.
func NegInt(v int64) []byte {
	if v >= 0 {
		panic("cbortest: NegInt requires a negative value")
	}
	return encodeHeader(1, uint64(-1-v))
}

// Bytes encodes a CBOR byte string (major type 2).
func Bytes(b []byte) []byte {
	return append(encodeHeader(2, uint64(len(b))), b...)
}

// Text encodes a CBOR text string (major type 3).
func Text(s string) []byte {
	return append(encodeHeader(3, uint64(len(s))), []byte(s)...)
}

// Array encodes a CBOR array (major type 4) from already-encoded items.
func Array(items ...[]byte) []byte {
	out := encodeHeader(4, uint64(len(items)))
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

// Entry is one already-encoded key/value pair for Map.
type Entry struct {
	Key []byte
	Val []byte
}

// Map encodes a CBOR map (major type 5) from already-encoded entries.
// Entries must already be given in canonical order (shorter-key-first,
// then bytewise lexicographic) — Map does not sort them, so a fixture can
// also be deliberately built out of order to test that a decoder rejects it.
func Map(entries ...Entry) []byte {
	out := encodeHeader(5, uint64(len(entries)))
	for _, e := range entries {
		out = append(out, e.Key...)
		out = append(out, e.Val...)
	}
	return out
}

// Bool encodes a CBOR boolean (major type 7).
func Bool(b bool) []byte {
	if b {
		return []byte{0xf5}
	}
	return []byte{0xf4}
}

// Null encodes CBOR null (major type 7).
func Null() []byte { return []byte{0xf6} }

func encodeHeader(major byte, arg uint64) []byte {
	b := major << 5
	switch {
	case arg < 24:
		return []byte{b | byte(arg)}
	case arg <= 0xff:
		return []byte{b | 24, byte(arg)}
	case arg <= 0xffff:
		buf := make([]byte, 3)
		buf[0] = b | 25
		binary.BigEndian.PutUint16(buf[1:], uint16(arg))
		return buf
	case arg <= 0xffffffff:
		buf := make([]byte, 5)
		buf[0] = b | 26
		binary.BigEndian.PutUint32(buf[1:], uint32(arg))
		return buf
	default:
		buf := make([]byte, 9)
		buf[0] = b | 27
		binary.BigEndian.PutUint64(buf[1:], arg)
		return buf
	}
}
