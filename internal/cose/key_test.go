package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"

	"github.com/jay-opensource/Vouchsafe/internal/cbor"
	"github.com/jay-opensource/Vouchsafe/internal/cbortest"
)

func encodeEC2(t *testing.T, crv int64, alg int64, x, y []byte) cbor.Value {
	t.Helper()
	enc := cbortest.Map(
		cbortest.Entry{Key: cbortest.Uint(labelKty), Val: cbortest.Uint(ktyEC2)},
		cbortest.Entry{Key: cbortest.Uint(labelAlg), Val: cbortest.NegInt(alg)},
		cbortest.Entry{Key: cbortest.NegInt(labelEC2Crv), Val: cbortest.Uint(uint64(crv))},
		cbortest.Entry{Key: cbortest.NegInt(labelEC2X), Val: cbortest.Bytes(x)},
		cbortest.Entry{Key: cbortest.NegInt(labelEC2Y), Val: cbortest.Bytes(y)},
	)
	v, _, err := cbor.Decode(enc)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return v
}

func fixedLen(b []byte, n int) []byte {
	if len(b) >= n {
		return b[len(b)-n:]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

func TestParseEC2_P256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	x := fixedLen(priv.X.Bytes(), 32)
	y := fixedLen(priv.Y.Bytes(), 32)
	v := encodeEC2(t, curveP256, AlgES256, x, y)

	key, err := Parse(v)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if key.Alg != AlgES256 {
		t.Fatalf("Alg = %d, want %d", key.Alg, AlgES256)
	}
	pub, ok := key.Public.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public is %T, want *ecdsa.PublicKey", key.Public)
	}
	if !pub.Equal(&priv.PublicKey) {
		t.Fatalf("parsed key does not match generated key")
	}
}

func TestParseEC2_RejectsPointNotOnCurve(t *testing.T) {
	// (1, 1) is not on P-256 for a=-3 short Weierstrass curves in general
	// use; crypto/ecdh must reject it regardless.
	x := fixedLen(big.NewInt(1).Bytes(), 32)
	y := fixedLen(big.NewInt(1).Bytes(), 32)
	v := encodeEC2(t, curveP256, AlgES256, x, y)

	if _, err := Parse(v); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("got %v, want ErrMalformedKey", err)
	}
}

func TestParseEC2_RejectsCoordinateLengthMismatch(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	x := fixedLen(priv.X.Bytes(), 31) // wrong length for P-256
	y := fixedLen(priv.Y.Bytes(), 32)
	v := encodeEC2(t, curveP256, AlgES256, x, y)

	if _, err := Parse(v); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("got %v, want ErrMalformedKey", err)
	}
}

func TestParseEC2_RejectsUnsupportedCurve(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	x := fixedLen(priv.X.Bytes(), 32)
	y := fixedLen(priv.Y.Bytes(), 32)
	v := encodeEC2(t, 99, AlgES256, x, y) // bogus curve id

	if _, err := Parse(v); !errors.Is(err, ErrUnsupportedCurve) {
		t.Fatalf("got %v, want ErrUnsupportedCurve", err)
	}
}

func encodeRSA(t *testing.T, n *big.Int, e int64) cbor.Value {
	t.Helper()
	enc := cbortest.Map(
		cbortest.Entry{Key: cbortest.Uint(labelKty), Val: cbortest.Uint(ktyRSA)},
		cbortest.Entry{Key: cbortest.Uint(labelAlg), Val: cbortest.NegInt(AlgRS256)},
		cbortest.Entry{Key: cbortest.NegInt(labelRSAN), Val: cbortest.Bytes(n.Bytes())},
		cbortest.Entry{Key: cbortest.NegInt(labelRSAE), Val: cbortest.Bytes(big.NewInt(e).Bytes())},
	)
	v, _, err := cbor.Decode(enc)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return v
}

func TestParseRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	v := encodeRSA(t, priv.N, int64(priv.E))

	key, err := Parse(v)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if key.Alg != AlgRS256 {
		t.Fatalf("Alg = %d, want %d", key.Alg, AlgRS256)
	}
	pub, ok := key.Public.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Public is %T, want *rsa.PublicKey", key.Public)
	}
	if !pub.Equal(&priv.PublicKey) {
		t.Fatalf("parsed key does not match generated key")
	}
}

func TestParseRSA_RejectsWeakModulus(t *testing.T) {
	// Go's own rsa.GenerateKey refuses to generate keys below its safety
	// floor, so a small modulus is fabricated directly — the parser's
	// bit-length check operates on n alone and does not require n to be
	// an actual product of two primes.
	weak := new(big.Int).Lsh(big.NewInt(1), 511) // exactly 512 bits
	v := encodeRSA(t, weak, 65537)

	if _, err := Parse(v); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("got %v, want ErrMalformedKey", err)
	}
}

func TestParseRSA_RejectsNonPositiveModulus(t *testing.T) {
	v := encodeRSA(t, big.NewInt(0), 65537)
	if _, err := Parse(v); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("got %v, want ErrMalformedKey", err)
	}
}

func TestParseRSA_RejectsBadExponent(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	v := encodeRSA(t, priv.N, 0)
	if _, err := Parse(v); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("exponent 0: got %v, want ErrMalformedKey", err)
	}
}

func TestParse_RejectsMissingKty(t *testing.T) {
	enc := cbortest.Map(
		cbortest.Entry{Key: cbortest.Uint(labelAlg), Val: cbortest.NegInt(AlgES256)},
	)
	v, _, err := cbor.Decode(enc)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if _, err := Parse(v); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("got %v, want ErrMalformedKey", err)
	}
}

func TestParse_RejectsUnsupportedKeyType(t *testing.T) {
	enc := cbortest.Map(
		cbortest.Entry{Key: cbortest.Uint(labelKty), Val: cbortest.Uint(4)}, // Symmetric
		cbortest.Entry{Key: cbortest.Uint(labelAlg), Val: cbortest.NegInt(AlgES256)},
	)
	v, _, err := cbor.Decode(enc)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if _, err := Parse(v); !errors.Is(err, ErrUnsupportedKeyType) {
		t.Fatalf("got %v, want ErrUnsupportedKeyType", err)
	}
}

func TestParse_RejectsOKPForNow(t *testing.T) {
	enc := cbortest.Map(
		cbortest.Entry{Key: cbortest.Uint(labelKty), Val: cbortest.Uint(ktyOKP)},
		cbortest.Entry{Key: cbortest.Uint(labelAlg), Val: cbortest.NegInt(AlgEdDSA)},
	)
	v, _, err := cbor.Decode(enc)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if _, err := Parse(v); !errors.Is(err, ErrUnsupportedKeyType) {
		t.Fatalf("got %v, want ErrUnsupportedKeyType", err)
	}
}

func TestParse_RejectsNonMap(t *testing.T) {
	v, _, err := cbor.Decode(cbortest.Uint(1))
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if _, err := Parse(v); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("got %v, want ErrMalformedKey", err)
	}
}
