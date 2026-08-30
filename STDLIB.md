# STDLIB.md

Every third-party package this project would normally need, and what actually replaced it. `go.mod` has no `require` block — this table is the receipt.

| Normally installed | What it does | Standard-library / hand-written replacement |
|---|---|---|
| `go-webauthn/webauthn`, `fxamacker/webauthn`, `duo-labs/webauthn` | The entire WebAuthn relying party | Hand-written ceremonies — `internal/ceremony` |
| `fxamacker/cbor` | CBOR decoding (chosen upstream for "doesn't crash," 375+ tests, billions of fuzz executions) | Hand-written CTAP2 canonical decoder, ~250 lines — `internal/cbor`. Smaller pure-Go alternatives exist (`digitalbazaar/cbor`, `quartzjer/cb0r`) but are still third-party; the zero-dependency rule forces a hand-written decoder either way. |
| go-webauthn's internal COSE helpers | COSE_Key parsing (EC2, RSA, OKP/Ed25519) | Hand-written parser — `internal/cose`. Validates EC points via `crypto/ecdh.NewPublicKey` rather than the deprecated `crypto/elliptic.IsOnCurve`. |
| — | ES256 signature verification | `crypto/ecdsa.VerifyASN1` |
| — | RS256 signature verification | `crypto/rsa.VerifyPKCS1v15` |
| — | EdDSA (Ed25519) signature verification | `crypto/ed25519.Verify` — against the raw message, never a pre-hashed digest (Ed25519 hashes internally with SHA-512; handing it a SHA-256 digest instead, the way ECDSA/RSA need, would silently verify the wrong thing) |
| — | Challenge generation | `crypto/rand` |
| — | Constant-time comparison | `crypto/subtle.ConstantTimeCompare` |
| `golang-jwt/jwt` | Session tokens | `crypto/hmac` + `crypto/sha256` — `internal/session`, deliberately not a JWT: no algorithm field for a verifier to be confused about, no library |
| `gin` / `chi` / `gorilla/mux` | HTTP routing | `net/http`, Go 1.22+ method+pattern routing (`"POST /register/begin"`, `"DELETE /credentials/{id}"`) |
| `spf13/cobra` + `pflag` | CLI | `flag` + hand-rolled subcommand dispatch |
| `sirupsen/logrus` | Structured logging | `log/slog` |
| `stretchr/testify` | Assertions | `testing`, table-driven subtests |
| `google/gofuzz` | Fuzzing | `testing.F` native fuzzing — `internal/cbor/fuzz_test.go` |
| `google/uuid` | Random IDs (per-registration WebAuthn user handle, discoverable-login flow IDs) | `crypto/rand` + `encoding/base64` |
| any front-end framework | The demo page | `html/template` + vanilla `fetch`, no build step — `internal/httpapi/templates/demo.html.tmpl` |
| — | Packed attestation verification (self and full, via `x5c`) | Hand-written `alg`/`sig`/`x5c` chain check — `internal/ceremony/attestation.go`. Full attestation is verified against the leaf certificate's own key via `crypto/x509.ParseCertificate`, deliberately not chained to a trust anchor (needs the FIDO Metadata Service — permanently out of scope). |
| `mkcert` | Local TLS certificate for non-localhost demos | `crypto/x509` + `crypto/tls`, self-signed at startup (`--tls` flag), fingerprint printed |
| `stretchr/testify/require` benchmark helpers | Verification-latency measurement | `testing.B` native benchmarks — `internal/ceremony/bench_test.go`, published including the honest number: durability (fsync) dominates latency, not cryptography |

## Package Killer

`go-webauthn/webauthn` and its own dependency `fxamacker/cbor` both die, stacked. This doesn't merely replace a convenience library — it replaces security-critical verification code that developers install precisely because they don't want to write it themselves. `tests/negative/` proves the replacement enforces every check the original does: 16 cases, one deliberate mutation per named defect, each asserting the specific rejection.

`go list -m all` and `go mod graph` both print nothing beyond the module itself. See `deps-proof.txt`.
