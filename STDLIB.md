# STDLIB.md

Every third-party package this project would normally need, and what actually replaced it. `go.mod` has no `require` block — this table is the receipt.

## Shipped (Tier 1)

| Normally installed | What it does | Standard-library / hand-written replacement |
|---|---|---|
| `go-webauthn/webauthn`, `fxamacker/webauthn`, `duo-labs/webauthn` | The entire WebAuthn relying party | Hand-written ceremonies — `internal/ceremony` |
| `fxamacker/cbor` | CBOR decoding (chosen upstream for "doesn't crash," 375+ tests, billions of fuzz executions) | Hand-written CTAP2 canonical decoder, ~250 lines — `internal/cbor`. Smaller pure-Go alternatives exist (`digitalbazaar/cbor`, `quartzjer/cb0r`) but are still third-party; the zero-dependency rule forces a hand-written decoder either way. |
| go-webauthn's internal COSE helpers | COSE_Key parsing (EC2, RSA) | Hand-written parser — `internal/cose`. Validates EC points via `crypto/ecdh.NewPublicKey` rather than the deprecated `crypto/elliptic.IsOnCurve`. |
| — | ES256 signature verification | `crypto/ecdsa.VerifyASN1` |
| — | RS256 signature verification | `crypto/rsa.VerifyPKCS1v15` |
| — | Challenge generation | `crypto/rand` |
| — | Constant-time comparison | `crypto/subtle.ConstantTimeCompare` |
| `golang-jwt/jwt` | Session tokens | `crypto/hmac` + `crypto/sha256` — `internal/session`, deliberately not a JWT: no algorithm field for a verifier to be confused about, no library |
| `gin` / `chi` / `gorilla/mux` | HTTP routing | `net/http`, Go 1.22+ method+pattern routing (`"POST /register/begin"`) |
| `spf13/cobra` + `pflag` | CLI | `flag` + hand-rolled subcommand dispatch |
| `sirupsen/logrus` | Structured logging | `log/slog` |
| `stretchr/testify` | Assertions | `testing`, table-driven subtests |
| `google/gofuzz` | Fuzzing | `testing.F` native fuzzing — `internal/cbor/fuzz_test.go` |
| `google/uuid` | Random IDs (per-registration WebAuthn user handle) | `crypto/rand` + `encoding/base64` |
| any front-end framework | The demo page | `html/template` + vanilla `fetch`, no build step — `internal/httpapi/templates/demo.html.tmpl` |

## Not yet built (Tier 2/3 — tracked, not claimed)

| Normally installed | What it does | Planned replacement |
|---|---|---|
| `mkcert` | Local TLS certificate for non-localhost demos | `crypto/x509` + `crypto/tls`, self-signed at startup (`--tls` flag) |
| — | EdDSA/Ed25519 signature support | `crypto/ed25519` |
| — | Packed attestation verification | Hand-written `alg`/`sig`/`x5c` chain check |

## Package Killer

`go-webauthn/webauthn` and its own dependency `fxamacker/cbor` both die, stacked. This doesn't merely replace a convenience library — it replaces security-critical verification code that developers install precisely because they don't want to write it themselves. `tests/negative/` proves the replacement enforces every check the original does: 16 cases, one deliberate mutation per named defect, each asserting the specific rejection.

`go list -m all` and `go mod graph` both print nothing beyond the module itself. See `deps-proof.txt`.
