# vouchsafe

Add passkey login to any application. One binary, no dependencies, no passwords stored — because there are none.

vouchsafe is a WebAuthn relying-party server: it lets an application replace passwords with fingerprint, face, or security-key login. It is **not** a password manager — it stores no secrets. Only public keys are kept, and the private key never leaves the authenticator's secure enclave. Steal the entire store file and you get nothing you can log in with.

## Quick start

```
go build ./cmd/vouchsafe
./vouchsafe serve
```

Open `http://localhost:8080/demo`, click Register, touch your sensor or security key. No certificate needed — browsers treat `localhost` as a secure context.

## How it works

Your application asks vouchsafe one question — *is this really user X?* — and gets back a cryptographically proven answer.

```
SIGNING UP
 1. user clicks "Sign up"
 2. your app  ->  POST /register/begin        ->  vouchsafe returns a challenge
 3. browser   ->  navigator.credentials.create(...)
 4. user touches Touch ID / a security key
 5. your app  ->  POST /register/finish        ->  credential stored (public key only)

LOGGING IN
 1. user clicks "Log in"
 2. your app  ->  POST /login/begin            ->  new challenge
 3. browser   ->  navigator.credentials.get(...)
 4. your app  ->  POST /login/finish           ->  {token, user, uv}
```

## Frozen scope

**Signature algorithms:**
- ES256 (ECDSA P-256 + SHA-256) — Apple, Android platform authenticators
- RS256 (RSASSA-PKCS1-v1_5 + SHA-256) — Windows Hello, most security keys
- EdDSA (Ed25519) — Tier 2, not yet implemented

**Attestation formats:**
- `none` — supported. What platform authenticators overwhelmingly return; most relying parties decline attestation for privacy reasons.
- `packed` — Tier 2, not yet implemented.
- Everything else (`tpm`, `android-key`, `android-safetynet`, `fido-u2f`, `apple`) — a named refusal, never a silent pass.

**Permanently out of scope:** FIDO Metadata Service lookups (needs a remote service), enterprise attestation, U2F/CTAP1 legacy compatibility, WebAuthn extensions beyond reading the ED flag, account recovery flows, a user-management UI.

## Limits

- **Secure context required.** WebAuthn only works over HTTPS, or over plain HTTP on `localhost`/loopback. Running vouchsafe on a non-loopback address without TLS makes the browser silently refuse to offer WebAuthn — vouchsafe prints a startup warning when this is the case. Self-signed `--tls` mode is Tier 2.
- **No discoverable/usernameless login yet.** The current flow needs a username at `/login/begin` to look up which credentials to allow.
- **Real-browser fixture testing is not yet done.** Every ceremony, security check, and the full negative-test suite (`tests/negative/`) are proven against a synthetic virtual-authenticator harness (`internal/webauthntest`) that generates real keys and real signatures — no actual Touch ID, Windows Hello, or hardware security key has exercised this code yet, only its compiled binary over real HTTP (`tests/e2e/`). Do a real-hardware pass across at least Safari/Touch ID, Edge/Windows Hello, and a hardware key before relying on this in front of anyone.

## Storage

`vouchsafe.json`, mode 0600 (POSIX systems), created atomically on every write. Holds public keys only — no passwords, no password hashes, no shared secrets.

## Prior art

Every Go WebAuthn library (`go-webauthn/webauthn`, `fxamacker/webauthn`, `duo-labs/webauthn`) depends on `fxamacker/cbor` — chosen, in the maintainers' own words, because it "doesn't crash" and is "the most well-tested CBOR library available," with 375+ tests and billions of fuzzing executions. Smaller pure-Go CBOR decoders exist too (`digitalbazaar/cbor`, `quartzjer/cb0r`) — all still third-party, so the zero-dependency rule forces a hand-written decoder regardless of which upstream option is being replaced. See `STDLIB.md` for the full substitution table and `tests/negative/` for the suite proving the replacement enforces every check the original does.

## License

MIT — see `LICENSE`.
