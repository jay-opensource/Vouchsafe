# vouchsafe

Add passkey login to any application. One binary, no dependencies, no passwords stored — because there are none.

vouchsafe is a WebAuthn relying-party server: it lets an application replace passwords with fingerprint, face, or security-key login. It is **not** a password manager — it stores no secrets. Only public keys are kept, and the private key never leaves the authenticator's secure enclave. Steal the entire store file and you get nothing you can log in with.

## Quick start

```
go build ./cmd/vouchsafe
./vouchsafe serve
```

Open `http://localhost:8080/demo`, click Register, touch your sensor or security key. No certificate needed — browsers treat `localhost` as a secure context. For anything not on loopback, add `--tls` (a self-signed certificate is generated at startup; see Limits).

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

Login also works without a username: `POST /login/begin` with no `username` returns a `flowId` instead of `allowCredentials`, the browser shows every resident credential it holds for the origin, and the server reports back who logged in. The demo page's "Log in (usernameless)" button exercises this path.

## Managing credentials

Once logged in (holding the token from `/login/finish`), a caller can list or revoke their own credentials:

```
GET    /credentials              Authorization: Bearer <token>   -> [{id, algorithm, createdAt, aaguid, nickname}]
DELETE /credentials/{id}         Authorization: Bearer <token>   -> 204, or 404 if not found or not yours
```

Ownership is always resolved from the session token, never from anything in the URL or body — one user can't list or delete another's credential by guessing an ID. A registration can carry an optional `nickname` (e.g. "Touch ID on MacBook") for display in this list; it's purely cosmetic and plays no part in any security decision.

A single ceremony can also request a *stricter* UV policy than the server's configured default by sending `"uv": "required"` in `/register/finish` or `/login/finish` — it can only tighten the floor, never loosen it (see `policy.EffectivePolicy`).

## Frozen scope

**Signature algorithms** (all three land in Tier 1 for both registration and login):
- ES256 (ECDSA P-256 + SHA-256) — Apple, Android platform authenticators
- RS256 (RSASSA-PKCS1-v1_5 + SHA-256) — Windows Hello, most security keys
- EdDSA (Ed25519) — YubiKey 5 and similar. Verified directly against the message, never against a pre-hashed digest — Ed25519 does its own internal SHA-512-based hashing, unlike ECDSA/RSA.

**Attestation formats:**
- `none` — supported. What platform authenticators overwhelmingly return; most relying parties decline attestation for privacy reasons.
- `packed` — supported, both self-attestation (credential's own key signs the statement) and full attestation (a certificate in `x5c` signs it). The certificate is verified as a signer, not chained to a trust anchor — that needs the FIDO Metadata Service, a remote lookup that's permanently out of scope.
- Everything else (`tpm`, `android-key`, `android-safetynet`, `fido-u2f`, `apple`) — a named refusal, never a silent pass.

**Permanently out of scope:** FIDO Metadata Service lookups (needs a remote service), enterprise attestation, U2F/CTAP1 legacy compatibility, WebAuthn extensions beyond reading the ED flag, account recovery flows, a full user-management UI beyond credential list/revoke.

## Limits

- **Secure context required.** WebAuthn only works over HTTPS, or over plain HTTP on `localhost`/loopback. `--tls` generates a fresh self-signed certificate at startup and prints its SHA-256 fingerprint — meant for demos and judges reaching a non-loopback address, not for anything that needs a certificate trusted long-term. Without `--tls`, a non-loopback `--listen` address gets a startup warning instead.
- **Real-browser fixture testing is not yet done.** Every ceremony, security check, and the full negative-test suite (`tests/negative/`) are proven against a synthetic virtual-authenticator harness (`internal/webauthntest`) that generates real keys and real signatures, plus the actual compiled binary driven over real HTTP (`tests/e2e/`) — but no actual Touch ID, Windows Hello, or hardware security key has exercised this code yet, and the demo page's browser-side JavaScript has never run in a real browser. Do a real-hardware pass across at least Safari/Touch ID, Edge/Windows Hello, and a hardware key before relying on this in front of anyone.
- **Verification is fast; durability is what costs.** `go test -bench=. ./internal/ceremony/` shows raw signature verification at 26-62µs, but a full `Login()` call costs ~9ms — almost entirely the fsync'd atomic write `UpdateSignCount` performs on every login. That's the honest cost of a durable counter, not a slow verifier; see `BUILD.md`.

## Storage

`vouchsafe.json`, mode 0600 (POSIX systems), created atomically on every write. Holds public keys only — no passwords, no password hashes, no shared secrets.

## Prior art

Every Go WebAuthn library (`go-webauthn/webauthn`, `fxamacker/webauthn`, `duo-labs/webauthn`) depends on `fxamacker/cbor` — chosen, in the maintainers' own words, because it "doesn't crash" and is "the most well-tested CBOR library available," with 375+ tests and billions of fuzzing executions. Smaller pure-Go CBOR decoders exist too (`digitalbazaar/cbor`, `quartzjer/cb0r`) — all still third-party, so the zero-dependency rule forces a hand-written decoder regardless of which upstream option is being replaced. See `STDLIB.md` for the full substitution table and `tests/negative/` for the suite proving the replacement enforces every check the original does.

## License

MIT — see `LICENSE`.
