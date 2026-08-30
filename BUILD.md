# BUILD.md

## Single-command build

```
go build ./cmd/vouchsafe
```

Produces `vouchsafe` (or `vouchsafe.exe` on Windows) in the working directory. No build tool, no code generation step, no network access required — `go.mod` has no `require` block, so there is nothing for `go build` to fetch.

## Verifying the empty dependency graph

```
go list -m all      # prints only the module itself
go mod graph         # prints only the module and the Go toolchain version
```

See `deps-proof.txt` for committed output.

## CGO_ENABLED=0

```
CGO_ENABLED=0 go build -o vouchsafe ./cmd/vouchsafe
```

Builds identically — nothing in this codebase touches cgo. This is a demonstration, not a required flag: unlike a project wrapping a C library, there is no native toolchain dependency here to disable.

## Reproducible build flags

```
go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o vouchsafe ./cmd/vouchsafe
```

- `-trimpath` — strips local filesystem paths from the binary
- `-buildvcs=false` — omits embedded VCS metadata (commit hash, dirty state)
- `-ldflags="-s -w -buildid="` — strips symbol table, DWARF debug info, and the build ID, all of which otherwise vary between otherwise-identical builds

Building reproducibly is good practice here, but **this project claims exactly one bonus: Package Killer** (see `.zero-dep.toml` and `STDLIB.md`). Bonuses don't stack under the event's rules — reproducible-build flags are not a second bonus claim.

## Running tests

```
go build ./...
go vet ./...
go test ./...                                   # unit + integration, ~250 tests
go test -run FuzzDecode -fuzz=FuzzDecode -fuzztime=30s ./internal/cbor/
go test ./tests/negative/...                     # the §9.3 negative-test suite alone
go test ./tests/e2e/...                          # builds and runs the real binary as a subprocess
go test -short ./...                             # skips the real-binary e2e test for fast iteration
```

## Benchmark

```
go test -bench=. -benchmem ./internal/ceremony/
```

Two sets, published together deliberately: `BenchmarkVerifySignatureOnly_*` isolates raw
cryptographic verification (no store I/O), `BenchmarkLogin_*` measures the full ceremony.
On the reference machine (11th Gen Intel i5-11400H):

```
BenchmarkLogin_ES256-12                  130    9104563 ns/op   14941 B/op   114 allocs/op
BenchmarkLogin_RS256-12                  130    9085998 ns/op   17103 B/op   105 allocs/op
BenchmarkLogin_EdDSA-12                  133    9016225 ns/op   13285 B/op    93 allocs/op
BenchmarkVerifySignatureOnly_ES256-12  19338      61643 ns/op     576 B/op    10 allocs/op
BenchmarkVerifySignatureOnly_RS256-12  45493      26281 ns/op    1376 B/op     9 allocs/op
BenchmarkVerifySignatureOnly_EdDSA-12  29152      41544 ns/op       0 B/op     0 allocs/op
```

The honest number: signature verification alone costs 26-62µs regardless of algorithm, but a
full `Login()` call costs ~150-300x more, at ~9ms — almost entirely the fsync'd atomic file
write `store.UpdateSignCount` performs on every successful login (§7 `internal/store`). That's
the real cost of a durable counter update, not a slow verifier. A deployment that needed
higher login throughput would batch or relax that write, not optimize the cryptography.
