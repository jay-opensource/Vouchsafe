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
go test ./...                                   # unit + integration, ~220 tests
go test -run FuzzDecode -fuzz=FuzzDecode -fuzztime=30s ./internal/cbor/
go test ./tests/negative/...                     # the §9.3 negative-test suite alone
go test ./tests/e2e/...                          # builds and runs the real binary as a subprocess
go test -short ./...                             # skips the real-binary e2e test for fast iteration
```
