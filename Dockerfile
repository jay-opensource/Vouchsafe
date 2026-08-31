# syntax=docker/dockerfile:1
#
# Three targets in one file:
#   docker build -t vouchsafe .                        -> runtime image (default)
#   docker build --target test -t vouchsafe-test .      -> vet + full suite + race detector;
#                                                          the build itself FAILS if anything fails
#   docker build --target builder -t vouchsafe-build .  -> just the compiled binary, nothing else
#
# This is the answer for anyone (Windows included) who wants to build,
# fully verify (including -race, which needs a C compiler this project
# itself has none of), or run vouchsafe without installing Go, a C
# toolchain, or anything else locally.

# ---- builder: compiles the static binary ----
FROM golang:1.25 AS builder
WORKDIR /src

# go.mod has no require block, so there is nothing to download here —
# this step exists so Docker's layer cache still separates
# "module setup" from "source changed", same as any Go project.
COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vouchsafe ./cmd/vouchsafe

# ---- test: vet + the full suite + the race detector ----
# `docker build --target test .` runs this stage. Any failing command
# aborts the build with that command's output — no separate "did it
# pass" step needed, a green build IS the passing result.
FROM builder AS test
RUN go vet ./...
RUN gofmt -l . | tee /tmp/gofmt.out && test ! -s /tmp/gofmt.out
RUN go test -count=1 ./...
RUN go test -race ./...
RUN go test -run FuzzDecode -fuzz=FuzzDecode -fuzztime=20s ./internal/cbor/

# ---- runtime: just the static binary, nothing else ----
# CGO_ENABLED=0 above means this binary has no shared-library
# dependencies at all, so scratch — a genuinely empty base image — is
# enough to run it. No shell, no package manager, no CVEs from an OS
# this project never needed.
FROM scratch AS runtime
COPY --from=builder /out/vouchsafe /vouchsafe
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["/vouchsafe", "serve"]
CMD ["--listen", "0.0.0.0:8080", "--origin", "http://localhost:8080", "--store", "/data/vouchsafe.json"]
