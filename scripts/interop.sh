#!/usr/bin/env bash
# Cross-implementation checks against go-jose and SUNET/vc (read-only use of ../vc).
#   scripts/interop.sh gen     regenerate tests/vectors (Go -> Rust), then run cargo test
#   scripts/interop.sh         Rust -> Go: emit vectors from Rust and verify them in Go
set -euo pipefail
cd "$(dirname "$0")/.."
export GOWORK=off GOFLAGS=-mod=mod
if [ "${1:-}" = "gen" ]; then
  (cd tools/interop-go && go run . gen)
  cargo test --features testutil --test interop
else
  cargo run --quiet --features testutil --example emit_vectors
  (cd tools/interop-go && go run . verify)
fi
