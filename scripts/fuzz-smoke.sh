#!/usr/bin/env bash
# Short, deterministic-start smoke runs for every parser target, not a substitute for long fuzzing.
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target/fuzz}"
# libFuzzer adds newly discovered inputs to its corpus. Use a scratch copy so
# the committed seeds stay small and reviewable.
CORPUS="$CARGO_TARGET_DIR/corpus"
rm -rf "$CORPUS"
mkdir -p "$CORPUS"
cp -a fuzz/corpus/. "$CORPUS/"
RUNS="${FUZZ_RUNS:-1000}"
# cargo-fuzz otherwise defaults to musl on Linux; use the host GNU target so
# ASan works with the runner's standard C library (and without -crt-static).
FUZZ_TARGET="${CARGO_FUZZ_TARGET:-x86_64-unknown-linux-gnu}"
for target in mdoc_response mdoc_session sdjwt oid4vp_jwe; do
  echo "=== fuzz $target ($RUNS runs) ==="
  cargo +nightly fuzz run "$target" "$CORPUS/$target" --target "$FUZZ_TARGET" -- \
    -runs="$RUNS" -max_len=65536 -timeout=5 -rss_limit_mb=2048
done
