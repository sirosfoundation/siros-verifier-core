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
for target in mdoc_response mdoc_session sdjwt oid4vp_jwe; do
  echo "=== fuzz $target ($RUNS runs) ==="
  cargo +nightly fuzz run "$target" "$CORPUS/$target" -- \
    -runs="$RUNS" -max_len=65536 -timeout=5 -rss_limit_mb=2048
done
