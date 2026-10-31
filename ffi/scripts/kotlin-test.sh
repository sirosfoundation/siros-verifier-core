#!/usr/bin/env bash
# Build the cdylib with the test-vector constructor, generate Kotlin bindings, run them on a JVM.
# Needs: Rust, JDK 21, a Gradle >= 8.11 (GRADLE=/path/to/gradle) and network for dependencies.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -p siros-verifier-core-ffi --features vector-tests
rm -rf kotlin-test/build/generated/bindings
cargo run -q -p siros-verifier-core-ffi --bin uniffi-bindgen -- \
  generate --library ../target/debug/libsiros_verifier_core_ffi.so --language kotlin \
  --out-dir kotlin-test/build/generated/bindings --no-format
cp ../tests/vectors/iso18013_annex_d5.json kotlin-test/src/test/resources/
cd kotlin-test
SIROS_VERIFIER_CORE_FFI_LIB_DIR="$PWD/../../target/debug" "${GRADLE:-gradle}" test --console=plain "$@"
