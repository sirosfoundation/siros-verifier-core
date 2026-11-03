#!/usr/bin/env bash
# Build release iOS static libraries and package them with generated Swift bindings.
set -euo pipefail
export LC_ALL=C
export TZ=UTC
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
export ZERO_AR_DATE=1

FFI_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
ROOT=$(cd "$FFI_DIR/.." && pwd -P)
if (( $# > 1 )); then
    echo "usage: $0 [output-directory]" >&2
    exit 2
fi
OUTPUT_DIR=${1:-"$FFI_DIR/dist/ios"}
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd -P)
TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target}
WORK="$TARGET_DIR/native-packaging/ios"
PACKAGE=siros-verifier-core-ffi
LIBRARY=libsiros_verifier_core_ffi.a
FRAMEWORK=SirosVerifierCore.xcframework

if [[ "$(uname -s)" != Darwin ]]; then
    echo "iOS XCFramework packaging requires macOS with Xcode; no files were built." >&2
    exit 1
fi
for tool in cargo xcodebuild lipo; do
    command -v "$tool" >/dev/null || { echo "Required tool not found: $tool" >&2; exit 1; }
done

rm -rf "$WORK"
mkdir -p "$WORK/swift" "$WORK/headers" "$WORK/simulator"
TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)
for target in "${TARGETS[@]}"; do
    (
        cd "$ROOT"
        cargo build --locked --release --no-default-features \
            --target "$target" --target-dir "$TARGET_DIR" -p "$PACKAGE"
    )
done

DEVICE_LIBRARY="$TARGET_DIR/aarch64-apple-ios/release/$LIBRARY"
# Generate Swift and C metadata from a static library built from this checkout.
(
    cd "$ROOT"
    cargo run --locked --no-default-features --target-dir "$TARGET_DIR" \
        -p "$PACKAGE" --bin uniffi-bindgen -- \
        generate --library "$DEVICE_LIBRARY" --language swift \
        --out-dir "$WORK/swift" --no-format
)
HEADER="$WORK/swift/siros_verifier_core_ffiFFI.h"
MODULE_MAP="$WORK/swift/siros_verifier_core_ffiFFI.modulemap"
SWIFT_SOURCE="$WORK/swift/siros_verifier_core_ffi.swift"
for file in "$HEADER" "$MODULE_MAP" "$SWIFT_SOURCE"; do
    if [[ ! -f "$file" ]]; then
        echo "Expected UniFFI output not found: $file" >&2
        exit 1
    fi
done
cp "$HEADER" "$WORK/headers/"
cp "$MODULE_MAP" "$WORK/headers/module.modulemap"
lipo -create \
    "$TARGET_DIR/aarch64-apple-ios-sim/release/$LIBRARY" \
    "$TARGET_DIR/x86_64-apple-ios/release/$LIBRARY" \
    -output "$WORK/simulator/$LIBRARY"
xcodebuild -create-xcframework \
    -library "$DEVICE_LIBRARY" -headers "$WORK/headers" \
    -library "$WORK/simulator/$LIBRARY" -headers "$WORK/headers" \
    -output "$WORK/$FRAMEWORK"

rm -rf "$OUTPUT_DIR/$FRAMEWORK"
cp -R "$WORK/$FRAMEWORK" "$OUTPUT_DIR/$FRAMEWORK"
rm -rf "$OUTPUT_DIR/swift"
mkdir -p "$OUTPUT_DIR/swift"
cp "$SWIFT_SOURCE" "$OUTPUT_DIR/swift/"
printf 'XCFramework: %s\nSwift bindings: %s\n' \
    "$OUTPUT_DIR/$FRAMEWORK" "$OUTPUT_DIR/swift"
