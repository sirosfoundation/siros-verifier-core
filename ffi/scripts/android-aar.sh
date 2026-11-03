#!/usr/bin/env bash
# Build release Android libraries and package them with generated Kotlin bindings as an AAR.
set -euo pipefail
export LC_ALL=C
export TZ=UTC
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

FFI_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
ROOT=$(cd "$FFI_DIR/.." && pwd -P)
if (( $# > 1 )); then
    echo "usage: $0 [output-directory]" >&2
    exit 2
fi
OUTPUT_DIR=${1:-"$FFI_DIR/dist/android"}
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd -P)
TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target}
WORK="$TARGET_DIR/native-packaging/android"
PACKAGE=siros-verifier-core-ffi
VERSION=$(cargo metadata --locked --no-deps --format-version 1 --manifest-path "$ROOT/Cargo.toml" \
    | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "siros-verifier-core-ffi"))')
LIBRARY=libsiros_verifier_core_ffi.so
NDK=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}
API=${ANDROID_API:-23}

if [[ -z "$NDK" || ! -d "$NDK" ]]; then
    echo "Set ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) to an existing Android NDK." >&2
    exit 1
fi
if [[ ! "$API" =~ ^[0-9]+$ ]] || (( API < 1 )); then
    echo "ANDROID_API must be a positive integer (got $API)." >&2
    exit 1
fi
HOST_TAG=${ANDROID_NDK_HOST_TAG:-}
if [[ -z "$HOST_TAG" ]]; then
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64) HOST_TAG=linux-x86_64 ;;
        Darwin-*) HOST_TAG=darwin-x86_64 ;;
        *) echo "Set ANDROID_NDK_HOST_TAG for this host." >&2; exit 1 ;;
    esac
fi
PREBUILT="$NDK/toolchains/llvm/prebuilt/$HOST_TAG"
if [[ ! -d "$PREBUILT/bin" ]]; then
    echo "Android NDK LLVM tools not found at $PREBUILT." >&2
    exit 1
fi
KOTLINC=${KOTLINC:-$(command -v kotlinc || true)}
if [[ -z "$KOTLINC" || ! -x "$KOTLINC" ]]; then
    echo "Set KOTLINC to a local Kotlin compiler executable; this script installs no tools." >&2
    exit 1
fi
JNA_JAR=${JNA_JAR:-}
if [[ -z "$JNA_JAR" || ! -f "$JNA_JAR" ]]; then
    echo "Set JNA_JAR to a local net.java.dev.jna:jna:5.14.0 JAR." >&2
    exit 1
fi
KOTLIN_STDLIB_JAR=${KOTLIN_STDLIB_JAR:-}
if [[ -z "$KOTLIN_STDLIB_JAR" || ! -f "$KOTLIN_STDLIB_JAR" ]]; then
    echo "Set KOTLIN_STDLIB_JAR to the Kotlin standard-library JAR matching KOTLINC." >&2
    exit 1
fi
for tool in cargo python3; do
    command -v "$tool" >/dev/null || { echo "Required tool not found: $tool" >&2; exit 1; }
done

rm -rf "$WORK"
mkdir -p "$WORK/kotlin" "$WORK/classes" "$WORK/aar/jni"
TARGETS=(aarch64-linux-android armv7-linux-androideabi x86_64-linux-android)
FIRST_LIBRARY=
for target in "${TARGETS[@]}"; do
    case "$target" in
        aarch64-linux-android)
            abi=arm64-v8a
            clang=aarch64-linux-android
            linker_var=CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER
            rustflags_var=CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS
            ;;
        armv7-linux-androideabi)
            abi=armeabi-v7a
            clang=armv7a-linux-androideabi
            linker_var=CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER
            rustflags_var=CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_RUSTFLAGS
            ;;
        x86_64-linux-android)
            abi=x86_64
            clang=x86_64-linux-android
            linker_var=CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER
            rustflags_var=CARGO_TARGET_X86_64_LINUX_ANDROID_RUSTFLAGS
            ;;
        *) echo "Unsupported target: $target" >&2; exit 1 ;;
    esac
    CC="$PREBUILT/bin/$clang$API-clang"
    if [[ ! -x "$CC" ]]; then
        echo "Android compiler not found: $CC" >&2
        exit 1
    fi
    (
        cd "$ROOT"
        env "$linker_var=$CC" \
            "$rustflags_var=-C link-arg=-Wl,-z,max-page-size=16384" \
            cargo build --locked --release --no-default-features \
            --target "$target" --target-dir "$TARGET_DIR" -p "$PACKAGE"
    )
    library="$TARGET_DIR/$target/release/$LIBRARY"
    alignments=$("$PREBUILT/bin/llvm-readelf" -lW "$library" | awk '/LOAD/{print $NF}')
    if [[ -z "$alignments" ]]; then
        echo "No LOAD segments found in $library" >&2
        exit 1
    fi
    for alignment in $alignments; do
        if (( alignment < 16384 )); then
            echo "$library is not 16 KB-page-aligned (LOAD alignment $alignment)." >&2
            exit 1
        fi
    done
    if [[ -z "$FIRST_LIBRARY" ]]; then
        FIRST_LIBRARY=$library
    fi
    mkdir -p "$WORK/aar/jni/$abi"
    cp "$library" "$WORK/aar/jni/$abi/$LIBRARY"
done

# Use this crate's bindgen binary and a just-built library from the same checkout.
(
    cd "$ROOT"
    cargo run --locked --no-default-features --target-dir "$TARGET_DIR" \
        -p "$PACKAGE" --bin uniffi-bindgen -- \
        generate --library "$FIRST_LIBRARY" --language kotlin \
        --out-dir "$WORK/kotlin" --no-format
)
KOTLIN_SOURCES=()
while IFS= read -r source; do
    KOTLIN_SOURCES+=("$source")
done < <(find "$WORK/kotlin" -type f -name '*.kt' -print | sort)
if (( ${#KOTLIN_SOURCES[@]} == 0 )); then
    echo "UniFFI did not generate Kotlin sources." >&2
    exit 1
fi
"$KOTLINC" -no-stdlib -no-reflect -jvm-target 1.8 \
    -classpath "$JNA_JAR:$KOTLIN_STDLIB_JAR" \
    -d "$WORK/classes" "${KOTLIN_SOURCES[@]}"
python3 "$FFI_DIR/scripts/zip-directory.py" "$WORK/aar/classes.jar" "$WORK/classes"
cat > "$WORK/aar/AndroidManifest.xml" <<EOF
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.sirosfoundation.verifiercore">
    <uses-sdk android:minSdkVersion="$API" />
</manifest>
EOF
python3 "$FFI_DIR/scripts/zip-directory.py" "$WORK/$PACKAGE.aar" "$WORK/aar"

cat > "$WORK/$PACKAGE-$VERSION.pom" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.siros</groupId>
  <artifactId>$PACKAGE</artifactId>
  <version>$VERSION</version>
  <packaging>aar</packaging>
  <name>SIROS verifier core FFI</name>
  <description>Native proximity Reader and generated Kotlin bindings.</description>
  <licenses><license><name>BSD-2-Clause</name><url>https://opensource.org/license/bsd-2-clause/</url></license></licenses>
  <dependencies>
    <dependency><groupId>net.java.dev.jna</groupId><artifactId>jna</artifactId><version>5.14.0</version><type>aar</type></dependency>
  </dependencies>
</project>
EOF

cp "$WORK/$PACKAGE.aar" "$OUTPUT_DIR/$PACKAGE.aar"
cp "$WORK/$PACKAGE.aar" "$OUTPUT_DIR/$PACKAGE-$VERSION.aar"
cp "$WORK/$PACKAGE-$VERSION.pom" "$OUTPUT_DIR/$PACKAGE-$VERSION.pom"
rm -rf "$OUTPUT_DIR/kotlin"
cp -R "$WORK/kotlin" "$OUTPUT_DIR/kotlin"
printf 'AAR: %s\nPOM: %s\nKotlin bindings: %s\n' \
    "$OUTPUT_DIR/$PACKAGE-$VERSION.aar" "$OUTPUT_DIR/$PACKAGE-$VERSION.pom" "$OUTPUT_DIR/kotlin"
