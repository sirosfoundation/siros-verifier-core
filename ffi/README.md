# Native FFI integration

`siros-verifier-core-ffi` exposes the proximity reader as UniFFI objects and
records. The application owns BLE/NFC transport and go-trust communication.

## Reader policy and trust evidence

- `Reader.start(deviceEngagement, handover)` retains the compatibility-default
  `pid-provider` mdoc issuer role.
- `Reader.startWithRole(deviceEngagement, handover, mdocIssuerRole)` selects a
  verifier-owned role. Roles must be non-empty, have no surrounding whitespace,
  and contain no control characters.
- `establishmentMessageFromDocuments(documents)` and
  `dataMessageFromDocuments(documents)` build and encrypt a DeviceRequest and
  retain its response policy in one operation. `openResponse` then requires
  every requested document type, namespace, and element in addition to the
  caller's `acceptedDocTypes` and cryptographic verification. Extra disclosed
  claims are allowed, and no claims are returned when policy checking fails.
- The separate `buildDeviceRequest` plus `establishmentMessage`/`dataMessage`
  path remains available with its legacy `acceptedDocTypes`-only response
  policy. Sending a raw request clears any policy retained by an earlier
  atomic request.

The role only populates AuthZEN evidence. It does not make a trust decision:
the application must submit `authzenRequestJson` to go-trust and use verified
claims only after a permit decision.

## Android AAR

`scripts/android-aar.sh [output-directory]` builds release `cdylib` libraries
for `arm64-v8a`, `armeabi-v7a`, and `x86_64`, generates Kotlin bindings from the
same checkout, compiles them, and writes:

- `siros-verifier-core-ffi.aar`, containing the native libraries, manifest, and
  compiled bindings in `classes.jar`;
- versioned AAR and POM files for Maven publication or a local Maven directory;
- `kotlin/`, the generated Kotlin source for inspection or source-based builds.

The default output is `ffi/dist/android`. Required local tools and settings:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
export ANDROID_NDK_HOME=/path/to/android-ndk
export KOTLINC=/path/to/kotlinc                 # Kotlin 2.1.0 recommended
export JNA_JAR=/path/to/jna-5.14.0.jar
export KOTLIN_STDLIB_JAR=/path/to/kotlin-stdlib-2.1.0.jar
ffi/scripts/android-aar.sh /path/to/output
```

`ANDROID_API` defaults to 23. `ANDROID_NDK_HOST_TAG` can override NDK host
auto-detection. Every native library is linked and checked for 16 KB LOAD-segment
alignment. The script does not install tools or dependencies. AAR consumers
must also provide the Kotlin standard library and `net.java.dev.jna:jna:5.14.0`.

## iOS XCFramework

Run `scripts/ios-xcframework.sh [output-directory]` on macOS with Xcode. It
builds release `staticlib` libraries for ARM64 devices and ARM64/x86_64
simulators, generates Swift bindings and C metadata from the same checkout,
and writes `SirosVerifierCore.xcframework` plus `swift/` containing the
high-level Swift source. The default output is `ffi/dist/ios`.

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
ffi/scripts/ios-xcframework.sh /path/to/output
```

Add both the XCFramework and generated Swift source to the Apple target.

Both packaging scripts use `--locked`, `--release`, and `--no-default-features`;
they never enable the test-only `vector-tests` feature. They use the crate's own
`uniffi-bindgen` binary rather than a globally installed version. AAR ZIP members
are sorted and have fixed timestamps. For byte-for-byte reproducibility, use
identical Rust, NDK/Xcode, Kotlin, and dependency versions and the same source
revision. `SOURCE_DATE_EPOCH` defaults to zero and can be overridden.
