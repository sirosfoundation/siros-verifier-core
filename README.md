# siros-verifier-core

[![CI](https://github.com/sirosfoundation/siros-verifier-core/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/siros-verifier-core/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40sirosfoundation%2Fpresentation-flow)](https://www.npmjs.com/package/@sirosfoundation/presentation-flow)
[![License: BSD-2-Clause](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)

Reusable Rust building blocks and a deployable gateway for verifying digital
credential presentations. Use the complete OpenID4VP/OIDC service, embed the
sans-I/O verification crates, or integrate the browser and mobile adapters.

The core separates parsing, protocol checks, and cryptographic verification
from transport, storage, time, key management, and trust policy. **All issuer
and verifier trust decisions are delegated to a tenant-configured policy
decision point, normally [go-trust](https://github.com/sirosfoundation/go-trust),
over AuthZEN.**

## Supported verification flows

| Flow | Functionality |
| --- | --- |
| SD-JWT VC over OpenID4VP | Signed requests, redirect and W3C DC API handovers, encrypted responses, SD-JWT and key-binding verification, verified-claim extraction, and JWT status-list revocation checks |
| ISO/IEC 18013-5 mdoc | DeviceResponse verification, issuer and device authentication, reader sessions, and OpenID4VP or proximity engagement |
| `zkp_req` nym_auth | Pseudonym and `age_check` verification with native Longfellow and Vega backends, exact circuit pins, and verifier-scoped pseudonyms |
| TS 119 602 metadata | Schema and VCTM/MDDL parsing, SRI validation, and registry-backed DCQL preset generation |

BBS and predicate-only ZK requests are not part of the supported profile and
fail closed.

## Choose an integration

### 1. Deploy the verifier gateway

`siros-verifier-service` combines the tunnelbana OIDC frontend, OpenID4VP
backend, verifier UI, and native proof backends. It is the shortest path when
you need a relying-party-facing verification service rather than a library.

```sh
cargo build --release -p siros-verifier-service

TUNNELBANA_BIND=127.0.0.1:9001 \
  ./target/release/siros-verifier-service /path/to/proxy.toml
```

The service exposes `/health` and expects TLS to be terminated upstream. See
[the configuration guide](docs/CONFIGURATION.md) for signing keys, AuthZEN/PDP
settings, UI presets, ZK profiles, circuit pins, cookies, and storage.

For more than one service process, configure the shared MongoDB backend. It
provides atomic flow claims, replay protection, OIDC token-use storage, sealed
one-time results, and bounded retention across replicas. Use a MongoDB replica
set or managed HA service for database failover; the in-memory backend is only
for explicitly single-process deployments.

### 2. Embed the Rust libraries

| Crate | Use it for |
| --- | --- |
| `siros-verifier-core` | SD-JWT VC, mdoc, OpenID4VP, reader sessions, AuthZEN query construction, session sealing, decision receipts, and TS 119 602 metadata |
| `siros-verifier-zkp` | `zkp_req` validation, nym_auth transcripts and functions, circuit allowlists/catalog artifacts, and native Longfellow/Vega verification |
| `siros-verifier-core-tunnelbana` | The OpenID4VP backend and registry-driven UI adapter for a tunnelbana deployment |
| `siros-verifier-core-ffi` | UniFFI proximity-reader bindings for Kotlin and Swift applications |

The root and ZK crates are sans-I/O at their verification boundaries. An
embedding application supplies time, keys, transport, storage, and trust
verdicts. A typical OpenID4VP integration:

1. Constructs a request from verifier-owned DCQL, nonce, client identity, and
   signing key.
2. Sends it through the redirect or DC API channel and receives the encrypted
   wallet response.
3. Uses the core to authenticate the response and credential cryptography.
4. Sends the resulting AuthZEN query to go-trust and accepts the credential only
   when the PDP permits it.
5. Maps verified claims into its own identity or authorization model.

For ZK verification, register the native backends and keep circuit artifacts
behind an exact allowlist. Catalog artifacts are prefetched at startup and
checked by decompressed size and SHA-256; wallet requests never trigger catalog
network access. The catalog provides artifact integrity, not issuer or verifier
trust.

Start with the public modules in [`src/lib.rs`](src/lib.rs) and
[`zkp/src/lib.rs`](zkp/src/lib.rs), or follow the service composition in
[`service/src/main.rs`](service/src/main.rs).

### 3. Add the browser presentation UI

The independently published, dependency-free ES module provides preset and
attribute selection, editable DCQL, QR/direct-link/DC API invocation, status
polling, and result handling:

```sh
npm install @sirosfoundation/presentation-flow
```

```js
import { PresentationFlow } from "@sirosfoundation/presentation-flow";

const flow = new PresentationFlow({
  root: document.querySelector("#app"),
  presets: registryBackedPresets,
  invocations: ["qr", "dc-api", "link"],
  startPath: "/ui/start",
  tenant: "example-tenant",
});
```

Only the QR display is modal. Completion navigates to the verifier's complete
page, which shows a neutral spinner while pending and then the decoded verified
response or an error. The backend remains authoritative for DCQL validation,
request signing, trust, and verification. See the [package integration guide
and backend contract](tunnelbana-plugin/src/assets/README.md).

### 4. Build a proximity reader with UniFFI

The FFI `Reader` accepts whole CBOR messages and leaves BLE/NFC transport to the
application:

1. `Reader.start(deviceEngagement, handover)` establishes the reader session
   with the default `pid-provider` role; `Reader.startWithRole` selects an
   explicit mdoc issuer role. `nfcHandoverCbor(select, request)` encodes static
   or negotiated NFC handovers.
2. `establishmentMessageFromDocuments` and `dataMessageFromDocuments`
   atomically build and encrypt ordered DocumentRequests and retain their
   response policy. For ReaderAuth, supply the leaf-first certificate chain and
   a `ReaderAuthSigner` callback; the host signs the exact COSE input with its
   long-term P-256 key and returns raw `r || s`. The ephemeral session key
   remains inside Rust. The separate `buildDeviceRequest` and raw message
   methods remain available for compatibility.
3. `openResponse(sessionData, now, acceptedDocTypes)` decrypts and verifies the
   DeviceResponse. For an atomic request it also enforces all requested document
   types, namespaces, and elements while allowing extra disclosed claims.
4. The application submits each document's AuthZEN request to its PDP and uses
   the returned elements only after a permit decision.

See [`ffi/src/lib.rs`](ffi/src/lib.rs) for the exported API,
[`ffi/README.md`](ffi/README.md) for Android AAR and iOS XCFramework packaging,
and [`ffi/scripts/kotlin-test.sh`](ffi/scripts/kotlin-test.sh) for the
native/Kotlin test setup.

## Trust and security boundary

Cryptographic validity is not a trust decision. The verifier can establish that
a presentation is intact and signed by a key; go-trust decides whether that key,
issuer, verifier, role, and credential type are acceptable for the tenant.

Keep request signing keys and session-sealing keys in a secret manager, use a
dedicated verifier identity, and pin ZK artifacts exactly. `zkp_req` commonly
uses an `x509_san_dns` verifier identity; other formats retain `x509_hash`.
Response bodies, decrypted plaintext, artifacts, metadata, and protocol parsers
are bounded, and flow completion and result collection are replay-protected.

## Build and test

The workspace uses stable Rust. Production builds have no default core
features; issuer and wallet simulators are opt-in through `testutil`.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
python3 scripts/mutate.py
scripts/audit.sh
npm test --prefix tunnelbana-plugin/src/assets
```

To exercise the MongoDB contract against a real server:

```sh
SIROS_VERIFIER_TEST_MONGODB_URI=mongodb://127.0.0.1:27017 \
  cargo test --workspace --all-features
```

Additional parser fuzz and Kotlin interoperability checks are documented in
[`fuzz/README.md`](fuzz/README.md) and [`AGENTS.md`](AGENTS.md).

## License

BSD-2-Clause. See [LICENSE](LICENSE).
