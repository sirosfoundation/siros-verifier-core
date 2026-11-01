# siros-verifier-core

[![CI](https://github.com/sirosfoundation/siros-verifier-core/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/siros-verifier-core/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40sirosfoundation%2Fpresentation-flow)](https://www.npmjs.com/package/@sirosfoundation/presentation-flow)
[![License: BSD-2-Clause](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)

A Rust digital-credential verifier core with native and gateway adapters. The
core is sans-I/O: parsing, protocol checks, and cryptographic verification are
kept separate from transport, storage, time, key management, and issuer-trust
policy. Issuer trust is delegated to a tenant-configured policy decision point,
normally [go-trust](https://github.com/sirosfoundation/go-trust), over AuthZEN.

This repository is being productized from the `vp-spike` experiments. It is not
production-ready yet.

## Components

- Root crate (`siros-verifier-core`): SD-JWT VC and mdoc OpenID4VP with the
  distinct redirect/DC API handovers, ISO 18013-5 reader sessions, mdoc
  DeviceResponse verification, and signed decision receipts.
- `ffi/` (`siros-verifier-core-ffi`): UniFFI facade for proximity-reader
  applications. BLE and NFC transport remain application responsibilities.
- `tunnelbana-plugin/` (`siros-verifier-core-tunnelbana`): OpenID4VP verifier
  backend for tunnelbana, intended for the gateway/OIDC/wallet flow.
- `service/` (`siros-verifier-service`): Actix gateway with a real OIDC frontend
  and a self-contained verifier UI offering QR-code and W3C DC API presentations
  plus a verified-claims result page.
- `zkp/` (`siros-verifier-zkp`): `zkp_req` response validation, nym_auth
  transcripts and predicates, issuer-set trust policy, and a real Longfellow
  proof backend. Vega and BBS are not enabled.
- `src/ts11.rs`: sans-I/O TS 119 602 schema parsing, VCTM/MDDL metadata
  extraction, SRI validation, and registry-backed DCQL preset generation. The
  tunnelbana adapter adds bounded HTTPS fetching and last-known-good caching.
- `tunnelbana-plugin/src/assets/presentation-flow.js`: independently publishable
  ES module for registry-driven request editing, configurable presets, QR,
  direct-link and inline DC API invocation, backend/tenant binding, and an async
  result/error API. See the package README and Node tests in that directory.

The initial operational target is an end-to-end gateway flow using the SIROS SDK
sample wallet, deployed through `sirosid-dev`. The gateway supports shared
MongoDB flow/replay storage with atomic response claims, sealed sessions and
results, one-time collection, and bounded retention. Single-process memory
storage remains available only through explicit configuration. Database
failover itself requires a MongoDB replica set or managed HA service.
`zkp_req` currently supports `mso_mdoc` nym_auth with the Longfellow proof
system, pseudonym and `age_check`. Vega, BBS, and predicate-only requests remain
outside the supported profile and fail closed.

## Build and test

The workspace uses stable Rust. Production builds have no default core features;
test simulators are opt-in through `testutil`.

```sh
cargo build --workspace
cargo test --workspace --all-features
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Also exercise the MongoDB contract against a real server.
SIROS_VERIFIER_TEST_MONGODB_URI=mongodb://127.0.0.1:27017 \
  cargo test --workspace --all-features
```

Additional checks:

```sh
# Mutation-check the security rules.
python3 scripts/mutate.py

# RustSec advisories, dependency policy, licenses, and sources.
scripts/audit.sh

# Short fuzz smoke runs for CBOR, SD-JWT, and OpenID4VP JWE parsers.
# Requires a nightly Rust toolchain and cargo-fuzz.
scripts/fuzz-smoke.sh

# Run the generated Kotlin bindings against the real native library.
# Requires JDK 21 and Gradle 8.11 or newer.
ffi/scripts/kotlin-test.sh

# Cross-check against go-jose and SUNET/vc. Requires a sibling ../vc checkout.
scripts/interop.sh gen
scripts/interop.sh
```

See [fuzz/README.md](fuzz/README.md) for the fuzz targets and seed-generation
commands, and [deny.toml](deny.toml) for the narrowly scoped advisory exceptions.

See [FINDINGS.md](FINDINGS.md) for the spike evidence, interoperability results,
known gaps, and upstream references. The findings are historical evidence, not a
claim that those gaps have all been resolved in this workspace.

## License

BSD-2-Clause. See [LICENSE](LICENSE).
