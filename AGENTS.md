# Agent guide: siros-verifier-core

## Scope and invariants

This workspace contains a sans-I/O verification core, UniFFI and tunnelbana adapters, the HTTP service, and native Longfellow/Vega nym_auth backends. Keep changes small and protocol-specific.

- **go-trust makes every issuer and verifier trust decision, including status-list signer trust.** Never create a parallel trust decision in Rust, the circuit catalog, the UI, or deployment fixtures.
- The circuit catalog supplies artifacts only. Enforce exact allowlist parameters and decompressed hash/size; startup prefetch must not become request-time network I/O.
- Keep SD-JWT and mdoc dispatch intact when adding formats. A flow selects its verifier from its own validated DCQL and sealed session.
- Do not take the verifier's statement from wallet input. Transcript, nonce, verifier identity, age bounds, and acceptable issuer keys are verifier-owned; the pseudonym is an output.
- Use dedicated verifier signing keys, not an issuer key. `zkp_req` normally uses `x509_san_dns`; other formats retain `x509_hash`.
- Preserve strict JSON/CBOR parsing, bounded bodies/artifacts/responses, replay protection, and sealed session state.

## Read first

- `docs/CONFIGURATION.md` for the complete service schema and the canonical TOML files under `fixtures/siros-verifier/`.
- `src/oid4vp.rs` for request/response policy, handovers, and bounded ECDH-ES decryption.
- `src/mdoc_request.rs` for ordered DeviceRequest construction and ReaderAuth; `src/mdoc_session.rs` for QR/NFC handover and transport-independent session messages.
- `src/status_list.rs` for sans-I/O JWT status-list verification; the tunnelbana adapter owns bounded fetching and go-trust signer evaluation.
- `zkp/src/verify.rs` for the two-phase response/trust/proof flow.
- `zkp/src/circuits.rs` and `zkp/src/catalog.rs` for artifact integrity and startup prefetch.
- `tunnelbana-plugin/src/lib.rs` for per-flow dispatch and independently validated ZK profiles.
- `service/src/config.rs` and `service/src/main.rs` for deployment-only schema and backend factories.

## Configuration rules

- Prefer `[[backend.config.zkp.profiles]]` for multiple nym_auth presets. The legacy single `query` form remains supported. Duplicate byte-equivalent queries are a startup error; sharing a query ID with different function lists is valid.
- UI and backend queries must match exactly, including result handles, age bounds, and attribute mapping. `subject_handle` must name a pseudonym function.
- Use exactly one of `artifact_path` and `artifact_id`. Hash/size always mean decompressed bytes. Vega entries reject Longfellow parameters.
- `request_uri_method = "post"` must echo the wallet's posted `wallet_nonce` in a re-signed request object and require exactly one valid form field at retrieval. GET remains the default and is always available alongside POST.
- Use `api.circuits.siros.org` for the API. `circuits.siros.org` is only the human site.
- Registry presets merge by format and type. A default claim subset must be answerable by the intended wallet; the first claim becomes the subject when no pointer is configured.
- Only the QR display is modal. Do not reintroduce appended QR sections or result modals. Completion navigates to the complete page, which shows a neutral spinner while pending and then the decoded response or an error.

## Build and test

Run all checks before committing:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
scripts/audit.sh
python3 scripts/mutate.py
```

Also run format-specific checks after relevant changes:

```sh
cargo test -p siros-verifier-zkp --test longfellow_native
cargo test -p siros-verifier-zkp --test vega_native
cargo test -p siros-verifier-core-tunnelbana --test zkp_flow
cargo test -p siros-verifier-core --test mdoc_request
cargo test -p siros-verifier-core-ffi --all-features
ffi/scripts/kotlin-test.sh
cargo test -p siros-verifier-zkp --test catalog the_live_siros_nymauth_circuit_matches_the_native_test_vector -- --ignored
npm test --prefix tunnelbana-plugin/src/assets
```

`scripts/mutate.py` disables each security check and requires a test to fail. If you refactor a checked expression, update its anchor rather than deleting the mutant or weakening the test. CI fails on missing anchors and surviving mutants.

Native tests use genuine proof vectors and negative mutations. Do not replace them with a model circuit. Model backends are only for dispatch and error-path tests.

## Integration recipe

1. Put deployment-only settings in `service/src/config.rs`; do not leak them into the sans-I/O core.
2. Register native backends through `BackendRegistry` and the existing `ProofBackend` trait. Do not bypass `check_claimed`, issuer-set policy, or go-trust.
3. Keep catalog and file sources behind `ArtifactSource`; production uses startup `prefetch`.
4. Add UI/backend profiles together and validate each plan at construction. Reject unknown systems and unsupported functions at startup.
5. Keep proximity transport and NDEF parsing in the application. Use `kryptering::Signer` for the reader's long-term ReaderAuth key, never the ephemeral session key; sign exact tag-24 values and preserve their bytes. Do not hold the FFI session lock during a foreign signing callback.
6. Add positive and negative tests, including public-input mutations and refusal codes. Update `docs/CONFIGURATION.md` for any schema change and this file for changed workflows.

## Releases

Use organization-wide workflows where they exist:

- Docker: `sirosfoundation/.github/.github/workflows/docker-build-push.yml`.
- SBOM: `sirosfoundation/.github/.github/workflows/sbom.yml`.
- Integration builds: `sirosfoundation/.github/.github/workflows/integration-build.yml`.

Release artifacts include the GHCR image and digest, crates.io packages, SBOM, vulnerability results, checksums, and provenance. Never invent an SBOM workflow when the reusable one exists.

Crates.io requires registry versions for every non-dev dependency. Do not tag a library release until those dependencies are published and `cargo package` succeeds for every public crate. Git revisions remain pinned for reproducible development; Cargo replaces them with registry versions when packaging.

See `docs/RELEASING.md` for dependency prerequisites, trusted-publisher configuration, publication order, and post-release verification. Tag `v0.1.0` only after full CI, live Longfellow and Vega verification, packaging checks, and documentation pass. Do not run `git commit`, `git push`, `git rebase`, `git reset`, or create a tag unless the user explicitly approved that operation.

## Common pitfalls

- `presentation_not_base64url` can mean an input exceeded the matcher's response budget, not malformed encoding. Check the actual token size before changing protocol code.
- Actix's body limit and jose-rs's compact-token default are different limits. Test both with genuine large responses.
- URI SAN identifies an mdoc issuer for go-trust; a leaf hash is only the fallback when no SAN identity exists.
- A valid credential can fail to match if the query requests claims it does not contain or uses the wrong result handle. Inspect the actual query and wallet claims.
- A new image is not a new trust decision. Keep go-trust configuration and verifier signing identity aligned when a leaf is reissued.
