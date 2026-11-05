# Agent guide: siros-verifier-core

## Scope and invariants

This workspace contains the sans-I/O verification core, UniFFI and tunnelbana
adapters, the HTTP service, and native Longfellow/Vega nym_auth backends. Keep
changes small and protocol-specific.

- **The core owns protocol and verification logic.** Request construction,
  matching, transcript binding, disclosure checks, proof verification and
  response construction have one implementation. UI, tunnelbana, native mobile
  adapters and deployment fixtures must not keep a second copy.
- **Use one verification pipeline per format across every entry point.** OIDC
  relying-party, standalone, UI and mobile flows never get a lighter
  extraction-only path. SD-JWT holder proof and mdoc DeviceAuth/session
  transcript verification complete before any claims are mapped.
- **Return every verified document.** A multi-credential response must not be
  fully verified and then collapsed to the first credential's identity or
  evidence. Preserve per-document results and errors.
- **Select the response channel from sealed session state.** Redirect versus
  DC API and its origin are never inferred from credential format or supplied
  again by the wallet.
- **The browser surface is deliberately thin.** The JS library initiates a
  presentation and asynchronously waits for its result. Backend code owns
  validation, trust, verification and result handling; do not add a rich UI,
  account flow or preset-management application. HA recovery uses the existing
  initiation/status/completion endpoints, not a new UI.
- **HA lifecycle preserves exactly-once completion.** Persist completion before
  notification and recover interrupted processing with leases, never by
  weakening replay protection or sealed one-time results.
- **Operational concerns belong to the service and adapters.** Readiness,
  metrics, concurrency budgets, processing leases, notifications, graceful
  shutdown, dynamic client registration and key resolution stay outside the
  sans-I/O core. Discovery and registration advertise only implemented,
  authorized behavior.
- **Treat remote URLs as hostile I/O targets.** Apply host/IP allow policy and
  redirect rules, and enforce streaming byte limits before allocation. A
  malformed status structure is a refusal, not an absent status; cache only
  validated public status artifacts.
- **The verification boundaries are sans-I/O.** Effects and verified results
  cross explicit interfaces. Transport, storage, time and trust verdicts belong
  to the host; production network and database work belongs in the service or
  adapter. Do not hide I/O in parsers or verification code.
- **go-trust makes every trust decision**, for issuers, verifiers and
  status-list signers. The core constructs AuthZEN evidence and consumes a
  permit; it never creates a local trust fallback. The circuit catalog supplies
  integrity-checked artifacts, not trust.
- **Claims are disclosed only after request/policy checks, cryptographic
  verification and an explicit per-document permit.** Logged-out sample
  verification does not relax this rule.
- **The verifier owns the statement.** Transcripts, nonce, handover, verifier
  identity, age bounds and acceptable issuer keys come from validated
  configuration and sealed session state, never from wallet assertions.
  Pseudonyms are outputs, not verifier-selected inputs.
- **`zkp_req` is protocol; nym_auth is one profile.** Add profiles and proof
  systems through the existing registries and `ProofBackend` implementations.
  Do not fork the protocol for a credential capability or create parallel
  profile-specific dispatch. Unsupported functions, systems, BBS and
  predicate-only requests fail closed.
- **Keep format dispatch and strict parsing intact.** SD-JWT and mdoc selection
  starts from validated DCQL and sealed session state. Preserve strict
  JSON/CBOR/container rules, unique identifiers, bounded bodies, artifacts,
  responses and lists, replay protection and sealed one-time results.
- **Use dedicated verifier signing keys.** `zkp_req` normally uses
  `x509_san_dns`; other formats retain `x509_hash`. ReaderAuth uses the host's
  long-term P-256 key through `kryptering::Signer`, never the ephemeral session
  key. Sign exact tag-24 values and preserve their bytes.
- **Transport stays outside verification.** BLE/NFC transport and NDEF parsing
  belong to the native application. The FFI exports transport-independent
  session messages and never holds its session lock during a foreign signing
  callback.
- **Caches are limited to validated public artifacts and initialized backends
  per immutable verifier.** Do not add a global backend, witness, pseudonym or
  proof-result cache.

## Configuration rules

- Prefer `[[backend.config.zkp.profiles]]` for multiple nym_auth presets. The
  legacy single `query` form remains supported. Duplicate byte-equivalent
  queries are a startup error; sharing a query ID with different function lists
  is valid.
- UI and backend profiles must agree exactly on query IDs, result handles, age
  bounds and attribute mapping. `subject_handle` names a pseudonym function.
  Reject unknown systems and unsupported functions during construction.
- Register native backends through `BackendRegistry` and `ProofBackend`; do not
  bypass `check_claimed`, issuer-set policy or go-trust.
- Keep catalog and file sources behind `ArtifactSource`. Production prefetches
  at startup and calls `ZkpVerifier::prewarm`; embedded users may keep lazy
  loading. Wallet responses never trigger catalog access or first-use native
  initialization.
- Use exactly one of `artifact_path` and `artifact_id`. Hash and size always
  describe decompressed bytes. Vega entries reject Longfellow parameters. Use
  `api.circuits.siros.org` for the API; `circuits.siros.org` is the human site.
- `request_uri_method = "post"` echoes the wallet's `wallet_nonce` in a
  re-signed request object and requires exactly one valid form field. GET
  remains the default and is always available alongside POST.
- Registry presets merge by format and type. A default claim subset must be
  answerable by the intended wallet; the first claim becomes the subject when
  no pointer is configured.
- Only the QR display is modal. Completion navigates to the complete page,
  which shows a neutral spinner while pending and then the verified response or
  an error. Do not reintroduce appended QR sections or result modals.

## Tests

- New tests live outside the source files, in each crate's `tests/` directory,
  and exercise the public API. Do not add `#[test]` or `#[cfg(test)]` under
  `src/`, and do not widen visibility for a test. Migrate an inline unit test
  when you touch it.
- Every test enforces a source of truth outside the code it tests: a
  specification, published vector, independent implementation or property that
  must hold. Delete a test whose expected value comes from the implementation:
  a snapshot, digest or count copied from a run, or a constant of the code under
  test.
- Trust the dependencies. Delete tests of guarantees owned by a dependency,
  such as a JSON parser parsing or a hash crate hashing. A dependency may serve
  as an independent oracle.
- Leave invariants to the compiler. Delete tests of a type that cannot be built
  invalid, an exhaustive match, a trait bound, visibility, or a compile-fail
  check of any of them.
- Use one test per guarantee and one fixture per refusal rule, with known
  answers in one table. A test of wording is no test. Every regression test
  must fail when its fix is reverted.
- Include positive and negative cases, public-input mutations and stable
  refusal codes. A refactor must not delete a mutant or weaken its test.
- `scripts/mutate.py` disables each security check and requires a test to fail.
  Update an anchor only when the checked expression intentionally moves.
- Native tests use genuine Longfellow and Vega proof vectors and negative
  mutations. Model backends are only for dispatch and error paths, never
  substitutes for real proof verification.
- Physical evidence must use stock consumer devices with locked bootloaders,
  production defaults and ordinary installation. Do not require a wipe,
  bootloader unlock or developer-only mode. Record device, build, page size and
  verifier endpoint separately, and do not claim 16 KB runtime evidence from a
  4 KB run.

## Types

- **Parse, don't validate.** Construct meaningful types at the trust boundary
  so invalid protocol states cannot be represented. Do not add a parallel
  `validate()` that lets malformed values circulate.
- Use newtypes for constrained identifiers, handles, paths, keys, catalog IDs
  and protocol values; a wrong role or format should fail to compile.
- Keep effects in and results out explicit. Runtime trust, time and selection
  checks belong to witness types between protocol steps, not hidden global
  state.
- Errors and refusals have stable machine-readable codes. Do not leak witness
  data, pseudonyms, decrypted responses or proof results into logs.

## Wording

- The core owns no end-user prose. UI adapters supply display text; core errors
  stay typed and suitable for logs and protocol error responses.
- Preserve public protocol/catalog IDs, native ABI names, public compatibility,
  engagement/handover/transcript behavior and dedicated P-256 ReaderAuth
  behavior. Rename only with an explicit compatibility plan.

## Read first

- `README.md` for integration boundaries and supported flows.
- `docs/README.md` for the integrator documentation index, including
  `docs/INTEGRATORS.md` and `docs/USERS.md`.
- `docs/CONFIGURATION.md` for the complete service schema and
  `examples/README.md` for runnable local, replica, production, mdoc-only,
  Compose and native-reader examples. The `examples/` directory is only for
  users and integrators.
- `docs/design/` for historical findings, design notes and developer-only Rust
  tools. It is not integrator documentation or a compatibility contract. The
  later-phase customer/RP and control-plane proposal is in
  `docs/design/MULTITENANCY.md`; do not implement its customer admin UI in the
  verifier runner.
- `src/oid4vp.rs` for request/response policy, handovers and bounded ECDH-ES
  decryption.
- `src/mdoc_request.rs` for ordered DeviceRequest construction and ReaderAuth;
  `src/mdoc_session.rs` for QR/NFC handover and session messages.
- `src/status_list.rs` for sans-I/O JWT status-list verification; the
  tunnelbana adapter owns bounded fetching and go-trust signer evaluation.
- `zkp/src/verify.rs` for the two-phase response/trust/proof flow;
  `zkp/src/circuits.rs` and `zkp/src/catalog.rs` for artifact integrity and
  startup prefetch.
- `tunnelbana-plugin/src/lib.rs` for per-flow dispatch and independently
  validated ZK profiles.
- `service/src/config.rs` and `service/src/main.rs` for deployment-only schema
  and backend factories. Deployment settings do not leak into the core.
- `ffi/README.md` for native Android/iOS packaging and host responsibilities.
- `docs/RELEASING.md` for source-based release artifacts and verification, and
  `RELEASES.md` for the post-release publication record.

## Build and test

Run all checks before committing:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
scripts/audit.sh
python3 scripts/mutate.py
npm test --prefix tunnelbana-plugin/src/assets
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
```

## Deployment

- `docker-compose.yml`, `.env.example` and `examples/compose.toml` provide a
  single-replica loopback-HTTP development setup: a source-built verifier, persistent
  MongoDB with a least-privilege application user, mounted verifier keys and
  the image's offline Longfellow artifact. MongoDB is not published to the
  host and the verifier binds to loopback by default.
- The Compose setup is not database HA or a production TLS profile. Production
  uses `examples/production.toml`, secure cookies, TLS termination, HA MongoDB
  and an immutable GHCR image digest. Use `--no-build` with a release digest;
  do not deploy `latest`.
- go-trust is external to this Compose file and must use an HTTPS evaluation
  endpoint reachable from the verifier container. It must explicitly permit
  each issuer, verifier and status-list signer. Never substitute an
  always-trusted registry or a local allow-all path. The circuit catalog is
  only an integrity source.
- To deploy locally, copy `.env.example` to `.env`, replace all placeholders
  with independent secrets from `openssl rand -hex 32`, provide a dedicated
  P-256 PKCS#8 PEM key (`PRIVATE KEY`) and chain whose DNS SAN matches
  `SIROS_VERIFIER_DNS_NAME`, then run
  the commands below. `MONGODB_APP_PASSWORD` must use only URI-unreserved
  characters `[A-Za-z0-9._~-]` because Compose inserts it into the Mongo URI;
  do not percent-encode the raw value. This profile is loopback HTTP only, not
  HTTPS staging.

  ```sh
  docker compose config --quiet
  docker compose up --build -d
  docker compose ps
  curl --fail http://localhost:9001/health
  ```

- Use `docker compose logs verifier mongodb` for diagnostics and
  `docker compose down` to stop. Never use `down --volumes` unless deletion of
  flow state and replay history is intentional. Keep `.env` and `/secrets/`
  excluded from both Git and the Docker build context; never commit generated
  credentials or send them to a remote builder.
- After changing the Compose model or templates, run
  `docker compose config --quiet` (never print the secret-bearing rendered
  configuration) and the `config_examples` service test. `examples/docker/mongo-init.js` runs
  only on a fresh MongoDB volume and creates the application's `readWrite`
  user for `siros_verifier`.

## Releases

Use organization-wide workflows where they exist:

- Docker: `sirosfoundation/.github/.github/workflows/docker-build-push.yml`.
- SBOM: `sirosfoundation/.github/.github/workflows/sbom.yml`.
- Integration builds: `sirosfoundation/.github/.github/workflows/integration-build.yml`.

Release artifacts include the GHCR image and digest, native Android/iOS
packages, SBOM, vulnerability results, checksums and provenance. Never invent
an SBOM workflow when the reusable one exists.

Build every release track from reviewed source/Git dependencies and lockfiles.
Do not add crates.io publication, trusted-publisher configuration, registry
preflights or external namespace negotiations as release prerequisites. Native
SDK releases are independent of Maven Central publication as well.

For native mobile packages, use `ffi/scripts/android-aar.sh` and
`ffi/scripts/ios-xcframework.sh`. They generate bindings from the same
checkout, support caller-selected output directories and never enable
`vector-tests` in release builds. The tag workflow publishes the AAR/POM and
attaches the XCFramework, Swift bindings and SPM checksum; ordinary GitHub CI
also builds and validates the iOS test package on `macos-latest`. Preserve flat
Android JAR/AAR entries; use `--include-root` only for the SwiftPM XCFramework.
Keep both native SDKs on the same core version.

See `docs/RELEASING.md` for release prerequisites and post-release verification.
After every testing or production release, immediately add its source/artifact
identities, validation evidence, deployment/rollback instructions, known
limitations and documentation updates to `RELEASES.md`.
Do not tag `v0.1.0` until full CI, live Longfellow and Vega verification,
packaging checks and documentation pass, and the user explicitly approves it.

## Working rules

- Cite the specification for non-obvious behavior (`OpenID4VP`, ISO/IEC
  18013-5, RFC 9901 or the nym_auth rulebook). Do not use another
  implementation as an unstated specification.
- Add UI/backend profiles together and validate each plan at construction.
  Update `docs/CONFIGURATION.md` for schema changes and this file for changed
  boundaries, workflows or release rules. Keep `docs/` and `examples/` limited
  to user/integrator material; put design history and developer-only examples
  in `docs/design/`.
- After every major PR, review and update the relevant documentation: user and
  integrator guides, examples, `AGENTS.md`, and design notes. Include those
  updates in the major PR or land an immediate documentation follow-up before
  starting dependent work.
- Fix every review finding and every instance of the same bug class. Merge only
  reviewed, green PRs with a successful GitHub Copilot review.
- Do not run `git commit`, `git push`, `git rebase`, `git reset`, or create a
  tag unless the user explicitly approved that operation.
- Report pull requests and issues with full URLs.

## Common pitfalls

- `presentation_not_base64url` can mean an input exceeded the matcher's response
  budget, not malformed encoding. Check the actual token size first.
- Actix's body limit and jose-rs's compact-token default are different limits.
  Test both with genuine large responses.
- URI SAN identifies an mdoc issuer for go-trust; a leaf hash is only the
  fallback when no SAN identity exists.
- A valid credential can fail to match if the query requests claims it does not
  contain or uses the wrong result handle. Inspect the query and wallet claims.
- A new image is not a new trust decision. Keep go-trust configuration and
  verifier signing identity aligned when a leaf is reissued.
