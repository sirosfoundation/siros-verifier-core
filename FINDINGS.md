# Spike 1 findings: SD-JWT VC and OpenID4VP on jose-rs

Scope: verify SD-JWT VC presentations, build a signed OpenID4VP request object, and handle an encrypted
`direct_post.jwt` response, using jose-rs and kryptering. Format layer only: trust is delegated (see
`src/trust.rs` and `docs/go-trust-issue.md`).

## Result

Feasible. About 1,230 lines of library code (plus 320 of test helpers) on top of jose-rs and kryptering.
28 tests, 39 mutation checks (every one caught), bidirectional interop with go-jose and SUNET/vc.

## What jose-rs and kryptering gave us, and what they did not

| Need | Status |
|---|---|
| JWS sign and verify (ES256), JWK, thumbprints | Used as is |
| Safe defaults | `alg: none` rejected, `verify_with_jwk` pins `alg`, `x5c`/`jwk`/`jku` headers refused on signing unless opted in |
| **ECDH-ES JWE** | **Missing.** `ECDH-ES` is in the algorithm enum, but `jwe::encrypt` and `decrypt` implement only `dir`, `A*KW`, `RSA-OAEP*` (checked in the 0.9.0 source). Written here (`src/jwe_ecdh.rs`, about 300 lines) from kryptering's `ecdh_p256`, `concat_kdf` and AES-GCM. Ready to propose upstream. |
| ConcatKDF | kryptering's `concat_kdf` builds `AlgorithmID || PartyUInfo || PartyVInfo` and has no SuppPubInfo, so the full RFC 7518 OtherInfo is passed through `algorithm_id`. Worth an upstream helper. |
| HPKE | Absent. Not needed for OpenID4VP JWE. Likely needed for ISO 18013-7 Annex C mdoc responses (from memory, check in spike 2). |
| SD-JWT, DCQL, mdoc, OpenID4VP | Not covered by either library. Written here (SD-JWT VC, minimal DCQL) |
| x5c chain validation | Not provided, by design. The trust layer (go-trust) does it. |

Packaging issues found:

- **Version coupling.** jose-rs 0.9.0 depends on kryptering 0.6; kryptering 0.7 is current. Depending on 0.7
  silently pulls in both and the traits no longer unify. Pin 0.6.
- **Coarse features.** With PKCS#11 off, kryptering still needs its `rustcrypto` feature, which pulls 145 crates
  including `rsa`, `dsa`, `ml-dsa`, `slh-dsa`, `des`, `md-5`, `ripemd`, `sha1` and a pre-release `ed448-goldilocks`.
  For a verifier that is attack surface and WASM size we do not need. Ask for finer features, or depend on the
  RustCrypto primitives directly in a verifier-only build. I did not run `cargo audit`; the `rsa` crate has had a
  published timing advisory (RUSTSEC-2023-0071, from memory), so check it.

## Interop evidence

| Direction | Result |
|---|---|
| RFC 7518 Appendix C KDF vector (with `apu`/`apv`) | Passes |
| go-jose v4.1.4 encrypts, Rust decrypts (A128GCM, A256GCM) | Passes |
| Rust encrypts, go-jose decrypts (both enc, with and without `apu`/`apv`) | Passes |
| vc `sdjwtvc` issues (nested disclosure, 3 decoys, KB-JWT), Rust verifies | Passes |
| Rust issues, vc `SDJWTHandler` verifies; same presentation under a wrong nonce is rejected by vc | Passes |

Quirk found: go-jose v4.1.4's *encrypter* writes `apu`/`apv` from `WithHeader` into the header but does not use
them in the KDF, so it cannot decrypt its own output. Do not use it to generate party-info vectors.

Reproduce: `scripts/interop.sh gen` (Go to Rust, regenerates `tests/vectors/`), `scripts/interop.sh` (Rust to Go).
The Go tool reads the local `../vc` checkout read-only.

## Test quality

- 28 tests: 6 JWE, 10 SD-JWT (selective and nested disclosure, hash algorithms, key binding, issuer and header
  checks, time claims, hostile structures, limits, `cnf`, `x5c` evidence), 10 OpenID4VP (end to end plus
  response-shape attacks asserted by exact error code), 2 interop.
- `scripts/mutate.py` disables 39 individual checks one at a time and requires a test failure. It aborts if the
  baseline is red.
- The mutation run found a vacuous test (a helper joined an empty disclosure list into `jwt~~`, so the
  "array digest with extra members" case failed on the *empty disclosure* rule instead of its own) and one check
  that was dead code (re-comparing `iss` between two parses of the same signed bytes), now removed.

## Design points that came out of the spike

- `CryptoVerified` is the return type of `sdjwt::verify`. It says "signatures and disclosures verified, trust
  not evaluated" and carries `IssuerEvidence` (iss, alg, kid, x5c DER chain, key) for the trust layer.
- `TrustQuery` produces exactly the AuthZEN request go-trust expects: `subject.type=key`,
  `resource.type=x5c` or `jwk` with `resource.id == subject.id`, `action.name` = role,
  `action.parameters.credential_types=[vct]`.
- Strictness implemented: non-disclosable claims (`iss`, `nbf`, `exp`, `cnf`, `vct`, `status`), reserved
  disclosure names, duplicate digests (anywhere, including nested), duplicate disclosures, unreferenced
  disclosures, claim-name collisions, array digest object shape, `cnf.jwk` must be public, `typ` checks for
  issuer and KB-JWT, algorithm allowlist, `sd_hash`, aud, nonce, `iat` window, depth and count limits, and
  unrequested or missing DCQL credential ids. Unsupported query features (`credential_sets`, non-sd-jwt
  formats, non-string claim paths) fail closed.
- The signer seam works: `create_request` takes any `kryptering::Signer`, so PKCS#11 and software keys share
  one path.

## Targets

| Target | Result |
|---|---|
| x86_64 Linux (native) | Builds, all tests pass |
| aarch64-linux-android (check) | Builds with `--no-default-features` |
| wasm32-wasip1 | Builds with `--no-default-features` |
| wasm32-unknown-unknown | Builds once getrandom is configured (`.cargo/config.toml`, two getrandom versions in the tree) |

UniFFI bindings, a WASM size measurement and a WASM runtime benchmark were not done (no WASM runtime installed
here).

## Native timings (release, one core, 4 KiB body)

| Operation | Time |
|---|---|
| SD-JWT VC verify with KB-JWT (two ES256 verifies, 4 disclosures) | about 0.37 ms |
| ECDH-ES decrypt, A128GCM | about 0.10 ms |
| ECDH-ES encrypt, A128GCM | about 0.19 ms |

## Not done, and next

- mdoc: see spike 2 below.
- Token Status List fetch and verification, `credential_sets`, claim path segments other than strings: use
  `siros-dcql` instead of the minimal matcher here.
- Reject duplicate JSON member names (serde_json keeps the last).
- Sealing of `Session` (AEAD under a per-tenant derived key). Today it is a plain serde struct holding the
  ephemeral private key.
- ES384 and EdDSA paths are allowed by configuration but untested. Only P-256 for ECDH-ES.
- Evaluate existing SD-JWT crates (`sd-jwt-payload`, `reallyme-sd-jwt`, `bh-sd-jwt`, ...) as differential-test
  oracles. They were listed by `cargo search`, not reviewed.
- Upstream: ECDH-ES to jose-rs, finer features and a SuppPubInfo-aware ConcatKDF helper to kryptering.

# Spike 2 findings: ISO 18013-5 reader, sans-IO, through UniFFI

## Result

Feasible, and small: `mdoc_session.rs` (about 170 lines) and `mdoc.rs` (about 400 lines), on `ciborium`, `p256`,
`hkdf`, `hmac`, `aes-gcm`. No COSE crate, no HPKE. The ISO/IEC 18013-5 Annex D.5 example verifies end to end.

| Layer | Evidence |
|---|---|
| Session keys and AES-GCM | SKReader/SKDevice reproduce the spec; our `encrypt` reproduces the spec's SessionEstablishment ciphertext **byte for byte**; the spec's SessionData decrypts. Vectors are extracted from the spec PDF by script, not retyped. |
| DeviceResponse | Spec example verifies: issuerAuth ES256 over the MSO, element digests, validity, `deviceMac` (EMacKey from the reader ephemeral key) bound to the SessionTranscript. |
| Other paths | `deviceSignature`, SHA-384 digests, and 20 negative cases run against an issuer/holder simulator. |
| Tamper sweep | Flipping a bit in every byte of the spec response: nothing verifies except inside the issuer certificate, and those flips show up in the returned chain so the PDP sees exactly what was presented. One more exception: ciborium decodes CBOR `undefined` as `null`. |
| Mutation | 23 new checks in the two mdoc modules (62 in total), all killed. The new harness also refuses a mutant that does not compile (that had counted as "killed"). It found 7 untested checks on the first run; all now have tests. |
| UniFFI | `ffi/` exports `Reader` (new, encrypt_request, open_response) with records and a typed error. Kotlin (1.7k lines) and Swift (1k lines) bindings generate from the cdylib. Facade tests run the spec vector through the FFI types. A Kotlin or Swift process has **not** executed it. |
| Targets | Core builds for wasm32-unknown-unknown, wasm32-wasip1 and aarch64-android. The FFI crate checks for aarch64-android. Stripped release cdylib: 944 KB (no size tuning). |

## Findings

- **HPKE is not needed for 18013-5.** It is probably needed for ISO 18013-7 Annex C (DC API mdoc); I do not
  have that document locally, so that is still unverified.
- **A reader session needs the reader's ephemeral private key** both for SKReader and to check `deviceMac`.
  The FFI constructor takes it as bytes for the spike; a real API should generate it inside Rust and never export it.
- **Spec example certificates are expired**, which is why `now` is an input. It also showed the right
  boundary: the verifier checks MSO validity and returns the chain; certificate validity and chaining are the PDP's job.
- **Strict maps matter.** A flipped bit in the key text of `status` was accepted until unknown or missing members
  were rejected at every level.
- **Same trap as spike 1:** the first duplicate-digest test failed for the wrong reason because the simulator overwrote the first digest.
- A TrustQuery for an mdoc issuer needs a subject id; an MSO has none, so it uses `x509_hash:<leaf hash>` (changed on 2026-10-26, see the spike 4 addendum).

## Not done

- Device engagement parsing (QR/NFC), the DeviceRequest builder, ReaderAuth (D.5.4) signing, `deviceSigned`
  namespaces beyond the empty set, handover for NFC, BLE/NFC transports (the app owns these by design).
- ES256 and P-256 only. Real mDL issuers also use P-384/P-521 and Brainpool; each needs a decision.
- mdoc zero-knowledge, MSO revocation (`status`), `documentErrors`.
- Executing the generated Kotlin/Swift in a real runtime (needs a JVM or a Mac builder).
- Differential test against the Kotlin SDK and `siros-verifier-cli` outputs. Note that vc's own DeviceAuthentication
  is known not to be ISO-conformant, so vc is not a valid oracle here.

# Spike 3 findings: decision receipts, entirely in the core

## Result

`src/receipt.rs` (about 330 lines, p256 + sha2, no go-trust change): RFC 8785 canonicalization, `issue`
(wrap an unsigned go-trust answer), `Verifier::verify` (the six rules), `Cache` (re-verify on every hit) and a
`Monotonic` clock guard. 20 tests, 19 new mutation checks (81 in total), all killed.

- RFC 8785: the sorting example (U+1F600 before U+FB33, i.e. UTF-16 order, not UTF-8 byte order) and the string
  escaping example pass. Floating-point numbers are refused rather than approximated; AuthZEN requests have none.
  Open: an independent Go implementation must agree on a shared vector set before this is a contract.
- Issuing refuses a permit built on trust data that is already past `next_update` (`trust_data_stale`) and clamps
  `exp` to the smallest of tenant ceiling and every `next_update`. Denials get a shorter TTL, still under the ceiling.
- A receipt for one request is rejected for any other (different role or chain), and a receipt filed under the
  wrong cache key is a miss.
- Re-verification on a hit means removing a key from the pin set takes effect on cached receipts immediately.
- The mutation run found one real gap: the clock guard's high-water mark could be ratcheted back in
  small steps. Fixed (`max`) and covered.

## Not done

- Receipt key via the `Signer` trait (KMS/HSM): the spike signs with a local P-256 key.
- ES256 only; multi-key rotation overlap is just "several pinned kids".
- Batch warm-up through the service, and the sealed local cache for embedded apps (AEAD at rest).
- Cross-language RFC 8785 vectors against a Go implementation.

## Spike 3 addendum: Go cross-check of the canonical form

`tools/jcs-go` canonicalizes a shared input set (`tests/vectors/jcs_inputs.json`) with Go's
`encoding/json/jsontext` (`Value.Canonicalize`, RFC 8785, `GOEXPERIMENT=jsonv2`) and writes
`tests/vectors/jcs_go_golden.json`; `canonical_form_and_hash_match_go` requires byte-identical output and equal
SHA-256 on 15 inputs.

- **Found and fixed:** RFC 8785 prints numbers as IEEE doubles. Go prints 2^64-1 as `18446744073709552000` and
  2^53+1 as `9007199254740992`; the Rust canonicalizer printed exact integers, so hashes would have diverged.
  Rust now refuses integers beyond +-(2^53-1) (`canonical_json_integer_range`) and all floats, instead of emulating
  double rounding. AuthZEN requests contain neither. Anything that needs big numbers must use strings (I-JSON).
- Agreement covers key ordering (UTF-16), escapes, control characters, non-ASCII, nested and empty structures.
- The cross-check caught nothing else, and the oracle shares no code with the Rust side. Both are written from RFC 8785, so
  a shared misreading remains possible; the RFC's own examples are in the unit tests.

# Spike 4 findings: an OpenID4VP verifier as a tunnelbana Backend

## Result

`tunnelbana-plugin/` (separate crate, git dependency on SUNET/tunnelbana at 4c0933f, 0.6.0): `VpBackend`
implements tunnelbana's `Backend` trait and joins spikes 1 and 3. 19 tests, 16 mutation checks, all killed.

Flow: `start_auth` builds a signed OpenID4VP request (spike 1) and shows an `openid4vp://` link; the wallet GETs the
request object and POSTs the encrypted response straight to the proxy; each issuer goes through the `TrustGate`
(go-trust behind the spike 3 receipt cache); verified claims become `InternalData` through a config map of JSON
pointers; the browser collects the result once at `/complete` using the opaque flow id in the sealed state cookie.

Tested through the `Backend` interface with a simulated wallet and a mocked PDP: happy path, untrusted issuer,
PDP down with a cold cache (fails closed), a warm receipt riding out an outage until `exp`, receipt lifetime clamped
by `trust_data.next_update`, replayed wallet response, a response meant for another flow, collection by a different
browser, expired flows, hostile flow ids, wrong method, missing parameter, missing subject claim, strict config.

## Findings about tunnelbana (nothing filed, nothing changed there)

- **The `Backend` seam fits.** Three routes (`request`, `response`, `complete`), `InternalData` as the output.
  The mapped result is flat strings, so structured claims and credential evidence do not travel to the frontend.
- **Registry constructors are plain `fn` pointers for frontends and backends** (microservices accept closures).
  A backend that needs key material or a PDP client cannot be built from config through `Registry`, so `register()`
  currently returns a clear error and applications call `VpBackend::new`. Fix upstream: closures for backends.
- **`HttpClient` has only `get` and `post_form`.** AuthZEN needs a JSON POST. The plugin uses its own `PdpClient` seam;
  a `post_json` in grindvakt would remove it.
- **Wallet traffic bypasses the browser**, so the cookie-sealed state cannot carry the result: a server-side flow store
  is needed. Mine is in-process, like tunnelbana's own caches, so it is not HA. Several instances need a shared store.
- jose-rs 0.7.1 (tunnelbana) and 0.9 (core) coexist because no jose types cross the boundary.

## Security notes

- Flow ids are 128-bit random, validated by length and alphabet before any lookup. A flow accepts exactly one wallet
  response (replay gets 409). Results are collected once, only by the browser holding the matching cookie.
- Failures surface as stable codes (`issuer_not_trusted`, `trust_unavailable`, `subject_claim_missing`, ...) and the
  wallet-facing responses carry no claim values.
- Cross-device flows have the usual phishing risk: whoever started the flow gets the identity of whoever scans the code.
  The plugin does not mitigate this; same-device flows (a link, not a QR) and user-visible confirmation are the usual answers.

## Not done

- Not run inside tunnelbana's real `Proxy` and HTTP server: only the `Backend` trait is exercised, so route
  dispatch, cookie sealing and body parsing in the proxy are unverified here.
- No real PDP HTTP client, no QR code, no DC API path, no config-driven key loading, no shared flow store.
- No frontend work (OIDC or SAML issuance of the result is tunnelbana's existing job).

## Spike 4 addendum (2026-10-26): against a real go-trust and the real tunnelbana Proxy

**Real go-trust.** Built b0ec45c and ran it with a whitelist registry (the issuer certificate as an extra root,
`trust_x509_via_system_ca`). The real answer is `{"decision":..., "context":{"reason":{...},"trust_metadata":{...}}}`:
**no `context.id` and no `trust_data`**. The strict parser from the first version would have rejected every real answer
(fail closed, but useless). Fixed:

- `context` and every member of it are optional; a missing id becomes a local `local-...` id.
- Without `trust_data` the receipt lifetime is capped at a conservative 5 minutes (configurable), under the tenant
  ceiling. The freshness metadata proposed in the go-trust issue is now an improvement, not a prerequisite.
- A real `HttpPdp` client (feature `http`, on by default): https only (http for loopback), no redirects, timeout,
  1 MiB response limit, optional bearer token. `live_go_trust` (ignored by default, set `GT_URL` and
  `GT_REQUEST_DIR`) passes against the running go-trust: the pinned issuer is permitted, another role is denied.
- **The mdoc subject id is now `x509_hash:<base64url SHA-256 of the leaf>`.** go-trust's whitelist already
  recognises that OpenID4VP scheme (`VerifyLeafBinding`); my earlier `x5t#S256:` was an invention.
- Reasons in the receipt are the keys of go-trust's `reason` object: noisy but harmless. A stable reason-code
  vocabulary would be a go-trust request.

**Real tunnelbana Proxy.** `tests/proxy.rs` drives `Proxy::run` (router, sealed state cookie, request and response
pipeline) with a minimal frontend: the full login, an untrusted issuer reaching the frontend as an error, one-time
collection, forged, flipped and missing cookies, and the documented path set. Findings:

- `Proxy::new` takes already-built backends, so the plugin runs in the real pipeline without upstream changes.
  Only config-driven construction needs the closure change.
- The state cookie is `__Host-<name>`, `Secure`, `SameSite=None`. The flow id fits easily.
- **Still not exercised:** tunnelbana's actix server layer (`build_request_data`, which is private to the binary
  crate) and a real OIDC or SAML frontend. `Proxy::run` is the layer below actix.

## Spike 2 addendum (2026-10-26): reader key inside Rust, DeviceEngagement, Kotlin on a JVM

- **The reader's ephemeral key is generated inside Rust and never exported.** `ReaderHandshake::generate()` then
  `.establish(device_engagement, handover)` parses the DeviceEngagement (version 1.0 or 1.1, cipher suite 1, tag-24 P-256
  device key), builds the SessionTranscript `[DeviceEngagementBytes, EReaderKeyBytes, Handover]` by splicing raw bytes (no
  re-encoding), and derives the keys. The session keeps the key for `deviceMac`; `verify_response` and
  `establishment_message` use it internally. Checked against Annex D: from the spec's DeviceEngagement and NFC handover
  plus the spec's reader key it rebuilds the spec's SessionTranscriptBytes, both session keys, and the **first message
  (`eReaderKey` + data) byte for byte**. 8 new handshake mutation checks, all caught (one needed a new test: a valid key under the wrong tag).
- **Generated Kotlin runs on a JVM.** `ffi/scripts/kotlin-test.sh` builds the cdylib (feature `vector-tests`, which adds a
  fixed-key constructor and must never be enabled in a release), generates the bindings, and runs 5 JUnit tests with
  JNA on JDK 21 and Gradle 8.14: the spec response verifies; the first message equals the spec's, with the plaintext
  recovered by `javax.crypto` independently of the Rust code; rejections are typed `FfiException.Rejected` with stable
  codes; termination is `SessionOver(20)`; a second establishment is refused.
- Still not done: Swift on the Mac mini (deferred by decision until a consumer exists), DeviceRequest builder,
  ReaderAuth, NFC handover construction (the handover is passed in as raw CBOR), P-384/Brainpool.

## Issues filed (2026-10-26)

- tunnelbana: closures for frontend/backend constructors https://github.com/SUNET/tunnelbana/issues/42 ; JSON POST on `HttpClient` https://github.com/SUNET/tunnelbana/issues/43
- go-trust: freshness metadata https://github.com/sirosfoundation/go-trust/issues/221 ; batch `/evaluations` https://github.com/sirosfoundation/go-trust/issues/222 ; anchor export design https://github.com/sirosfoundation/go-trust/issues/223 (eMRTD left out of scope)
- jose-rs: ECDH-ES offer https://github.com/kushaldas/jose-rs/issues/25

## ECDH-ES: jose-rs 0.10 now has it (2026-10-26)

Issue kushaldas/jose-rs#25 was filed from a stale read. jose-rs 0.9.0 (2026-10-01) lacked ECDH-ES; the maintainer landed
it on 2026-10-02 (ADR 0017, plus the `+A*KW` modes in ADR 0018) and it ships in 0.10.0 (2026-10-20, on kryptering 0.7).
`tests/interop_jose_rs_010.rs` runs our `jwe_ecdh` against 0.10's implementation in both directions (A128GCM and A256GCM,
with `apu`/`apv`, tamper rejected on both sides): they agree. The issue was closed with that note; no PR is needed.
Consequence: `src/jwe_ecdh.rs` (about 300 lines of security-sensitive code we maintain) can be replaced by jose-rs 0.10,
at the price of moving the core to jose-rs 0.10 and kryptering 0.7. See the consolidated design document.

## D2 migration completed (2026-10-30)

The core and tunnelbana adapter now use jose-rs 0.10 and kryptering 0.7. The custom `src/jwe_ecdh.rs` implementation and
its same-library differential tests have been removed. OpenID4VP response decryption uses jose-rs's authenticated JWK API,
with the verifier's response policy retained in `src/oid4vp.rs`: ECDH-ES only, A128GCM/A256GCM only, bounded token and
ciphertext/plaintext sizes, an empty encrypted-key part, no `zip` or `crit`, no private material in `epk`, and an exact
response-key `kid` check.

The OpenID4VP integration suite now exercises both content-encryption algorithms and preserves the policy, structure, and
tampering checks. The independent go-jose checks still pass in both directions, including `apu`/`apv`: committed Go-produced
vectors decrypt through jose-rs, and `scripts/interop.sh` verifies new jose-rs-produced vectors with go-jose.

## D3 hardening milestone (2026-10-30)

- **Strict JSON.** `src/json_strict.rs` rejects repeated member names at any depth, including escaped-equivalent names.
  It is used for SD-JWT headers, payloads and disclosures, OpenID4VP JWE headers and decrypted responses, decision receipts,
  and PDP responses. Correctly signed regression inputs prove that duplicate claims are rejected for that reason rather than
  for a later policy or signature failure.
- **Sealed request sessions.** `SessionSealer` derives a tenant key with HKDF-SHA256 and uses AES-256-GCM with a fresh nonce;
  the flow id is associated data. The tunnelbana flow store now holds only sealed sessions and a separate public expiry.
  `with_session_sealer` allows all instances of a shared-store deployment to be configured from the same high-entropy master.
  Tests cover tenant/flow binding, wrong keys, tampering, truncation, version/size limits, weak masters and nonce uniqueness.
- **Fuzzing.** The isolated `fuzz/` workspace has four targets: mdoc DeviceResponse, mdoc session messages, SD-JWT, and
  OpenID4VP JWE. `prepare_seeds` builds a committed corpus from the Annex D.5, go-jose and vc vectors plus authenticated
  malformed responses. All four targets completed 1,000-run smoke jobs without a crash. Longer fuzzing remains necessary.
- **Dependencies.** Direct dependencies now align with the current jose-rs stack: p256 0.14, aes-gcm 0.11, hkdf/hmac 0.13,
  sha2 0.11 and getrandom 0.4; crypto-bigint is 0.7.10 and ctutils 0.4.7. This removes the old direct p256 0.13 and duplicate
  primitive versions from our own crates. jose-rs itself requires kryptering's broad `rustcrypto` feature, so removing its
  unused RSA/DSA/PQ dependency surface requires an upstream feature split rather than a local manifest tweak.
- **Supply chain.** `scripts/audit.sh` runs both `cargo audit` and `cargo deny --locked check`; the same checks and parser
  fuzz smoke jobs are in CI. The only vulnerability exceptions are the no-RSA-private-operations Marvin advisory and the
  crypto-bigint 0.5.5 chain retained by tunnelbana/dev dependencies, each documented with its removal condition in `deny.toml`.
- **Mutation coverage.** New checks cover duplicate-JSON rejection and session-sealing policy, alongside the migrated
  OpenID4VP response checks. All 124 checks are killed, with no survivors or missing snippets. The gateway flow tests
  exercise sealing and unsealing on every login, and the Kotlin tests pass after the primitive upgrades.
