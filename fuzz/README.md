# Fuzzing

Isolated `cargo-fuzz` workspace for attacker-controlled verifier inputs. It does
not perform network I/O and does not add test-only APIs to the production crate.
Each target caps an input at 64 KiB.

Targets:

- `mdoc_response`: CBOR `DeviceResponse` verification.
- `mdoc_session`: ISO 18013-5 encrypted session-message parsing.
- `sdjwt`: SD-JWT VC headers, payloads, disclosures, and key binding.
- `oid4vp_jwe`: OpenID4VP JWE envelope and decrypted response parsing.

Regenerate the committed seed corpora from the independent test vectors:

```sh
cargo run --manifest-path fuzz/Cargo.toml --bin prepare_seeds
```

Run short smoke jobs (requires `cargo-fuzz` and a nightly Rust toolchain). The
script fuzzes a scratch copy of the corpus, so newly discovered inputs do not
expand the committed seed set:

```sh
scripts/fuzz-smoke.sh
```

For a longer local run, use `cargo +nightly fuzz run <target>` from `fuzz/`.
