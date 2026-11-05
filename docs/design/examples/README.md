# Rust developer examples

These are developer tools, not user-facing integration examples or production services. Each has an explicit Cargo `[[example]]` path so Cargo continues to build it after the documentation reorganization.

- `bench.rs`: rough per-operation timing, including SD-JWT and JWE operations. Run with `cargo run --release --example bench --features testutil`.
- `emit_vectors.rs`: writes Rust-produced JWE and SD-JWT interoperability vectors under `target/interop/` for the Go oracle. Run with `cargo run --example emit_vectors --features testutil`.
- `live_pdp_fixture.rs`: creates an issuer certificate and the AuthZEN request used by a live go-trust fixture. Run with `cargo run --example live_pdp_fixture --features testutil -- <output-directory>`.

`testutil` is deliberately opt-in. Do not enable these tools or their fixed test keys in release builds.
