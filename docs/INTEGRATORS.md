# Integrating the verifier

## Choose an integration

| Integration | Use it when | Start with |
| --- | --- | --- |
| `siros-verifier-service` gateway | You need an OIDC relying-party service and OpenID4VP verification with a small JS initiation/status interface. | [Examples](../examples/README.md) and [Configuration](CONFIGURATION.md) |
| Rust verification crates | You need to embed request, credential, proof, transcript, and session logic in another application. | [`src/lib.rs`](../src/lib.rs) and [`zkp/src/lib.rs`](../zkp/src/lib.rs) |
| Browser presentation library | You need a thin JS adapter to initiate a presentation and asynchronously wait for the result. | [Presentation-flow package](../tunnelbana-plugin/src/assets/README.md) |
| Native proximity reader | You need ISO/IEC 18013-5 reader sessions in an Android or iOS app. | [FFI guide](../ffi/README.md) and [native-reader snippets](../examples/native-reader/README.md) |

The gateway remains almost UI-free. The backend is authoritative for DCQL, signing, trust, verification, and result handling.

## Required trust and deployment boundaries

- Configure a go-trust/AuthZEN evaluation endpoint. There is no local allow-all or trust fallback. Every document needs a permit before its claims are returned.
- Use a dedicated verifier request-signing key and matching certificate chain, not an issuer key or the ephemeral proximity-session key.
- Terminate TLS upstream. Keep request keys, state-sealing masters, MongoDB credentials, and PDP bearer tokens in a secret manager.
- Use MongoDB for every deployment with more than one process. `memory` is only for explicitly single-process deployments.
- Keep artifact hashes and sizes exact. The circuit catalog is an integrity source, not a trust registry.
- BLE/NFC transport and NDEF handling belong to the native application, not the protocol core.

## Quickstart

1. Copy `examples/quickstart.toml` to a private configuration directory.
2. Set `SIROS_VERIFIER_STATE_KEY` through your secret manager and replace every `/replace/me` path with real key/certificate paths.
3. Set the PDP evaluation URL and the OIDC relying-party redirect URI.
4. Provision the exact Longfellow artifact at the path in the template, or replace it with an `artifact_id` from the circuit catalog.
5. Run:

   ```sh
   TUNNELBANA_BIND=127.0.0.1:9001 siros-verifier-service /private/config/quickstart.toml
   ```

`ProxyConfig` expands `${VARIABLE}` placeholders at load time. The replica and production templates inject the state key and MongoDB URI through the environment. Add `pdp_bearer_token = "${SIROS_PDP_BEARER_TOKEN}"` only if your PDP requires bearer authentication; it is not mandatory for these templates. See [Secret injection](../examples/README.md#secret-injection).

The quickstart uses in-memory storage and a loopback PDP only. Exact loopback HTTP is allowed by default; `allow_insecure_http` remains `false`. Enabling it additionally permits plaintext HTTP to a non-loopback PDP on a trusted development network and is not a production setting.

For Docker, use the same configuration with `TUNNELBANA_BIND=0.0.0.0:9001` and mount the configuration, key material, and circuit artifact read-only.

## Common setups

- `examples/quickstart.toml`: local single-process SD-JWT plus nym_auth.
- `examples/mdoc-only.toml`: local mdoc-over-OpenID4VP without a ZK backend.
- `examples/replicas.toml`: shared MongoDB and catalog-backed Longfellow for multiple replicas.
- `examples/production.toml`: HTTPS, secure cookies, shared MongoDB, and both Longfellow and Vega.
- `examples/native-reader/`: small Kotlin and Swift snippets showing native FFI use without a full app.

See the [examples index](../examples/README.md) for prerequisites and each file's intended use.

## Versioned releases

Deploy a specific image digest rather than `latest`. Verify the release checksums, SBOM, vulnerability results, and provenance before deployment. The release process does not require internal crates.io or Maven Central publication; Docker and native artifacts build from reviewed source and lockfiles. See [Releasing](RELEASING.md).

After deployment, test startup, one complete presentation, an explicit PDP denial, and rollback to the previous image. Do not infer a trust decision from a new image or from the circuit catalog alone.
