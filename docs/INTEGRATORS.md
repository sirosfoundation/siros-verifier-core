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

## Docker Compose

The root `docker-compose.yml` starts one verifier and one MongoDB container using `examples/compose.toml`. It is a loopback-HTTP development setup, not database HA or an HTTPS staging profile. MongoDB is not published to the host, its application user has only `readWrite` on `siros_verifier`, and the verifier listens on loopback by default.

1. Create a private environment file and replace every placeholder. Use independent secrets from `openssl rand -hex 32` for the state key and both database passwords. `MONGODB_APP_PASSWORD` must contain only URI-unreserved characters `[A-Za-z0-9._~-]` because Compose inserts it into the MongoDB URI; do not percent-encode the raw value:

   ```sh
   cp .env.example .env
   ```

2. Put the dedicated P-256 private key in PKCS#8 PEM format (a `PRIVATE KEY` block) and its certificate chain at the paths in `.env`. The certificate's DNS SAN must match `SIROS_VERIFIER_DNS_NAME` (`localhost` by default).
3. Set `SIROS_PDP_ENDPOINT` to an **HTTPS** go-trust/AuthZEN evaluation URL reachable from inside the verifier container. The Compose setup does not provide go-trust or an allow-all fallback. Configure issuer, verifier, and status-list signer policy there. Add `pdp_bearer_token` in `examples/compose.toml` only if your PDP requires it.
4. Validate and start the stack:

   ```sh
   docker compose config --quiet
   docker compose up --build -d
   docker compose ps
   curl --fail http://localhost:9001/health
   ```

   The image already contains the exact Longfellow artifact used by `examples/compose.toml`. MongoDB initialization creates the least-privilege application user only on a fresh data volume.

Use `docker compose logs verifier mongodb` for diagnostics and `docker compose down` to stop. Do not use `down --volumes` unless you intentionally want to erase flow state and replay-protection history.

For a released image, set `SIROS_VERIFIER_IMAGE=ghcr.io/sirosfoundation/siros-verifier-core@sha256:<release-digest>` and start with `docker compose up --no-build -d`. Do not point this loopback-HTTP profile at an HTTPS staging or public base URL: for production, use TLS with secure cookies and HA MongoDB as described by `examples/production.toml`. The single MongoDB container and loopback cookie settings in this Compose example are not a production HA profile.

## Common setups

- `examples/quickstart.toml`: local single-process SD-JWT plus nym_auth.
- `examples/mdoc-only.toml`: local mdoc-over-OpenID4VP without a ZK backend.
- `examples/replicas.toml`: shared MongoDB and catalog-backed Longfellow for multiple replicas.
- `examples/production.toml`: HTTPS, secure cookies, shared MongoDB, and both Longfellow and Vega.
- `docker-compose.yml` plus `examples/compose.toml`: one verifier and one least-privilege MongoDB container for loopback development.
- `examples/native-reader/`: small Kotlin and Swift snippets showing native FFI use without a full app.

See the [examples index](../examples/README.md) for prerequisites and each file's intended use.

## Versioned releases

Deploy a specific image digest rather than `latest`. Verify the release checksums, SBOM, vulnerability results, and provenance before deployment. The release process does not require internal crates.io or Maven Central publication; Docker and native artifacts build from reviewed source and lockfiles. See [Releasing](RELEASING.md).

After deployment, test startup, one complete presentation, an explicit PDP denial, and rollback to the previous image. Do not infer a trust decision from a new image or from the circuit catalog alone.
