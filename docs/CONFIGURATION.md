# Verifier configuration

Runnable local, replica, production, and mdoc-only examples are maintained in [`examples/`](../examples/README.md). Run the service with:

```sh
siros-verifier-service /etc/siros-verifier/proxy.toml
```

For a single-replica container setup with MongoDB, see [Docker Compose](INTEGRATORS.md#docker-compose) and `examples/compose.toml`.

Set `TUNNELBANA_BIND=0.0.0.0:9001` when the service is behind a public proxy. Keep request signing keys, the state-sealing master, MongoDB credentials, and any PDP bearer token in a secret manager, not in the TOML file. The configuration loader expands `${VARIABLE}` placeholders, so use `state_encryption_key = "${SIROS_VERIFIER_STATE_KEY}"`, `uri = "${SIROS_VERIFIER_MONGODB_URI}"`, and `pdp_bearer_token = "${SIROS_PDP_BEARER_TOKEN}"` and let the secret manager inject those environment variables at process start. Do not commit real values to the examples.

## Plugin roles: `frontend` and `backend`

These are tunnelbana plugin roles, not the usual browser-frontend/server-backend split. Each `[[frontend]]` is a different **entry surface** into the same verification service; frontends are alternatives, not stages that call one another.

| TOML block | Meaning |
| --- | --- |
| `[[frontend]] type = "ui"` | The thin browser catalog and presentation-initiation surface. It offers QR, DC API, or link invocation and asynchronously reaches status/completion. It does not make trust decisions. |
| `[[frontend]] type = "oidc"` | The relying-party-facing OpenID Connect provider endpoint. It handles RP clients, authorization, codes, and tokens; it is a protocol adapter, not a human user interface. |
| `[[backend]] type = "openid4vp"` | The wallet-facing verification engine. It creates and signs OpenID4VP requests, verifies wallet responses, obtains per-document go-trust permits, and returns verified results. The service requires exactly one block of this type. |

The quickstart, replica, and production examples configure both frontends so the same `openid4vp` backend can be used in two ways:

- **Direct browser flow:** browser → `ui` frontend → `openid4vp` backend ↔ wallet, followed by the existing status/completion endpoints.
- **OIDC relying-party flow:** RP → `oidc` frontend → `openid4vp` backend ↔ wallet, then the OIDC code/token flow returns the result to the RP.

The mdoc-only example configures only the `ui` frontend: its name disclosures are not unique, never-reassigned OIDC subject identifiers. For an SD-JWT or mdoc OIDC deployment, configure `subject_pointer` to a suitable identifier rather than a holder's name. For `zkp_req`, `subject_handle` selects the profile's pseudonym result handle; that verifier-scoped pseudonym becomes the OIDC subject instead of `subject_pointer`. When a response carries several credentials, every verified document contributes: each `attribute_map` pointer resolves against that credential's own claims (matched values merge into multi-valued attributes), the first credential names the reported issuer, and the subject comes from the first credential that carries `subject_pointer`.

`name` identifies a plugin instance and its routes; `type` selects its behavior. The nested `[backend.config.storage]` setting only selects memory or MongoDB state storage, and Longfellow/Vega “proof backends” are cryptographic implementations inside the OpenID4VP backend—neither is another top-level `[[backend]]` plugin.

## Trust boundary

**All issuer and verifier trust decisions belong to go-trust, including status-list signer trust.** Configure `pdp_endpoint`, `pdp_id`, and issuer/verifier policies there, including the `status-list-signer` action when credentials carry status references. The circuit catalog and the local circuit allowlist are integrity controls, not a trust registry. Do not add a second issuer/verifier trust path in this service.

The signing certificate chain is configured separately from the issuer's keys. Use a dedicated verifier key. `zkp_req` normally uses `x509_san_dns:<host>` as `client_id`; other formats retain `x509_hash`. Put the public host in the certificate SAN and authorize both subject forms, plus the test CA when SAN chain validation is required, in go-trust.

## HTTP, sessions, and storage

```toml
base_url = "https://verifier.example"
state_encryption_key = "replace-with-at-least-32-random-bytes"
previous_state_encryption_keys = ["previous-master-during-rotation"]
cookie_secure = true
cookie_same_site = "None"
state_cookie_max_age = 900
```

Use `mongodb` for every deployment with more than one process:

```toml
[backend.config.storage]
backend = "mongodb"
uri = "mongodb://verifier-user:password@mongo.internal:27017"
database = "siros_verifier"
collection = "presentation_flows"
```

Flow claims, replay protection, OIDC token consumption, and result collection must share one database. Use a least-privilege user with `readWrite` only on `siros_verifier`. A standalone MongoDB is shared storage, not database-level HA; use a replica set or managed HA service when required. `memory` is for explicitly single-process tests only.

A wallet response is processed under a `processing_lease_secs` lease (default 60, range 1..=900 but always strictly above `processing_deadline_secs`, so a value of 1 can never be valid) held on the flow. While the lease is live, a repeated wallet POST is refused as a replay. While the request is still live, a retry after the lease expires — for example after a runner crash — re-claims the slot and re-drives verification, so an interrupted flow recovers instead of hanging; the dispossessed claim can no longer finish. Once the request itself has expired, a retry is refused as a replay and the original claim may still finish and deliver late, since no re-drive could succeed by then. Terminal results are still persisted before notification, collection still delivers exactly once, and replay protection is unchanged. Records written before the lease field existed are treated as having an expired lease and are equally recoverable while the request is live.

Processing one claimed response is additionally bounded by `processing_deadline_secs` (default 45, range 1..=900, always strictly shorter than the lease). The budget is also capped by the lease time remaining after the claim, less a one-second finalize reserve, so the terminal write always happens while the claim is still held. When the budget expires — for example when go-trust or a status endpoint stalls — the flow fails closed with the `processing_deadline` refusal, the wallet receives HTTP 504, and the browser's status page shows the failure instead of waiting. Verification itself cannot touch the store: it produces a decision that the caller persists in a single bounded write, and a decision completing after the claim's safe window has closed (a synchronous verification overrun) is replaced by the deadline refusal instead of being persisted. Each outbound call has its own deadline as well: go-trust evaluations allow 10 seconds and status-list fetches 5 seconds, both with redirects disabled.

The current hard limits are 2 MiB for an HTTP body and compact JWE, and 1 MiB for decrypted response plaintext. Genuine Longfellow and Vega responses fit these bounds. The go-trust receipt cache holds at most 4096 receipts per verifier, evicting the oldest-inserted first; receipts that stop verifying are also evicted on their next lookup.

SD-JWT `status.status_list` references are fetched over HTTPS with a 5-second timeout, no redirects or ambient proxies, a streaming 64 KiB token limit, and a 1 MiB decompressed-list limit. Userinfo is refused. Only public IP addresses are allowed: literal private addresses are refused before dialing and DNS results are filtered at connection time, including IPv4-mapped IPv6 addresses. The credential issuer must be permitted before any status-list fetch occurs. Tokens must be `statuslist+jwt` with a valid ES256 signature, integer `iat`/`exp` values when present, a valid time window, and a subject matching the reference. Subject, structure, decompression, and index checks run before go-trust evaluates the signer with the `status-list-signer` action. Fetch/parse failures, untrusted signers, and nonzero status values fail closed.

`allow_invalid_status_list_certificates = true` disables TLS certificate validation and the public-address restriction for local conformance fixtures with self-signed servers. Never enable it in a real deployment. PDP responses have a streaming 1 MiB limit and also ignore ambient proxy settings.

## Request object retrieval

The default is `request_uri_method = "get"`. Set `request_uri_method = "post"` for wallets that require POST retrieval. The wallet supplies `wallet_nonce` in its form POST; the service echoes it in a re-signed request object and requires exactly one valid field. Missing, duplicate, unknown, or malformed fields are refused. GET retrieval remains unchanged and is always available alongside POST retrieval.

## UI presets

`frontend.config.presets` is an array of tables with `id`, `label`, and `dcql`. Registry-derived presets are merged by credential format and type; the registry's full claim list remains available for editing. Configure the requested claim subset for your deployment and include a subject claim—the first claim becomes the subject when no custom pointer is configured.

`backend.config.dcql` is the fallback when a request supplies no custom UI DCQL. Both this fallback and configured UI presets are validated during construction; an invalid configured default prevents startup. Browser-edited DCQL is still validated at flow initiation.

Only the QR display is modal, and its contents are replaced on every request. The complete page shows a neutral spinner while pending and then renders the decoded verified response or an error.

## `zkp_req`

The supported nym_auth profile is pseudonym plus optional `age_check`, with Longfellow and Vega native verification. Vega and Longfellow artifacts are independent allowlist entries. BBS and predicate-only requests fail closed.

Shared backend settings:

```toml
[backend.config.zkp]
system_id_values = ["urn:circuits:longfellow:nym_auth:v1", "urn:circuits:vega:nym_auth:v1"]
proof_system_values = ["longfellow-libzk-v1", "vega-v1"]
role = "mdoc-issuer"
verifier_id = "x509_san_dns:verifier.example"
auth_class_ref = "urn:eudi:loa:high"
```

Configure each UI/backend pair independently. Query ID, result handles, age bounds, subject handle, and attribute map must agree:

```toml
[[backend.config.zkp.profiles]]
query = { id = "nym_auth", format = "zkp_req",
  meta = { source_format = "mso_mdoc", doctype_value = "eu.europa.ec.eudi.nym_auth.1" },
  _req = [
    { fn_id = "pseudonym", return = "nym", params = {
      config = "known-offender-matching-ssc", ver = 1, prf = "sha-256" } },
  ] }
subject_handle = "nym"
attribute_map = { pseudonym = "nym" }

[[backend.config.zkp.profiles]]
query = { id = "nym_auth", format = "zkp_req",
  meta = { source_format = "mso_mdoc", doctype_value = "eu.europa.ec.eudi.nym_auth.1" },
  _req = [
    { fn_id = "pseudonym", return = "nym", params = {
      config = "known-offender-matching-ssc", ver = 1, prf = "sha-256" } },
    { fn_id = "age_check", return = "age", params = {
      ge = "1980-01-01", le = "2000-12-31" } },
  ] }
subject_handle = "nym"
attribute_map = { pseudonym = "nym", age = "age" }
```

The UI uses the same two objects with IDs `nym_auth_pseudonym` and `nym_auth_pseudonym_age`. Multiple profiles may share a query ID because their function lists differ; two byte-equivalent queries are rejected at startup. The legacy single `query`/`subject_handle`/`attribute_map` form remains supported for compatibility.

Age windows are inclusive and must span at least 365 days. Use a range satisfied by the intended holder; gdc's 1980–2000 range matches its 1990 test credential.

## Circuit catalog and allowlist

```toml
[backend.config.zkp.circuits]
sources = ["https://api.circuits.siros.org"]

[[backend.config.zkp.circuits.allow]]
system_id = "urn:circuits:longfellow:nym_auth:v1"
config = "known-offender-matching-ssc"
hash_circuit_id = "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729"
sig_circuit_id = "00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb"
block_enc_hash = 6983
block_enc_sig = 4679
artifact_id = "nymauth-longfellow-mdoc-v1"
artifact_sha256 = "92dd42fdf99673249eec33c7d07850bd9da66fbdab01ef26391e04c8341c1b7f"
artifact_bytes = 1062842

[[backend.config.zkp.circuits.allow]]
system_id = "urn:circuits:vega:nym_auth:v1"
config = "known-offender-matching-ssc"
artifact_id = "nymauth-vega-mdoc-v1"
artifact_sha256 = "4da5e73afb9be2682e70be793c9956a73304e21f31246aa10da0d3e95c926425"
artifact_bytes = 12205144
```

`api.circuits.siros.org` serves descriptors and immutable artifacts; `circuits.siros.org` is the human-facing site. Sources are ordered mirrors, each subject to the same operator pin. Startup prefetches and verifies catalog artifacts; wallet responses never fetch them. The service then prewarms every allowlisted native backend, validating local files and initializing Longfellow/Vega before the first presentation. If startup cannot obtain, verify, or initialize the exact allowed artifact, the service fails closed. Embedded library users may instead keep lazy backend loading by not calling `ZkpVerifier::prewarm`.

`artifact_sha256` and `artifact_bytes` always describe the **decompressed** bytes. Use exactly one of `artifact_id` and `artifact_path` per entry. `artifact_path` is the explicit offline alternative and bypasses catalog access. Do not put Longfellow parameters on a Vega entry.
