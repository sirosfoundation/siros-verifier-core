# RP and customer multitenancy design

Status: proposed, not implemented. This is a later-phase design and is not a
prerequisite for the current Docker testing release. Basic dynamic client
registration may land first with static verifier profiles; the full
customer-scoped configuration/control plane must not delay Phase 0,
operational maturity, algorithm agility, HA, or basic registration work.

## Goals

Support both of these without separate verification implementations:

- one container serving one RP or a small static set of RPs;
- a load-balanced cluster serving thousands of RPs, grouped into customers,
  with dynamic registration and customer-managed configuration.

The model must also:

- keep go-trust as the only issuer, verifier, and status-list signer authority;
- preserve strict parsing, replay protection, sealed sessions, ReaderAuth, and
  exactly-once completion;
- keep the verifier's browser surface thin and put customer administration in
  a separate control plane;
- allow a customer database to remain outside the verifier cluster's trusted
  network and administrative boundary.

## Terminology and current limitations

Use these identities explicitly instead of overloading `tenant`:

- **Customer:** an administrative organization that owns one or more RPs.
- **RP:** one registered OIDC client, identified by an immutable, globally
  unique `client_id` and associated with exactly one `customer_id`.
- **Verifier deployment:** one static or clustered verifier installation, with
  its own supported algorithms, trust connectors, keys, and flow storage.
- **Sector:** a set of RPs intentionally sharing a pseudonym/subject domain.
  The default is one sector per RP; a customer may explicitly group RPs.
- **Presentation flow:** one verification attempt, bound to an RP and an
  immutable configuration revision.

Current behavior is one static OpenID4VP verification tenant per process:

- `VpBackend` owns one signer, request policy, PDP/receipt identity, ZK
  verifier identity, and `SessionSealer` tenant name.
- `Flow` has no customer, RP, or configuration revision. `requester` is not an
  RP configuration selector. MongoDB flow transitions are keyed by flow ID.
- Receipt-cache entries are keyed only by the canonical AuthZEN request, so
  different RP policies could collide.
- OIDC clients are statically loaded into an in-memory store. There is no
  ordinary dynamic `/register` endpoint, although the upstream OIDC
  `ClientStore` interface is a reusable registration seam.
- The JS `tenant` option is only a form field. The built-in `UiFrontend` reads
  `dcql` and `scheme` and discards it. `backendOrigins` constrains URLs, not RP
  identity. It must never become an unauthenticated tenant selector.

A static single-RP deployment fits the current model. Multiple statically
registered RPs may intentionally share that model, but per-RP dynamic
configuration requires the changes below.

## Architecture

Separate registration, RP configuration, and presentation state:

1. **`ClientRegistrationService`** validates enrollment and performs dynamic
   registration. It uses the existing OIDC `ClientStore` abstraction where
   practical rather than creating a second client repository.
2. **`RelyingPartyConfigProvider`** resolves an RP's immutable verifier
   configuration snapshot. This is a new read-side abstraction.
3. **The existing `FlowStore`** continues to own presentation state, replay
   protection, and one-time results. It is not a customer configuration store.

Provide three configuration-provider implementations:

| Provider | Intended deployment |
| --- | --- |
| Static TOML | Current one-container/one-RP or small-static-RP deployments. No database or registration endpoint is required. |
| Shared MongoDB | Runners and registration service share a trusted configuration database. |
| Remote control plane | Runners call a bounded HTTPS API in front of the customer/configuration database. The database need not be network-accessible to runners. |

All providers return the same `RpConfigSnapshot`; the verification pipeline
does not branch on the provider's implementation.

### Configuration snapshot

A snapshot contains at least:

```text
schema_version
customer_id
client_id
revision (opaque, monotonic within the control plane)
valid_until / cache metadata
OIDC client registration and authentication data
presentation profile (DCQL, attribute map, subject policy, UI presets, TTLs)
go-trust policy alias
sector identity and approved verifier-identity reference
```

Snapshots are immutable and validated against the deployment's capability
set. Customers may edit only supported fields. They cannot set:

- arbitrary PDP endpoints or credentials, trust bypasses, or insecure HTTP;
- verifier signing private keys, circuit paths, or unsupported algorithms;
- arbitrary sealing masters or storage locations;
- status-list certificate-validation bypasses.

Private keys stay in deployment-managed KMS/HSM/secret references. OIDC client
secrets are stored only as hashes. Configuration responses never return secret
material or enrollment tokens.

## Enrollment and registration flow

1. A control-plane administrator creates a customer and an enrollment token.
2. The token record contains its hash, `customer_id`, expiry, revocation
   state, optional maximum uses, and an atomic use counter. A token may be
   shared by all RPs of that customer, as required by the enrollment model.
3. The customer sends a dynamic registration request with
   `Authorization: Bearer <enrollment-token>`. The request does not select a
   `customer_id`; the token determines it.
4. Registration validates exact redirect URIs, grant/response types, token
   authentication methods, JWKS/JWKS URI policy, and the deployment's supported
   profile. Public clients use PKCE. Wildcard redirect URIs and unbounded JWKS
   retrieval are refused.
5. The service atomically consumes/increments the token's allowance and
   creates the client. An idempotency key prevents duplicate clients on retry.
6. The response contains a server-generated `client_id` and a separate
   registration-access credential for subsequent RP management.

The enrollment token is not a customer-admin credential. Configuration edits
use customer-admin authentication and authorization in the control plane.
Changes are validated, versioned, audited, and guarded by an expected revision
for optimistic concurrency. Disable/revoke operations are also audited.

Registration writes go through the control plane or shared registration
service, not independently through every runner. This avoids split-brain
creation and inconsistent token consumption.

## Configuration API and cache

A remote control plane exposes a runner-specific API such as:

```http
GET /v1/verifier/clients/{client_id}
If-None-Match: "<revision>"

200 OK { "snapshot": { ... } }
304 Not Modified
```

Optional additions are a revision/cursor change feed and authenticated
invalidation notifications. Administrative customer/client CRUD belongs to a
separate API and must not be exposed through the runner API.

Each replica has a bounded cache with:

- immutable snapshot/revision entries and ETag revalidation;
- short positive and negative TTLs;
- per-`client_id` singleflight to prevent provider stampedes;
- provider connection/read/total deadlines and concurrency limits;
- bounded last-known-good behavior during provider outages;
- authenticated immediate invalidation for disable/revoke operations, with
  short revalidation as the fallback when notifications are unavailable.

Unknown, malformed, unsupported, expired, or revoked configurations fail
closed. Stale data never becomes an indefinite offline authorization path.
Cache size and negative-cache size are bounded independently.

The control plane offers strong consistency for registration and admin reads.
Runner reads may be eventually consistent within a documented propagation
SLO. Metrics include cache hits, provider latency/errors, revision lag,
invalidations, and rejected unknown clients.

## Flow and isolation rules

Resolve and validate the RP at flow initiation. Persist at least:

```text
customer_id
client_id
config_revision
sector_id
```

Pin the immutable snapshot, or the fields required to complete the flow, in
sealed flow state. A revision alone is insufficient if the provider disappears
or the configuration changes during holder consent. In-flight flows never
silently switch signers, DCQL, claim maps, PDP policy, or sector.

Every isolation boundary includes the RP namespace:

- session/result sealing keys and associated data;
- MongoDB keys or collections and atomic claim/finish/collect operations;
- browser state, OIDC codes, refresh tokens, and token-use replay markers;
- decision-receipt audience and cache keys;
- per-RP subjects and sector-scoped pseudonyms.

Use a migration namespace such as `deployment/customer/client/flow`. Existing
backend-name-sealed flows remain readable only until they expire; new flows
use the hierarchical namespace. Current backend-level atomic operations and
TTL handling are reusable after adding this scoping.

go-trust continues to make every trust decision. RP configuration selects only
a deployment-approved policy alias. Receipt caches must be partitioned by RP
or policy identity, not shared solely by AuthZEN request hash.

### Subject and ZK identity

RP separation does not automatically provide unlinkability. Ordinary OIDC
subjects and ZK pseudonyms need an explicit sector policy. Per-RP sectors are
the default; grouping within a customer is an intentional correlation choice.

For ZK, `verifier_id` is part of both proof verification and pseudonym
derivation. A sector therefore references a deployment-approved verifier
identity and its signing-key/certificate profile rather than an arbitrary
customer string. Per-RP sectors may require distinct identities; customer
sectors allow intentional sharing. Native circuit/backend caches remain
shared by `(system_id, config)` across RPs, so per-RP identities do not require
duplicate circuit loads.

## Deployment profiles

### Static single container / small RP set

Use the static provider and current inline client configuration. Registration
endpoints remain disabled. The backend name remains the sealing namespace for
that deployment unless the hierarchical model is explicitly enabled. This is
a compatibility profile, not a separate verification path.

### Large cluster

Use shared flow storage, the shared or remote registration/configuration
provider, and the same state-sealing masters and supported capability set on
every replica. Any replica may initiate, resume, complete, or collect any
flow; sticky load-balancer sessions are unnecessary. Configuration is lazy
and bounded per RP, so startup does not require loading thousands of clients.
Circuits and initialized native backends are shared only by their existing
immutable identifiers.

## Delivery plan

Full customer self-service is later-phase work. Deliver it in independently
reviewed steps:

1. Introduce snapshot/provider interfaces and static-TOML parity. Clarify the
   JS tenant documentation without changing presentation behavior.
2. Add shared client storage, enrollment-token handling, and dynamic
   registration with idempotency and strict client validation.
3. Add flow RP/revision binding, sealing/storage/receipt namespacing, and
   migration for in-flight sessions.
4. Add the remote configuration API, ETag caching, singleflight, and
   invalidation.
5. Integrate the external customer admin UI/API and deployment-managed sector
   identity provisioning.
6. Run scale and failure acceptance tests.

The customer admin UI is never added to the verifier runner. Basic dynamic
registration may ship before steps 4–5 using static verifier profiles.

## Acceptance criteria

- Existing static configurations behave unchanged and require no database.
- Registration retries are idempotent and one customer cannot register or edit
  another customer's RP.
- Any replica can complete any flow without cross-RP session, replay, result,
  token, receipt, or pseudonym leakage.
- Thousands of RPs have bounded memory use and no startup-wide configuration
  fetch or duplicate circuit initialization.
- Configuration revocation propagates within the documented SLO; provider
  outages do not create an indefinite stale-authorization path.
- Rolling upgrades preserve in-flight flows and old sealing namespaces only
  until their normal expiry.
- Cross-customer registration, replay, result collection, and configuration
  writes are denied in integration tests.
