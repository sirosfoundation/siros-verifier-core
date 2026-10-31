<!--
FILED 2026-10-26 as three separate issues (this document is the long-form background; the issues are shorter):
  freshness metadata: https://github.com/sirosfoundation/go-trust/issues/221
  batch /evaluations: https://github.com/sirosfoundation/go-trust/issues/222
  anchor export (design): https://github.com/sirosfoundation/go-trust/issues/223
The eMRTD source was dropped from scope (decision 2026-10-26). Grounded in go-trust at b0ec45c.
-->

# Batch evaluation, trust-data freshness and trust-anchor export for offline verifiers

## Why

A verifier library that runs inside native apps (proximity flows) and in a multi-tenant service needs to keep
working when the PDP is briefly unreachable, and eventually to run offline. go-trust stays a pure trust
service: it **does not sign decisions or exports**. The verifier core service wraps what go-trust returns in
its own signed, TTL-bound decision (see "Division of labour"). That needs three small, additive features in
go-trust. Existing clients are unaffected: they ignore the new fields.

## Division of labour

- go-trust: evaluates trust, serves anchors. Transport is authenticated by TLS and the tenant's PDP
  credentials. No signing key, no JWKS.
- Core service: calls go-trust, then signs a decision receipt (`typ authzen-decision+jwt`, claims: iss, aud,
  decision, req_sha256 over the JCS request, iat, nbf, refresh_after, exp, scope, reasons, trust_data, jti)
  with its own key. Apps and proximity clients pin the core service's key, not go-trust's. The core service
  clamps TTL to the `next_update` that go-trust reports, and to tenant `pdp.max_ttl`.
- The same applies to anchor lists: the core service snapshots go-trust's export and signs the curated list it
  distributes to apps.

## What exists today (checked in the code)

- `POST /evaluation` accepts `resource.type` of `jwk`, `x5c` and `kid` (`pkg/authzen/types.go`,
  `authzenclient.EvaluateX5C`). x5c chains are already supported.
- `action.name` selects a policy, which selects registries and constraints (`pkg/registry/policy.go`).
- `GET /.well-known/authzen-configuration` serves `PDPMetadata`. `access_evaluations_endpoint` and
  `signed_metadata` exist in the type but are **not served** (`pkg/api/handlers.go`: batch endpoint is commented
  out).
- go-trust only **verifies** signatures today (TSLs, LoTEs). It holds no signing key and this proposal keeps
  it that way.
- Registries that hold X.509 anchors: `etsi` (TSL), `lote`, `mdociaca`, `vical`, `mdocrical`, `static`, `rpcert`.
  An `emrtd` registry is described in `emrtd-trust-anchors` (CSCA anchors and CRLs); I did not find it in the
  checkout I read, so confirm the branch.

## Proposal

### A. Freshness metadata on decisions (unsigned)

So the core service can set a correct TTL, add to the existing response `context`:

```json
{ "decision": true,
  "context": { "id": "dec-123",
               "reason": { "...": "..." },
               "trust_data": [ { "registry": "etsi", "as_of": "2026-10-19T00:00:00Z",
                                 "next_update": "2026-10-26T00:00:00Z" } ] } }
```

- `trust_data`: for each registry consulted, the issue time and `next_update` of the underlying data (TSL
  issue and next-update time, LoTE sequence). The core service never caches past the earliest `next_update`.
- `reason` stays machine-readable (reason codes) so receipts can carry them.
- Optional per-action `cache_hint` (default, deny, max seconds) as policy config. The core service may
  shorten it, never extend it.
- Canonicalization of the request for `req_sha256` is the core service's concern (RFC 8785), not go-trust's.

### B. Batch evaluation

Serve `POST /evaluations` (AuthZEN access evaluations) and advertise `access_evaluations_endpoint`. Each item
yields its own decision with the metadata from A. Used for cache warming (all known issuers for a tenant's policies) before a
device goes offline.

### C. Trust-anchor export for offline X.509 validation

Cached decisions cover only previously seen keys and chains. Offline verification of *new* document-signer
certificates needs anchors. Add an export that builds on the existing registries and policies:

`GET /trust-anchors?action=<action.name>` (or `/trust-anchors/{policy}`)

- **Format: ETSI TS 119 602 LoTE-shaped JSON, unsigned**, built with the g119612 LoTE generator (without the
  signing step). An existing standard shape, so no new format is invented. The core service verifies nothing
  here beyond the TLS and PDP credentials it already trusts, then signs its own snapshot, so Rust and mobile
  clients need no XML-DSig and no per-registry parsing.
- **Content:** for the named policy, the anchors that the policy would accept, each with
  - certificate (DER, base64),
  - role (`action.name`) and credential-type or doctype scope (VICAL per-certificate doctype restrictions,
    ETSI service type, `credential_types`),
  - validity window and the **source** (registry name, TSL or LoTE URL, publisher, `as_of`),
  - constraints needed for path validation: allowed EKUs and certificate policy OIDs, max path length,
    status history (ETSI "granted at" date semantics),
  - CRLs where the registry has them (eMRTD) and their `next_update`.
- Envelope: `sequence` number, `issued_at`, `valid_until` (hard expiry for offline use), `ETag` and
  `If-None-Match`, `Cache-Control`.
- **Fail-closed export.** Anchors that cannot be expressed in the profile are omitted and listed under
  `excluded` with a reason (the eMRTD tooling already does this with `UNLOADABLE.txt`). The PDP must not
  silently skip a certificate it cannot parse.
- Registries without X.509 anchors (`didweb`, `didjwks`, `oidfed`, `fidomds3`) are reported as
  `unsupported_registries`. They keep working online only.

**Semantic parity is the hard part.** The online PDP does more than anchor matching (certificate policy OID
enrichment, RP identity extraction, over-request checks, ETSI status history). Offline evaluation in a client
is a conservative subset. Acceptance requires a differential test: for a corpus of chains (existing go-trust
testdata plus negative cases), online PDP decision and offline evaluation of the exported list must agree, and
any disagreement must be in the safe direction (offline denies).

**eMRTD anchors are out of scope** for this work (decision 2026-10-26); the licence question for `emrtd-trust-anchors` is not addressed here and no eMRTD source is part of the export.

### D. Discovery

Advertise in `/.well-known/authzen-configuration`: `access_evaluations_endpoint` and capability URNs for
`trust-data-freshness` and `trust-anchors`.

## Non-goals

No change to evaluation semantics, registry behavior or existing request and response shapes. No requirement
on existing clients. No new trust framework.

## Rollout

1. A: `trust_data` and `cache_hint` in the response context.
2. B: batch endpoint.
3. C: export for `lote`, `vical`, `mdociaca`, `static` first (X.509 anchors with clear scope), then `etsi`.
4. D: metadata and the draft profile text.

## Acceptance criteria

- `trust_data.next_update` is present and correct for every registry type consulted.
- The core service's signed receipt (separate repo) verifies in an independent client and is rejected when
  tampered, replayed for another request, expired, or signed by an unpinned key. This is tested in the core,
  not in go-trust.
- Exported list verifies offline and reproduces PDP decisions on the differential corpus, with zero
  offline-allow / online-deny disagreements.
- Existing clients and golden tests pass unchanged.

## Open questions

1. Should `exp` clamping to the soonest `next_update` also be offered as a server-side `max_valid_until`?
2. Is LoTE expressive enough for per-anchor path-validation constraints, or do we need an extension block?
3. Who may call `/trust-anchors`: public, or per-tenant authentication (licence question)?
