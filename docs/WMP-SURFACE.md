# The verifier's WMP surface — design

## Purpose

The verifier service gains a WMP (Wallet Messaging Protocol) surface: it
joins and **stays joined** to MLS groups, receives requests over them,
answers with its own verifiable presentations, consigns verified
presentation results, and relays inbound presentations onward — with
every decision policy-driven.

The orchestration this enables: a combination of verifier, issuers,
wallets and other tools in a WMP MLS group, coordinated as a group —
the QERDS consignment pattern (evidence chains, consignments) with the
verifier as a first-class group member.

## The embedding

The verifier embeds siros-wallet-core's client-side pieces as a library
— the engine-adapter-server (the wallet-facing HTTP engine) is NOT
embedded:

| Crate | What it gives |
|---|---|
| `wmp-core` | invitation parse/verify, sessions, the JSON-RPC method surface, the §5.6 identity-assertion shapes |
| `wmp-mls` | the OpenMLS `MlsProvider` — one provider = one WMP member (one identity, one key store, every group it holds is a group this member belongs to) |
| `siros-presentation`, `siros-credential` | holder-side presentation machinery — the vp_token generation |

The verifier's WMP identity is its own leaf (`x509:san:dns:<host>`);
the group state (MLS epochs, key schedules) persists in the flow store,
so membership survives restarts.

## The two policy engines — what decides what

**go-trust is a trust policy engine, not a generic PDP.** It is not
consulted for WMP decisions. The join/request/relay decisions are
**authorization** decisions delegated to the deployment's go-spocp PDP —
an external rules engine that speaks AuthZEN (`POST
/access/v1/evaluation`, the S-expressions documented in its ADR-10).
The verifier reuses its AuthZEN client shape (`HttpPdp`): a second
endpoint instance, fail-closed on any evaluation failure.

**The subject is the resource owner — the verifier.** The verifier owns
the resources every decision acts on (its membership, its credentials,
its consignments); the counterpart (the invite sender, the flow
initiator, the requester) rides the context. One uniform rule-writing
surface: every decision is "may **the verifier** do X, given context
C".

| Decision | Engine | Shape |
|---|---|---|
| Join this group? | go-spocp PDP | subject: the verifier; resource: the group; context: sender, provider, relay, purpose; action: `join` |
| Complete this flow? | go-spocp PDP | subject: the verifier; resource: the held credential; context: the initiator, the query; action: `present_credential` |
| Relay this presentation? | go-spocp PDP | subject: the verifier; resource: the candidate group; context: the presentation's process context; action: `relay_presentation` |

## The components

### 1. The invite gate

Invitations arrive through two channels, **both optional**:

- **Config-declared** (`[[wmp.invites]]` in the config): joined at boot.
- **HTTP** (`wmp.invite_endpoint = true`): `POST /wmp/invites` on the
  service, accepting an invite URI.

The gate parses the signed invitation, verifies its signature, and asks
the go-spocp PDP for the join decision. Refused invitations are
logged with the named reason; the group is never joined.

### 2. Multi-group membership

`wmp-mls`'s provider holds every joined group's MLS state, persisted
per-group in the flow store keyed by group id. The boot rehydrates
every group; membership survives restarts. The provider's one-identity
keystore holds the verifier's WMP key material.

### 2.1 Config-defined groups — the headless compositions

Groups may be **defined by configuration**: static combinations of
headless participants — verifiers, issuers, headless wallets, other
tools — that require no user interaction to assemble. The verifier
does not create such groups: **creation is an orchestrating
component's job** (the engine class — the wmp-mcp relay's, an
orchestration service's — the MLS create → KeyPackage resolution →
add-commit → Welcome flow driven by the orchestrator). The verifier's
role is the member's: it accepts the assembly the orchestrator
performs.

For this surface that means **joining config-identified groups is a
first-class requirement** — a bootstrap path alongside the invite: the
`[[wmp.groups]]` config names the groups the verifier belongs to (and
the counterpart/relay the membership is established through); the
orchestrating component assembles them headlessly; the same policy
gate decides each membership (the orchestrator is just another
counterpart whose request the go-spocp PDP evaluates — the
fail-closed posture unchanged, only the invitation UX replaced by the
declaration). The join machinery treats a config-declared group and a
received invite as two entrances to the same MLS exchange; the gate
evaluates both (the declaration's context names the configured group,
an invite's context names the signed invitation).

**Persistent group membership may itself be represented as AuthZEN PDP
queries**: "is this entity (its client_id) allowed to join the group
named X?" — subject: the entity's identifier; resource: the group
name; action: `join`. This is the SAME query shape the invite gate
already uses (the group name as the resource instead of the invite's
provider), so the PDP's rules can carry the membership policy for
persistent groups — the rules engine as the authority for who belongs
where — and the two bootstrap channels (an invite, a config
declaration) become two entrances to one policy primitive. A
deployment may then need no group roster in its config at all: the
verifier asks the PDP which groups it may join (or is told, per
query, for a named group).

The concrete mechanisms — how the group definition is expressed in
configuration, how the orchestrator discovers the participants and
drives the assembly, and how the declaration reconciles with the live
group across redeploys — are deliberately not chosen here: there are
many ways to define such constructions, and the options are discussed
later. The design records the requirement, the actor split, and the
PDP-query representation above as an input to that discussion.

### 3. The responder — a presentation flow, spec-native

The verifier's API is not an ad-hoc message body: it is an **OpenID4VP
flow for WMP**, following the wmp specification as the model —
`wmp-core` §6's structured flows, `wmp-openid4x` §3.2 (`oid4vp`) as the
reference shape, §6.5's extension requirements for a profile-defined
flow type. The verifier implements the **responder** role (the holder
producing presentations); any group member (a QERDS application,
another tool) initiates.

The flow (the verifier profile defines it per §6.5 — identifier,
capability, start params, steps, actions, completion result):

```
initiator (group member)              responder (the verifier)
    │                                     │
    │── wmp.flow.start ──────────────────>│   flow_type: the verifier profile's
    │        params: dcql_query (which     │   presentation flow type; the DCQL query
    │        credentials/claims wanted),   │   names what the initiator needs
    │        nonce, audience               │
    │                                     │── policy evaluation (go-spocp PDP):
    │<── wmp.flow.progress ───────────────│   `evaluating_policy` → `policy_evaluated`
    │                                     │   (the machine holder's analogue of
    │                                     │    awaiting_consent — §3.2's consent UX
    │                                     │    steps become the policy decision)
    │<── wmp.flow.progress ───────────────│   `generating_presentation`
    │<── wmp.flow.complete ───────────────│   the result (below) — or wmp.flow.error
    │                                     │   with the refusal reason
```

**The completion result follows the spec's own multi-token shape**
(`wmp-openid4x` §3.2.4): `vp_token` is a non-empty string, a non-empty
array of strings, or — for a DCQL request — **the object form
`{"<credential query id>": ["<presentation>", ...]}`**. A presentation
may result in multiple tokens; the held credentials are an array
(`[[wmp.credential]]`), and the query ids key the responses.

**The raw vp_token.** The QERDS application needs the raw token — the
result carries it verbatim, per the spec (the `vp_token` IS the raw
presentation; there is no processed form on this wire). Where the
relay leg consigns verified presentations onward, the same rule holds:
the raw token rides the consignment, per the QERDS evidence model.

### 3.1 The `verifier.present` flow type — the profile definition

Following wmp-core §6.5's extension requirements (the six things a
profile MUST define), the verifier profile:

**1. Flow type identifier:** `verifier.present`

**2. Capability:** `verifier` — negotiated at session create; a
`wmp.flow.start` of type `verifier.present` without the negotiated
capability answers `-31005` (Section 3.8.1's rule).

**3. `wmp.flow.start` params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `dcql_query` | object | REQUIRED | The DCQL query naming the credentials/claims the initiator wants from the verifier (the §3.2.1 model; `request_uri`/`presentation_definition` are not used — the verifier's credential catalogue is addressed directly) |
| `nonce` | string | REQUIRED | The initiator's challenge — binds the presentation (the §3.2.5 sign sub-flow's `nonce`) |
| `audience` | string | REQUIRED | The initiator's WMP identifier — the presentation's audience |
| `client_metadata` | object | OPTIONAL | The initiator's metadata, verbatim when its acceptance policy wants more |

**4. Progress steps:** `evaluating_policy` (the go-spocp evaluation
underway), `policy_evaluated` (payload: the decision's public shape —
allowed/denied, never the rule text), `generating_presentation`.

**5. Actions:** `cancel` (reason OPTIONAL) — the initiator may cancel;
the responder has no user-facing actions (the policy decision IS the
selection — no `select_credentials` equivalent, the machine holder
selects from its catalogue per the query).

**6. `wmp.flow.complete` result:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vp_token` | string / string[] / object | REQUIRED | The §3.2.4 shape: a non-empty string, a non-empty array of strings, or — for a DCQL request — **the object form `{"<credential query id>": ["<presentation>", ...]}`**. Multiple tokens per presentation; the raw presentation verbatim |

A policy denial completes as `wmp.flow.error` (code `-32603`-class,
`data.cause: policy_denied` — the reason is public, the rule text
never is).

**Two distinct mechanisms, both spec-native, both carrying raw
vp_tokens:**

| Mechanism | Spec | Who initiates | Use |
|---|---|---|---|
| The presentation flow | `wmp-openid4x` §3.2 (the model) | the group member | a QERDS application *requests* a presentation from the verifier |
| The identity_assertion | `wmp-core` §5.6 | the verifier (sender-initiated) | the verifier *attaches* its own vp_token to messages it sends — session binding, consignments |

### 4. The relay leg (inbound presentations → outbound WMP messages)

A verified presentation has a **process context** — the reason it
exists:

- **Expected**: the presentation completes an ongoing process (an armed
  flow, a session, a WMP request). It is consumed by the process that
  asked for it; no new decision fires.
- **Triggering**: the presentation (or its absence of a consuming
  process) starts other processes. Whether it may — and which — is a
  policy decision.

The verifier records the origin at start (the invocation, the
requester, the preset, the flow id); the verified outcome carries the
context forward — never inferred, always known.

On a verified outcome, each candidate relay target (`[[wmp.relay]]`:
the group, what rides — `verified_claims` | `vp_token` | `digest`) is an
AuthZEN evaluate with the full context:

```
(wmp_relay
  (action relay_presentation)
  (resource (type wmp_group)(id <group>))
  (subject (type verifier)(id <wmp-id>))
  (context (flow_kind qr|dc-api|link|wmp-request)
           (requester <id>)
           (credential <vct>)
           (result verified)))
```

No matching rule → no relay (fail-closed). The **conditions** live in
the deployment's `.spoc` artifact; the config names only endpoints and
candidate targets — the same division as the trust config (endpoints
in config, trust in go-trust).

The sending mechanics are the wmp-flows generic side: the §5.4 content
signature (raw P-1363), the MLS encrypt at the current epoch, the
unique message id, the evidence poll — owned by the embedded wmp-core;
the consignment references the flow for the evidence chain.

### 5. The two message-generating triggers

| Trigger | Outbound message |
|---|---|
| An inbound WMP request directed to the verifier | The §5.6 `verifiable_presentation` response (the verifier's own credential) |
| An inbound OID4VP presentation (verified) | The §5.4-signed consignment to an authorized group — the QERDS evidence leg |

Both are policy-gated; neither is a default.

## The config surface

The block rides the deployment config — `[backend.config.wmp]`, the
same place the keys and the PDP endpoint live:

```toml
[backend.config.wmp]
join_pdp_url = "http://sirosid-gdc-spocp.internal:8000/access/v1/evaluation"
invite_endpoint = true                          # POST /wmp/invites (optional)
allow_insecure_pdp = true                       # the private-network PDP posture (explicit)
identity = "x509:san:dns:sirosid-gdc-siros-verifier.fly.dev"
identity_chain_path = "/pki/verifier_ec_chain.pem"   # leaf first; its SAN DNS must match the identity
identity_key_path = "/pki/verifier_ec_private.pem"    # the leaf's key — the MLS signer (required)

[[backend.config.wmp.credentials]]              # the held credentials (an array:
format = "vc+sd-jwt"                            # a presentation may result in
type_id = "urn:example:verifier:1"              # multiple tokens, per the spec)
key_path = "..."
credential_path = "..."

[[backend.config.wmp.groups]]                   # config-identified groups the
id = "wmp:group:evidence-qerds"                # verifier JOINS (the orchestrator
via = "x509:san:dns:sirosid-gdc-wmp-mcp.fly.dev"  # creates; the gate decides)

[[backend.config.wmp.invites]]                  # config-declared (optional)
uri = "wmp://invite?data=..."

[[backend.config.wmp.relay]]                    # candidate targets; the PDP
group = "wmp:group:..."                        # decides per presentation
content = "verified_claims"                    # or vp_token | digest
```

No `wmp` block → no WMP surface at all. **The identity chain's leaf
must carry the identity's SAN DNS** — a chain for another host refuses
the boot. **The identity key is required** — the MLS credential is the
X.509 chain with the leaf's key as the signer (wallet-core 0.5.0's
signer-accepting constructor; the RFC 9420 §5.3.1 binding live, a
fresh-key signer never minted), and the validated chain feeds the §5.6
`x509_chain` assertions.

## The increments

1. **The WMP embedding skeleton** — `wmp-core` + `wmp-mls` as service
   dependencies; the config block; the multi-group session state in the
   flow store; the boot/rehydration. *(Landed — #78.)*
2. **The invite gate** — parse/verify; the go-spocp AuthZEN join
   client; both channels; the fail-closed refusals. *(The client and
   the join decision landed in #78; the signature verification and the
   MLS join exchange land with the wallet-core 0.5.0 re-pin.)*
3. **Config-defined group membership** — the verifier joins the
   config-identified groups (§2.1): the `[[wmp.groups]]` declarations,
   the same MLS join exchange as the invites, the same go-spocp gate
   evaluating each. **The join machinery — both channels — is the next
   implementation increment (on the wallet-core 0.5.0 re-pin); the
   config surface lands with it.** The orchestration side (how the
   orchestrator creates and assembles) is out of scope here.
4. **The responder** — the request shape, the PDP evaluation, the §5.6
   assertion generation.
5. **The relay leg** — the verified-outcome hook, the per-target PDP
   evaluation with the process context, the consignment.
6. **Tests + drills** — the invite refusal path, the multi-group
   persistence-across-restart, the request/response round trip, the
   relay policy branches.

## What this design deliberately is not

- No in-process rules engine — the PDP is always external and
  replaceable.
- No static credential→group mappings — conditions live in the rules
  artifact.
- No silent defaults — every join, request and relay is a fail-closed
  policy decision.
- The verifier does not process group messages not directed to it.
