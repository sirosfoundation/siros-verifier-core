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

| Decision | Engine | Shape |
|---|---|---|
| Join this group? | go-spocp PDP | subject: the invite sender; resource: the group/relay; action: `join` |
| Answer this request? | go-spocp PDP | resource: the verifier's credential; action: `request_vp_token` |
| Relay this presentation? | go-spocp PDP | resource: the candidate group; context: the presentation's process context; action: `relay_presentation` |

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

### 3. The responder API (inbound requests)

The verifier only acts on WMP messages **directed to it**. A group
message carrying a request (name the claims, carry a challenge) is
authorized at the PDP (`action: request_vp_token`) and answered with a
§5.6 `verifiable_presentation` — the verifier's **configured credential**
(the `[wmp.credential]` block, the same style as every other credential
surface: key paths + metadata), `audience` = the session, `nonce` =
the request's challenge. This is the QERDS identity_assertion exactly.

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

```toml
[wmp]
join_pdp_url = "http://sirosid-gdc-spocp.internal:8000/access/v1/evaluation"
invite_endpoint = true                          # POST /wmp/invites (optional)

[wmp.member_key]                                # the verifier's WMP key material
private_key_path = "..."
public_key_path = "..."

[wmp.credential]                                # the held credential for vp_tokens
key_path = "..."
chain_path = "..."

[[wmp.invites]]                                 # config-declared (optional)
uri = "wmp://invite?data=..."

[[wmp.relay]]                                   # candidate targets; the PDP
group = "wmp:group:..."                        # decides per presentation
content = "verified_claims"                    # or vp_token | digest
```

No `[wmp]` block → no WMP surface at all.

## The increments

1. **The WMP embedding skeleton** — `wmp-core` + `wmp-mls` as service
   dependencies; the config block; the multi-group session state in the
   flow store; the boot/rehydration.
2. **The invite gate** — parse/verify; the go-spocp AuthZEN join
   client; both channels; the fail-closed refusals.
3. **The responder** — the request shape, the PDP evaluation, the §5.6
   assertion generation.
4. **The relay leg** — the verified-outcome hook, the per-target PDP
   evaluation with the process context, the consignment.
5. **Tests + drills** — the invite refusal path, the multi-group
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
