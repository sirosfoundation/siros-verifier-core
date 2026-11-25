//! The verifier's WMP surface: MLS group membership, policy-driven.
//!
//! A verifier, issuers, wallets and other tools in a WMP MLS group,
//! orchestrated together — the verifier as a first-class group member
//! that joins groups, receives requests over them, answers with its own
//! verifiable presentations, and consigns verified presentation
//! results onward. The design lives in `docs/WMP-SURFACE.md`.
//!
//! **The two policy engines:** go-trust is a trust policy engine and is
//! never consulted for WMP decisions. The join/request/relay decisions
//! are authorization decisions delegated to the deployment's go-spocp
//! PDP — an external rules engine speaking AuthZEN — fail-closed.
//!
//! The subject of every AuthZEN evaluation is the resource owner: the
//! verifier. The counterpart (the invite sender, the flow initiator)
//! rides the context.
//!
//! This module is the skeleton (the first increment of the design doc's
//! five): the config, the member identity, the invitation parsing. The
//! join machinery (the session transport, the MLS Welcome exchange),
//! the `verifier.present` flow responder and the relay leg are the
//! following increments.

use anyhow::{anyhow, Context as _, Result};
use serde::Deserialize;
use wmp_core::invitation;
use wmp_mls::OpenMlsProvider;

/// The `[wmp]` block: the WMP surface's deployment config. Absent —
/// the whole block — the service has no WMP surface at all.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WmpConfig {
    /// The go-spocp PDP: the AuthZEN endpoint that decides every join,
    /// presentation and relay. Fail-closed: unreachable or malformed
    /// answers deny.
    pub join_pdp_url: String,
    /// Serve `POST /wmp/invites` (the live invite channel). Optional;
    /// the config-declared invites alone are a valid surface.
    #[serde(default)]
    pub invite_endpoint: bool,
    /// Permit a plain-HTTP PDP on a non-loopback address (the fly 6PN
    /// posture). Off by default: the URL refuses and names this switch,
    /// the same explicit policy edge the deployment's own PDP has.
    #[serde(default)]
    pub allow_insecure_pdp: bool,
    /// The verifier's WMP identifier (its `x509:san:dns:<host>` leaf
    /// identity; the MLS credential carries the certificate chain).
    pub identity: String,
    /// The member's X.509 chain (PEM file, leaf first): the MLS
    /// credential and the §5.6 `x509_chain` assertions derive from it.
    pub identity_chain_path: String,
    /// The held credentials — an array: a presentation may result in
    /// multiple tokens (the spec's §3.2.4 object form). The
    /// `verifier.present` responder draws from these.
    #[serde(default)]
    pub credentials: Vec<WmpCredential>,
    /// Config-declared invites: joined at boot. Optional (the HTTP
    /// channel alone is a valid surface).
    #[serde(default)]
    pub invites: Vec<WmpInvite>,
    /// The relay targets: candidate groups a verified presentation may
    /// consign to. The PDP decides per presentation — the config names
    /// the candidates, never the conditions.
    #[serde(default)]
    pub relay: Vec<WmpRelayTarget>,
}

/// One held credential: the verifier's own credential for the
/// `verifier.present` flow's vp_tokens and the §5.6 assertions.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WmpCredential {
    /// The credential's format on the wire (`vc+sd-jwt`, `mso_mdoc`).
    pub format: String,
    /// The credential's type identifier (the `vct` / `doctype`): what
    /// a DCQL query's `vct_values`/`doctype_value` matches.
    pub type_id: String,
    /// The holder key (PEM): the credential's subject key.
    pub key_path: String,
    /// The credential itself (the issued artifact: the SD-JWT, the
    /// mdoc) — the presentation machinery's input.
    pub credential_path: String,
}

/// A config-declared invite: joined at boot.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WmpInvite {
    /// The `wmp://invite?data=...` URI.
    pub uri: String,
}

/// One candidate relay target.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WmpRelayTarget {
    /// The group the consignment lands in.
    pub group: String,
    /// What rides: `verified_claims` | `vp_token` | `digest`. The raw
    /// vp_token is the QERDS application's need — the spec knows no
    /// processed form on this wire.
    pub content: String,
}

/// One DER certificate's SAN DNS names (the same x509-cert parse the
/// core crate's trust evaluation uses). A leaf that does not parse
/// refuses the boot — a malformed identity is worse than none.
fn leaf_dns_names(der: &[u8]) -> Result<Vec<String>> {
    use x509_cert::der::Decode;
    use x509_cert::ext::pkix::SubjectAltName;
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|e| anyhow!("the leaf does not parse as a certificate: {e}"))?;
    let san_oid = x509_cert::der::oid::ObjectIdentifier::new_unwrap("2.5.29.17");
    let mut dns_names = Vec::new();
    for extension in cert.tbs_certificate.extensions.iter().flatten() {
        if extension.extn_id == san_oid {
            let san = SubjectAltName::from_der(extension.extn_value.as_bytes())
                .map_err(|e| anyhow!("the leaf's SAN does not parse: {e}"))?;
            for name in san.0.iter() {
                if let x509_cert::ext::pkix::name::GeneralName::DnsName(host) = name {
                    dns_names.push(host.to_string());
                }
            }
        }
    }
    Ok(dns_names)
}

/// A parsed, validated invite: the join decision's input.
///
/// The signature verification (`wmp-core`'s `InvitationVerifier`) and
/// the go-spocp join evaluation are the next increment's work; this
/// skeleton records what the gate will consume.
#[derive(Debug)]
pub struct ParsedInvite {
    /// The raw URI (for logs and the report).
    pub uri: String,
    /// The counterpart whose group this is.
    pub provider: String,
    /// The invite sender.
    pub sender: String,
    /// The relay the sender is reached through.
    pub relay: String,
    /// The purpose (`join` for group invitations; `session` ones are
    /// refused at this gate — they bootstrap sessions, not groups).
    pub purpose: String,
}

impl ParsedInvite {
    /// Parse an invite URI into the gate's input, refusing what cannot
    /// be parsed or is not a group invitation.
    pub fn parse(uri: &str) -> Result<Self> {
        let inv =
            invitation::parse_invitation_uri(uri).map_err(|e| anyhow!("invite {uri}: {e}"))?;
        if inv.purpose != invitation::INVITATION_PURPOSE_JOIN {
            return Err(anyhow!(
                "invite {uri}: purpose {:?} is not a group invitation (join) — the WMP surface joins groups, it does not bootstrap sessions",
                inv.purpose
            ));
        }
        Ok(Self {
            uri: uri.to_string(),
            provider: inv.provider,
            sender: inv.sender,
            relay: inv.relay,
            purpose: inv.purpose,
        })
    }
}

/// The WMP surface: the member identity, the held credentials, the
/// parsed invites. The group state (the MLS membership) arrives with
/// the join machinery's increment.
pub struct WmpSurface {
    /// Held for the following increments (the relay targets, the
    /// credentials the responder draws from); the skeleton reads the
    /// invites at construction.
    #[allow(dead_code)]
    config: WmpConfig,
    #[allow(dead_code)]
    provider: OpenMlsProvider,
    /// The go-spocp PDP: every join decision evaluates here.
    pdp: SpocpPdp,
    /// The config-declared invites, parsed at construction (fail-fast
    /// at boot on any malformed URI or non-join purpose).
    config_invites: Vec<ParsedInvite>,
}

impl WmpSurface {
    /// Build the surface from the config: the member provider (the
    /// identity chain loaded from its path), the config invites parsed
    /// and validated. Any failure refuses the boot — a half-joined
    /// surface is worse than none.
    pub fn new(config: WmpConfig, config_dir: &std::path::Path) -> Result<Self> {
        // The identity chain: leaf first, the same convention every
        // other certificate path in this service uses.
        let chain_path = std::path::Path::new(&config.identity_chain_path);
        let chain_path = if chain_path.is_absolute() {
            chain_path.to_path_buf()
        } else {
            config_dir.join(chain_path)
        };
        let chain_pem = std::fs::read_to_string(&chain_path)
            .with_context(|| format!("reading the WMP identity chain {}", chain_path.display()))?;
        let chain_der: Vec<Vec<u8>> = pem::parse_many(chain_pem)?
            .into_iter()
            .filter(|block| block.tag() == "CERTIFICATE")
            .map(|block| block.into_contents())
            .collect();
        if chain_der.is_empty() {
            return Err(anyhow!(
                "the WMP identity chain {} carries no certificates",
                chain_path.display()
            ));
        }
        // The leaf's DNS name must match the configured identity (the
        // x509:san:dns form): a chain for another host is not this
        // member's identity, and the failure refuses the boot.
        let dns_name = config
            .identity
            .strip_prefix("x509:san:dns:")
            .unwrap_or(&config.identity);
        if !leaf_dns_names(&chain_der[0])?.contains(&dns_name.to_string()) {
            return Err(anyhow!(
                "the WMP identity chain's leaf carries no SAN DNS {dns_name:?} — it is not this member's identity"
            ));
        }
        // One provider = one WMP member. At wallet-core 0.4.4 the basic
        // credential is the only HONEST construction:
        // for_identity_with_certificate mints a fresh Ed25519 signer
        // regardless of the chain's key, so an X.509 MLS credential
        // built from a P-256 leaf violates RFC 9420 §5.3.1's key
        // binding (this PR's review found it). The basic credential is
        // authenticated outside MLS — the session's own channel — and
        // the validated chain still feeds the §5.6 x509_chain
        // assertions. The X.509 MLS credential lands when wmp-mls
        // gains the signer-accepting constructor; the switch is this
        // one call.
        let provider = OpenMlsProvider::for_identity(&config.identity)
            .map_err(|e| anyhow!("the WMP member provider: {}", e.to_rpc()))?;
        // The config invites: parsed now, fail-fast.
        let config_invites = config
            .invites
            .iter()
            .map(|invite| ParsedInvite::parse(&invite.uri))
            .collect::<Result<Vec<_>>>()
            .with_context(|| "the [wmp] invites: a config-declared invite refused the parse")?;
        let pdp = SpocpPdp::new(&config.join_pdp_url, config.allow_insecure_pdp)
            .with_context(|| "the [wmp] join_pdp_url")?;
        Ok(Self {
            config,
            provider,
            pdp,
            config_invites,
        })
    }

    /// The config-declared invites (parsed, validated).
    pub fn config_invites(&self) -> &[ParsedInvite] {
        &self.config_invites
    }

    /// The verifier's WMP identity.
    pub fn identity(&self) -> &str {
        self.provider.identity()
    }

    /// The invite gate: the join decision for one parsed invite. The
    /// go-spocp PDP evaluates — the subject the resource owner (this
    /// verifier), the group the resource, the sender/relay/purpose the
    /// context — fail-closed.
    ///
    /// The signature verification (`wmp-core`'s `InvitationVerifier`,
    /// the sender's key resolved via `wmp.resolve`) and the MLS join
    /// exchange are the next increment's work; until they land, an
    /// Allow is recorded as authorized-not-yet-joined and nothing is
    /// joined — the surface never pretends a join it did not perform.
    pub async fn join_decision(&self, invite: &ParsedInvite) -> Decision {
        let request = AuthZenRequest::join(self.identity(), invite);
        let decision = self.pdp.evaluate(&request).await;
        match decision {
            Decision::Allow => tracing::info!(
                group = %invite.provider,
                sender = %invite.sender,
                "the join decision allows — the MLS join exchange is the next increment (not yet joined)"
            ),
            Decision::Deny => tracing::info!(
                group = %invite.provider,
                sender = %invite.sender,
                "the join decision denies"
            ),
        }
        decision
    }

    /// The config-declared invites' decisions, evaluated at boot.
    pub async fn evaluate_config_invites(&self) -> Vec<(&ParsedInvite, Decision)> {
        let mut decisions = Vec::with_capacity(self.config_invites.len());
        for invite in &self.config_invites {
            let decision = self.join_decision(invite).await;
            decisions.push((invite, decision));
        }
        decisions
    }
}

// ---- the go-spocp AuthZEN client ------------------------------------------------

/// One AuthZEN entity: the go-spocp `EvaluationRequest`'s subject or
/// resource shape (`{type, id, properties?}`).
#[derive(Debug, Clone)]
pub struct AuthZenEntity {
    pub kind: &'static str,
    pub id: String,
    pub properties: Option<serde_json::Value>,
}

impl AuthZenEntity {
    /// The entity as the go-spocp wire JSON.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = serde_json::json!({
            "type": self.kind,
            "id": self.id,
        });
        if let Some(properties) = &self.properties {
            value["properties"] = properties.clone();
        }
        value
    }
}

/// One AuthZEN evaluation request: the go-spocp PDP's exact wire shape
/// (`POST /access/v1/evaluation`, the `EvaluationRequest` of its
/// pkg/authzen). The subject is the resource owner — the verifier —
/// for every decision this surface makes; the counterpart rides the
/// context.
#[derive(Debug, Clone)]
pub struct AuthZenRequest {
    pub subject: AuthZenEntity,
    pub resource: AuthZenEntity,
    pub action: &'static str,
    pub context: serde_json::Value,
}

impl AuthZenRequest {
    /// The request as the go-spocp wire JSON.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "subject": self.subject.to_json(),
            "resource": self.resource.to_json(),
            "action": {"name": self.action},
            "context": self.context,
        })
    }

    /// The join decision's request: may **the verifier** join this
    /// group, given the invite's attributes in context.
    pub fn join(verifier_id: &str, invite: &ParsedInvite) -> Self {
        Self {
            subject: AuthZenEntity {
                kind: "verifier",
                id: verifier_id.to_string(),
                properties: None,
            },
            resource: AuthZenEntity {
                kind: "wmp_group",
                id: invite.provider.clone(),
                properties: None,
            },
            action: "join",
            context: serde_json::json!({
                "sender": invite.sender,
                "relay": invite.relay,
                "purpose": invite.purpose,
            }),
        }
    }
}

/// The evaluation's outcome. Fail-closed: every failure mode — the
/// PDP unreachable, the response malformed, the decision not a
/// boolean — denies, with the reason named for the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// Parse a go-spocp `EvaluationResponse`: `{"decision": <bool>,
/// "context"?: ...}`. A present-but-non-boolean decision is malformed
/// (refused), never guessed.
pub fn parse_authzen_decision(response: &serde_json::Value) -> Result<Decision> {
    match response.get("decision") {
        Some(serde_json::Value::Bool(true)) => Ok(Decision::Allow),
        Some(serde_json::Value::Bool(false)) => Ok(Decision::Deny),
        Some(other) => Err(anyhow!(
            "the go-spocp PDP answered a non-boolean decision ({other}) — refusing rather than guessing"
        )),
        None => Err(anyhow!(
            "the go-spocp PDP answered no decision — refusing rather than guessing"
        )),
    }
}

/// The go-spocp PDP client: the deployment's external rules engine.
/// The transport is the service's existing hardened AuthZEN client
/// (bounded, no redirects, no ambient proxies); the policy URL scheme
/// discipline is the same as the deployment's own PDP — HTTPS or
/// loopback, plain HTTP on a private network only behind the explicit
/// config switch.
pub struct SpocpPdp {
    pdp: siros_verifier_core_tunnelbana::HttpPdp,
}

// evaluate rides the PdpClient trait.
use siros_verifier_core_tunnelbana::PdpClient as _;

impl SpocpPdp {
    /// Build the client from the config: the URL's scheme is enforced
    /// here (HTTPS or loopback; plain HTTP only when the explicit
    /// `allow_insecure_pdp` is set).
    pub fn new(url: &str, allow_insecure: bool) -> Result<Self> {
        let pdp = if allow_insecure {
            siros_verifier_core_tunnelbana::HttpPdp::new_allow_http(
                url,
                None,
                std::time::Duration::from_secs(10),
            )
        } else {
            siros_verifier_core_tunnelbana::HttpPdp::new(
                url,
                None,
                std::time::Duration::from_secs(10),
            )
        }
        .map_err(|e| anyhow!("the go-spocp PDP URL: {e}"))?;
        Ok(Self { pdp })
    }

    /// Evaluate one request, fail-closed: any transport or parse
    /// failure denies.
    pub async fn evaluate(&self, request: &AuthZenRequest) -> Decision {
        match self.pdp.evaluate(&request.to_json()).await {
            Ok(response) => match parse_authzen_decision(&response) {
                Ok(decision) => decision,
                Err(e) => {
                    tracing::warn!("the go-spocp PDP answered malformed: {e:#} — denying");
                    Decision::Deny
                }
            },
            Err(e) => {
                tracing::warn!("the go-spocp PDP unreachable: {e} — denying");
                Decision::Deny
            }
        }
    }
}
