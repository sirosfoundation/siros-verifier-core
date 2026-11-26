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
    /// The member's private key (PKCS#8 PEM): the leaf's key, the MLS
    /// signer. Required — the credential's key must bind (RFC 9420
    /// §5.3.1); a fresh-key signer is never minted.
    pub identity_key_path: String,
    /// The held credentials — an array: a presentation may result in
    /// multiple tokens (the spec's §3.2.4 object form). The
    /// `verifier.present` responder draws from these.
    #[serde(default)]
    pub credentials: Vec<WmpCredential>,
    /// Config-declared invites: joined at boot. Optional (the HTTP
    /// channel alone is a valid surface).
    #[serde(default)]
    pub invites: Vec<WmpInvite>,
    /// The config-identified groups (the candidate enumeration —
    /// permanent groups are delegated to the authz infrastructure):
    /// each is evaluated at boot ("may this entity join the group
    /// named X?"), the intent recorded; the join itself fires when
    /// the orchestrator delivers the Welcome (the restart
    /// reconciliation model — the member state is process-lifetime).
    #[serde(default)]
    pub groups: Vec<WmpGroupDeclaration>,
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

/// One config-identified group: a candidate the PDP decides on. The
/// `via` names the orchestrating counterpart the membership is
/// established through (the gate's context).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WmpGroupDeclaration {
    /// The group's identifier (the MLS GroupId the Welcome will carry).
    pub id: String,
    /// The orchestrating counterpart (the gate's context; the Welcome
    /// arrives from it).
    pub via: String,
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

/// A decoded public key, either MLS suite algorithm (Ed25519 RFC
/// 8410, P-256 RFC 5915). Decoded, not SPKI bytes: RFC 5480 §2.2
/// permits a compressed SEC1 point in a certificate's SPKI while the
/// key's own SPKI emits the uncompressed form — the same key, two
/// encodings. Comparison is on the key.
#[derive(Debug, PartialEq)]
pub enum PublicKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::PublicKey),
}

/// The private key's public half, decoded.
pub fn key_public(pkcs8_der: &[u8]) -> Result<PublicKey> {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    if let Ok(ed) = ed25519_dalek::SigningKey::from_pkcs8_der(pkcs8_der) {
        return Ok(PublicKey::Ed25519(ed.verifying_key()));
    }
    if let Ok(ec) = <p256::SecretKey as p256::pkcs8::DecodePrivateKey>::from_pkcs8_der(pkcs8_der) {
        return Ok(PublicKey::P256(ec.public_key()));
    }
    Err(anyhow!(
        "the private key is neither Ed25519 (RFC 8410) nor P-256 (RFC 5915) PKCS#8"
    ))
}

/// The leaf certificate's public key, decoded from its SPKI.
pub fn leaf_public_key(der: &[u8]) -> Result<PublicKey> {
    use ed25519_dalek::pkcs8::DecodePublicKey;
    use x509_cert::der::{Decode, Encode};
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|e| anyhow!("the leaf does not parse as a certificate: {e}"))?;
    // The full SPKI structure, DER-encoded — the pkcs8 decoders
    // accept the structure (RFC 5280 §4.1: the SubjectPublicKeyInfo).
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| anyhow!("the leaf's SPKI does not encode: {e}"))?;
    if let Ok(ed) = ed25519_dalek::VerifyingKey::from_public_key_der(&spki) {
        return Ok(PublicKey::Ed25519(ed));
    }
    if let Ok(p) = <p256::PublicKey as p256::pkcs8::DecodePublicKey>::from_public_key_der(&spki) {
        return Ok(PublicKey::P256(p));
    }
    Err(anyhow!(
        "the leaf's public key is neither Ed25519 (RFC 8410) nor P-256 (RFC 5915)"
    ))
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

/// The membership record: one joined group (the in-memory registry;
/// the MLS state itself is process-lifetime — the persistence model
/// in the design doc).
#[derive(Debug, Clone)]
pub struct JoinedGroup {
    /// The group's identifier (the MLS GroupId, base64url).
    pub id: String,
    /// The epoch at join time.
    pub epoch: i64,
}

/// The WMP surface: the member identity, the held credentials, the
/// parsed invites, the joined groups.
pub struct WmpSurface {
    /// Held for the following increments (the relay targets, the
    /// credentials the responder draws from); the skeleton reads the
    /// invites at construction.
    #[allow(dead_code)]
    config: WmpConfig,
    provider: OpenMlsProvider,
    /// The go-spocp PDP: every join decision evaluates here.
    pdp: SpocpPdp,
    /// The config-declared invites, parsed at construction (fail-fast
    /// at boot on any malformed URI or non-join purpose).
    config_invites: Vec<ParsedInvite>,
    /// The config-identified groups (the candidates the PDP decides
    /// on; the intent evaluated at boot).
    config_groups: Vec<WmpGroupDeclaration>,
    /// The joined groups: the in-memory registry. The MLS state is
    /// process-lifetime (the persistence model); the orchestrator
    /// reconciles membership across restarts.
    joined: tokio::sync::Mutex<Vec<JoinedGroup>>,
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
        // The configured identity is the x509:san:dns form — the
        // prefix is REQUIRED (a bare hostname is not a WMP identifier
        // scheme, and the AuthZEN subject must be the documented form).
        // The leaf's DNS name must then match: a chain for another host
        // is not this member's identity, and the failure refuses the
        // boot.
        let Some(dns_name) = config.identity.strip_prefix("x509:san:dns:") else {
            return Err(anyhow!(
                "the [wmp] identity must be the x509:san:dns:<host> form (got {:?}) — a bare name is not a WMP identifier scheme",
                config.identity
            ));
        };
        if !leaf_dns_names(&chain_der[0])?.contains(&dns_name.to_string()) {
            return Err(anyhow!(
                "the WMP identity chain's leaf carries no SAN DNS {dns_name:?} — it is not this member's identity"
            ));
        }
        // The member's private key (PKCS#8 PEM): the leaf's key, the
        // MLS signer. Required — the credential's key must bind (RFC
        // 9420 §5.3.1); wallet-core 0.5.0's signer-accepting
        // constructor makes the X.509 MLS credential honest, and this
        // surface requires the key (it never mints a fresh signer).
        let key_path = std::path::Path::new(&config.identity_key_path);
        let key_path = if key_path.is_absolute() {
            key_path.to_path_buf()
        } else {
            config_dir.join(key_path)
        };
        let key_pem = std::fs::read_to_string(&key_path)
            .with_context(|| format!("reading the WMP identity key {}", key_path.display()))?;
        let key_der = pem::parse_many(key_pem)?
            .into_iter()
            .find(|block| block.tag() == "PRIVATE KEY")
            .map(pem::Pem::into_contents)
            .ok_or_else(|| {
                anyhow!(
                    "the WMP identity key {} carries no PRIVATE KEY block",
                    key_path.display()
                )
            })?;
        // RFC 9420 §5.3.1's binding, checked HERE: the leaf's public
        // key must be the private key's public half, compared DECODED
        // not as SPKI bytes (RFC 5480 §2.2 permits a compressed SEC1
        // point in the certificate while the key's SPKI emits the
        // uncompressed form — the encodings differ for the SAME key).
        // (wmp-mls's signer-accepting constructor imports the key but
        // does not check the match — a peer's "leaf node signature is
        // not valid" would be the late, far side, failure. Both MLS
        // suite algorithms: Ed25519 RFC 8410 and P-256 RFC 5915.)
        let key_public = key_public(&key_der)
            .with_context(|| format!("the WMP identity key {}", key_path.display()))?;
        let leaf_public =
            leaf_public_key(&chain_der[0]).with_context(|| "the chain leaf's public key")?;
        if key_public != leaf_public {
            return Err(anyhow!(
                "the WMP identity key {} is not the chain leaf's key — the MLS credential's key must bind (RFC 9420 §5.3.1)",
                key_path.display()
            ));
        }
        // One provider = one WMP member: the identity string with the
        // X.509 chain as the MLS credential AND the leaf's key as the
        // signer — the key binding RFC 9420 §5.3.1 requires.
        let provider = OpenMlsProvider::for_identity_with_certificate_and_key(
            &config.identity,
            Some(chain_der),
            Some(key_der),
        )
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
        let config_groups = config.groups.clone();
        Ok(Self {
            config,
            provider,
            pdp,
            config_invites,
            config_groups,
            joined: tokio::sync::Mutex::new(Vec::new()),
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

    /// The config-identified groups' join decisions, evaluated at
    /// boot — the candidate enumeration: permanent groups are
    /// delegated to the authz infrastructure, so the config names the
    /// candidates and the PDP decides each ("may this entity join the
    /// group named X?"). An Allow is recorded as authorized; the join
    /// itself fires when the orchestrator delivers the Welcome (the
    /// restart reconciliation model).
    pub async fn evaluate_config_groups(&self) -> Vec<(&WmpGroupDeclaration, Decision)> {
        let mut decisions = Vec::with_capacity(self.config_groups.len());
        for group in &self.config_groups {
            let request = AuthZenRequest::join_group(self.identity(), group);
            let decision = self.pdp.evaluate(&request).await;
            match decision {
                Decision::Allow => tracing::info!(
                    group = %group.id,
                    via = %group.via,
                    "the group join is authorized — awaiting the orchestrator's Welcome"
                ),
                Decision::Deny => tracing::info!(
                    group = %group.id,
                    via = %group.via,
                    "the group join is denied"
                ),
            }
            decisions.push((group, decision));
        }
        decisions
    }

    /// The join: process a Welcome the orchestrator delivered, through
    /// the policy gate. The declared group id must match the Welcome's
    /// own MLS GroupId — a mismatch is a misdelivery, refused loudly.
    /// The joined group enters the registry (the epoch at join time).
    pub async fn join_by_welcome(
        &self,
        declaration: &WmpGroupDeclaration,
        welcome: &str,
    ) -> Result<JoinedGroup> {
        // The gate first: may this verifier join the group named X?
        // (Fail-closed — the PDP's denial refuses before any MLS
        // state touches the provider.)
        let request = AuthZenRequest::join_group(self.identity(), declaration);
        match self.pdp.evaluate(&request).await {
            Decision::Allow => {}
            Decision::Deny => {
                return Err(anyhow!(
                    "the group join for {:?} is denied by policy",
                    declaration.id
                ))
            }
        }
        // The Welcome processes: the provider's own key store holds the
        // KeyPackage's private key (the orchestrator added the member
        // by this surface's KeyPackage).
        use wmp_core::mls::MlsProvider as _;
        let (group_id, epoch) = self
            .provider
            .process_welcome(welcome)
            .map_err(|e| anyhow!("processing the Welcome: {}", e.to_rpc()))?;
        if group_id != declaration.id {
            return Err(anyhow!(
                "the Welcome is for group {group_id:?} but the join was declared for {:?} — a misdelivery",
                declaration.id
            ));
        }
        let joined = JoinedGroup {
            id: group_id,
            epoch,
        };
        tracing::info!(
            group = %joined.id,
            epoch = joined.epoch,
            "joined the group (the orchestrator's Welcome processed)"
        );
        self.joined.lock().await.push(joined.clone());
        Ok(joined)
    }

    /// The joined groups (the registry snapshot).
    pub async fn joined_groups(&self) -> Vec<JoinedGroup> {
        self.joined.lock().await.clone()
    }

    /// A fresh KeyPackage for this member — the orchestrator's add
    /// flow consumes it (the restart reconciliation: a restarted
    /// verifier presents a fresh package; the orchestrator re-adds).
    pub fn fresh_key_package(&self, cipher_suite: i64) -> Result<String> {
        use wmp_core::mls::MlsProvider as _;
        let package = self
            .provider
            .generate_key_package(cipher_suite)
            .map_err(|e| anyhow!("the key package: {}", e.to_rpc()))?;
        Ok(package.key_package)
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

    /// The persistent-group join's request: may **the verifier** join
    /// the group named X, established through the orchestrator `via`?
    /// The subject the resource owner, the group the resource — the
    /// same primitive as the invite's, the declaration's context.
    pub fn join_group(verifier_id: &str, group: &WmpGroupDeclaration) -> Self {
        Self {
            subject: AuthZenEntity {
                kind: "verifier",
                id: verifier_id.to_string(),
                properties: None,
            },
            resource: AuthZenEntity {
                kind: "wmp_group",
                id: group.id.clone(),
                properties: None,
            },
            action: "join",
            context: serde_json::json!({
                "via": group.via,
                "source": "config",
            }),
        }
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
                // The documented contract: the group's provider rides
                // the context alongside the sender/relay/purpose (the
                // resource names it too — the SPOCP rules may match on
                // either).
                "provider": invite.provider,
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
