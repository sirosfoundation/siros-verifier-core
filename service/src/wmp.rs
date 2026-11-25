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
        // One provider = one WMP member: the identity string with the
        // X.509 chain as the MLS credential (the mtls/x5c schemes' shape).
        let provider =
            OpenMlsProvider::for_identity_with_certificate(&config.identity, Some(chain_der))
                .map_err(|e| anyhow!("the WMP member provider: {}", e.to_rpc()))?;
        // The config invites: parsed now, fail-fast.
        let config_invites = config
            .invites
            .iter()
            .map(|invite| ParsedInvite::parse(&invite.uri))
            .collect::<Result<Vec<_>>>()
            .with_context(|| "the [wmp] invites: a config-declared invite refused the parse")?;
        Ok(Self {
            config,
            provider,
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
}
