//! The WMP surface's inbound HTTP: the orchestrator's delivery channel.
//!
//! `POST /wmp/joins` — the headless join. The orchestrating component
//! (which created the group and added this verifier by its fresh
//! KeyPackage) delivers the Welcome; the surface's policy gate
//! evaluates the membership ("may this verifier join the group named
//! X?"), verifies the declared id against the Welcome's own MLS
//! GroupId, and processes the join. Served only when the `[wmp]` block
//! is present.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::wmp::WmpSurface;

/// The endpoint's state: the surface, present only when `[wmp]` is.
pub struct WmpEndpointState {
    pub surface: std::sync::Arc<WmpSurface>,
}

/// The join delivery's body. The `group_id` SELECTS the configured
/// candidate — it is never trusted policy context itself: the gate
/// evaluates the candidate's own `via`, and an id naming no candidate
/// is refused before any evaluation. The sender's own authentication
/// (mTLS, a delivery signature) is the open item; the configured
/// candidate is the trust anchor of today's channel.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinDelivery {
    /// The group's identifier — selects the config-declared candidate
    /// this Welcome completes. Must match the Welcome's own MLS GroupId.
    pub group_id: String,
    /// The base64url MLS Welcome (the add-commit's Welcome for this
    /// member's KeyPackage).
    pub welcome: String,
}

/// `POST /wmp/joins` — the orchestrator's delivery channel.
pub async fn post_join(
    state: web::Data<WmpEndpointState>,
    _req: HttpRequest,
    body: web::Json<JoinDelivery>,
) -> HttpResponse {
    // The candidate resolves from the CONFIG — the caller's context is
    // never trusted; the gate sees the configured `via`.
    let declaration = match state.surface.resolve_candidate(&body.group_id) {
        Ok(declaration) => declaration,
        Err(e) => {
            tracing::info!("the join delivery refused: {e:#}");
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "join_refused",
                "reason": format!("{e:#}"),
            }));
        }
    };
    match state
        .surface
        .join_by_welcome(&declaration, &body.welcome)
        .await
    {
        Ok(joined) => HttpResponse::Ok().json(serde_json::json!({
            "group_id": joined.id,
            "epoch": joined.epoch,
        })),
        Err(e) => {
            tracing::info!("the join delivery refused: {e:#}");
            HttpResponse::BadRequest().json(serde_json::json!({
                "error": "join_refused",
                // The refusal's reason — public, never the rule text
                // (the gate's denials carry no rule detail).
                "reason": format!("{e:#}"),
            }))
        }
    }
}

/// `GET /wmp/key-package` — mint a fresh KeyPackage for this member.
///
/// The orchestrating component fetches a package (minting fresh per
/// call — RFC 9420 KeyPackages are single-use), adds the member by
/// it, and delivers the resulting Welcome to `POST /wmp/joins`. The
/// private key material stays in the service's provider keystore.
///
/// **Known limit (wallet-core #127):** the pinned provider's
/// `generate_key_package` mints a fresh signer and a BasicCredential,
/// ignoring the configured certificate chain — the package advertises
/// the basic identity, not the X.509 one. The upstream
/// cert-bound packages close it; the re-pin drops this note.
pub async fn get_key_package(state: web::Data<WmpEndpointState>) -> HttpResponse {
    // Suite 1 (X25519/AES128GCM/Ed25519, the MUST) — the group's own
    // suite governs; this is the package the orchestrator's group
    // accepts.
    match state.surface.fresh_key_package(1) {
        Ok(key_package) => HttpResponse::Ok().json(serde_json::json!({
            "key_package": key_package,
        })),
        Err(e) => {
            tracing::error!("the key package mint failed: {e:#}");
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "key_package_failed",
            }))
        }
    }
}
