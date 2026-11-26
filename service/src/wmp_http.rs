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

use crate::wmp::{WmpGroupDeclaration, WmpSurface};

/// The endpoint's state: the surface, present only when `[wmp]` is.
pub struct WmpEndpointState {
    pub surface: std::sync::Arc<WmpSurface>,
}

/// The join delivery's body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinDelivery {
    /// The group's identifier — the config-declared candidate this
    /// Welcome completes. Must match the Welcome's own MLS GroupId.
    pub group_id: String,
    /// The orchestrating counterpart (the gate's context).
    pub via: String,
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
    let declaration = WmpGroupDeclaration {
        id: body.group_id.clone(),
        via: body.via.clone(),
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
