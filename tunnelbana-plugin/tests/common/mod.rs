//! Fixtures shared by the tunnelbana integration test binaries.
//!
//! Each integration binary compiles this module independently, so a binary
//! that uses only part of it would warn the rest dead — allow that here.

#![allow(dead_code)]

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use siros_verifier_core_tunnelbana::{
    ClaimResult, CollectResult, FinishResult, Flow, FlowStore, MemoryFlowStore, StoreResult,
    TerminalOutcome,
};

/// A flow store whose claim round-trip advances the shared clock as if the
/// store call had consumed `advance` seconds.
pub struct ClockBumpingClaimStore {
    pub inner: MemoryFlowStore,
    pub clock: Arc<AtomicI64>,
    pub advance: i64,
}

#[async_trait]
impl FlowStore for ClockBumpingClaimStore {
    async fn insert(&self, flow: Flow, now: i64) -> StoreResult<()> {
        self.inner.insert(flow, now).await
    }

    async fn get(&self, id: &str, now: i64) -> StoreResult<Option<Flow>> {
        self.inner.get(id, now).await
    }

    async fn claim(
        &self,
        id: &str,
        now: i64,
        claim_id: &str,
        lease_secs: i64,
    ) -> StoreResult<ClaimResult> {
        self.clock.fetch_add(self.advance, Ordering::SeqCst);
        self.inner.claim(id, now, claim_id, lease_secs).await
    }

    async fn finish(
        &self,
        id: &str,
        now: i64,
        claim_id: &str,
        outcome: TerminalOutcome,
        response_code: Option<&str>,
    ) -> StoreResult<FinishResult> {
        self.inner
            .finish(id, now, claim_id, outcome, response_code)
            .await
    }

    async fn collect(
        &self,
        id: &str,
        now: i64,
        response_code: Option<&str>,
    ) -> StoreResult<CollectResult> {
        self.inner.collect(id, now, response_code).await
    }
}

/// The §14.2 answer channel (issue #84): the done answer's `redirect_uri`
/// carries the one-time response code the completing browser presents.
/// Shared by the integration binaries so the channel's shape is pinned once.
pub fn bound_code(answer_body: &str) -> String {
    let answer: serde_json::Value =
        serde_json::from_str(answer_body).expect("the wallet answer is JSON");
    let redirect = answer["redirect_uri"]
        .as_str()
        .expect("the done answer carries redirect_uri");
    let code = redirect
        .rsplit("response_code=")
        .next()
        .expect("redirect_uri carries response_code");
    assert!(!code.is_empty(), "an empty response_code: {redirect}");
    code.to_owned()
}
