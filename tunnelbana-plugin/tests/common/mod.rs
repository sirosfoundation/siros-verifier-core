//! Fixtures shared by the tunnelbana integration test binaries.

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
    ) -> StoreResult<FinishResult> {
        self.inner.finish(id, now, claim_id, outcome).await
    }

    async fn collect(&self, id: &str, now: i64) -> StoreResult<CollectResult> {
        self.inner.collect(id, now).await
    }
}
