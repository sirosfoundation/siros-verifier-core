//! Shared flow state and atomic wallet-response replay protection.
//!
//! A record is both the presentation flow and its replay tombstone. Terminal
//! results are sealed by the caller; storage implementations never see verified
//! attributes or the wallet-response private key in plaintext.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub const FLOW_SCHEMA_VERSION: u32 = 1;
pub const FLOW_RETENTION_GRACE_SECS: i64 = 900;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
pub enum Outcome {
    Pending,
    Processing(String),
    Done(String),
    Failed(String),
    Collected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flow {
    #[serde(rename = "_id")]
    pub id: String,
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub jar: String,
    /// The response-decryption key exists only inside this sealed session.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sealed_session: String,
    pub expires_at: i64,
    /// Absolute retention deadline for terminal results and replay tombstones.
    pub retain_until: i64,
    pub requester: Option<String>,
    pub attribute_map: BTreeMap<String, String>,
    pub subject_pointer: String,
    pub outcome: Outcome,
}

impl Flow {
    pub fn expired(&self, now: i64) -> bool {
        matches!(self.outcome, Outcome::Pending) && now >= self.expires_at
    }

    pub fn retained(&self, now: i64) -> bool {
        now < self.retain_until
    }

    fn clear_secrets(&mut self) {
        self.jar.clear();
        self.sealed_session.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalOutcome {
    Done(String),
    Failed(String),
}

impl From<TerminalOutcome> for Outcome {
    fn from(value: TerminalOutcome) -> Self {
        match value {
            TerminalOutcome::Done(result) => Self::Done(result),
            TerminalOutcome::Failed(code) => Self::Failed(code),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimResult {
    Claimed(Flow),
    Unknown,
    Expired,
    Replay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishResult {
    Finished,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectResult {
    Unknown,
    Pending,
    Expired,
    Done(String),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowStoreError(pub String);

impl std::fmt::Display for FlowStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FlowStoreError {}

pub type StoreResult<T> = std::result::Result<T, FlowStoreError>;

#[async_trait]
pub trait FlowStore: Send + Sync {
    async fn insert(&self, flow: Flow, now: i64) -> StoreResult<()>;
    async fn get(&self, id: &str, now: i64) -> StoreResult<Option<Flow>>;
    async fn claim(&self, id: &str, now: i64, claim_id: &str) -> StoreResult<ClaimResult>;
    async fn finish(
        &self,
        id: &str,
        now: i64,
        claim_id: &str,
        outcome: TerminalOutcome,
    ) -> StoreResult<FinishResult>;
    async fn collect(&self, id: &str, now: i64) -> StoreResult<CollectResult>;
}

/// Single-process store used by tests and explicitly configured local deployments.
#[derive(Default)]
pub struct MemoryFlowStore {
    flows: Mutex<HashMap<String, Flow>>,
}

impl MemoryFlowStore {
    fn lock(&self) -> StoreResult<std::sync::MutexGuard<'_, HashMap<String, Flow>>> {
        self.flows
            .lock()
            .map_err(|_| FlowStoreError("flow store lock poisoned".into()))
    }

    fn remove_expired_retention(flows: &mut HashMap<String, Flow>, id: &str, now: i64) {
        if flows.get(id).is_some_and(|flow| !flow.retained(now)) {
            flows.remove(id);
        }
    }
}

#[async_trait]
impl FlowStore for MemoryFlowStore {
    async fn insert(&self, flow: Flow, now: i64) -> StoreResult<()> {
        let mut flows = self.lock()?;
        // Start-only abandonment must not accumulate sealed records forever.
        flows.retain(|_, existing| existing.retained(now));
        if flows.contains_key(&flow.id) {
            return Err(FlowStoreError("duplicate flow id".into()));
        }
        flows.insert(flow.id.clone(), flow);
        Ok(())
    }

    async fn get(&self, id: &str, now: i64) -> StoreResult<Option<Flow>> {
        let mut flows = self.lock()?;
        Self::remove_expired_retention(&mut flows, id, now);
        Ok(flows.get(id).cloned())
    }

    async fn claim(&self, id: &str, now: i64, claim_id: &str) -> StoreResult<ClaimResult> {
        let mut flows = self.lock()?;
        Self::remove_expired_retention(&mut flows, id, now);
        let Some(flow) = flows.get_mut(id) else {
            return Ok(ClaimResult::Unknown);
        };
        if flow.expired(now) {
            return Ok(ClaimResult::Expired);
        }
        if !matches!(flow.outcome, Outcome::Pending) {
            return Ok(ClaimResult::Replay);
        }
        flow.outcome = Outcome::Processing(claim_id.to_owned());
        Ok(ClaimResult::Claimed(flow.clone()))
    }

    async fn finish(
        &self,
        id: &str,
        now: i64,
        claim_id: &str,
        outcome: TerminalOutcome,
    ) -> StoreResult<FinishResult> {
        let mut flows = self.lock()?;
        Self::remove_expired_retention(&mut flows, id, now);
        let Some(flow) = flows.get_mut(id) else {
            return Ok(FinishResult::Conflict);
        };
        if !matches!(&flow.outcome, Outcome::Processing(current) if current == claim_id) {
            return Ok(FinishResult::Conflict);
        }
        flow.outcome = outcome.into();
        flow.clear_secrets();
        Ok(FinishResult::Finished)
    }

    async fn collect(&self, id: &str, now: i64) -> StoreResult<CollectResult> {
        let mut flows = self.lock()?;
        Self::remove_expired_retention(&mut flows, id, now);
        let Some(flow) = flows.get_mut(id) else {
            return Ok(CollectResult::Unknown);
        };
        let result = match &flow.outcome {
            Outcome::Pending if flow.expired(now) => CollectResult::Expired,
            Outcome::Pending | Outcome::Processing(_) => return Ok(CollectResult::Pending),
            Outcome::Done(result) => CollectResult::Done(result.clone()),
            Outcome::Failed(code) => CollectResult::Failed(code.clone()),
            Outcome::Collected => return Ok(CollectResult::Unknown),
        };
        flow.outcome = Outcome::Collected;
        flow.clear_secrets();
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const NOW: i64 = 1_800_000_000;

    fn flow(id: &str) -> Flow {
        Flow {
            id: id.into(),
            schema_version: FLOW_SCHEMA_VERSION,
            jar: "request-jwt".into(),
            sealed_session: "sealed-private-session".into(),
            expires_at: NOW + 300,
            retain_until: NOW + 300 + FLOW_RETENTION_GRACE_SECS,
            requester: Some("https://rp.example".into()),
            attribute_map: BTreeMap::new(),
            subject_pointer: "/sub".into(),
            outcome: Outcome::Pending,
        }
    }

    #[tokio::test]
    async fn only_one_response_claim_and_one_collection_win() {
        let store = Arc::new(MemoryFlowStore::default());
        store.insert(flow("flow-1"), NOW).await.unwrap();
        let (a, b) = tokio::join!(
            store.claim("flow-1", NOW, "claim-a"),
            store.claim("flow-1", NOW, "claim-b")
        );
        assert!(matches!(a.unwrap(), ClaimResult::Claimed(_)));
        assert_eq!(b.unwrap(), ClaimResult::Replay);
        assert_eq!(
            store
                .finish(
                    "flow-1",
                    NOW,
                    "claim-b",
                    TerminalOutcome::Failed("stale".into())
                )
                .await
                .unwrap(),
            FinishResult::Conflict
        );
        assert_eq!(
            store
                .finish(
                    "flow-1",
                    NOW + 301,
                    "claim-a",
                    TerminalOutcome::Done("sealed-result".into())
                )
                .await
                .unwrap(),
            FinishResult::Finished,
            "a response claimed before request expiry may finish"
        );
        let (a, b) = tokio::join!(
            store.collect("flow-1", NOW + 302),
            store.collect("flow-1", NOW + 302)
        );
        assert_eq!(a.unwrap(), CollectResult::Done("sealed-result".into()));
        assert_eq!(b.unwrap(), CollectResult::Unknown);
        assert_eq!(
            store.claim("flow-1", NOW + 302, "replay").await.unwrap(),
            ClaimResult::Replay,
            "collection retains the replay tombstone"
        );
        assert_eq!(
            store
                .finish(
                    "flow-1",
                    NOW + 302,
                    "claim-a",
                    TerminalOutcome::Failed("stale".into())
                )
                .await
                .unwrap(),
            FinishResult::Conflict,
            "stale completion cannot overwrite collection"
        );
    }

    #[tokio::test]
    async fn expiry_and_retention_have_exact_boundaries() {
        let store = MemoryFlowStore::default();
        store.insert(flow("flow-1"), NOW).await.unwrap();
        assert_eq!(
            store.claim("flow-1", NOW + 300, "late").await.unwrap(),
            ClaimResult::Expired
        );
        assert_eq!(
            store.collect("flow-1", NOW + 300).await.unwrap(),
            CollectResult::Expired
        );
        assert_eq!(
            store.collect("flow-1", NOW + 300).await.unwrap(),
            CollectResult::Unknown
        );

        store.insert(flow("flow-2"), NOW).await.unwrap();
        assert!(matches!(
            store.claim("flow-2", NOW + 299, "claim").await.unwrap(),
            ClaimResult::Claimed(_)
        ));
        assert_eq!(
            store
                .finish(
                    "flow-2",
                    NOW + 1200,
                    "claim",
                    TerminalOutcome::Failed("too_late".into())
                )
                .await
                .unwrap(),
            FinishResult::Conflict
        );
        assert_eq!(store.get("flow-2", NOW + 1200).await.unwrap(), None);
    }

    #[tokio::test]
    async fn new_flow_activity_prunes_abandoned_records() {
        let store = MemoryFlowStore::default();
        store.insert(flow("abandoned"), NOW).await.unwrap();
        let mut current = flow("current");
        current.expires_at = NOW + 1500;
        current.retain_until = NOW + 2400;
        store.insert(current, NOW + 1200).await.unwrap();
        assert_eq!(store.get("abandoned", NOW + 1200).await.unwrap(), None);
        assert!(store.get("current", NOW + 1200).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn terminal_finish_clears_secrets_without_deleting_the_tombstone() {
        let store = MemoryFlowStore::default();
        store.insert(flow("flow-1"), NOW).await.unwrap();
        assert!(matches!(
            store.claim("flow-1", NOW, "claim").await.unwrap(),
            ClaimResult::Claimed(_)
        ));
        store
            .finish(
                "flow-1",
                NOW,
                "claim",
                TerminalOutcome::Done("sealed-result".into()),
            )
            .await
            .unwrap();
        let stored = store.get("flow-1", NOW).await.unwrap().unwrap();
        assert!(stored.jar.is_empty());
        assert!(stored.sealed_session.is_empty());
        assert_eq!(stored.outcome, Outcome::Done("sealed-result".into()));
    }
}
