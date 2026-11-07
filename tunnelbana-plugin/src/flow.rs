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
/// Upper bound on one flow-store write (the MongoDB operation timeout),
/// reserved at the end of every processing lease so the single terminal
/// write fits while the claim is still held.
pub const FLOW_STORE_WRITE_BOUND_SECS: i64 = 5;

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
    /// Deadline of the in-flight response-processing lease. Zero means no
    /// lease is held. Once the deadline passes the slot may be re-claimed by
    /// a wallet retry, so a runner that dies mid-processing cannot strand the
    /// flow. Replay protection and one-time collection are unaffected.
    #[serde(default)]
    pub lease_until: i64,
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
    // Boxed: the claimed flow is far larger than the refusal variants, and a
    // claim is returned once per wallet response, not on any hot path.
    Claimed(Box<Flow>),
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
    /// Atomically claim the wallet-response slot. The claim holds a
    /// `lease_secs` processing lease: while the lease is live a retrying
    /// wallet is a replay, and once it expires the slot may be re-claimed so
    /// a crashed runner cannot strand the flow. Terminal results, replay
    /// protection and one-time collection are unaffected by lease expiry.
    async fn claim(
        &self,
        id: &str,
        now: i64,
        claim_id: &str,
        lease_secs: i64,
    ) -> StoreResult<ClaimResult>;
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

    async fn claim(
        &self,
        id: &str,
        now: i64,
        claim_id: &str,
        lease_secs: i64,
    ) -> StoreResult<ClaimResult> {
        let mut flows = self.lock()?;
        Self::remove_expired_retention(&mut flows, id, now);
        let Some(flow) = flows.get_mut(id) else {
            return Ok(ClaimResult::Unknown);
        };
        if flow.expired(now) {
            return Ok(ClaimResult::Expired);
        }
        match &flow.outcome {
            Outcome::Pending => {}
            // The holder's lease expired without a terminal result while the
            // request is still live, so the slot is free again: a retrying
            // wallet re-claims it and re-drives verification under a fresh
            // claim. Past request expiry no re-drive could succeed anyway, and
            // the original holder may still finish and deliver late.
            Outcome::Processing(_) if flow.lease_until <= now && now < flow.expires_at => {}
            _ => return Ok(ClaimResult::Replay),
        }
        flow.outcome = Outcome::Processing(claim_id.to_owned());
        flow.lease_until = now.saturating_add(lease_secs);
        Ok(ClaimResult::Claimed(Box::new(flow.clone())))
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
