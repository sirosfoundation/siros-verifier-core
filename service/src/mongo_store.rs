//! MongoDB flow storage with atomic response claims and one-time collection.

use std::future::IntoFuture;
use std::time::Duration;

use async_trait::async_trait;
use mongodb::bson::{self, doc, DateTime, Document};
use mongodb::options::{
    Acknowledgment, ClientOptions, FindOneAndUpdateOptions, IndexOptions, ReturnDocument,
    WriteConcern,
};
use mongodb::{Client, Collection, IndexModel};
use serde::{Deserialize, Serialize};
use siros_verifier_core_tunnelbana::{
    ClaimResult, CollectResult, FinishResult, Flow, FlowStore, FlowStoreError, Outcome,
    StoreResult, TerminalOutcome, FLOW_SCHEMA_VERSION,
};

const OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const RETENTION_INDEX: &str = "retain_at_ttl";

#[derive(Debug, Serialize, Deserialize)]
struct MongoFlow {
    #[serde(flatten)]
    flow: Flow,
    /// BSON DateTime required by MongoDB's TTL index. Application filters use
    /// `retain_until` because TTL deletion itself is asynchronous.
    retain_at: DateTime,
}

impl MongoFlow {
    fn new(flow: Flow) -> Self {
        let retain_at = DateTime::from_millis(flow.retain_until.saturating_mul(1000));
        Self { flow, retain_at }
    }

    fn decode(self) -> StoreResult<Flow> {
        if self.flow.schema_version != FLOW_SCHEMA_VERSION {
            return Err(FlowStoreError("unsupported flow schema version".into()));
        }
        if self.retain_at.timestamp_millis() != self.flow.retain_until.saturating_mul(1000) {
            return Err(FlowStoreError(
                "inconsistent flow retention deadline".into(),
            ));
        }
        Ok(self.flow)
    }
}

pub struct MongoFlowStore {
    flows: Collection<MongoFlow>,
}

impl MongoFlowStore {
    pub async fn connect(uri: &str, database: &str, collection: &str) -> StoreResult<Self> {
        let mut options =
            bounded("invalid MongoDB configuration", ClientOptions::parse(uri)).await?;
        options.app_name = Some("siros-verifier-service".into());
        options.connect_timeout = Some(OPERATION_TIMEOUT);
        options.server_selection_timeout = Some(OPERATION_TIMEOUT);
        options.write_concern = Some(
            WriteConcern::builder()
                .w(Acknowledgment::Majority)
                .w_timeout(OPERATION_TIMEOUT)
                .build(),
        );
        let client = Client::with_options(options)
            .map_err(|e| store_error("MongoDB client initialization failed", e))?;
        bounded(
            "MongoDB ping failed",
            client
                .database("admin")
                .run_command(doc! { "ping": 1, "maxTimeMS": 5000 }),
        )
        .await?;
        let flows = client
            .database(database)
            .collection::<MongoFlow>(collection);
        bounded(
            "MongoDB retention index creation failed",
            flows
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "retain_at": 1 })
                        .options(
                            IndexOptions::builder()
                                .name(Some(RETENTION_INDEX.to_owned()))
                                .expire_after(Duration::ZERO)
                                .build(),
                        )
                        .build(),
                )
                .max_time(OPERATION_TIMEOUT),
        )
        .await?;
        Ok(Self { flows })
    }

    async fn load(&self, id: &str, now: i64) -> StoreResult<Option<Flow>> {
        bounded(
            "MongoDB flow read failed",
            self.flows
                .find_one(doc! { "_id": id, "retain_until": { "$gt": now } })
                .max_time(OPERATION_TIMEOUT),
        )
        .await?
        .map(MongoFlow::decode)
        .transpose()
    }

    fn update_options(return_document: ReturnDocument) -> FindOneAndUpdateOptions {
        FindOneAndUpdateOptions::builder()
            .return_document(return_document)
            .max_time(OPERATION_TIMEOUT)
            .build()
    }

    async fn transition(
        &self,
        filter: Document,
        outcome: Outcome,
        return_document: ReturnDocument,
    ) -> StoreResult<Option<Flow>> {
        let clear_secrets = !matches!(&outcome, Outcome::Processing(_));
        let outcome = bson::to_bson(&outcome)
            .map_err(|e| FlowStoreError(format!("flow outcome encoding failed: {e}")))?;
        let update = if clear_secrets {
            doc! {
                "$set": {
                    "outcome": outcome,
                    "jar": "",
                    "sealed_session": "",
                }
            }
        } else {
            doc! { "$set": { "outcome": outcome } }
        };
        bounded(
            "MongoDB flow transition failed",
            self.flows
                .find_one_and_update(filter, update)
                .with_options(Self::update_options(return_document)),
        )
        .await?
        .map(MongoFlow::decode)
        .transpose()
    }
}

#[async_trait]
impl FlowStore for MongoFlowStore {
    async fn insert(&self, flow: Flow, _now: i64) -> StoreResult<()> {
        bounded(
            "MongoDB flow insert failed",
            self.flows.insert_one(MongoFlow::new(flow)),
        )
        .await?;
        Ok(())
    }

    async fn get(&self, id: &str, now: i64) -> StoreResult<Option<Flow>> {
        self.load(id, now).await
    }

    async fn claim(&self, id: &str, now: i64, claim_id: &str) -> StoreResult<ClaimResult> {
        let Some(current) = self.load(id, now).await? else {
            return Ok(ClaimResult::Unknown);
        };
        if current.expired(now) {
            return Ok(ClaimResult::Expired);
        }
        if !matches!(current.outcome, Outcome::Pending) {
            return Ok(ClaimResult::Replay);
        }
        let claimed = self
            .transition(
                doc! {
                    "_id": id,
                    "retain_until": { "$gt": now },
                    "expires_at": { "$gt": now },
                    "outcome.state": "pending",
                },
                Outcome::Processing(claim_id.to_owned()),
                ReturnDocument::After,
            )
            .await?;
        if let Some(flow) = claimed {
            return Ok(ClaimResult::Claimed(flow));
        }
        // A competing replica won or the request crossed its expiry boundary.
        Ok(match self.load(id, now).await? {
            None => ClaimResult::Unknown,
            Some(flow) if flow.expired(now) => ClaimResult::Expired,
            Some(_) => ClaimResult::Replay,
        })
    }

    async fn finish(
        &self,
        id: &str,
        now: i64,
        claim_id: &str,
        outcome: TerminalOutcome,
    ) -> StoreResult<FinishResult> {
        let finished = self
            .transition(
                doc! {
                    "_id": id,
                    "retain_until": { "$gt": now },
                    "outcome.state": "processing",
                    "outcome.value": claim_id,
                },
                outcome.into(),
                ReturnDocument::Before,
            )
            .await?
            .is_some();
        Ok(if finished {
            FinishResult::Finished
        } else {
            FinishResult::Conflict
        })
    }

    async fn collect(&self, id: &str, now: i64) -> StoreResult<CollectResult> {
        let collected = self
            .transition(
                doc! {
                    "_id": id,
                    "retain_until": { "$gt": now },
                    "$or": [
                        { "outcome.state": "done" },
                        { "outcome.state": "failed" },
                        { "outcome.state": "pending", "expires_at": { "$lte": now } },
                    ],
                },
                Outcome::Collected,
                ReturnDocument::Before,
            )
            .await?;
        if let Some(flow) = collected {
            let expired = flow.expired(now);
            return match flow.outcome {
                Outcome::Done(result) => Ok(CollectResult::Done(result)),
                Outcome::Failed(code) => Ok(CollectResult::Failed(code)),
                Outcome::Pending if expired => Ok(CollectResult::Expired),
                _ => Err(FlowStoreError("invalid MongoDB collect transition".into())),
            };
        }
        // A valid response may have claimed the record after our conditional
        // update. It is still in progress, never an unknown flow.
        Ok(match self.load(id, now).await? {
            None => CollectResult::Unknown,
            Some(flow) if matches!(flow.outcome, Outcome::Collected) => CollectResult::Unknown,
            Some(_) => CollectResult::Pending,
        })
    }
}

async fn bounded<T>(
    context: &str,
    operation: impl IntoFuture<Output = std::result::Result<T, mongodb::error::Error>>,
) -> StoreResult<T> {
    bounded_with_timeout(context, OPERATION_TIMEOUT, operation).await
}

async fn bounded_with_timeout<T>(
    context: &str,
    timeout: Duration,
    operation: impl IntoFuture<Output = std::result::Result<T, mongodb::error::Error>>,
) -> StoreResult<T> {
    match tokio::time::timeout(timeout, operation.into_future()).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(store_error(context, error)),
        Err(_) => Err(FlowStoreError(format!("{context}: operation timed out"))),
    }
}

fn store_error(context: &str, error: mongodb::error::Error) -> FlowStoreError {
    FlowStoreError(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::TryStreamExt;
    use std::collections::BTreeMap;

    fn pending_flow(id: &str, now: i64) -> Flow {
        Flow {
            id: id.into(),
            schema_version: FLOW_SCHEMA_VERSION,
            jar: "signed-request".into(),
            sealed_session: "v1.sealed-private-key".into(),
            expires_at: now + 300,
            retain_until: now + 1200,
            requester: None,
            attribute_map: BTreeMap::new(),
            subject_pointer: "/sub".into(),
            outcome: Outcome::Pending,
        }
    }

    #[test]
    fn mongo_document_contains_only_sealed_sensitive_values() {
        let flow = Flow {
            id: "flow-1".into(),
            schema_version: FLOW_SCHEMA_VERSION,
            jar: "signed-request".into(),
            sealed_session: "v1.sealed-private-key".into(),
            expires_at: 1_800_000_300,
            retain_until: 1_800_001_200,
            requester: Some("https://rp.example".into()),
            attribute_map: BTreeMap::new(),
            subject_pointer: "/sub".into(),
            outcome: Outcome::Done("v1.sealed-Lovelace-result".into()),
        };
        let document = bson::to_document(&MongoFlow::new(flow)).unwrap();
        assert_eq!(
            document.get_str("sealed_session").unwrap(),
            "v1.sealed-private-key"
        );
        assert_eq!(
            document
                .get_document("outcome")
                .unwrap()
                .get_str("value")
                .unwrap(),
            "v1.sealed-Lovelace-result"
        );
        assert!(!document.contains_key("attributes"));
        assert!(!document.contains_key("session"));
    }

    #[tokio::test]
    async fn outer_deadline_fails_closed_for_a_stalled_operation() {
        let started = std::time::Instant::now();
        let error = bounded_with_timeout(
            "stalled test operation",
            Duration::from_millis(20),
            std::future::pending::<std::result::Result<(), mongodb::error::Error>>(),
        )
        .await
        .unwrap_err();
        assert!(error.0.contains("operation timed out"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn real_mongo_atomic_contract_and_ttl_index() {
        let Ok(uri) = std::env::var("SIROS_VERIFIER_TEST_MONGODB_URI") else {
            return;
        };
        let database = format!("siros_verifier_test_{}", std::process::id());
        let store = MongoFlowStore::connect(&uri, &database, "flows")
            .await
            .unwrap();
        let now = 1_800_000_000;
        store
            .insert(pending_flow("flow-1", now), now)
            .await
            .unwrap();
        let (a, b) = tokio::join!(
            store.claim("flow-1", now, "claim-a"),
            store.claim("flow-1", now, "claim-b")
        );
        let (claimed, winning_claim) = match (a.unwrap(), b.unwrap()) {
            (ClaimResult::Claimed(flow), ClaimResult::Replay) => (flow, "claim-a"),
            (ClaimResult::Replay, ClaimResult::Claimed(flow)) => (flow, "claim-b"),
            other => panic!("expected exactly one response winner, got {other:?}"),
        };
        assert_eq!(claimed.sealed_session, "v1.sealed-private-key");
        assert_eq!(claimed.jar, "signed-request");
        assert_eq!(
            store
                .finish(
                    "flow-1",
                    now + 301,
                    winning_claim,
                    TerminalOutcome::Done("v1.sealed-result".into())
                )
                .await
                .unwrap(),
            FinishResult::Finished
        );
        assert_eq!(
            store.collect("flow-1", now + 302).await.unwrap(),
            CollectResult::Done("v1.sealed-result".into())
        );
        assert_eq!(
            store.collect("flow-1", now + 302).await.unwrap(),
            CollectResult::Unknown
        );

        store
            .insert(pending_flow("flow-2", now), now)
            .await
            .unwrap();
        assert!(matches!(
            store
                .claim("flow-2", now, "claim-before-expiry")
                .await
                .unwrap(),
            ClaimResult::Claimed(_)
        ));
        assert_eq!(
            store.collect("flow-2", now + 301).await.unwrap(),
            CollectResult::Pending,
            "a valid claim winning before collection is not an unknown flow"
        );
        assert_eq!(
            store
                .finish(
                    "flow-2",
                    now + 301,
                    "claim-before-expiry",
                    TerminalOutcome::Done("v1.second-result".into())
                )
                .await
                .unwrap(),
            FinishResult::Finished
        );
        assert_eq!(
            store.collect("flow-2", now + 301).await.unwrap(),
            CollectResult::Done("v1.second-result".into())
        );

        store
            .insert(pending_flow("flow-3", now), now)
            .await
            .unwrap();
        assert_eq!(
            store.collect("flow-3", now + 300).await.unwrap(),
            CollectResult::Expired
        );
        assert_eq!(
            store.claim("flow-3", now + 300, "too-late").await.unwrap(),
            ClaimResult::Replay
        );

        let client = Client::with_uri_str(&uri).await.unwrap();
        let indexes = client
            .database(&database)
            .collection::<Document>("flows")
            .list_indexes()
            .await
            .unwrap();
        let indexes: Vec<_> = indexes.try_collect().await.unwrap();
        assert!(indexes.iter().any(|index| {
            index.keys.get_i32("retain_at") == Ok(1)
                && index
                    .options
                    .as_ref()
                    .and_then(|options| options.expire_after)
                    == Some(Duration::ZERO)
        }));
        client.database(&database).drop().await.unwrap();
    }
}
