//! MongoDB flow storage with atomic response claims and one-time collection.

use std::future::IntoFuture;
use std::time::Duration;

use async_trait::async_trait;
use grindvakt::provider::TokenUseStore;
use mongodb::bson::{self, doc, DateTime, Document};
use mongodb::error::{ErrorKind, WriteFailure};
use mongodb::options::{
    Acknowledgment, ClientOptions, FindOneAndUpdateOptions, IndexOptions, ReturnDocument,
    WriteConcern,
};
use mongodb::{Client, Collection, IndexModel};
use serde::{Deserialize, Serialize};
use siros_verifier_core_tunnelbana::{
    ClaimResult, CollectResult, FinishResult, Flow, FlowStore, FlowStoreError, Outcome,
    StoreResult, TerminalOutcome, FLOW_SCHEMA_VERSION, FLOW_STORE_WRITE_BOUND_SECS,
};

/// The adapter reserves this bound at the end of every processing lease;
/// the stores never take longer for one write.
const OPERATION_TIMEOUT: Duration = Duration::from_secs(FLOW_STORE_WRITE_BOUND_SECS as u64);
const RETENTION_INDEX: &str = "retain_at_ttl";
const TOKEN_USE_INDEX: &str = "expires_at_ttl";

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
        let client = mongo_client(uri).await?;
        let flows = client
            .database(database)
            .collection::<MongoFlow>(collection);
        create_ttl_index(&flows, "retain_at", RETENTION_INDEX).await?;
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
        lease_until: i64,
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
            // Only in-flight claims carry a processing lease deadline; the
            // terminal transitions below never read it.
            doc! { "$set": { "outcome": outcome, "lease_until": lease_until } }
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

    async fn claim(
        &self,
        id: &str,
        now: i64,
        claim_id: &str,
        lease_secs: i64,
    ) -> StoreResult<ClaimResult> {
        let Some(current) = self.load(id, now).await? else {
            return Ok(ClaimResult::Unknown);
        };
        if current.expired(now) {
            return Ok(ClaimResult::Expired);
        }
        match &current.outcome {
            Outcome::Pending => {}
            // An expired lease frees the slot for a retrying wallet while the
            // request is still live, so a runner that died mid-processing
            // cannot strand the flow. Past request expiry no re-drive could
            // succeed, and the original holder may still finish and deliver.
            Outcome::Processing(_) if current.lease_until <= now && now < current.expires_at => {}
            _ => return Ok(ClaimResult::Replay),
        }
        let claimed = self
            .transition(
                doc! {
                    "_id": id,
                    "retain_until": { "$gt": now },
                    "$or": [
                        { "outcome.state": "pending", "expires_at": { "$gt": now } },
                        { "outcome.state": "processing", "expires_at": { "$gt": now }, "lease_until": { "$lte": now } },
                        { "outcome.state": "processing", "expires_at": { "$gt": now }, "lease_until": { "$exists": false } },
                    ],
                },
                Outcome::Processing(claim_id.to_owned()),
                now.saturating_add(lease_secs),
                ReturnDocument::After,
            )
            .await?;
        if let Some(flow) = claimed {
            return Ok(ClaimResult::Claimed(Box::new(flow)));
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
                0,
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
                0,
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

#[derive(Debug, Serialize, Deserialize)]
struct TokenUseMarker {
    #[serde(rename = "_id")]
    token_hash: String,
    expires_at: DateTime,
}

/// Shared one-time use markers for authorization codes, refresh tokens, and
/// private-key client assertions. Only Grindvakt's hashes are stored.
pub struct MongoTokenUseStore {
    markers: Collection<TokenUseMarker>,
}

impl MongoTokenUseStore {
    pub async fn connect(uri: &str, database: &str, collection: &str) -> StoreResult<Self> {
        let client = mongo_client(uri).await?;
        let markers = client
            .database(database)
            .collection::<TokenUseMarker>(collection);
        create_ttl_index(&markers, "expires_at", TOKEN_USE_INDEX).await?;
        Ok(Self { markers })
    }
}

#[async_trait]
impl TokenUseStore for MongoTokenUseStore {
    async fn consume(&self, token_hash: &str, ttl_secs: u64) -> Result<bool, String> {
        let now = DateTime::now();
        let ttl_millis = ttl_secs.max(1).min(i64::MAX as u64) as i64;
        let expires_at = DateTime::from_millis(
            now.timestamp_millis()
                .saturating_add(ttl_millis.saturating_mul(1000)),
        );
        let options = FindOneAndUpdateOptions::builder()
            .upsert(true)
            .return_document(ReturnDocument::Before)
            .max_time(OPERATION_TIMEOUT)
            .build();
        let operation = self
            .markers
            .find_one_and_update(
                doc! { "_id": token_hash, "expires_at": { "$lte": now } },
                doc! { "$set": { "expires_at": expires_at } },
            )
            .with_options(options);
        match tokio::time::timeout(OPERATION_TIMEOUT, operation.into_future()).await {
            Ok(Ok(_)) => Ok(true),
            Ok(Err(error)) if is_duplicate_key(&error) => Ok(false),
            Ok(Err(error)) => Err(store_error("MongoDB token-use consume failed", error).0),
            Err(_) => Err("MongoDB token-use consume failed: operation timed out".into()),
        }
    }
}

fn is_duplicate_key(error: &mongodb::error::Error) -> bool {
    match error.kind.as_ref() {
        ErrorKind::Write(WriteFailure::WriteError(error)) => error.code == 11000,
        ErrorKind::Command(error) => error.code == 11000,
        _ => false,
    }
}

async fn mongo_client(uri: &str) -> StoreResult<Client> {
    let mut options = bounded("invalid MongoDB configuration", ClientOptions::parse(uri)).await?;
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
    Ok(client)
}

async fn create_ttl_index<T: Send + Sync>(
    collection: &Collection<T>,
    field: &str,
    name: &str,
) -> StoreResult<()> {
    bounded(
        "MongoDB retention index creation failed",
        collection
            .create_index(
                IndexModel::builder()
                    .keys(doc! { field: 1 })
                    .options(
                        IndexOptions::builder()
                            .name(Some(name.to_owned()))
                            .expire_after(Duration::ZERO)
                            .build(),
                    )
                    .build(),
            )
            .max_time(OPERATION_TIMEOUT),
    )
    .await?;
    Ok(())
}

/// Every MongoDB operation runs inside the write bound: the timeout fails
/// closed, and no operation outlives the window a processing lease reserves.
async fn bounded<T>(
    context: &str,
    operation: impl IntoFuture<Output = std::result::Result<T, mongodb::error::Error>>,
) -> StoreResult<T> {
    match tokio::time::timeout(OPERATION_TIMEOUT, operation.into_future()).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(store_error(context, error)),
        Err(_) => Err(FlowStoreError(format!("{context}: operation timed out"))),
    }
}

fn store_error(context: &str, error: mongodb::error::Error) -> FlowStoreError {
    FlowStoreError(format!("{context}: {error}"))
}
