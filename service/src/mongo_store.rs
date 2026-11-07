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

    fn token_provider(store: std::sync::Arc<MongoTokenUseStore>) -> grindvakt::provider::Provider {
        use grindvakt::client::{InMemoryClientStore, AUTH_CLIENT_SECRET_POST};
        use grindvakt::keys::signing_key_from_jwk_json;
        use grindvakt::metadata::ProviderMetadata;
        use grindvakt::provider::TokenLifetimes;
        use grindvakt::tokens::TokenCodec;
        let client = grindvakt::client::Client {
            client_id: "rp-conf".into(),
            client_secret: Some("s3cret".into()),
            redirect_uris: vec!["https://rp.example.com/cb".into()],
            response_types: vec!["code".into()],
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            token_endpoint_auth_method: AUTH_CLIENT_SECRET_POST.into(),
            jwks: None,
            scope: Some("openid".into()),
            subject_type: "public".into(),
            client_name: None,
        };
        let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
        jwk.alg = Some("ES256".into());
        let signing_key =
            signing_key_from_jwk_json(&jwk.to_json().unwrap(), Some("ES256"), Some("op-key"))
                .unwrap();
        grindvakt::provider::Provider::new(
            ProviderMetadata::new("https://op.example.com", "https://op.example.com"),
            signing_key,
            std::sync::Arc::new(InMemoryClientStore::with_clients(vec![client])),
            TokenCodec::new("shared-op-test-secret"),
            TokenLifetimes::default(),
            store,
        )
        .unwrap()
    }

    fn pending_flow(id: &str, now: i64) -> Flow {
        Flow {
            id: id.into(),
            schema_version: FLOW_SCHEMA_VERSION,
            jar: "signed-request".into(),
            sealed_session: "v1.sealed-private-key".into(),
            expires_at: now + 300,
            retain_until: now + 1200,
            lease_until: 0,
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
            lease_until: 0,
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
    async fn real_mongo_token_use_is_atomic_and_bounded_by_ttl() {
        let Ok(uri) = std::env::var("SIROS_VERIFIER_TEST_MONGODB_URI") else {
            return;
        };
        let database = format!("siros_verifier_token_test_{}", std::process::id());
        let store_a = MongoTokenUseStore::connect(&uri, &database, "oidc_token_use")
            .await
            .unwrap();
        let store_b = MongoTokenUseStore::connect(&uri, &database, "oidc_token_use")
            .await
            .unwrap();
        assert!(store_a.consume("code:first", 60).await.unwrap());
        assert!(!store_b.consume("code:first", 60).await.unwrap());
        assert!(store_a.consume("refresh:independent", 60).await.unwrap());
        assert!(store_a.consume("code:zero-ttl", 0).await.unwrap());
        assert!(!store_b.consume("code:zero-ttl", 0).await.unwrap());

        let (a, b) = tokio::join!(
            store_a.consume("code:race", 60),
            store_b.consume("code:race", 60)
        );
        let results = [a.unwrap(), b.unwrap()];
        assert_eq!(results.into_iter().filter(|won| *won).count(), 1);

        let client = Client::with_uri_str(&uri).await.unwrap();
        let markers = client
            .database(&database)
            .collection::<Document>("oidc_token_use");
        markers
            .update_one(
                doc! { "_id": "code:expired" },
                doc! { "$set": { "expires_at": DateTime::from_millis(0) } },
            )
            .upsert(true)
            .await
            .unwrap();
        assert!(store_a.consume("code:expired", 60).await.unwrap());
        assert!(!store_b.consume("code:expired", 60).await.unwrap());
        markers
            .update_one(
                doc! { "_id": "code:expired-race" },
                doc! { "$set": { "expires_at": DateTime::from_millis(0) } },
            )
            .upsert(true)
            .await
            .unwrap();
        let (a, b) = tokio::join!(
            store_a.consume("code:expired-race", 60),
            store_b.consume("code:expired-race", 60)
        );
        let results = [a.unwrap(), b.unwrap()];
        assert_eq!(results.into_iter().filter(|won| *won).count(), 1);

        let stored = markers
            .find_one(doc! { "_id": "code:first" })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.len(), 2);
        assert!(stored.get_datetime("expires_at").is_ok());
        let indexes = markers.list_indexes().await.unwrap();
        let indexes: Vec<_> = indexes.try_collect().await.unwrap();
        assert!(indexes.iter().any(|index| {
            index.keys.get_i32("expires_at") == Ok(1)
                && index
                    .options
                    .as_ref()
                    .and_then(|options| options.expire_after)
                    == Some(Duration::ZERO)
        }));
        client.database(&database).drop().await.unwrap();
    }

    #[tokio::test]
    async fn two_providers_share_code_and_refresh_replay_protection() {
        let Ok(uri) = std::env::var("SIROS_VERIFIER_TEST_MONGODB_URI") else {
            return;
        };
        let database = format!("siros_verifier_oidc_test_{}", std::process::id());
        let store_a = std::sync::Arc::new(
            MongoTokenUseStore::connect(&uri, &database, "oidc_token_use")
                .await
                .unwrap(),
        );
        let store_b = std::sync::Arc::new(
            MongoTokenUseStore::connect(&uri, &database, "oidc_token_use")
                .await
                .unwrap(),
        );
        let op_a = token_provider(store_a);
        let op_b = token_provider(store_b);
        let request = grindvakt::request::AuthorizationRequest::from_pairs(&[
            ("client_id".into(), "rp-conf".into()),
            ("response_type".into(), "code".into()),
            ("redirect_uri".into(), "https://rp.example.com/cb".into()),
            ("scope".into(), "openid".into()),
            ("nonce".into(), "nonce-abc".into()),
        ])
        .unwrap();
        let redirect = op_a
            .authorization_redirect(&request, "subject-123", &BTreeMap::new(), None)
            .await
            .unwrap();
        let location = redirect
            .headers
            .iter()
            .find(|(name, _)| name == "location")
            .map(|(_, value)| value.clone())
            .unwrap();
        let query = location.split_once('?').unwrap().1;
        let code = form_urlencoded::parse(query.as_bytes())
            .find(|(name, _)| name == "code")
            .map(|(_, value)| value.into_owned())
            .unwrap();
        let token_request = vec![
            ("grant_type".into(), "authorization_code".into()),
            ("code".into(), code),
            ("redirect_uri".into(), "https://rp.example.com/cb".into()),
            ("client_id".into(), "rp-conf".into()),
            ("client_secret".into(), "s3cret".into()),
        ];
        let (a, b) = tokio::join!(
            op_a.handle_token_request(&token_request, None, "https://op.example.com/token", None),
            op_b.handle_token_request(&token_request, None, "https://op.example.com/token", None)
        );
        let (tokens, replay) = match (a, b) {
            (Ok(tokens), Err(replay)) | (Err(replay), Ok(tokens)) => (tokens, replay),
            _ => panic!("exactly one provider must redeem the authorization code"),
        };
        assert_eq!(replay.code, grindvakt::OAuthErrorCode::InvalidGrant);
        let refresh = tokens.refresh_token.clone().expect("refresh token issued");
        let refresh_request = vec![
            ("grant_type".into(), "refresh_token".into()),
            ("refresh_token".into(), refresh),
            ("client_id".into(), "rp-conf".into()),
            ("client_secret".into(), "s3cret".into()),
        ];
        let (a, b) = tokio::join!(
            op_a.handle_token_request(&refresh_request, None, "https://op.example.com/token", None),
            op_b.handle_token_request(&refresh_request, None, "https://op.example.com/token", None)
        );
        let (refreshed, replay) = match (a, b) {
            (Ok(tokens), Err(replay)) | (Err(replay), Ok(tokens)) => (tokens, replay),
            _ => panic!("exactly one provider must redeem the refresh token"),
        };
        assert_eq!(replay.code, grindvakt::OAuthErrorCode::InvalidGrant);
        assert!(refreshed.refresh_token.is_some());

        Client::with_uri_str(&uri)
            .await
            .unwrap()
            .database(&database)
            .drop()
            .await
            .unwrap();
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
            store.claim("flow-1", now, "claim-a", 60),
            store.claim("flow-1", now, "claim-b", 60)
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
                .claim("flow-2", now, "claim-before-expiry", 60)
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
            store
                .claim("flow-3", now + 300, "too-late", 60)
                .await
                .unwrap(),
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

    #[tokio::test]
    async fn real_mongo_lease_recovery_mirrors_the_memory_contract() {
        let Ok(uri) = std::env::var("SIROS_VERIFIER_TEST_MONGODB_URI") else {
            return;
        };
        let database = format!("siros_verifier_lease_test_{}", std::process::id());
        let store = MongoFlowStore::connect(&uri, &database, "flows")
            .await
            .unwrap();
        let now = 1_800_000_000;
        store
            .insert(pending_flow("flow-1", now), now)
            .await
            .unwrap();
        // A runner claimed the slot and died; its short lease expires.
        assert!(matches!(
            store.claim("flow-1", now, "dead-claim", 10).await.unwrap(),
            ClaimResult::Claimed(_)
        ));
        assert_eq!(
            store
                .claim("flow-1", now + 9, "early-retry", 60)
                .await
                .unwrap(),
            ClaimResult::Replay,
            "a live lease is not stealable"
        );
        assert!(
            matches!(
                store
                    .claim("flow-1", now + 10, "retry-claim", 60)
                    .await
                    .unwrap(),
                ClaimResult::Claimed(_)
            ),
            "an expired lease is re-claimed by the wallet's retry"
        );
        assert_eq!(
            store
                .finish(
                    "flow-1",
                    now + 11,
                    "dead-claim",
                    TerminalOutcome::Done("late-result".into())
                )
                .await
                .unwrap(),
            FinishResult::Conflict,
            "the dead claim can no longer finish after the re-claim"
        );
        assert_eq!(
            store
                .finish(
                    "flow-1",
                    now + 11,
                    "retry-claim",
                    TerminalOutcome::Done("v1.sealed-result".into())
                )
                .await
                .unwrap(),
            FinishResult::Finished
        );
        assert_eq!(
            store.collect("flow-1", now + 12).await.unwrap(),
            CollectResult::Done("v1.sealed-result".into())
        );
        assert_eq!(
            store.collect("flow-1", now + 12).await.unwrap(),
            CollectResult::Unknown,
            "recovered processing still delivers exactly once"
        );

        // The recovery window closes at request expiry: a retry is a replay
        // there, and the slow original holder may still finish and deliver.
        store
            .insert(pending_flow("flow-window", now), now)
            .await
            .unwrap();
        assert!(matches!(
            store
                .claim("flow-window", now, "dead-claim", 10)
                .await
                .unwrap(),
            ClaimResult::Claimed(_)
        ));
        assert!(
            matches!(
                store
                    .claim("flow-window", now + 299, "retry", 60)
                    .await
                    .unwrap(),
                ClaimResult::Claimed(_)
            ),
            "a dead lease is re-claimed up to the request-expiry boundary"
        );
        store
            .insert(pending_flow("flow-late", now), now)
            .await
            .unwrap();
        assert!(matches!(
            store.claim("flow-late", now, "claim-a", 10).await.unwrap(),
            ClaimResult::Claimed(_)
        ));
        assert_eq!(
            store
                .claim("flow-late", now + 300, "retry", 60)
                .await
                .unwrap(),
            ClaimResult::Replay,
            "no re-drive can succeed once the request expired"
        );
        assert_eq!(
            store
                .finish(
                    "flow-late",
                    now + 300,
                    "claim-a",
                    TerminalOutcome::Done("late-result".into())
                )
                .await
                .unwrap(),
            FinishResult::Finished,
            "the original holder may still complete an in-flight response"
        );
        assert_eq!(
            store.collect("flow-late", now + 301).await.unwrap(),
            CollectResult::Done("late-result".into())
        );
        assert_eq!(
            store.collect("flow-late", now + 301).await.unwrap(),
            CollectResult::Unknown
        );

        // Pre-lease records (no `lease_until` field) are recoverable too.
        store
            .insert(pending_flow("flow-legacy", now), now)
            .await
            .unwrap();
        let client = Client::with_uri_str(&uri).await.unwrap();
        client
            .database(&database)
            .collection::<Document>("flows")
            .update_one(
                doc! { "_id": "flow-legacy" },
                doc! { "$set": { "outcome": { "state": "processing", "value": "old" } }, "$unset": { "lease_until": "" } },
            )
            .await
            .unwrap();
        assert!(
            matches!(
                store
                    .claim("flow-legacy", now + 1, "retry", 60)
                    .await
                    .unwrap(),
                ClaimResult::Claimed(_)
            ),
            "a record written before the lease field exists is re-claimable"
        );
        client.database(&database).drop().await.unwrap();
    }
}
