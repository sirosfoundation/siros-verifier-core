//! The MongoDB flow store against a real MongoDB, through the public API.
//!
//! Every test is gated on `SIROS_VERIFIER_TEST_MONGODB_URI` (CI provisions a
//! genuine MongoDB); without the variable they self-skip, which also gives
//! the service's exact-once HA contract — atomic claims, lease recovery, TTL
//! retention, one-time collection — its only live validation.

use std::collections::BTreeMap;
use std::time::Duration;

use futures_util::TryStreamExt;
use grindvakt::provider::TokenUseStore;
use mongodb::bson::{doc, DateTime, Document};
use mongodb::Client;
use siros_verifier_core_tunnelbana::{
    ClaimResult, CollectResult, FinishResult, Flow, FlowStore, Outcome, TerminalOutcome,
    FLOW_SCHEMA_VERSION,
};
use siros_verifier_service::mongo_store::{MongoFlowStore, MongoTokenUseStore};

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
        signing_key_from_jwk_json(&jwk.to_json().unwrap(), Some("ES256"), Some("op-key")).unwrap();
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

#[tokio::test]
async fn a_stalled_mongodb_endpoint_fails_closed_rather_than_hanging() {
    // Nothing listens on loopback port 1: connect must terminate with an
    // error inside a bounded window — never hang, never report ready.
    let connect = MongoFlowStore::connect("mongodb://127.0.0.1:1/", "unreachable", "flows");
    let store = match tokio::time::timeout(Duration::from_secs(30), connect)
        .await
        .expect("connect resolves inside its operation bound")
    {
        Ok(_) => panic!("an unreachable endpoint must not yield a store"),
        Err(store) => store,
    };
    assert!(!store.0.is_empty());
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

#[tokio::test]
async fn the_persisted_flow_document_carries_secrets_only_under_sealed_keys() {
    let Ok(uri) = std::env::var("SIROS_VERIFIER_TEST_MONGODB_URI") else {
        return;
    };
    let database = format!("siros_verifier_shape_test_{}", std::process::id());
    let store = MongoFlowStore::connect(&uri, &database, "flows")
        .await
        .unwrap();
    let now = 1_800_000_000;
    let mut flow = pending_flow("stored-shape", now);
    flow.requester = Some("https://rp.example".into());
    flow.attribute_map
        .insert("given_name".into(), "Ada Lovelace".into());
    store.insert(flow, now).await.unwrap();

    // Read the raw BSON MongoDB actually holds — not the Rust view — and
    // pin the exact key set: the session and the terminal result appear
    // only under their sealed keys, the mapped attributes travel as data,
    // and no undeclared field exists for a secret to hide behind.
    let client = Client::with_uri_str(&uri).await.unwrap();
    let stored = client
        .database(&database)
        .collection::<Document>("flows")
        .find_one(doc! { "_id": "stored-shape" })
        .await
        .unwrap()
        .expect("the inserted flow is persisted");
    let mut keys: Vec<&str> = stored.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "_id",
            "attribute_map",
            "expires_at",
            "jar",
            "lease_until",
            "outcome",
            "requester",
            "retain_at",
            "retain_until",
            "schema_version",
            "sealed_session",
            "subject_pointer",
        ]
    );
    assert_eq!(
        stored.get_str("sealed_session").unwrap(),
        "v1.sealed-private-key"
    );
    assert_eq!(
        stored
            .get_document("attribute_map")
            .unwrap()
            .get_str("given_name")
            .unwrap(),
        "Ada Lovelace"
    );
    client.database(&database).drop().await.unwrap();
}
