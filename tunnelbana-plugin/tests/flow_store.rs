//! Flow-store contracts: atomic response claims, processing leases, exact
//! expiry/retention boundaries, and one-time collection. The in-memory store
//! is the reference implementation; the service's MongoDB store must keep the
//! same contracts against a real database.

use std::collections::BTreeMap;
use std::sync::Arc;

use siros_verifier_core_tunnelbana::{
    ClaimResult, CollectResult, FinishResult, Flow, FlowStore, MemoryFlowStore, Outcome,
    TerminalOutcome, FLOW_RETENTION_GRACE_SECS, FLOW_SCHEMA_VERSION,
};

const NOW: i64 = 1_800_000_000;

fn flow(id: &str) -> Flow {
    Flow {
        id: id.into(),
        schema_version: FLOW_SCHEMA_VERSION,
        jar: "request-jwt".into(),
        sealed_session: "sealed-private-session".into(),
        expires_at: NOW + 300,
        retain_until: NOW + 300 + FLOW_RETENTION_GRACE_SECS,
        lease_until: 0,
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
        store.claim("flow-1", NOW, "claim-a", 60),
        store.claim("flow-1", NOW, "claim-b", 60)
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
        store
            .claim("flow-1", NOW + 302, "replay", 60)
            .await
            .unwrap(),
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
        store.claim("flow-1", NOW + 300, "late", 60).await.unwrap(),
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
        store.claim("flow-2", NOW + 299, "claim", 60).await.unwrap(),
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
        store.claim("flow-1", NOW, "claim", 60).await.unwrap(),
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

#[tokio::test]
async fn a_live_processing_lease_is_not_stealable() {
    let store = MemoryFlowStore::default();
    store.insert(flow("flow-1"), NOW).await.unwrap();
    assert!(matches!(
        store.claim("flow-1", NOW, "claim-a", 60).await.unwrap(),
        ClaimResult::Claimed(_)
    ));
    assert_eq!(
        store
            .claim("flow-1", NOW + 59, "claim-b", 60)
            .await
            .unwrap(),
        ClaimResult::Replay,
        "while the lease is live a second wallet POST is a replay"
    );
}

#[tokio::test]
async fn an_expired_processing_lease_is_reclaimed_and_the_dead_claim_conflicts() {
    let store = MemoryFlowStore::default();
    store.insert(flow("flow-1"), NOW).await.unwrap();
    assert!(matches!(
        store.claim("flow-1", NOW, "dead-claim", 10).await.unwrap(),
        ClaimResult::Claimed(_)
    ));
    // The runner died mid-processing; its lease expires and the wallet's
    // retry re-claims the slot under a fresh claim id.
    assert!(matches!(
        store
            .claim("flow-1", NOW + 10, "retry-claim", 60)
            .await
            .unwrap(),
        ClaimResult::Claimed(_)
    ));
    assert_eq!(
        store
            .finish(
                "flow-1",
                NOW + 11,
                "dead-claim",
                TerminalOutcome::Done("late-result".into())
            )
            .await
            .unwrap(),
        FinishResult::Conflict,
        "a claim whose lease expired and was re-claimed can no longer finish"
    );
    assert_eq!(
        store
            .finish(
                "flow-1",
                NOW + 11,
                "retry-claim",
                TerminalOutcome::Done("sealed-result".into())
            )
            .await
            .unwrap(),
        FinishResult::Finished
    );
    assert_eq!(
        store.collect("flow-1", NOW + 12).await.unwrap(),
        CollectResult::Done("sealed-result".into())
    );
    assert_eq!(
        store.collect("flow-1", NOW + 12).await.unwrap(),
        CollectResult::Unknown,
        "recovered processing still delivers exactly once"
    );
}

#[tokio::test]
async fn a_dead_lease_is_not_reclaimed_once_the_request_expired() {
    let store = MemoryFlowStore::default();
    // Both flows expire at NOW + 300; a dead lease may be re-claimed right up
    // to that boundary but not at it.
    store.insert(flow("flow-retry"), NOW).await.unwrap();
    assert!(matches!(
        store
            .claim("flow-retry", NOW, "dead-claim", 10)
            .await
            .unwrap(),
        ClaimResult::Claimed(_)
    ));
    assert!(
        matches!(
            store
                .claim("flow-retry", NOW + 299, "retry", 60)
                .await
                .unwrap(),
            ClaimResult::Claimed(_)
        ),
        "a dead lease is re-claimed up to the request-expiry boundary"
    );

    // Past request expiry a retry is a replay, and the slow original holder
    // may still finish and deliver its result exactly once.
    store.insert(flow("flow-late"), NOW).await.unwrap();
    assert!(matches!(
        store.claim("flow-late", NOW, "claim-a", 10).await.unwrap(),
        ClaimResult::Claimed(_)
    ));
    assert_eq!(
        store
            .claim("flow-late", NOW + 300, "retry", 60)
            .await
            .unwrap(),
        ClaimResult::Replay,
        "no re-drive can succeed once the request expired"
    );
    assert_eq!(
        store
            .finish(
                "flow-late",
                NOW + 300,
                "claim-a",
                TerminalOutcome::Done("late-result".into())
            )
            .await
            .unwrap(),
        FinishResult::Finished,
        "the original holder may still complete an in-flight response"
    );
    assert_eq!(
        store.collect("flow-late", NOW + 301).await.unwrap(),
        CollectResult::Done("late-result".into())
    );
    assert_eq!(
        store.collect("flow-late", NOW + 301).await.unwrap(),
        CollectResult::Unknown
    );
}
