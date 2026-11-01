mod support;
use support::*;

type Mutation = Box<dyn Fn(&mut Statement)>;

use siros_verifier_core::issuer_set::{IssuerSetPolicy, MemberVerdict};
use siros_verifier_zkp::nym_auth::*;
use siros_verifier_zkp::refusal::*;
use siros_verifier_zkp::verify::*;
use std::sync::atomic::Ordering;

fn code<T: std::fmt::Debug>(r: ZkpResult<T>) -> String {
    match r {
        Ok(v) => format!("OK {v:?}"),
        Err(e) => e
            .code()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("FAULT {e}")),
    }
}

fn run(
    f: &Fx,
    channel: &Channel,
    thumb: Option<&[u8]>,
    token: &str,
    verdicts: &[Vec<MemberVerdict>],
) -> ZkpResult<Vec<VerifiedPresentation>> {
    f.verifier
        .begin(&f.exchange(channel, thumb), token)?
        .finish(verdicts)
}

#[test]
fn an_honest_presentation_verifies_over_the_dc_api() {
    let f = fx(Opts::default());
    let r = run(
        &f,
        &dc_channel(),
        None,
        &vp_token(&[f.honest()]),
        &trusted(1),
    )
    .unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(
        r[0].pseudonyms["nym-1"],
        reference_pseudonym(VERIFIER_ID),
        "the pseudonym is the one the backend returned"
    );
    assert_eq!(r[0].satisfied, vec!["age-1".to_string()]);
    assert_eq!(r[0].system_id, SYSTEM_LONGFELLOW);
    assert!(!r[0].issuer_key_thumbprint.is_empty());
    assert_eq!(
        r[0].proof_time,
        siros_verifier_core::mdoc::format_utc(NOW - 5).unwrap()
    );
}

#[test]
fn an_honest_presentation_verifies_over_a_redirect_and_the_handovers_differ() {
    let mut f = fx(Opts::default());
    f.statement.channel = redirect_channel(true);
    f.statement.thumbprint = Some(THUMB.to_vec());
    let ch = redirect_channel(true);
    let r = run(&f, &ch, Some(&THUMB), &vp_token(&[f.honest()]), &trusted(1)).unwrap();
    assert_eq!(r[0].pseudonyms["nym-1"], reference_pseudonym(VERIFIER_ID));
    // a proof made for the DC API handover does not verify as a redirect one (the opaque failure the table prevents)
    let dc_proof = fx(Opts::default());
    let e = run(
        &f,
        &ch,
        Some(&THUMB),
        &vp_token(&[dc_proof.honest()]),
        &trusted(1),
    );
    assert_eq!(code(e), PROOF_DID_NOT_VERIFY);
}

#[test]
fn every_public_input_is_bound_a_proof_for_any_other_value_does_not_verify() {
    let f = fx(Opts::default());
    let ch = dc_channel();
    let cases: Vec<(&str, Mutation)> = vec![
        (
            "nonce",
            Box::new(|s| s.nonce = "a-different-nonce-of-length".into()),
        ),
        (
            "origin",
            Box::new(|s| {
                s.channel = Channel::DcApi {
                    origin: "https://evil.example".into(),
                }
            }),
        ),
        (
            "verifier id",
            Box::new(|s| s.verifier_id = "x509_san_dns:other.example".into()),
        ),
        (
            "issuer key",
            Box::new(|s| {
                s.issuer_key = p256::SecretKey::from_slice(&[5u8; 32])
                    .unwrap()
                    .public_key()
            }),
        ),
        ("proof time", Box::new(|s| s.proof_time -= 1)),
        (
            "age earliest",
            Box::new(|s| s.age_earliest = "2008-10-11".into()),
        ),
        (
            "age cutoff",
            Box::new(|s| s.age_cutoff = "2013-10-10".into()),
        ),
    ];
    for (name, mutate) in cases {
        let mut st = f.statement.clone();
        mutate(&mut st);
        // the holder claims the pseudonym for the verifier id the *verifier* has, with a proof for another statement
        let p = presentation_cbor(
            SYSTEM_LONGFELLOW,
            &model_proof(&st),
            std::slice::from_ref(&f.cert),
            Some(f.statement.proof_time),
            &reference_pseudonym(VERIFIER_ID),
        );
        let r = run(&f, &ch, None, &vp_token(&[p]), &trusted(1));
        assert_eq!(code(r), PROOF_DID_NOT_VERIFY, "{name}");
    }
    // and the redirect-only inputs
    let mut g = fx(Opts::default());
    g.statement.channel = redirect_channel(true);
    g.statement.thumbprint = Some(THUMB.to_vec());
    let rc = redirect_channel(true);
    for (name, mutate) in [
        (
            "response_uri",
            Box::new(|s: &mut Statement| {
                s.channel = Channel::Redirect {
                    client_id: CLIENT_ID.into(),
                    response_uri: "https://verifier.example/other".into(),
                    encrypted: true,
                }
            }) as Box<dyn Fn(&mut Statement)>,
        ),
        (
            "client_id",
            Box::new(|s: &mut Statement| {
                s.channel = Channel::Redirect {
                    client_id: "x509_san_dns:other.example".into(),
                    response_uri: RESPONSE_URI.into(),
                    encrypted: true,
                }
            }),
        ),
        (
            "thumbprint",
            Box::new(|s: &mut Statement| s.thumbprint = Some(vec![0x22; 32])),
        ),
    ] {
        let mut st = g.statement.clone();
        mutate(&mut st);
        let p = presentation_cbor(
            SYSTEM_LONGFELLOW,
            &model_proof(&st),
            std::slice::from_ref(&g.cert),
            Some(g.statement.proof_time),
            &reference_pseudonym(VERIFIER_ID),
        );
        assert_eq!(
            code(run(&g, &rc, Some(&THUMB), &vp_token(&[p]), &trusted(1))),
            PROOF_DID_NOT_VERIFY,
            "{name}"
        );
    }
}

#[test]
fn a_claimed_pseudonym_the_proof_does_not_reveal_is_refused_and_never_returned() {
    let f = fx(Opts::default());
    let p = f.present(
        &f.statement,
        std::slice::from_ref(&f.cert),
        &reference_pseudonym("x509_san_dns:somebody-else.example"),
    );
    let r = run(&f, &dc_channel(), None, &vp_token(&[p]), &trusted(1));
    assert_eq!(code(r), PSEUDONYM_MISMATCH);
}

#[test]
fn proof_time_is_checked_first_and_before_any_circuit_is_loaded() {
    let f = fx(Opts::default());
    for (name, t) in [("too old", NOW - 601), ("in the future", NOW + 61)] {
        let mut st = f.statement.clone();
        st.proof_time = t;
        let p = f.present(
            &st,
            std::slice::from_ref(&f.cert),
            &reference_pseudonym(VERIFIER_ID),
        );
        assert_eq!(
            code(
                f.verifier
                    .begin(&f.exchange(&dc_channel(), None), &vp_token(&[p]))
                    .map(|_| ())
            ),
            PROOF_TIME_OUT_OF_RANGE,
            "{name}"
        );
    }
    // the edges are inclusive
    for t in [NOW - 600, NOW + 60] {
        let mut st = f.statement.clone();
        st.proof_time = t;
        let p = f.present(
            &st,
            std::slice::from_ref(&f.cert),
            &reference_pseudonym(VERIFIER_ID),
        );
        run(&f, &dc_channel(), None, &vp_token(&[p]), &trusted(1)).unwrap();
    }
    // a missing proof_time is a shape refusal for mso_mdoc, carrying the shared code
    let p = presentation_cbor(
        SYSTEM_LONGFELLOW,
        &model_proof(&f.statement),
        std::slice::from_ref(&f.cert),
        None,
        &reference_pseudonym(VERIFIER_ID),
    );
    assert_eq!(
        code(
            f.verifier
                .begin(&f.exchange(&dc_channel(), None), &vp_token(&[p]))
                .map(|_| ())
        ),
        "proof_time_missing"
    );
    let g = fx(Opts::default());
    let mut st = g.statement.clone();
    st.proof_time = NOW - 601;
    let p = g.present(
        &st,
        std::slice::from_ref(&g.cert),
        &reference_pseudonym(VERIFIER_ID),
    );
    let _ = g
        .verifier
        .begin(&g.exchange(&dc_channel(), None), &vp_token(&[p]));
    assert_eq!(
        g.loads.load(Ordering::SeqCst),
        0,
        "no circuit was loaded for a presentation refused on time"
    );
}

#[test]
fn a_custom_tolerance_replaces_the_recommendation() {
    let f = fx(Opts {
        tolerance: Tolerance {
            skew_secs: 5,
            max_age_secs: 10,
        },
        ..Default::default()
    });
    let mut st = f.statement.clone();
    st.proof_time = NOW - 11;
    let p = f.present(
        &st,
        std::slice::from_ref(&f.cert),
        &reference_pseudonym(VERIFIER_ID),
    );
    assert_eq!(
        code(
            f.verifier
                .begin(&f.exchange(&dc_channel(), None), &vp_token(&[p]))
                .map(|_| ())
        ),
        PROOF_TIME_OUT_OF_RANGE
    );
}

#[test]
fn an_untrusted_issuer_is_refused_and_a_wrong_curve_key_is_named() {
    let f = fx(Opts::default());
    let tok = vp_token(&[f.honest()]);
    let untrusted = vec![vec![MemberVerdict {
        trusted_now: false,
        trusted_at_expiry: None,
    }]];
    assert_eq!(
        code(run(&f, &dc_channel(), None, &tok, &untrusted)),
        ISSUER_NOT_TRUSTED
    );
    // trusted, but a P-384 key: the circuit takes P-256 and nothing else
    let p384 = cert("issuer384.example", (2035, 1, 1), true);
    let p = f.present(
        &f.statement,
        std::slice::from_ref(&p384),
        &reference_pseudonym(VERIFIER_ID),
    );
    assert_eq!(
        code(run(&f, &dc_channel(), None, &vp_token(&[p]), &trusted(1))),
        ISSUER_KEY_WRONG_CURVE
    );
    // garbage where a certificate belongs
    let p = f.present(
        &f.statement,
        &[vec![1, 2, 3, 4]],
        &reference_pseudonym(VERIFIER_ID),
    );
    assert_eq!(
        code(
            f.verifier
                .begin(&f.exchange(&dc_channel(), None), &vp_token(&[p]))
                .map(|_| ())
        ),
        ISSUER_KEY_NOT_A_CERTIFICATE
    );
}

#[test]
fn the_issuer_key_set_size_follows_the_system_not_the_shared_shape() {
    let f = fx(Opts::default()); // the model system takes exactly one
    let two = [f.cert.clone(), good_cert()];
    let p = f.present(&f.statement, &two, &reference_pseudonym(VERIFIER_ID));
    assert_eq!(
        code(
            f.verifier
                .begin(&f.exchange(&dc_channel(), None), &vp_token(&[p]))
                .map(|_| ())
        ),
        ISSUER_KEY_SET_SIZE
    );
}

#[test]
fn key_rollover_the_proof_may_be_under_the_just_expired_key() {
    let old = cert("old.example", (2026, 9, 10), false); // expired 11 days before NOW
    let new = good_cert();
    let f = fx(Opts {
        policy: IssuerSetPolicy::AtLeastOne {
            expired_grace_secs: 10_000_000_000,
        },
        issuer_key_set_max: 2,
        ..Default::default()
    });
    // the holder's credential was signed under the OLD key
    let old_key = siros_verifier_core::issuer_set::parse_members(std::slice::from_ref(&old))
        .unwrap()[0]
        .p256_key()
        .unwrap();
    let mut st = f.statement.clone();
    st.issuer_key = old_key;
    let p = f.present(
        &st,
        &[new.clone(), old.clone()],
        &reference_pseudonym(VERIFIER_ID),
    );
    let pending = f
        .verifier
        .begin(&f.exchange(&dc_channel(), None), &vp_token(&[p]))
        .unwrap();
    let q = pending.trust_queries();
    assert_eq!(q[0].len(), 2);
    assert!(
        q[0][1].at_expiry.is_some(),
        "the expired element is asked about at its expiry"
    );
    let verdicts = vec![vec![
        MemberVerdict {
            trusted_now: true,
            trusted_at_expiry: None,
        },
        MemberVerdict {
            trusted_now: false,
            trusted_at_expiry: Some(true),
        },
    ]];
    let r = pending.finish(&verdicts).unwrap();
    assert_eq!(r[0].pseudonyms["nym-1"], reference_pseudonym(VERIFIER_ID));

    // the trust layer says the old key was NOT trusted when it expired: only the new key is usable, and the proof
    // (made under the old one) does not verify under it
    let p = f.present(&st, &[new, old], &reference_pseudonym(VERIFIER_ID));
    let pending = f
        .verifier
        .begin(&f.exchange(&dc_channel(), None), &vp_token(&[p]))
        .unwrap();
    let verdicts = vec![vec![
        MemberVerdict {
            trusted_now: true,
            trusted_at_expiry: None,
        },
        MemberVerdict {
            trusted_now: false,
            trusted_at_expiry: Some(false),
        },
    ]];
    assert_eq!(code(pending.finish(&verdicts)), PROOF_DID_NOT_VERIFY);
}

#[test]
fn a_predicate_only_request_has_nothing_checked_and_is_refused() {
    let mut f = fx(Opts::default());
    f.plan = make_plan(&query(None, true), &[SYSTEM_LONGFELLOW]);
    // an honest holder answers only the age check
    let mut m = vec![];
    ciborium::into_writer(
        &ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("system_id".into()),
                ciborium::Value::Text(SYSTEM_LONGFELLOW.into()),
            ),
            (
                ciborium::Value::Text("proof".into()),
                ciborium::Value::Bytes(vec![1; 8]),
            ),
            (
                ciborium::Value::Text("issuer_key_set".into()),
                ciborium::Value::Array(vec![ciborium::Value::Bytes(f.cert.clone())]),
            ),
            (
                ciborium::Value::Text("proof_time".into()),
                ciborium::Value::Tag(
                    0,
                    Box::new(ciborium::Value::Text(
                        siros_verifier_core::mdoc::format_utc(NOW - 5).unwrap(),
                    )),
                ),
            ),
            (
                ciborium::Value::Text("results".into()),
                ciborium::Value::Map(vec![(
                    ciborium::Value::Text("age-1".into()),
                    ciborium::Value::Bool(true),
                )]),
            ),
        ]),
        &mut m,
    )
    .unwrap();
    let r = run(&f, &dc_channel(), None, &vp_token(&[m]), &trusted(1));
    assert_eq!(code(r), NOTHING_CHECKED);
    assert_eq!(
        f.loads.load(Ordering::SeqCst),
        0,
        "there was no pseudonym to verify, so nothing was loaded either"
    );
}

#[test]
fn the_channel_decides_the_transcript_and_a_cleartext_redirect_is_a_fault() {
    let mut f = fx(Opts::default());
    f.statement.channel = redirect_channel(true);
    f.statement.thumbprint = Some(THUMB.to_vec());
    let tok = vp_token(&[f.honest()]);
    // not encrypted
    let e = f
        .verifier
        .begin(&f.exchange(&redirect_channel(false), Some(&THUMB)), &tok)
        .map(|_| ())
        .unwrap_err();
    assert!(!e.is_refusal(), "{e}");
    assert!(e.to_string().contains("direct_post.jwt"));
    // no thumbprint to rebuild the transcript from
    let e = f
        .verifier
        .begin(&f.exchange(&redirect_channel(true), None), &tok)
        .map(|_| ())
        .unwrap_err();
    assert!(!e.is_refusal());
    // a short nonce is the verifier's own defect, a fault and not a wallet refusal
    let g = fx(Opts::default());
    let ch = dc_channel();
    let ex = Exchange {
        nonce: "short",
        ..g.exchange(&ch, None)
    };
    let e = g
        .verifier
        .begin(&ex, &vp_token(&[g.honest()]))
        .map(|_| ())
        .unwrap_err();
    assert!(!e.is_refusal(), "{e}");
}

#[test]
fn the_verifier_id_must_be_a_rulebook_form() {
    let f = fx(Opts::default());
    let ch = dc_channel();
    for bad in ["verifier.example", "x509_hash:abc", ""] {
        let ex = Exchange {
            verifier_id: bad,
            ..f.exchange(&ch, None)
        };
        let e = f
            .verifier
            .begin(&ex, &vp_token(&[f.honest()]))
            .map(|_| ())
            .unwrap_err();
        assert!(
            !e.is_refusal(),
            "{bad:?}: a verifier id is the verifier's own, so a bad one is a fault"
        );
    }
    let ex = Exchange {
        verifier_id: "semantic_id:acme",
        ..f.exchange(&ch, None)
    };
    f.verifier
        .begin(&ex, &vp_token(&[f.honest()]))
        .expect("semantic ids are usable");
}

#[test]
fn shape_refusals_keep_the_shared_codes() {
    let f = fx(Opts::default());
    let ch = dc_channel();
    // a system the request did not offer
    let p = presentation_cbor(
        "urn:circuits:vega:nym_auth:v1",
        &[1],
        std::slice::from_ref(&f.cert),
        Some(NOW - 5),
        &reference_pseudonym(VERIFIER_ID),
    );
    assert_eq!(
        code(
            f.verifier
                .begin(&f.exchange(&ch, None), &vp_token(&[p]))
                .map(|_| ())
        ),
        "system_id_not_offered"
    );
    // not a presentation at all
    assert_eq!(
        code(
            f.verifier
                .begin(&f.exchange(&ch, None), "{\"nym_attestation\": 5}")
                .map(|_| ())
        ),
        "presentations_not_array"
    );
    assert_eq!(
        code(
            f.verifier
                .begin(&f.exchange(&ch, None), "not json")
                .map(|_| ())
        ),
        "response_not_parseable"
    );
    // a repeated query id is judged on the text
    let tok = format!("{{\"{QUERY_ID}\":[\"AA\"],\"{QUERY_ID}\":[\"AA\"]}}");
    assert_eq!(
        code(f.verifier.begin(&f.exchange(&ch, None), &tok).map(|_| ())),
        "duplicate_member"
    );
    // a presentation that answers the predicate with false is refused, not recorded
    let mut m = vec![];
    ciborium::into_writer(
        &ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("system_id".into()),
                ciborium::Value::Text(SYSTEM_LONGFELLOW.into()),
            ),
            (
                ciborium::Value::Text("proof".into()),
                ciborium::Value::Bytes(vec![1]),
            ),
            (
                ciborium::Value::Text("issuer_key_set".into()),
                ciborium::Value::Array(vec![ciborium::Value::Bytes(f.cert.clone())]),
            ),
            (
                ciborium::Value::Text("proof_time".into()),
                ciborium::Value::Tag(
                    0,
                    Box::new(ciborium::Value::Text(
                        siros_verifier_core::mdoc::format_utc(NOW - 5).unwrap(),
                    )),
                ),
            ),
            (
                ciborium::Value::Text("results".into()),
                ciborium::Value::Map(vec![
                    (
                        ciborium::Value::Text("nym-1".into()),
                        ciborium::Value::Bytes(vec![0; 32]),
                    ),
                    (
                        ciborium::Value::Text("age-1".into()),
                        ciborium::Value::Bool(false),
                    ),
                ]),
            ),
        ]),
        &mut m,
    )
    .unwrap();
    assert_eq!(
        code(
            f.verifier
                .begin(&f.exchange(&ch, None), &vp_token(&[m]))
                .map(|_| ())
        ),
        "result_not_satisfied"
    );
}

#[test]
fn a_circuit_is_loaded_once_for_many_presentations() {
    let mut f = fx(Opts::default());
    f.plan = {
        let q = serde_json::json!({"id": QUERY_ID, "format": "zkp_req", "multiple": true,
            "meta": {"source_format": "mso_mdoc", "doctype_value": DOC},
            "_req": [{"fn_id":"pseudonym","return":"nym-1","params":{"config":CONFIG,"ver":1,"prf":"sha-256"}},
                     {"fn_id":"age_check","return":"age-1","params":{"ge":"2008-10-10","le":"2013-10-09"}}]});
        make_plan(&q, &[SYSTEM_LONGFELLOW])
    };
    let tok = vp_token(&[f.honest(), f.honest(), f.honest()]);
    let r = run(
        &f,
        &dc_channel(),
        None,
        &tok,
        &[
            trusted(1)[0].clone(),
            trusted(1)[0].clone(),
            trusted(1)[0].clone(),
        ],
    )
    .unwrap();
    assert_eq!(r.len(), 3);
    assert_eq!(f.loads.load(Ordering::SeqCst), 1);
}

#[test]
fn the_number_of_trust_answers_must_match_the_presentations() {
    let f = fx(Opts::default());
    let pending = f
        .verifier
        .begin(&f.exchange(&dc_channel(), None), &vp_token(&[f.honest()]))
        .unwrap();
    let e = pending.finish(&[]).unwrap_err();
    assert!(!e.is_refusal());
    let pending = f
        .verifier
        .begin(&f.exchange(&dc_channel(), None), &vp_token(&[f.honest()]))
        .unwrap();
    // a missing per-element answer is never read as trust
    assert_eq!(code(pending.finish(&[vec![]])), ISSUER_NOT_TRUSTED);
}
