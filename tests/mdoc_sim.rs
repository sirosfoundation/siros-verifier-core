//! mdoc verification against a simulated issuer and holder (deviceSignature and negative cases).
use ciborium::Value as C;
use p256::elliptic_curve::Generate;
use p256::SecretKey;
use siros_verifier_core::mdoc::*;
use siros_verifier_core::testutil::mdoc_sim::*;

const NOW: i64 = 1_790_000_000; // 2026-09-21

struct Fx {
    issuer: Party,
    device: SecretKey,
    er: SecretKey,
    st: Vec<u8>,
}
fn fx() -> Fx {
    let er = SecretKey::generate();
    let st = transcript(&er.public_key(), 1);
    Fx {
        issuer: issuer(),
        device: device(),
        er,
        st,
    }
}
fn verify(f: &Fx, resp: &[u8], mac: bool) -> Result<Vec<MdocVerified>, String> {
    verify_device_response(
        resp,
        &Params {
            session_transcript_bytes: &f.st,
            now: NOW,
            device_auth: if mac {
                DeviceKeyAuth::Mac { ereader: &f.er }
            } else {
                DeviceKeyAuth::SignatureOnly
            },
            expected_doc_types: None,
        },
    )
    .map_err(|e| e.to_string())
}
fn build(f: &Fx, spec: &Spec) -> Vec<u8> {
    response(spec, &f.issuer, &f.device, &f.st, Some(&f.er.public_key()))
}
fn rejects(spec: Spec, want: &str) {
    let f = fx();
    let mac = spec.use_mac;
    let r = verify(&f, &build(&f, &spec), mac);
    match r {
        Err(e) => assert!(e.contains(want), "wanted {want:?}, got {e:?}"),
        Ok(_) => panic!("accepted, wanted {want:?}"),
    }
}

#[test]
fn signature_and_mac_paths_both_verify() {
    let f = fx();
    for mac in [false, true] {
        let r = verify(
            &f,
            &build(
                &f,
                &Spec {
                    use_mac: mac,
                    ..Default::default()
                },
            ),
            mac,
        )
        .unwrap();
        assert_eq!(
            r[0].elements["eu.europa.ec.eudi.pid.1"]["family_name"],
            C::Text("Svensson".into())
        );
        assert_eq!(r[0].issuer.x5c_der[0], f.issuer.cert_der);
    }
}

#[test]
fn sha384_digests_work() {
    let f = fx();
    let s = Spec {
        digest_alg: "SHA-384".into(),
        ..Default::default()
    };
    verify(&f, &build(&f, &s), false).unwrap();
}

#[test]
fn rejects_wrong_element_digest() {
    rejects(
        Spec {
            bad_digest_for: Some(1),
            ..Default::default()
        },
        "element_digest",
    );
}
#[test]
fn rejects_element_without_digest() {
    rejects(
        Spec {
            omit_digest_for: Some(0),
            ..Default::default()
        },
        "digest_id_not_in_mso",
    );
}
#[test]
fn rejects_duplicate_digest_ids() {
    rejects(
        Spec {
            duplicate_digest_id: true,
            ..Default::default()
        },
        "duplicate_digest_id",
    );
}
#[test]
fn rejects_short_salt() {
    rejects(
        Spec {
            random_len: 15,
            ..Default::default()
        },
        "salt_too_short",
    );
}
#[test]
fn rejects_doc_type_mismatch_between_document_and_mso() {
    rejects(
        Spec {
            mso_doc_type: "org.iso.18013.5.1.mDL".into(),
            ..Default::default()
        },
        "doc_type_mismatch",
    );
}
#[test]
fn rejects_unknown_digest_algorithm() {
    rejects(
        Spec {
            digest_alg: "SHA-1".into(),
            ..Default::default()
        },
        "digest_algorithm",
    );
}
#[test]
fn rejects_unknown_root_member_and_bad_status() {
    rejects(
        Spec {
            extra_root_member: true,
            ..Default::default()
        },
        "unknown_member_extra",
    );
    rejects(
        Spec {
            status: 10,
            ..Default::default()
        },
        "response_status_not_ok",
    );
}
#[test]
fn rejects_expired_and_not_yet_valid() {
    rejects(
        Spec {
            valid_until: "2026-06-01T00:00:00Z".into(),
            ..Default::default()
        },
        "expired",
    );
    rejects(
        Spec {
            valid_from: "2027-01-01T00:00:00Z".into(),
            valid_until: "2028-01-01T00:00:00Z".into(),
            ..Default::default()
        },
        "not_yet_valid",
    );
}
#[test]
fn rejects_malformed_dates() {
    rejects(
        Spec {
            valid_until: "2027-01-01T00:00:00.5Z".into(),
            ..Default::default()
        },
        "tdate_format",
    );
    rejects(
        Spec {
            valid_until: "2027-13-01T00:00:00Z".into(),
            ..Default::default()
        },
        "tdate_range",
    );
}

#[test]
fn signature_from_a_different_device_key_is_rejected() {
    let f = fx();
    let other = device();
    // MSO names f.device; the response is signed by `other`
    let good = build(&f, &Spec::default());
    let forged = {
        let g = Fx {
            issuer: Party {
                sk: f.issuer.sk.clone(),
                cert_der: f.issuer.cert_der.clone(),
            },
            device: other,
            er: f.er.clone(),
            st: f.st.clone(),
        };
        build(&g, &Spec::default())
    };
    verify(&f, &good, false).unwrap();
    // forged has an MSO naming `other` and is signed by it, but the issuer is the same: it verifies by itself...
    assert!(verify(&f, &forged, false).is_ok());
    // ...so splice: take the genuine issuerSigned and the forged deviceSigned.
    let (a, b): (C, C) = (
        ciborium::from_reader(&good[..]).unwrap(),
        ciborium::from_reader(&forged[..]).unwrap(),
    );
    let splice = |a: &C, b: &C| -> Vec<u8> {
        let (C::Map(ra), C::Map(rb)) = (a, b) else {
            panic!()
        };
        let docs = |m: &Vec<(C, C)>| -> Vec<(C, C)> {
            let C::Array(d) = &m
                .iter()
                .find(|(k, _)| *k == C::Text("documents".into()))
                .unwrap()
                .1
            else {
                panic!()
            };
            let C::Map(d) = &d[0] else { panic!() };
            d.clone()
        };
        let (da, db) = (docs(ra), docs(rb));
        let pick = |m: &Vec<(C, C)>, k: &str| {
            m.iter()
                .find(|(x, _)| *x == C::Text(k.into()))
                .unwrap()
                .clone()
        };
        let doc = C::Map(vec![
            pick(&da, "docType"),
            pick(&da, "issuerSigned"),
            pick(&db, "deviceSigned"),
        ]);
        enc(&C::Map(vec![
            (C::Text("version".into()), C::Text("1.0".into())),
            (C::Text("documents".into()), C::Array(vec![doc])),
            (C::Text("status".into()), C::Integer(0.into())),
        ]))
    };
    let e = verify(&f, &splice(&a, &b), false).unwrap_err();
    assert!(e.contains("cose_signature"), "{e}");
}

#[test]
fn response_for_another_session_is_rejected() {
    let f = fx();
    let resp = build(&f, &Spec::default());
    let other = Fx {
        st: transcript(&f.er.public_key(), 2),
        ..fx_like(&f)
    };
    let e = verify(&other, &resp, false).unwrap_err();
    assert!(e.contains("cose_signature"), "{e}");
}
fn fx_like(f: &Fx) -> Fx {
    Fx {
        issuer: Party {
            sk: f.issuer.sk.clone(),
            cert_der: f.issuer.cert_der.clone(),
        },
        device: f.device.clone(),
        er: f.er.clone(),
        st: f.st.clone(),
    }
}

#[test]
fn signature_only_mode_rejects_mac_and_vice_versa() {
    let f = fx();
    let mac = build(
        &f,
        &Spec {
            use_mac: true,
            ..Default::default()
        },
    );
    assert!(verify(&f, &mac, false)
        .unwrap_err()
        .contains("device_mac_not_accepted"));
    let sig = build(&f, &Spec::default());
    // a MAC-accepting verifier still takes a signature
    verify(&f, &sig, true).unwrap();
}

#[test]
fn rejects_issuer_alg_other_than_es256() {
    rejects(
        Spec {
            issuer_alg: -35,
            ..Default::default()
        },
        "issuer_alg_not_es256",
    );
}
#[test]
fn rejects_too_many_documents() {
    rejects(
        Spec {
            doc_count: 9,
            ..Default::default()
        },
        "document_count",
    );
}
#[test]
fn rejects_duplicate_map_keys() {
    rejects(
        Spec {
            duplicate_status: true,
            ..Default::default()
        },
        "duplicate_map_key",
    );
}
#[test]
fn rejects_device_key_with_private_part() {
    rejects(
        Spec {
            device_key_private: true,
            ..Default::default()
        },
        "cose_key_has_private_part",
    );
}
#[test]
fn rejects_more_than_the_item_limit() {
    let elements = (0..1001)
        .map(|n| ("ns".to_string(), format!("e{n}"), C::Bool(true)))
        .collect();
    rejects(
        Spec {
            elements,
            ..Default::default()
        },
        "too_many_items",
    );
}
#[test]
fn rejects_trailing_bytes() {
    let f = fx();
    let mut r = build(&f, &Spec::default());
    r.push(0);
    assert!(verify(&f, &r, false)
        .unwrap_err()
        .contains("cbor_trailing_bytes"));
}

#[test]
fn mdoc_trust_query_has_gotrusts_shape() {
    let f = fx();
    let r = verify(&f, &build(&f, &Spec::default()), false).unwrap();
    let q = siros_verifier_core::trust::TrustQuery::for_mdoc_issuer(
        &r[0].issuer,
        "pid-provider",
        &r[0].doc_type,
    )
    .to_authzen();
    assert_eq!(q["resource"]["type"], "x5c");
    assert_eq!(q["resource"]["id"], q["subject"]["id"]);
    assert_eq!(q["subject"]["id"], "https://issuer.example");
    assert_eq!(q["resource"]["key"].as_array().unwrap().len(), 1);
    assert_eq!(
        q["action"]["parameters"]["credential_types"][0],
        "eu.europa.ec.eudi.pid.1"
    );
}

#[test]
fn non_ascii_date_is_a_format_error_not_a_slicing_panic() {
    rejects(
        Spec {
            valid_until: "2027-01-01T00:00:\u{e9}Z".into(),
            ..Default::default()
        },
        "tdate_format",
    );
}
