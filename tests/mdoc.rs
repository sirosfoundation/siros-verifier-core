//! DeviceResponse verification against the ISO/IEC 18013-5 Annex D.5 example
//! (session from D.5.1, issuer data from D.5.2, deviceMac from D.5.3).
use ciborium::Value as C;
use p256::SecretKey;
use serde_json::Value;
use siros_verifier_core::mdoc::*;
use siros_verifier_core::mdoc_session::*;

fn vec_() -> Value {
    serde_json::from_str(include_str!("vectors/iso18013_annex_d5.json")).unwrap()
}
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn h(v: &Value, k: &str) -> Vec<u8> {
    hex(v[k].as_str().unwrap())
}
fn ereader() -> SecretKey {
    SecretKey::from_slice(&hex(vec_()["ereader"]["d"].as_str().unwrap())).unwrap()
}
fn response() -> Vec<u8> {
    let v = vec_();
    let mut sec1 = vec![4u8];
    sec1.extend(hex(v["edevice"]["x"].as_str().unwrap()));
    sec1.extend(hex(v["edevice"]["y"].as_str().unwrap()));
    let pk = p256::PublicKey::from_sec1_bytes(&sec1).unwrap();
    let mut s = ReaderSession::new(&ereader(), &pk, &h(&v, "session_transcript_bytes")).unwrap();
    match s.decrypt(&h(&v, "session_data")).unwrap() {
        Incoming::Data { plaintext, .. } => plaintext,
        _ => panic!(),
    }
}
// Inside the example validity window (the MSO is valid 2020-10-01 .. 2021-10-01).
const NOW: i64 = 1_610_000_000; // 2021-01-07

fn run(resp: &[u8], now: i64) -> siros_verifier_core::Result<Vec<MdocVerified>> {
    let v = vec_();
    let er = ereader();
    let st = h(&v, "session_transcript_bytes");
    verify_device_response(
        resp,
        &Params {
            session_transcript_bytes: &st,
            now,
            device_auth: DeviceKeyAuth::Mac { ereader: &er },
            expected_doc_types: None,
        },
    )
}
fn code(r: siros_verifier_core::Result<Vec<MdocVerified>>) -> String {
    r.err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "OK".into())
}

#[test]
fn accepts_the_spec_example() {
    let docs = run(&response(), NOW).unwrap();
    assert_eq!(docs.len(), 1);
    let d = &docs[0];
    assert_eq!(d.doc_type, "org.iso.18013.5.1.mDL");
    let ns = &d.elements["org.iso.18013.5.1"];
    assert_eq!(ns["family_name"], C::Text("Doe".into()));
    assert_eq!(d.issuer.x5c_der.len(), 1);
}

#[test]
fn rejects_outside_validity() {
    assert!(code(run(&response(), 1_500_000_000)).contains("not_yet_valid"));
    assert!(code(run(&response(), 1_700_000_000)).contains("expired"));
}

#[test]
fn mac_needs_the_reader_key() {
    let v = vec_();
    let st = h(&v, "session_transcript_bytes");
    let r = verify_device_response(
        &response(),
        &Params {
            session_transcript_bytes: &st,
            now: NOW,
            device_auth: DeviceKeyAuth::SignatureOnly,
            expected_doc_types: None,
        },
    );
    assert!(code(r).contains("device_mac_not_accepted"));
}

#[test]
fn wrong_session_transcript_fails_device_auth() {
    let v = vec_();
    let mut st = h(&v, "session_transcript_bytes");
    let n = st.len();
    st[n - 1] ^= 1;
    let er = ereader();
    let r = verify_device_response(
        &response(),
        &Params {
            session_transcript_bytes: &st,
            now: NOW,
            device_auth: DeviceKeyAuth::Mac { ereader: &er },
            expected_doc_types: None,
        },
    );
    assert!(code(r).contains("device_mac"));
}

#[test]
fn doc_type_filter() {
    let v = vec_();
    let st = h(&v, "session_transcript_bytes");
    let er = ereader();
    let r = verify_device_response(
        &response(),
        &Params {
            session_transcript_bytes: &st,
            now: NOW,
            device_auth: DeviceKeyAuth::Mac { ereader: &er },
            expected_doc_types: Some(&["eu.europa.ec.eudi.pid.1"]),
        },
    );
    assert!(code(r).contains("doc_type_not_requested"));
}

/// Flip every bit-0 of every byte. The only flips that may verify are inside the issuer certificate
/// (the chain is evidence for the trust layer, not verified here beyond its public key), and those
/// must surface in `issuer.x5c_der` so the PDP sees exactly what was presented.
/// One more exception, documented: ciborium decodes CBOR `undefined` as `null`, so the detached-payload
/// slot of a COSE_Mac0 may be 0xf6 or 0xf7.
#[test]
fn bit_flips_only_verify_inside_the_certificate() {
    let good = response();
    let original = run(&good, NOW).unwrap().remove(0).issuer.x5c_der.remove(0);
    let start = good
        .windows(original.len())
        .position(|w| w == original)
        .unwrap();
    let range = start..start + original.len();
    let mut outside = vec![];
    for i in 0..good.len() {
        let mut b = good.clone();
        b[i] ^= 0x01;
        if let Ok(mut docs) = run(&b, NOW) {
            if range.contains(&i) {
                assert_ne!(
                    docs.remove(0).issuer.x5c_der.remove(0),
                    original,
                    "flip at {i} not reflected in evidence"
                );
            } else {
                outside.push(i);
            }
        }
    }
    assert_eq!(
        outside.len(),
        1,
        "unexpected accepted flips outside the cert: {outside:?}"
    );
    assert_eq!(good[outside[0]], 0xf6);
}
