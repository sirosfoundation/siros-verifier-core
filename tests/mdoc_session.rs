//! ISO/IEC 18013-5 Annex D.5.1 vectors (text-extracted from the spec PDF, not retyped).
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use ciborium::Value as C;
use p256::{PublicKey, SecretKey};
use serde_json::Value;
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
fn session() -> ReaderSession {
    let v = vec_();
    let sk = SecretKey::from_slice(&hex(v["ereader"]["d"].as_str().unwrap())).unwrap();
    let mut sec1 = vec![4u8];
    sec1.extend(hex(v["edevice"]["x"].as_str().unwrap()));
    sec1.extend(hex(v["edevice"]["y"].as_str().unwrap()));
    let pk = PublicKey::from_sec1_bytes(&sec1).unwrap();
    ReaderSession::new(&sk, &pk, &h(&v, "session_transcript_bytes")).unwrap()
}
fn map_get(v: &C, key: &str) -> C {
    let C::Map(m) = v else { panic!("not a map") };
    m.iter()
        .find(|(k, _)| k == &C::Text(key.into()))
        .unwrap_or_else(|| panic!("no {key}"))
        .1
        .clone()
}

#[test]
fn derives_the_spec_keys() {
    let v = vec_();
    let (r, d) = session().keys();
    assert_eq!(r.to_vec(), h(&v, "sk_reader"));
    assert_eq!(d.to_vec(), h(&v, "sk_device"));
}

#[test]
fn decrypts_the_spec_device_response() {
    let v = vec_();
    let Incoming::Data { plaintext, .. } = session().decrypt(&h(&v, "session_data")).unwrap()
    else {
        panic!("expected data")
    };
    let resp: C = ciborium::from_reader(&plaintext[..]).unwrap();
    assert_eq!(map_get(&resp, "version"), C::Text("1.0".into()));
    let C::Array(docs) = map_get(&resp, "documents") else {
        panic!()
    };
    assert_eq!(docs.len(), 1);
}

#[test]
fn reader_ciphertext_reproduces_the_spec_byte_for_byte() {
    // Decrypt the spec's SessionEstablishment payload with SKReader (independent AES-GCM use), then
    // require our encrypt() to reproduce the spec's ciphertext exactly. This pins key, IV layout
    // and counter start together.
    let v = vec_();
    let est: C = ciborium::from_reader(&h(&v, "session_establishment")[..]).unwrap();
    let C::Bytes(spec_ct) = map_get(&est, "data") else {
        panic!()
    };
    let (sk_reader, _) = session().keys();
    let mut iv = [0u8; 12];
    iv[11] = 1;
    let pt = Aes256Gcm::new_from_slice(&sk_reader)
        .unwrap()
        .decrypt(&Nonce::from(iv), &spec_ct[..])
        .unwrap();
    let req: C = ciborium::from_reader(&pt[..]).unwrap();
    assert_eq!(map_get(&req, "version"), C::Text("1.0".into()));
    assert_eq!(session().encrypt(&pt).unwrap(), spec_ct);
}

#[test]
fn counter_advances_so_equal_plaintexts_differ() {
    let mut s = session();
    let a = s.encrypt(b"x").unwrap();
    assert_ne!(a, s.encrypt(b"x").unwrap());
}

#[test]
fn tampered_session_data_poisons_the_session() {
    let v = vec_();
    let good = h(&v, "session_data");
    let mut bad = good.clone();
    *bad.last_mut().unwrap() ^= 1;
    let mut s = session();
    assert!(s.decrypt(&bad).is_err());
    // fail closed afterwards, even for the genuine message
    assert!(s.decrypt(&good).is_err());
}

#[test]
fn replayed_session_data_is_rejected() {
    let good = h(&vec_(), "session_data");
    let mut s = session();
    s.decrypt(&good).unwrap();
    assert!(s.decrypt(&good).is_err());
}

#[test]
fn status_only_message_is_termination() {
    assert_eq!(
        session().decrypt(&hex("a16673746174757314")).unwrap(),
        Incoming::Status(20)
    );
    assert_eq!(session_termination().unwrap(), hex("a16673746174757314"));
}

#[test]
fn unknown_or_duplicate_members_are_rejected() {
    // { "data": h'00', "extra": 1 }
    assert!(session()
        .decrypt(&hex("a26464617461410065657874726101"))
        .is_err());
}

#[test]
fn duplicate_data_member_is_malformed_not_a_decrypt_failure() {
    // { "data": h'00', "data": h'01' }: the error class matters, since a decrypt failure would
    // also be an error but for the wrong reason.
    let e = session()
        .decrypt(&hex("a2646461746141006464617461 4101"
            .replace(' ', "")
            .as_str()))
        .unwrap_err();
    assert_eq!(e.code(), "malformed");
}

// ---- handshake: the reader key is generated or injected inside the library ----
mod handshake {
    use super::*;
    use ciborium::Value as C;
    use siros_verifier_core::mdoc_session::ReaderHandshake;

    /// Pull DeviceEngagement and Handover back out of the spec's SessionTranscriptBytes.
    fn parts() -> (Vec<u8>, Vec<u8>) {
        let v = vec_();
        let C::Tag(24, inner) =
            ciborium::from_reader::<C, _>(&h(&v, "session_transcript_bytes")[..]).unwrap()
        else {
            panic!()
        };
        let C::Bytes(st) = *inner else { panic!() };
        let C::Array(a) = ciborium::from_reader::<C, _>(&st[..]).unwrap() else {
            panic!()
        };
        let C::Tag(24, de) = &a[0] else { panic!() };
        let C::Bytes(de) = &**de else { panic!() };
        let mut ho = vec![];
        ciborium::into_writer(&a[2], &mut ho).unwrap();
        (de.clone(), ho)
    }
    fn reader_key() -> SecretKey {
        SecretKey::from_slice(&hex(vec_()["ereader"]["d"].as_str().unwrap())).unwrap()
    }
    fn establish(de: &[u8], ho: &[u8]) -> siros_verifier_core::Result<ReaderSession> {
        ReaderHandshake::from_secret(reader_key()).establish(de, ho)
    }

    #[test]
    fn rebuilds_the_spec_transcript_and_keys_from_engagement_and_handover() {
        let (de, ho) = parts();
        let s = establish(&de, &ho).unwrap();
        let v = vec_();
        assert_eq!(s.transcript_bytes(), &h(&v, "session_transcript_bytes")[..]);
        let (r, d) = s.keys();
        assert_eq!(r.to_vec(), h(&v, "sk_reader"));
        assert_eq!(d.to_vec(), h(&v, "sk_device"));
    }

    #[test]
    fn session_verifies_the_spec_response_without_the_caller_holding_any_key() {
        let (de, ho) = parts();
        let mut s = establish(&de, &ho).unwrap();
        let Incoming::Data { plaintext, .. } = s.decrypt(&h(&vec_(), "session_data")).unwrap()
        else {
            panic!()
        };
        let docs = s
            .verify_response(&plaintext, 1_610_000_000, Some(&["org.iso.18013.5.1.mDL"]))
            .unwrap();
        assert_eq!(docs[0].doc_type, "org.iso.18013.5.1.mDL");
    }

    #[test]
    fn first_message_carries_the_reader_key_and_matches_the_spec_ciphertext() {
        let (de, ho) = parts();
        let v = vec_();
        // the plaintext DeviceRequest the spec encrypted
        let est: C = ciborium::from_reader(&h(&v, "session_establishment")[..]).unwrap();
        let C::Bytes(spec_ct) = map_get(&est, "data") else {
            panic!()
        };
        let (sk_reader, _) = establish(&de, &ho).unwrap().keys();
        let mut iv = [0u8; 12];
        iv[11] = 1;
        use aes_gcm::aead::{Aead, KeyInit};
        let pt = aes_gcm::Aes256Gcm::new_from_slice(&sk_reader)
            .unwrap()
            .decrypt(&aes_gcm::Nonce::from(iv), &spec_ct[..])
            .unwrap();

        let mut s = establish(&de, &ho).unwrap();
        let msg = s.establishment_message(&pt).unwrap();
        assert_eq!(
            msg,
            h(&v, "session_establishment"),
            "byte for byte the spec's SessionEstablishment"
        );
        // a second establishment, or data before establishment, is refused
        assert!(s
            .establishment_message(&pt)
            .unwrap_err()
            .to_string()
            .contains("already_established"));
        assert!(establish(&de, &ho)
            .unwrap()
            .data_message(&pt)
            .unwrap_err()
            .to_string()
            .contains("not_established"));
        assert!(s.data_message(&pt).is_ok());
    }

    fn map_get(v: &C, key: &str) -> C {
        let C::Map(m) = v else { panic!() };
        m.iter()
            .find(|(k, _)| k == &C::Text(key.into()))
            .unwrap()
            .1
            .clone()
    }

    fn reencode(f: impl Fn(&mut C)) -> Vec<u8> {
        let (de, _) = parts();
        let mut v: C = ciborium::from_reader(&de[..]).unwrap();
        f(&mut v);
        let mut o = vec![];
        ciborium::into_writer(&v, &mut o).unwrap();
        o
    }
    fn set(v: &mut C, k: i64, val: C) {
        let C::Map(m) = v else { panic!() };
        for (kk, vv) in m.iter_mut() {
            if *kk == C::Integer(k.into()) {
                *vv = val.clone();
            }
        }
    }
    fn err(r: siros_verifier_core::Result<ReaderSession>) -> String {
        r.err()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "OK".into())
    }

    #[test]
    fn rejects_bad_engagement_and_handover() {
        let (de, ho) = parts();
        assert!(err(establish(
            &reencode(|v| set(v, 0, C::Text("2.0".into()))),
            &ho
        ))
        .contains("device_engagement_version"));
        assert!(err(establish(
            &reencode(|v| set(v, 1, C::Array(vec![C::Integer(2.into()), C::Null]))),
            &ho
        ))
        .contains("cipher_suite"));
        assert!(err(establish(
            &reencode(|v| set(
                v,
                1,
                C::Array(vec![C::Integer(1.into()), C::Bytes(vec![1])])
            )),
            &ho
        ))
        .contains("device_key_not_tag24"));
        assert!(err(establish(
            &reencode(|v| set(
                v,
                1,
                C::Array(vec![
                    C::Integer(1.into()),
                    C::Tag(24, Box::new(C::Bytes(vec![0xa0])))
                ])
            )),
            &ho
        ))
        .contains("device_key"));
        // a valid key under the wrong tag
        let retag = reencode(|v| {
            let C::Map(m) = v else { panic!() };
            for (k, val) in m.iter_mut() {
                if *k == C::Integer(1.into()) {
                    let C::Array(a) = val else { panic!() };
                    let C::Tag(_, inner) = a[1].clone() else {
                        panic!()
                    };
                    a[1] = C::Tag(25, inner);
                }
            }
        });
        assert!(err(establish(&retag, &ho)).contains("device_key_not_tag24"));
        assert!(err(establish(&[0x80], &ho)).contains("device_engagement_not_map"));
        let mut t = de.clone();
        t.push(0);
        assert!(err(establish(&t, &ho)).contains("device_engagement_cbor_trailing_bytes"));
        let mut t = ho.clone();
        t.push(0);
        assert!(err(establish(&de, &t)).contains("handover_cbor_trailing_bytes"));
        assert!(err(establish(&de, &[])).contains("handover_cbor"));
    }

    #[test]
    fn generated_keys_differ_and_a_full_round_trip_works() {
        let (de, _) = parts();
        let a = ReaderHandshake::generate();
        let b = ReaderHandshake::generate();
        assert_ne!(a.ereader_cose_key(), b.ereader_cose_key());
        // QR-style handover (null) with a generated key: establishes, and its transcript differs from the spec's
        let s = a.establish(&de, &[0xf6]).unwrap();
        assert_ne!(
            s.transcript_bytes(),
            &h(&vec_(), "session_transcript_bytes")[..]
        );
    }
}
