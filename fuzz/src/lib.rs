use std::sync::OnceLock;

use jose_rs::jwk::Jwk;
use p256::{PublicKey, SecretKey};
use serde_json::{json, Value};
use siros_verifier_core::oid4vp::Session;
use siros_verifier_core::sdjwt::StaticKey;

pub const MAX_INPUT: usize = 64 * 1024;

pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

pub struct IsoFixture {
    pub transcript: Vec<u8>,
    pub session_data: Vec<u8>,
    pub ereader: SecretKey,
    pub edevice: PublicKey,
}

pub fn iso() -> &'static IsoFixture {
    static FIXTURE: OnceLock<IsoFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let v: Value = serde_json::from_str(include_str!(
            "../../tests/vectors/iso18013_annex_d5.json"
        ))
        .unwrap();
        let mut sec1 = vec![4u8];
        sec1.extend(hex(v["edevice"]["x"].as_str().unwrap()));
        sec1.extend(hex(v["edevice"]["y"].as_str().unwrap()));
        IsoFixture {
            transcript: hex(v["session_transcript_bytes"].as_str().unwrap()),
            session_data: hex(v["session_data"].as_str().unwrap()),
            ereader: SecretKey::from_slice(&hex(v["ereader"]["d"].as_str().unwrap())).unwrap(),
            edevice: PublicKey::from_sec1_bytes(&sec1).unwrap(),
        }
    })
}

pub struct VcFixture {
    pub resolver: StaticKey,
    pub now: i64,
    pub aud: String,
    pub nonce: String,
    pub presentation: String,
}

fn vc_value() -> Value {
    serde_json::from_str(include_str!("../../tests/vectors/vc_sdjwt.json")).unwrap()
}

pub fn vc() -> &'static VcFixture {
    static FIXTURE: OnceLock<VcFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let v = vc_value();
        VcFixture {
            resolver: StaticKey(
                serde_json::from_value(v["issuer_public_jwk"].clone()).unwrap(),
            ),
            now: v["generated_at"].as_i64().unwrap() + 2,
            aud: v["aud"].as_str().unwrap().to_owned(),
            nonce: v["nonce"].as_str().unwrap().to_owned(),
            presentation: v["presentation"].as_str().unwrap().to_owned(),
        }
    })
}

pub struct GoFixture {
    pub session: Session,
    pub resolver: StaticKey,
    pub vectors: Vec<(String, String)>,
}

pub fn go() -> &'static GoFixture {
    static FIXTURE: OnceLock<GoFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let v: Value = serde_json::from_str(include_str!("../../tests/vectors/go_jwe.json")).unwrap();
        let mut enc_key: Jwk = serde_json::from_value(v["private_jwk"].clone()).unwrap();
        enc_key.alg = Some("ECDH-ES".into());
        enc_key.use_ = Some("enc".into());
        enc_key.kid = Some("go-recipient".into());
        let vectors = v["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| {
                (
                    item["enc"].as_str().unwrap().to_owned(),
                    item["jwe"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        GoFixture {
            session: Session {
                client_id: "x509_hash:fuzz".into(),
                nonce: "fuzz-nonce".into(),
                state: "s-from-go".into(),
                response_uri: "https://verifier.example/response/fuzz".into(),
                dcql_query: json!({"credentials":[{"id":"pid","format":"dc+sd-jwt"}]}),
                expires_at: i64::MAX,
                enc_key,
                dc_api_origin: None,
            },
            resolver: StaticKey(
                serde_json::from_value(vc_value()["issuer_public_jwk"].clone()).unwrap(),
            ),
            vectors,
        }
    })
}
