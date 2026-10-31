//! Issuer and wallet simulators used by the tests. Not part of the verifier.

use crate::sdjwt::HashAlg;
use crate::{b64u, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use jose_rs::jwk::Jwk;
use jose_rs::jws::compact::{sign_with_jwk_options, SignOptions};
use jose_rs::JoseHeader;
use serde_json::{json, Map, Value};

#[derive(Clone, Debug)]
pub enum Seg {
    Key(&'static str),
    Idx(usize),
}

pub struct IssueSpec {
    pub claims: Value,
    /// Paths to conceal. Parents and children may both be listed.
    pub conceal: Vec<Vec<Seg>>,
    pub decoys: usize,
    pub hash: HashAlg,
    pub holder_pub: Option<Jwk>,
    pub x5c_der: Vec<Vec<u8>>,
    pub typ: &'static str,
}

impl IssueSpec {
    pub fn new(claims: Value) -> Self {
        Self {
            claims,
            conceal: vec![],
            decoys: 0,
            hash: HashAlg::Sha256,
            holder_pub: None,
            x5c_der: vec![],
            typ: "dc+sd-jwt",
        }
    }
}

pub struct Issued {
    pub jwt: String,
    /// Raw disclosure strings in creation order (children before parents).
    pub disclosures: Vec<String>,
}

fn salt() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("OS randomness");
    b64u(&b)
}

pub fn ec_jwk(alg: &str, kid: &str) -> Jwk {
    let mut jwk = jose_rs::jwk::generate_ec("P-256").expect("keygen");
    jwk.alg = Some(alg.to_owned());
    jwk.kid = Some(kid.to_owned());
    jwk
}

pub fn public_of(jwk: &Jwk) -> Jwk {
    let mut p = jwk.to_public_jwk();
    p.alg = None;
    p
}

fn navigate<'a>(root: &'a mut Value, path: &[Seg]) -> &'a mut Value {
    let mut cur = root;
    for seg in path {
        cur = match seg {
            Seg::Key(k) => cur.get_mut(*k).expect("path key"),
            Seg::Idx(i) => cur.get_mut(*i).expect("path index"),
        };
    }
    cur
}

pub fn issue(issuer: &Jwk, spec: &IssueSpec) -> Result<Issued> {
    let mut claims = spec.claims.clone();
    let mut disclosures = Vec::new();

    let mut paths = spec.conceal.clone();
    paths.sort_by_key(|p| std::cmp::Reverse(p.len()));
    for path in &paths {
        let (last, parent_path) = path.split_last().expect("non-empty path");
        let parent = navigate(&mut claims, parent_path);
        match last {
            Seg::Key(name) => {
                let obj = parent.as_object_mut().expect("parent object");
                let value = obj.remove(*name).expect("claim to conceal");
                let raw = b64u(
                    serde_json::to_string(&json!([salt(), name, value]))
                        .unwrap()
                        .as_bytes(),
                );
                let digest = spec.hash.digest_b64u(raw.as_bytes());
                obj.entry("_sd")
                    .or_insert_with(|| json!([]))
                    .as_array_mut()
                    .unwrap()
                    .push(json!(digest));
                disclosures.push(raw);
            }
            Seg::Idx(i) => {
                let arr = parent.as_array_mut().expect("parent array");
                let value = arr[*i].clone();
                let raw = b64u(
                    serde_json::to_string(&json!([salt(), value]))
                        .unwrap()
                        .as_bytes(),
                );
                let digest = spec.hash.digest_b64u(raw.as_bytes());
                arr[*i] = json!({ "...": digest });
                disclosures.push(raw);
            }
        }
    }
    let top = claims.as_object_mut().expect("claims object");
    for _ in 0..spec.decoys {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).expect("OS randomness");
        top.entry("_sd")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .unwrap()
            .push(json!(spec.hash.digest_b64u(&b)));
    }
    if let Some(sd) = top.get_mut("_sd").and_then(Value::as_array_mut) {
        sd.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    }
    if spec.hash != HashAlg::Sha256 {
        top.insert("_sd_alg".into(), json!(spec.hash.name()));
    }
    if let Some(h) = &spec.holder_pub {
        top.insert("cnf".into(), json!({ "jwk": h }));
    }

    let mut header = JoseHeader::new(issuer.alg.as_deref().expect("issuer alg"));
    header.typ = Some(spec.typ.to_owned());
    header.kid = issuer.kid.clone();
    let mut opts = SignOptions::new();
    if !spec.x5c_der.is_empty() {
        header.x5c = Some(spec.x5c_der.iter().map(|d| B64.encode(d)).collect());
        opts = opts.with_key_reference_headers(true);
    }
    let jwt = sign_with_jwk_options(
        issuer,
        &serde_json::to_vec(&claims).unwrap(),
        &header,
        &opts,
    )?;
    Ok(Issued { jwt, disclosures })
}

pub struct KbSpec<'a> {
    pub holder: &'a Jwk,
    pub aud: &'a str,
    pub nonce: &'a str,
    pub iat: i64,
}

/// Build a presentation with the disclosures at `select`, optionally with a KB-JWT.
pub fn present(
    issued: &Issued,
    select: &[usize],
    kb: Option<KbSpec>,
    hash: HashAlg,
) -> Result<String> {
    present_with_kb_typ(issued, select, kb, hash, "kb+jwt")
}

/// Like [`present`], with a chosen KB-JWT `typ` (for negative tests).
pub fn present_with_kb_typ(
    issued: &Issued,
    select: &[usize],
    kb: Option<KbSpec>,
    hash: HashAlg,
    typ: &str,
) -> Result<String> {
    let mut s = issued.jwt.clone();
    s.push('~');
    for i in select {
        s.push_str(&issued.disclosures[*i]);
        s.push('~');
    }
    if let Some(kb) = kb {
        let claims = json!({
            "iat": kb.iat, "aud": kb.aud, "nonce": kb.nonce,
            "sd_hash": hash.digest_b64u(s.as_bytes()),
        });
        let mut header = JoseHeader::new(kb.holder.alg.as_deref().expect("holder alg"));
        header.typ = Some(typ.to_owned());
        let jwt = sign_with_jwk_options(
            kb.holder,
            &serde_json::to_vec(&claims).unwrap(),
            &header,
            &SignOptions::new(),
        )?;
        s.push_str(&jwt);
    }
    Ok(s)
}

/// A self-signed P-256 certificate for `dns` plus the matching private JWK.
pub fn self_signed_ec(dns: &str, alg: &str) -> (Vec<u8>, Jwk) {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("rcgen key");
    let params = rcgen::CertificateParams::new(vec![dns.to_owned()]).expect("params");
    let cert = params.self_signed(&kp).expect("self-signed");
    let mut jwk = jose_rs::jwk::jwk_from_pkcs8_der(kp.serialized_der()).expect("pkcs8");
    jwk.alg = Some(alg.to_owned());
    (cert.der().to_vec(), jwk)
}

/// Raw claims map helper for assertions.
pub fn obj(v: Value) -> Map<String, Value> {
    v.as_object().cloned().expect("object")
}

/// What a simulated wallet presents for one DCQL credential id.
pub struct WalletCredential<'a> {
    pub id: &'a str,
    pub issued: &'a Issued,
    pub disclose: &'a [usize],
}

/// A wallet that checks the request object the way a real one must, then
/// answers with an encrypted `direct_post.jwt` response body.
pub fn wallet_respond(
    jar: &str,
    holder: &Jwk,
    creds: &[WalletCredential],
    now: i64,
) -> Result<String> {
    wallet_respond_inner(jar, holder, creds, now, None)
}

/// A DC API wallet response using the platform-attested origin as KB-JWT aud.
pub fn wallet_respond_dc_api(
    jar: &str,
    holder: &Jwk,
    creds: &[WalletCredential],
    now: i64,
    origin: &str,
) -> Result<String> {
    wallet_respond_inner(jar, holder, creds, now, Some(origin))
}

fn wallet_respond_inner(
    jar: &str,
    holder: &Jwk,
    creds: &[WalletCredential],
    now: i64,
    dc_api_origin: Option<&str>,
) -> Result<String> {
    use crate::{oid4vp, sdjwt};
    use jose_rs::algorithm::{JweAlgorithm, JweEncryption};
    use jose_rs::jwe::compact as jwe_compact;
    use jose_rs::jws;

    let header = jws::decode_header(jar)?;
    assert_eq!(header.typ.as_deref(), Some("oauth-authz-req+jwt"));
    let chain = sdjwt::x5c_chain(&header)?;
    let leaf_key = sdjwt::jwk_from_cert_der(&chain[0])?;
    let payload: Value =
        serde_json::from_slice(&jws::compact::verify_with_jwk(&leaf_key, jar)?).expect("jar json");
    assert_eq!(
        payload["client_id"],
        json!(oid4vp::x509_hash_client_id(&chain[0])),
        "client_id must bind to the signing certificate"
    );
    let mode = payload["response_mode"].as_str().unwrap();
    let audience = match dc_api_origin {
        Some(origin) => {
            assert_eq!(mode, "dc_api.jwt");
            format!("origin:{origin}")
        }
        None => {
            assert_eq!(mode, "direct_post.jwt");
            payload["client_id"].as_str().unwrap().to_owned()
        }
    };

    let nonce = payload["nonce"].as_str().unwrap();
    let mut vp = Map::new();
    for c in creds {
        let kb = KbSpec {
            holder,
            aud: &audience,
            nonce,
            iat: now,
        };
        let pres = present(c.issued, c.disclose, Some(kb), HashAlg::Sha256)?;
        vp.insert(c.id.to_owned(), json!([pres]));
    }
    let body = json!({ "vp_token": vp, "state": payload["state"] });

    let enc_jwk: Jwk =
        serde_json::from_value(payload["client_metadata"]["jwks"]["keys"][0].clone())
            .expect("enc jwk");
    let mut header = JoseHeader::for_jwe(JweAlgorithm::EcdhEs, JweEncryption::A128GCM);
    header.kid = enc_jwk.kid.clone();
    Ok(jwe_compact::encrypt_with_jwk_header(
        &enc_jwk,
        header,
        body.to_string().as_bytes(),
        JweEncryption::A128GCM,
    )?)
}

/// Sign an arbitrary payload as an issuer JWT. For crafting hostile inputs.
pub fn sign_raw(issuer: &Jwk, typ: &str, payload: &Value, x5c_der: &[Vec<u8>]) -> String {
    sign_raw_bytes(issuer, typ, &serde_json::to_vec(payload).unwrap(), x5c_der)
}

/// As [`sign_raw`] but with the payload bytes exactly as given, so a test can sign JSON a `Value` cannot hold
/// (repeated member names, odd escapes).
pub fn sign_raw_bytes(issuer: &Jwk, typ: &str, payload: &[u8], x5c_der: &[Vec<u8>]) -> String {
    let mut header = JoseHeader::new(issuer.alg.as_deref().expect("alg"));
    header.typ = Some(typ.to_owned());
    let mut opts = SignOptions::new();
    if !x5c_der.is_empty() {
        header.x5c = Some(x5c_der.iter().map(|d| B64.encode(d)).collect());
        opts = opts.with_key_reference_headers(true);
    }
    sign_with_jwk_options(issuer, payload, &header, &opts).expect("sign")
}

/// A property disclosure `(raw, digest)` for the given hash.
pub fn disclosure_prop(name: &str, value: Value, hash: HashAlg) -> (String, String) {
    let raw = b64u(
        serde_json::to_string(&json!([salt(), name, value]))
            .unwrap()
            .as_bytes(),
    );
    let d = hash.digest_b64u(raw.as_bytes());
    (raw, d)
}

/// An array-element disclosure `(raw, digest)`.
pub fn disclosure_elem(value: Value, hash: HashAlg) -> (String, String) {
    let raw = b64u(
        serde_json::to_string(&json!([salt(), value]))
            .unwrap()
            .as_bytes(),
    );
    let d = hash.digest_b64u(raw.as_bytes());
    (raw, d)
}

/// ISO 18013-5 issuer and holder simulator.
pub mod mdoc_sim {
    use ciborium::Value as C;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::elliptic_curve::Generate;
    use p256::pkcs8::DecodePrivateKey;
    use p256::SecretKey;
    use sha2::{Digest, Sha256};

    pub fn enc(v: &C) -> Vec<u8> {
        let mut o = Vec::new();
        ciborium::into_writer(v, &mut o).unwrap();
        o
    }
    fn t(s: &str) -> C {
        C::Text(s.into())
    }
    fn i(n: i64) -> C {
        C::Integer(n.into())
    }
    fn tag24(inner: Vec<u8>) -> C {
        C::Tag(24, Box::new(C::Bytes(inner)))
    }
    fn tdate(s: &str) -> C {
        C::Tag(0, Box::new(t(s)))
    }

    pub struct Spec {
        pub doc_type: String,
        pub mso_doc_type: String,
        pub elements: Vec<(String, String, C)>,
        pub valid_from: String,
        pub valid_until: String,
        pub digest_alg: String,
        pub random_len: usize,
        /// Corrupt the digest for element index n in the MSO.
        pub bad_digest_for: Option<usize>,
        /// Give two items the same digestID.
        pub duplicate_digest_id: bool,
        /// Drop this element from the MSO digests (released but undigested).
        pub omit_digest_for: Option<usize>,
        /// Sign the response with deviceMac instead of deviceSignature (needs `ereader_pub`).
        pub use_mac: bool,
        pub extra_root_member: bool,
        pub status: i64,
        /// COSE alg label put in the issuerAuth protected header (signature is still ES256).
        pub issuer_alg: i64,
        pub doc_count: usize,
        pub duplicate_status: bool,
        pub device_key_private: bool,
    }

    impl Default for Spec {
        fn default() -> Self {
            Spec {
                doc_type: "eu.europa.ec.eudi.pid.1".into(),
                mso_doc_type: "eu.europa.ec.eudi.pid.1".into(),
                elements: vec![
                    (
                        "eu.europa.ec.eudi.pid.1".into(),
                        "family_name".into(),
                        t("Svensson"),
                    ),
                    (
                        "eu.europa.ec.eudi.pid.1".into(),
                        "age_over_18".into(),
                        C::Bool(true),
                    ),
                ],
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: "2027-01-01T00:00:00Z".into(),
                digest_alg: "SHA-256".into(),
                random_len: 16,
                bad_digest_for: None,
                duplicate_digest_id: false,
                omit_digest_for: None,
                use_mac: false,
                extra_root_member: false,
                status: 0,
                issuer_alg: -7,
                doc_count: 1,
                duplicate_status: false,
                device_key_private: false,
            }
        }
    }

    pub struct Party {
        pub sk: SecretKey,
        pub cert_der: Vec<u8>,
    }

    pub fn issuer() -> Party {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["issuer.example".to_owned()])
            .unwrap()
            .self_signed(&kp)
            .unwrap();
        Party {
            sk: SecretKey::from_pkcs8_der(kp.serialized_der()).unwrap(),
            cert_der: cert.der().to_vec(),
        }
    }

    pub fn device() -> SecretKey {
        SecretKey::generate()
    }

    fn cose_key(sk: &SecretKey, with_private: bool) -> C {
        let pt = sk.public_key().to_sec1_bytes();
        let mut m = vec![
            (i(1), i(2)),
            (i(-1), i(1)),
            (i(-2), C::Bytes(pt[1..33].to_vec())),
            (i(-3), C::Bytes(pt[33..65].to_vec())),
        ];
        if with_private {
            m.push((i(-4), C::Bytes(sk.to_bytes().to_vec())));
        }
        C::Map(m)
    }

    fn sign(sk: &SecretKey, tbs: &[u8]) -> Vec<u8> {
        let s: Signature = SigningKey::from(sk).sign(tbs);
        s.to_bytes().to_vec()
    }

    fn digest(alg: &str, d: &[u8]) -> Vec<u8> {
        use sha2::{Sha384, Sha512};
        match alg {
            "SHA-256" => Sha256::digest(d).to_vec(),
            "SHA-384" => Sha384::digest(d).to_vec(),
            _ => Sha512::digest(d).to_vec(),
        }
    }

    /// `transcript_bytes`: tag-24 wrapped SessionTranscript. `ereader_pub`: reader ephemeral key for MAC mode.
    pub fn response(
        spec: &Spec,
        issuer: &Party,
        device: &SecretKey,
        transcript_bytes: &[u8],
        ereader_pub: Option<&p256::PublicKey>,
    ) -> Vec<u8> {
        // items
        let mut items: Vec<(String, C)> = vec![];
        let mut digests: Vec<(C, C)> = vec![];
        let mut by_ns: Vec<(String, Vec<C>)> = vec![];
        for (n, (ns, id, val)) in spec.elements.iter().enumerate() {
            let digest_id = if spec.duplicate_digest_id {
                0
            } else {
                n as i64
            };
            let item = C::Map(vec![
                (t("digestID"), i(digest_id)),
                (
                    t("random"),
                    C::Bytes(vec![0x42u8.wrapping_add(n as u8); spec.random_len]),
                ),
                (t("elementIdentifier"), t(id)),
                (t("elementValue"), val.clone()),
            ]);
            let item_bytes = enc(&item);
            let wrapped = enc(&tag24(item_bytes.clone()));
            let mut d = digest(&spec.digest_alg, &wrapped);
            if spec.bad_digest_for == Some(n) {
                d[0] ^= 1;
            }
            if spec.omit_digest_for != Some(n) {
                match digests.iter_mut().find(|(k, _)| *k == i(digest_id)) {
                    Some(_) => {} // duplicate id: the first digest stays, so only the duplicate rule can fire
                    None => digests.push((i(digest_id), C::Bytes(d))),
                }
            }
            match by_ns.iter_mut().find(|(k, _)| k == ns) {
                Some(e) => e.1.push(tag24(item_bytes)),
                None => by_ns.push((ns.clone(), vec![tag24(item_bytes)])),
            }
            items.push((ns.clone(), C::Null));
        }
        let ns_list: Vec<String> = by_ns.iter().map(|(k, _)| k.clone()).collect();
        let value_digests = C::Map(
            ns_list
                .iter()
                .map(|ns| (t(ns), C::Map(digests.clone())))
                .collect(),
        );
        let mso = C::Map(vec![
            (t("version"), t("1.0")),
            (t("digestAlgorithm"), t(&spec.digest_alg)),
            (t("valueDigests"), value_digests),
            (
                t("deviceKeyInfo"),
                C::Map(vec![(
                    t("deviceKey"),
                    cose_key(device, spec.device_key_private),
                )]),
            ),
            (t("docType"), t(&spec.mso_doc_type)),
            (
                t("validityInfo"),
                C::Map(vec![
                    (t("signed"), tdate("2026-01-01T00:00:00Z")),
                    (t("validFrom"), tdate(&spec.valid_from)),
                    (t("validUntil"), tdate(&spec.valid_until)),
                ]),
            ),
        ]);
        let payload = enc(&tag24(enc(&mso)));
        let protected = enc(&C::Map(vec![(i(1), i(spec.issuer_alg))]));
        let sig_struct = enc(&C::Array(vec![
            t("Signature1"),
            C::Bytes(protected.clone()),
            C::Bytes(vec![]),
            C::Bytes(payload.clone()),
        ]));
        let issuer_auth = C::Array(vec![
            C::Bytes(protected),
            C::Map(vec![(i(33), C::Bytes(issuer.cert_der.clone()))]),
            C::Bytes(payload),
            C::Bytes(sign(&issuer.sk, &sig_struct)),
        ]);

        // device auth
        let dns = tag24(enc(&C::Map(vec![])));
        let C::Tag(_, dns_inner) = &dns else {
            unreachable!()
        };
        let C::Bytes(dns_bytes) = &**dns_inner else {
            unreachable!()
        };
        let C::Tag(_, st) = ciborium::from_reader::<C, _>(transcript_bytes).unwrap() else {
            panic!()
        };
        let C::Bytes(st_inner) = *st else { panic!() };
        let mut da_inner = vec![0x84];
        da_inner.extend(enc(&t("DeviceAuthentication")));
        da_inner.extend(&st_inner);
        da_inner.extend(enc(&t(&spec.doc_type)));
        da_inner.extend(enc(&tag24(dns_bytes.clone())));
        let da_bytes = enc(&tag24(da_inner));
        let device_auth = if spec.use_mac {
            use hkdf::Hkdf;
            use hmac::{Hmac, KeyInit, Mac};
            let z = p256::ecdh::diffie_hellman(
                device.to_nonzero_scalar(),
                ereader_pub.unwrap().as_affine(),
            );
            let hk = Hkdf::<Sha256>::new(
                Some(&Sha256::digest(transcript_bytes)),
                z.raw_secret_bytes(),
            );
            let mut k = [0u8; 32];
            hk.expand(b"EMacKey", &mut k).unwrap();
            let prot = enc(&C::Map(vec![(i(1), i(5))]));
            let tbm = enc(&C::Array(vec![
                t("MAC0"),
                C::Bytes(prot.clone()),
                C::Bytes(vec![]),
                C::Bytes(da_bytes),
            ]));
            let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&k).unwrap();
            m.update(&tbm);
            C::Map(vec![(
                t("deviceMac"),
                C::Array(vec![
                    C::Bytes(prot),
                    C::Map(vec![]),
                    C::Null,
                    C::Bytes(m.finalize().into_bytes().to_vec()),
                ]),
            )])
        } else {
            let prot = enc(&C::Map(vec![(i(1), i(-7))]));
            let tbs = enc(&C::Array(vec![
                t("Signature1"),
                C::Bytes(prot.clone()),
                C::Bytes(vec![]),
                C::Bytes(da_bytes),
            ]));
            C::Map(vec![(
                t("deviceSignature"),
                C::Array(vec![
                    C::Bytes(prot),
                    C::Map(vec![]),
                    C::Null,
                    C::Bytes(sign(device, &tbs)),
                ]),
            )])
        };

        let doc = C::Map(vec![
            (t("docType"), t(&spec.doc_type)),
            (
                t("issuerSigned"),
                C::Map(vec![
                    (
                        t("nameSpaces"),
                        C::Map(
                            by_ns
                                .into_iter()
                                .map(|(k, v)| (t(&k), C::Array(v)))
                                .collect(),
                        ),
                    ),
                    (t("issuerAuth"), issuer_auth),
                ]),
            ),
            (
                t("deviceSigned"),
                C::Map(vec![(t("nameSpaces"), dns), (t("deviceAuth"), device_auth)]),
            ),
        ]);
        let mut root = vec![
            (t("version"), t("1.0")),
            (t("documents"), C::Array(vec![doc; spec.doc_count])),
            (t("status"), i(spec.status)),
        ];
        if spec.duplicate_status {
            root.push((t("status"), i(spec.status)));
        }
        if spec.extra_root_member {
            root.push((t("extra"), i(1)));
        }
        let _ = items;
        enc(&C::Map(root))
    }

    /// A minimal tag-24 SessionTranscript for tests that do not need a real handover.
    pub fn transcript(ereader: &p256::PublicKey, tag: u8) -> Vec<u8> {
        let pt = ereader.to_sec1_bytes();
        let key = enc(&C::Map(vec![
            (i(1), i(2)),
            (i(-1), i(1)),
            (i(-2), C::Bytes(pt[1..33].to_vec())),
            (i(-3), C::Bytes(pt[33..65].to_vec())),
        ]));
        let st = enc(&C::Array(vec![
            C::Null,
            tag24(key),
            C::Array(vec![t("test-handover"), i(tag as i64)]),
        ]));
        enc(&tag24(st))
    }
}
