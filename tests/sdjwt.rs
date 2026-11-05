use jose_rs::jwk::Jwk;
use serde_json::{json, Value};
use siros_verifier_core::sdjwt::*;
use siros_verifier_core::testutil::*;
use siros_verifier_core::Error;

const NOW: i64 = 1_800_000_000;

struct Fx {
    issuer: Jwk,
    holder: Jwk,
}

fn fx() -> Fx {
    Fx {
        issuer: ec_jwk("ES256", "iss-1"),
        holder: ec_jwk("ES256", "holder-1"),
    }
}

fn base_claims() -> Value {
    json!({
        "iss": "https://issuer.example",
        "vct": "urn:eudi:pid:1",
        "iat": NOW - 100,
        "exp": NOW + 100_000,
        "given_name": "Ada",
        "family_name": "Lovelace",
        "address": { "street": "St James's Square 1", "locality": "London" },
        "nationalities": ["GB", "SE", "FR"],
    })
}

fn spec(f: &Fx) -> IssueSpec {
    let mut s = IssueSpec::new(base_claims());
    s.holder_pub = Some(public_of(&f.holder));
    s
}

fn kb<'a>(f: &'a Fx, aud: &'a str, nonce: &'a str) -> KbSpec<'a> {
    KbSpec {
        holder: &f.holder,
        aud,
        nonce,
        iat: NOW,
    }
}

fn params(aud: &'static str, nonce: &'static str) -> VerifyParams<'static> {
    VerifyParams::new(
        NOW,
        HolderBinding::Required {
            aud,
            nonce,
            max_age_secs: 300,
        },
    )
}

fn resolver(f: &Fx) -> StaticKey {
    StaticKey(public_of(&f.issuer))
}

#[test]
fn selective_disclosure_reconstructs_claims() {
    let f = fx();
    let mut s = spec(&f);
    s.conceal = vec![
        vec![Seg::Key("given_name")],
        vec![Seg::Key("family_name")],
        vec![Seg::Key("address"), Seg::Key("street")],
        vec![Seg::Key("nationalities"), Seg::Idx(1)],
    ];
    s.decoys = 4;
    let issued = issue(&f.issuer, &s).unwrap();
    assert_eq!(issued.disclosures.len(), 4);

    // everything disclosed
    let all: Vec<usize> = (0..4).collect();
    let p = present(
        &issued,
        &all,
        Some(kb(&f, "verifier", "n1")),
        HashAlg::Sha256,
    )
    .unwrap();
    let v = verify(&p, &resolver(&f), &params("verifier", "n1")).unwrap();
    assert_eq!(v.vct, "urn:eudi:pid:1");
    assert_eq!(v.claims["given_name"], "Ada");
    assert_eq!(v.claims["address"]["street"], "St James's Square 1");
    assert_eq!(v.claims["nationalities"], json!(["GB", "SE", "FR"]));
    assert!(v.claims.get("_sd").is_none() && v.claims.get("_sd_alg").is_none());
    assert!(v.holder_key.is_some());

    // only given_name (index into creation order; paths sorted longest first, so find it)
    let idx_given = issued
        .disclosures
        .iter()
        .position(|d| {
            String::from_utf8(jose_rs::base64url::decode(d).unwrap())
                .unwrap()
                .contains("given_name")
        })
        .unwrap();
    let p = present(
        &issued,
        &[idx_given],
        Some(kb(&f, "verifier", "n1")),
        HashAlg::Sha256,
    )
    .unwrap();
    let v = verify(&p, &resolver(&f), &params("verifier", "n1")).unwrap();
    assert_eq!(v.claims["given_name"], "Ada");
    assert!(v.claims.get("family_name").is_none());
    assert!(v.claims["address"].get("street").is_none());
    assert_eq!(
        v.claims["nationalities"],
        json!(["GB", "FR"]),
        "concealed array element is dropped"
    );
}

#[test]
fn nested_parent_and_child() {
    let f = fx();
    let mut s = spec(&f);
    s.conceal = vec![
        vec![Seg::Key("address")],
        vec![Seg::Key("address"), Seg::Key("street")],
    ];
    let issued = issue(&f.issuer, &s).unwrap();
    // creation order: child first, then parent
    let both = present(&issued, &[0, 1], Some(kb(&f, "v", "n")), HashAlg::Sha256).unwrap();
    let v = verify(&both, &resolver(&f), &params("v", "n")).unwrap();
    assert_eq!(v.claims["address"]["street"], "St James's Square 1");

    let parent_only = present(&issued, &[1], Some(kb(&f, "v", "n")), HashAlg::Sha256).unwrap();
    let v = verify(&parent_only, &resolver(&f), &params("v", "n")).unwrap();
    assert_eq!(v.claims["address"]["locality"], "London");
    assert!(v.claims["address"].get("street").is_none());

    // child without its parent is unreferenced
    let child_only = present(&issued, &[0], Some(kb(&f, "v", "n")), HashAlg::Sha256).unwrap();
    assert!(matches!(
        verify(&child_only, &resolver(&f), &params("v", "n")),
        Err(Error::Policy(_))
    ));
}

#[test]
fn other_hash_algorithms() {
    let f = fx();
    for h in [HashAlg::Sha384, HashAlg::Sha512] {
        let mut s = spec(&f);
        s.hash = h;
        s.conceal = vec![vec![Seg::Key("given_name")]];
        let issued = issue(&f.issuer, &s).unwrap();
        let p = present(&issued, &[0], Some(kb(&f, "v", "n")), h).unwrap();
        let v = verify(&p, &resolver(&f), &params("v", "n")).unwrap();
        assert_eq!(v.claims["given_name"], "Ada");
    }
}

#[test]
fn key_binding_checks() {
    let f = fx();
    let mut s = spec(&f);
    s.conceal = vec![vec![Seg::Key("given_name")]];
    let issued = issue(&f.issuer, &s).unwrap();
    let good = present(&issued, &[0], Some(kb(&f, "v", "n")), HashAlg::Sha256).unwrap();
    verify(&good, &resolver(&f), &params("v", "n")).unwrap();

    // wrong nonce / aud
    assert!(matches!(
        verify(&good, &resolver(&f), &params("v", "other")),
        Err(Error::Policy(_))
    ));
    assert!(matches!(
        verify(&good, &resolver(&f), &params("other", "n")),
        Err(Error::Policy(_))
    ));

    // missing KB when required
    let none = present(&issued, &[0], None, HashAlg::Sha256).unwrap();
    assert!(matches!(
        verify(&none, &resolver(&f), &params("v", "n")),
        Err(Error::Policy(_))
    ));

    // KB present but not expected
    let mut p = params("v", "n");
    p.holder_binding = HolderBinding::NotRequired;
    assert!(matches!(
        verify(&good, &resolver(&f), &p),
        Err(Error::Policy(_))
    ));
    verify(&none, &resolver(&f), &p).unwrap();

    // signed by a different holder key
    let other = ec_jwk("ES256", "x");
    let forged = present(
        &issued,
        &[0],
        Some(KbSpec {
            holder: &other,
            aud: "v",
            nonce: "n",
            iat: NOW,
        }),
        HashAlg::Sha256,
    )
    .unwrap();
    assert!(matches!(
        verify(&forged, &resolver(&f), &params("v", "n")),
        Err(Error::Integrity(_))
    ));

    // stale and future KB iat
    for iat in [NOW - 10_000, NOW + 10_000] {
        let p = present(
            &issued,
            &[0],
            Some(KbSpec {
                holder: &f.holder,
                aud: "v",
                nonce: "n",
                iat,
            }),
            HashAlg::Sha256,
        )
        .unwrap();
        assert!(
            matches!(
                verify(&p, &resolver(&f), &params("v", "n")),
                Err(Error::Policy(_))
            ),
            "iat {iat}"
        );
    }

    // KB-JWT typ must be kb+jwt
    let wrong_typ = present_with_kb_typ(
        &issued,
        &[0],
        Some(kb(&f, "v", "n")),
        HashAlg::Sha256,
        "JWT",
    )
    .unwrap();
    assert!(matches!(
        verify(&wrong_typ, &resolver(&f), &params("v", "n")),
        Err(Error::Policy(_))
    ));

    // sd_hash binds the disclosure set: KB made for [] cannot vouch for an added disclosure
    let kb_only = present(&issued, &[], Some(kb(&f, "v", "n")), HashAlg::Sha256).unwrap();
    let kb_jwt = kb_only.rsplit('~').next().unwrap();
    let swapped = format!("{}~{}~{}", issued.jwt, issued.disclosures[0], kb_jwt);
    assert!(matches!(
        verify(&swapped, &resolver(&f), &params("v", "n")),
        Err(Error::Integrity(_))
    ));
}

#[test]
fn issuer_signature_and_header_checks() {
    let f = fx();
    let mut s = spec(&f);
    s.conceal = vec![vec![Seg::Key("given_name")]];
    let issued = issue(&f.issuer, &s).unwrap();
    let pres = |jwt: &str| format!("{jwt}~{}~", issued.disclosures[0]);

    // payload swapped, signature kept
    let mut parts: Vec<String> = issued.jwt.split('.').map(str::to_owned).collect();
    let mut p: Value =
        serde_json::from_slice(&jose_rs::base64url::decode(&parts[1]).unwrap()).unwrap();
    p["vct"] = "urn:other".into();
    parts[1] = jose_rs::base64url::encode(&serde_json::to_vec(&p).unwrap());
    let bad = pres(&parts.join("."));
    let mut np = params("v", "n");
    np.holder_binding = HolderBinding::NotRequired;
    assert!(matches!(
        verify(&bad, &resolver(&f), &np),
        Err(Error::Integrity(_))
    ));

    // wrong issuer key
    let other = StaticKey(public_of(&ec_jwk("ES256", "o")));
    assert!(matches!(
        verify(&pres(&issued.jwt), &other, &np),
        Err(Error::Integrity(_))
    ));

    // alg none and a disallowed alg are refused before any key use
    for alg in ["none", "HS256", "ES384"] {
        let hdr = jose_rs::base64url::encode(
            format!(r#"{{"alg":"{alg}","typ":"dc+sd-jwt"}}"#).as_bytes(),
        );
        let forged = format!("{hdr}.{}.{}", parts[1], parts[2]);
        assert!(
            matches!(
                verify(&pres(&forged), &resolver(&f), &np),
                Err(Error::Policy(_))
            ),
            "alg {alg}"
        );
    }

    // typ
    let legacy = sign_raw(&f.issuer, "vc+sd-jwt", &base_claims(), &[]);
    let lp = format!("{legacy}~");
    assert!(matches!(
        verify(&lp, &resolver(&f), &np),
        Err(Error::Policy(_))
    ));
    let mut allow = VerifyParams::new(NOW, HolderBinding::NotRequired);
    allow.allow_legacy_typ = true;
    verify(&lp, &resolver(&f), &allow).unwrap();
    let wrong = sign_raw(&f.issuer, "JWT", &base_claims(), &[]);
    assert!(matches!(
        verify(&format!("{wrong}~"), &resolver(&f), &np),
        Err(Error::Policy(_))
    ));
}

fn plain(f: &Fx, claims: Value) -> String {
    format!("{}~", sign_raw(&f.issuer, "dc+sd-jwt", &claims, &[]))
}

fn nokb() -> VerifyParams<'static> {
    VerifyParams::new(NOW, HolderBinding::NotRequired)
}

#[test]
fn time_claims() {
    let f = fx();
    let mut c = base_claims();
    c["exp"] = json!(NOW - 1000);
    assert!(matches!(
        verify(&plain(&f, c), &resolver(&f), &nokb()),
        Err(Error::Policy(_))
    ));
    let mut c = base_claims();
    c["nbf"] = json!(NOW + 1000);
    assert!(matches!(
        verify(&plain(&f, c), &resolver(&f), &nokb()),
        Err(Error::Policy(_))
    ));
    let mut c = base_claims();
    c["iat"] = json!(NOW + 1000);
    assert!(matches!(
        verify(&plain(&f, c), &resolver(&f), &nokb()),
        Err(Error::Policy(_))
    ));
    let mut c = base_claims();
    c["exp"] = json!("tomorrow");
    assert!(matches!(
        verify(&plain(&f, c), &resolver(&f), &nokb()),
        Err(Error::Malformed(_))
    ));
    let mut c = base_claims();
    c.as_object_mut().unwrap().remove("vct");
    assert!(matches!(
        verify(&plain(&f, c), &resolver(&f), &nokb()),
        Err(Error::Malformed(_))
    ));
}

fn with_sd(f: &Fx, sd: Vec<&str>, extra: Value, disclosures: &[&str]) -> String {
    let mut c = base_claims();
    for (k, v) in extra.as_object().unwrap() {
        c[k] = v.clone();
    }
    c["_sd"] = json!(sd);
    let jwt = sign_raw(&f.issuer, "dc+sd-jwt", &c, &[]);
    if disclosures.is_empty() {
        format!("{jwt}~")
    } else {
        format!("{jwt}~{}~", disclosures.join("~"))
    }
}

#[test]
fn hostile_disclosure_structures() {
    let f = fx();
    let r = resolver(&f);
    let h = HashAlg::Sha256;

    // digest appearing twice
    let (raw, d) = disclosure_prop("a", json!(1), h);
    let dup = with_sd(&f, vec![&d, &d], json!({}), &[&raw]);
    assert!(matches!(verify(&dup, &r, &nokb()), Err(Error::Policy(_))));

    // same digest in two places (top-level and nested)
    let both = with_sd(
        &f,
        vec![&d],
        json!({"nested": {"_sd": [d.clone()]}}),
        &[&raw],
    );
    assert!(matches!(verify(&both, &r, &nokb()), Err(Error::Policy(_))));

    // disclosed name collides with a claim in the clear
    let (raw2, d2) = disclosure_prop("given_name", json!("Mallory"), h);
    let col = with_sd(&f, vec![&d2], json!({"given_name": "Ada"}), &[&raw2]);
    assert!(matches!(verify(&col, &r, &nokb()), Err(Error::Policy(_))));

    // non-disclosable and reserved names
    for name in ["iss", "vct", "exp", "cnf", "status"] {
        let (raw3, d3) = disclosure_prop(name, json!("x"), h);
        let p = with_sd(&f, vec![&d3], json!({}), &[&raw3]);
        // `iss`/`vct`/`exp` also exist in the clear, but the non-disclosable rule fires first or collision does; either is a policy error
        assert!(
            matches!(verify(&p, &r, &nokb()), Err(Error::Policy(_))),
            "name {name}"
        );
    }
    for name in ["_sd", "..."] {
        let (raw4, d4) = disclosure_prop(name, json!("x"), h);
        let p = with_sd(&f, vec![&d4], json!({}), &[&raw4]);
        assert!(
            matches!(verify(&p, &r, &nokb()), Err(Error::Policy(_))),
            "name {name}"
        );
    }

    // unreferenced disclosure
    let (raw5, _) = disclosure_prop("ghost", json!(1), h);
    let ghost = with_sd(&f, vec![], json!({}), &[&raw5]);
    assert!(matches!(verify(&ghost, &r, &nokb()), Err(Error::Policy(_))));

    // duplicate disclosure strings
    let (raw6, d6) = disclosure_prop("b", json!(2), h);
    let twice = with_sd(&f, vec![&d6], json!({}), &[&raw6, &raw6]);
    assert!(matches!(verify(&twice, &r, &nokb()), Err(Error::Policy(_))));

    // an array-element disclosure referenced from _sd, and the reverse
    let (rawe, de) = disclosure_elem(json!("x"), h);
    let wrong = with_sd(&f, vec![&de], json!({}), &[&rawe]);
    assert!(matches!(
        verify(&wrong, &r, &nokb()),
        Err(Error::Malformed(_))
    ));
    let (rawp, dp) = disclosure_prop("p", json!(1), h);
    let wrong2 = with_sd(&f, vec![], json!({"arr": [{"...": dp}]}), &[&rawp]);
    assert!(matches!(
        verify(&wrong2, &r, &nokb()),
        Err(Error::Malformed(_))
    ));

    // array digest object with extra members
    let extra = with_sd(
        &f,
        vec![],
        json!({"arr": [{"...": "abc", "other": 1}]}),
        &[],
    );
    assert!(matches!(
        verify(&extra, &r, &nokb()),
        Err(Error::Malformed(_))
    ));

    // malformed disclosures
    for bad in [
        jose_rs::base64url::encode(b"not json"),
        jose_rs::base64url::encode(br#"["only-salt"]"#),
        jose_rs::base64url::encode(br#"[1,"name","v"]"#),
        jose_rs::base64url::encode(br#"["s",2,"v"]"#),
        jose_rs::base64url::encode(br#"["s","n","v","extra"]"#),
    ] {
        let p = with_sd(&f, vec![], json!({}), &[&bad]);
        assert!(
            matches!(verify(&p, &r, &nokb()), Err(Error::Malformed(_))),
            "disclosure {bad}"
        );
    }

    // _sd must be an array of strings
    let mut c = base_claims();
    c["_sd"] = json!("abc");
    assert!(matches!(
        verify(&plain(&f, c), &r, &nokb()),
        Err(Error::Malformed(_))
    ));
    let mut c = base_claims();
    c["_sd"] = json!([1, 2]);
    assert!(matches!(
        verify(&plain(&f, c), &r, &nokb()),
        Err(Error::Malformed(_))
    ));

    // unsupported _sd_alg
    let mut c = base_claims();
    c["_sd_alg"] = json!("md5");
    assert!(matches!(
        verify(&plain(&f, c), &r, &nokb()),
        Err(Error::Policy(_))
    ));
}

#[test]
fn resource_limits() {
    let f = fx();
    let r = resolver(&f);
    // depth bomb: serde_json's recursion limit (128) stops the extreme case at parse
    // time; our own MAX_DEPTH (32) stops what serde would still accept.
    for (levels, want_policy) in [(200, false), (60, true)] {
        let mut v = json!("leaf");
        for _ in 0..levels {
            v = json!({ "n": v });
        }
        let mut c = base_claims();
        c["deep"] = v;
        let res = verify(&plain(&f, c), &r, &nokb());
        if want_policy {
            assert!(matches!(res, Err(Error::Policy(_))), "levels {levels}");
        } else {
            assert!(
                matches!(res, Err(Error::Malformed(_)) | Err(Error::Policy(_))),
                "levels {levels}"
            );
        }
    }

    // too many disclosures, every one of them referenced, so only the count limit can reject it
    for (n, want_ok) in [(1000usize, true), (1001, false)] {
        let pairs: Vec<(String, String)> = (0..n)
            .map(|i| disclosure_prop(&format!("c{i}"), json!(i), HashAlg::Sha256))
            .collect();
        let digests: Vec<&str> = pairs.iter().map(|(_, d)| d.as_str()).collect();
        let raws: Vec<&str> = pairs.iter().map(|(r, _)| r.as_str()).collect();
        let p = with_sd(&f, digests, json!({}), &raws);
        let res = verify(&p, &r, &nokb());
        if want_ok {
            assert_eq!(
                res.expect("1000 disclosures is within the limit")
                    .claims
                    .len(),
                8 + n
            );
        } else {
            assert!(matches!(res, Err(Error::Policy(_))), "n = {n}");
        }
    }

    // missing separator and empty disclosure
    assert!(matches!(
        verify("abc", &r, &nokb()),
        Err(Error::Malformed(_))
    ));
    let p = format!(
        "{}~~x",
        sign_raw(&f.issuer, "dc+sd-jwt", &base_claims(), &[])
    );
    assert!(matches!(verify(&p, &r, &nokb()), Err(Error::Malformed(_))));
}

#[test]
fn cnf_must_be_public() {
    let f = fx();
    let mut c = base_claims();
    c["cnf"] = json!({ "jwk": f.holder });
    let p = plain(&f, c);
    let mut kbp = nokb();
    kbp.holder_binding = HolderBinding::NotRequired;
    assert!(matches!(
        verify(&p, &resolver(&f), &kbp),
        Err(Error::Policy(_))
    ));
}

#[test]
fn malformed_status_list_structures_are_not_treated_as_absent() {
    let f = fx();
    let r = resolver(&f);
    // The Token Status List specification defines status as an object and a
    // status_list reference as an object with an unsigned integer idx and a
    // string uri. A malformed reference must not silently disable checking.
    for status in [
        json!(null),
        json!("status"),
        json!({}),
        json!({ "status_list": null }),
        json!({ "status_list": [] }),
        json!({ "status_list": {} }),
        json!({ "status_list": { "idx": 7 } }),
        json!({ "status_list": { "uri": "https://status.example/1" } }),
        json!({ "status_list": { "idx": -1, "uri": "https://status.example/1" } }),
        json!({ "status_list": { "idx": "7", "uri": "https://status.example/1" } }),
        json!({ "status_list": { "idx": 7, "uri": null } }),
        json!({ "status_list": { "idx": 7, "uri": "" } }),
        json!({ "status_list": { "idx": 7, "uri": "not a URI" } }),
        json!({ "status_list": { "idx": 7, "uri": "https://status.example/a b" } }),
        json!({ "status_list": { "idx": 7, "uri": "https://status.example/é" } }),
        json!({ "status_list": { "idx": 7, "uri": "https://status.example/%ZZ" } }),
        json!({ "status_list": { "idx": 7, "uri": "https://status.example/\\path" } }),
        json!({ "status_list": { "idx": 7, "uri": "https://status.example/<path>" } }),
        json!({ "status_list": { "idx": 7, "uri": "https://status.example/1#one#two" } }),
        json!({ "status_list": { "idx": 7, "uri": "HTTPS:status.example" } }),
        json!({ "status_list": { "idx": 7, "uri": "https://[v1]/status.jwt" } }),
        json!({ "status_list": { "idx": 7, "uri": "status:/a:b" } }),
        json!({ "status_list": { "idx": 7, "uri": "https://user[info]@status.example/1" } }),
    ] {
        let mut claims = base_claims();
        claims["status"] = status.clone();
        let error = verify(&plain(&f, claims), &r, &nokb())
            .err()
            .unwrap_or_else(|| panic!("accepted malformed status {status}"));
        assert_eq!(error.code(), "malformed", "status {status}");
    }
}

#[test]
fn rfc3986_status_uris_are_accepted() {
    let f = fx();
    let r = resolver(&f);
    for uri in [
        "https://status.example/a%20b",
        "https://status.example?x:y",
        "file:///status.jwt",
        "https://[v1.fe]/status.jwt",
        "status://status.example:65536/list",
        "status:/a/b:c",
    ] {
        let mut claims = base_claims();
        claims["status"] = json!({ "status_list": { "idx": 7, "uri": uri } });
        verify(&plain(&f, claims), &r, &nokb()).unwrap();
    }
}

#[test]
fn x5c_issuer_evidence_and_status() {
    let f = fx();
    let (cert, issuer_jwk) = self_signed_ec("issuer.example", "ES256");
    let mut s = spec(&f);
    s.x5c_der = vec![cert.clone()];
    s.claims["status"] = json!({ "status_list": { "idx": 42, "uri": "https://status.example/1" } });
    let issued = issue(&issuer_jwk, &s).unwrap();
    let p = present(&issued, &[], Some(kb(&f, "v", "n")), HashAlg::Sha256).unwrap();
    let v = verify(&p, &X5cLeaf, &params("v", "n")).unwrap();
    assert_eq!(v.issuer.x5c_der, vec![cert]);
    assert_eq!(v.issuer.iss, "https://issuer.example");
    let st = v.status.unwrap();
    assert_eq!((st.idx, st.uri.as_str()), (42, "https://status.example/1"));

    // x5c leaf from another key does not verify the signature
    let (other_cert, _) = self_signed_ec("issuer.example", "ES256");
    let mut s2 = spec(&f);
    s2.x5c_der = vec![other_cert];
    let issued2 = issue(&issuer_jwk, &s2).unwrap();
    let p2 = present(&issued2, &[], Some(kb(&f, "v", "n")), HashAlg::Sha256).unwrap();
    assert!(matches!(
        verify(&p2, &X5cLeaf, &params("v", "n")),
        Err(Error::Integrity(_))
    ));

    // X5cLeaf without an x5c header
    let issued3 = issue(&f.issuer, &spec(&f)).unwrap();
    let p3 = present(&issued3, &[], Some(kb(&f, "v", "n")), HashAlg::Sha256).unwrap();
    assert!(verify(&p3, &X5cLeaf, &params("v", "n")).is_err());
}
