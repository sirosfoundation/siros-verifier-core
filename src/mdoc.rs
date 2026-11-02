//! ISO/IEC 18013-5 DeviceResponse verification (reader side), sans-IO.
//!
//! Establishes that a response is authentic: the issuer's COSE_Sign1 over the MSO
//! verifies under the leaf of its `x5chain`, every released element hashes to an MSO
//! digest, and DeviceAuth (signature or MAC) binds the response to this session's
//! transcript and the device key in the MSO. It does **not** evaluate trust in the
//! issuer; the chain is returned as [`MdocVerified::issuer`] for the AuthZEN layer.

use std::collections::{BTreeMap, HashSet};

use ciborium::Value;
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::der::{Decode, Encode};

use crate::{Error, Result};

const MAX_DOCS: usize = 8;
const MAX_ITEMS: usize = 1000;
const MIN_RANDOM: usize = 16;

fn malformed(s: &str) -> Error {
    Error::Malformed(s.into())
}
fn policy(s: &str) -> Error {
    Error::Policy(s.into())
}

/// Where the issuer's key came from. Not trust.
#[derive(Clone, Debug)]
pub struct MdocIssuer {
    /// DER certificates from `x5chain`, leaf first.
    pub x5c_der: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validity {
    pub signed: i64,
    pub valid_from: i64,
    pub valid_until: i64,
}

#[derive(Debug)]
pub struct MdocVerified {
    pub doc_type: String,
    /// namespace -> element identifier -> value, only elements that were released and digest-checked.
    pub elements: BTreeMap<String, BTreeMap<String, Value>>,
    pub issuer: MdocIssuer,
    pub validity: Validity,
    pub device_key: PublicKey,
}

pub enum DeviceKeyAuth<'a> {
    /// Needed to verify `deviceMac`: the reader's ephemeral private key for this session.
    Mac { ereader: &'a SecretKey },
    /// Only `deviceSignature` is acceptable.
    SignatureOnly,
}

pub struct Params<'a> {
    /// Tag-24 wrapped SessionTranscript, exactly as used for session key derivation.
    pub session_transcript_bytes: &'a [u8],
    pub now: i64,
    pub device_auth: DeviceKeyAuth<'a>,
    /// If set, only these document types are accepted.
    pub expected_doc_types: Option<&'a [&'a str]>,
}

// ---- CBOR helpers --------------------------------------------------------------------------

pub(crate) fn enc(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory cbor write");
    out
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Value> {
    // from_reader leaves trailing bytes unread; require exact consumption.
    let mut cur = bytes;
    let v: Value = ciborium::from_reader(&mut cur).map_err(|_| malformed("cbor"))?;
    if !cur.is_empty() {
        return Err(malformed("cbor_trailing_bytes"));
    }
    Ok(v)
}

fn text_map(v: &Value) -> Result<BTreeMap<String, &Value>> {
    let Value::Map(m) = v else {
        return Err(malformed("expected_map"));
    };
    let mut out = BTreeMap::new();
    for (k, val) in m {
        let Value::Text(k) = k else {
            return Err(malformed("map_key_not_text"));
        };
        if out.insert(k.clone(), val).is_some() {
            return Err(malformed("duplicate_map_key"));
        }
    }
    Ok(out)
}

/// Reject members this verifier does not understand: a renamed or extra member must not be ignored.
fn only(m: &BTreeMap<String, &Value>, allowed: &[&str]) -> Result<()> {
    match m.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(Error::Malformed(format!("unknown_member_{k}"))),
        None => Ok(()),
    }
}
fn empty_map(v: &Value) -> Result<()> {
    match v {
        Value::Map(m) if m.is_empty() => Ok(()),
        _ => Err(malformed("expected_empty_map")),
    }
}

fn as_text(v: &Value) -> Result<&str> {
    if let Value::Text(s) = v {
        Ok(s)
    } else {
        Err(malformed("expected_text"))
    }
}
fn as_bytes(v: &Value) -> Result<&[u8]> {
    if let Value::Bytes(b) = v {
        Ok(b)
    } else {
        Err(malformed("expected_bytes"))
    }
}
fn as_array(v: &Value) -> Result<&[Value]> {
    if let Value::Array(a) = v {
        Ok(a)
    } else {
        Err(malformed("expected_array"))
    }
}
fn get<'a>(m: &BTreeMap<String, &'a Value>, k: &str) -> Result<&'a Value> {
    m.get(k)
        .copied()
        .ok_or_else(|| Error::Malformed(format!("missing_{k}")))
}
pub(crate) fn tag24(v: &Value) -> Result<&[u8]> {
    match v {
        Value::Tag(24, inner) => as_bytes(inner),
        _ => Err(malformed("expected_tag24")),
    }
}

/// `tdate` -> unix seconds. Only `YYYY-MM-DDThh:mm:ssZ` (UTC, no fraction) is accepted.
fn tdate(v: &Value) -> Result<i64> {
    match v {
        Value::Tag(0, inner) => parse_utc(as_text(inner)?),
        _ => Err(malformed("expected_tdate")),
    }
}

/// Render unix seconds as `YYYY-MM-DDThh:mm:ssZ`. Years outside 0000..=9999 have no such spelling and are refused.
pub fn format_utc(secs: i64) -> Result<String> {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // civil from days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    if !(0..=9999).contains(&y) {
        return Err(malformed("time_out_of_range"));
    }
    Ok(format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    ))
}

/// Parse `YYYY-MM-DDThh:mm:ssZ` (UTC, no fraction, no offset) to unix seconds.
pub fn parse_utc(s: &str) -> Result<i64> {
    let b = s.as_bytes();
    if !s.is_ascii()
        || b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return Err(malformed("tdate_format"));
    }
    let n = |r: std::ops::Range<usize>| -> Result<i64> {
        s[r].parse::<i64>().map_err(|_| malformed("tdate_digits"))
    };
    let (y, mo, d, h, mi, se) = (
        n(0..4)?,
        n(5..7)?,
        n(8..10)?,
        n(11..13)?,
        n(14..16)?,
        n(17..19)?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return Err(malformed("tdate_range"));
    }
    // days from civil (Howard Hinnant)
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Ok(days * 86400 + h * 3600 + mi * 60 + se)
}

// ---- COSE ----------------------------------------------------------------------------------

struct CoseHeader {
    alg: i64,
}

fn protected_alg(protected: &[u8]) -> Result<CoseHeader> {
    let v = parse(protected)?;
    let Value::Map(m) = v else {
        return Err(malformed("cose_protected_not_map"));
    };
    let mut alg = None;
    for (k, val) in m {
        if k == Value::Integer(1.into()) {
            if alg.is_some() {
                return Err(malformed("duplicate_alg"));
            }
            let Value::Integer(i) = val else {
                return Err(malformed("alg_type"));
            };
            alg = Some(i64::try_from(i).map_err(|_| malformed("alg_range"))?);
        }
    }
    Ok(CoseHeader {
        alg: alg.ok_or_else(|| malformed("missing_alg"))?,
    })
}

pub(crate) fn sig_structure(context: &str, protected: &[u8], payload: &[u8]) -> Vec<u8> {
    enc(&Value::Array(vec![
        Value::Text(context.into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(vec![]),
        Value::Bytes(payload.to_vec()),
    ]))
}

pub(crate) fn verify_es256(key: &VerifyingKey, tbs: &[u8], sig: &[u8]) -> Result<()> {
    let sig = Signature::from_slice(sig).map_err(|_| malformed("signature_length"))?;
    key.verify(tbs, &sig)
        .map_err(|_| Error::Integrity("cose_signature".into()))
}

pub(crate) fn cose_key_p256(v: &Value) -> Result<PublicKey> {
    let Value::Map(m) = v else {
        return Err(malformed("cose_key_not_map"));
    };
    let (mut kty, mut crv, mut x, mut y) = (None, None, None, None);
    for (k, val) in m {
        let Value::Integer(k) = k else { continue };
        match i64::try_from(*k).unwrap_or(i64::MAX) {
            1 => kty = Some(val.clone()),
            -1 => crv = Some(val.clone()),
            -2 => x = Some(val.clone()),
            -3 => y = Some(val.clone()),
            -4 => return Err(policy("cose_key_has_private_part")),
            _ => {}
        }
    }
    if kty != Some(Value::Integer(2.into())) || crv != Some(Value::Integer(1.into())) {
        return Err(policy("device_key_not_p256"));
    }
    let (Some(Value::Bytes(x)), Some(Value::Bytes(y))) = (x, y) else {
        return Err(malformed("cose_key_xy"));
    };
    if x.len() != 32 || y.len() != 32 {
        return Err(malformed("cose_key_xy_len"));
    }
    let mut sec1 = vec![4u8];
    sec1.extend(x);
    sec1.extend(y);
    PublicKey::from_sec1_bytes(&sec1).map_err(|_| malformed("device_key_off_curve"))
}

pub(crate) fn leaf_key(der: &[u8]) -> Result<VerifyingKey> {
    let cert = x509_cert::Certificate::from_der(der).map_err(|_| malformed("x5chain_cert"))?;
    let spki = cert.tbs_certificate.subject_public_key_info;
    spki.to_der().map_err(|_| malformed("x5chain_spki"))?;
    VerifyingKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())
        .map_err(|_| policy("issuer_key_not_p256"))
}

fn x5chain(unprotected: &Value) -> Result<Vec<Vec<u8>>> {
    let Value::Map(m) = unprotected else {
        return Err(malformed("unprotected_not_map"));
    };
    let mut found = None;
    for (k, v) in m {
        if *k == Value::Integer(33.into()) {
            if found.is_some() {
                return Err(malformed("duplicate_x5chain"));
            }
            found = Some(v);
        }
    }
    match found.ok_or_else(|| policy("missing_x5chain"))? {
        Value::Bytes(b) => Ok(vec![b.clone()]),
        Value::Array(a) if !a.is_empty() => {
            a.iter().map(|c| as_bytes(c).map(|b| b.to_vec())).collect()
        }
        _ => Err(malformed("x5chain_shape")),
    }
}

// ---- verification --------------------------------------------------------------------------

/// Verify a DeviceResponse. All documents must verify; any failure rejects the response.
pub fn verify_device_response(response: &[u8], p: &Params) -> Result<Vec<MdocVerified>> {
    let root = parse(response)?;
    let root = text_map(&root)?;
    only(&root, &["version", "documents", "documentErrors", "status"])?;
    if as_text(get(&root, "version")?)? != "1.0" {
        return Err(policy("unsupported_version"));
    }
    if *get(&root, "status")? != Value::Integer(0.into()) {
        return Err(policy("response_status_not_ok"));
    }
    let docs = as_array(get(&root, "documents")?)?;
    if docs.is_empty() || docs.len() > MAX_DOCS {
        return Err(policy("document_count"));
    }
    docs.iter().map(|d| verify_document(d, p)).collect()
}

fn digest(alg: &str, data: &[u8]) -> Result<Vec<u8>> {
    Ok(match alg {
        "SHA-256" => Sha256::digest(data).to_vec(),
        "SHA-384" => Sha384::digest(data).to_vec(),
        "SHA-512" => Sha512::digest(data).to_vec(),
        _ => return Err(policy("digest_algorithm")),
    })
}

fn verify_document(doc: &Value, p: &Params) -> Result<MdocVerified> {
    let doc = text_map(doc)?;
    only(&doc, &["docType", "issuerSigned", "deviceSigned", "errors"])?;
    let doc_type = as_text(get(&doc, "docType")?)?.to_owned();
    if let Some(allowed) = p.expected_doc_types {
        if !allowed.contains(&doc_type.as_str()) {
            return Err(policy("doc_type_not_requested"));
        }
    }
    let issuer_signed = text_map(get(&doc, "issuerSigned")?)?;
    only(&issuer_signed, &["nameSpaces", "issuerAuth"])?;

    // --- issuerAuth: COSE_Sign1 over the MSO
    let ia = as_array(get(&issuer_signed, "issuerAuth")?)?;
    if ia.len() != 4 {
        return Err(malformed("issuer_auth_shape"));
    }
    let protected = as_bytes(&ia[0])?;
    if protected_alg(protected)?.alg != -7 {
        return Err(policy("issuer_alg_not_es256"));
    }
    let chain = x5chain(&ia[1])?;
    let payload = as_bytes(&ia[2])?;
    let key = leaf_key(&chain[0])?;
    verify_es256(
        &key,
        &sig_structure("Signature1", protected, payload),
        as_bytes(&ia[3])?,
    )?;

    // --- MSO
    let mso = parse(payload)?;
    let mso_bytes = tag24(&mso)?;
    let mso = parse(mso_bytes)?;
    let mso = text_map(&mso)?;
    if as_text(get(&mso, "version")?)? != "1.0" {
        return Err(policy("mso_version"));
    }
    let dig_alg = as_text(get(&mso, "digestAlgorithm")?)?.to_owned();
    if as_text(get(&mso, "docType")?)? != doc_type {
        return Err(policy("doc_type_mismatch"));
    }
    let vi = text_map(get(&mso, "validityInfo")?)?;
    let validity = Validity {
        signed: tdate(get(&vi, "signed")?)?,
        valid_from: tdate(get(&vi, "validFrom")?)?,
        valid_until: tdate(get(&vi, "validUntil")?)?,
    };
    if p.now < validity.valid_from {
        return Err(policy("not_yet_valid"));
    }
    if p.now >= validity.valid_until {
        return Err(policy("expired"));
    }
    let dki = text_map(get(&mso, "deviceKeyInfo")?)?;
    let device_key = cose_key_p256(get(&dki, "deviceKey")?)?;

    // --- element digests
    let value_digests = text_map(get(&mso, "valueDigests")?)?;
    let ns_items = text_map(get(&issuer_signed, "nameSpaces")?)?;
    let mut elements: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
    let mut total = 0usize;
    for (ns, items) in ns_items {
        let Value::Map(digests) = *value_digests
            .get(&ns)
            .ok_or_else(|| policy("namespace_not_in_mso"))?
        else {
            return Err(malformed("value_digests_not_map"));
        };
        let mut seen_ids: HashSet<i128> = HashSet::new();
        let out = elements.entry(ns.clone()).or_default();
        for item in as_array(items)? {
            total += 1;
            if total > MAX_ITEMS {
                return Err(policy("too_many_items"));
            }
            let inner = tag24(item)?;
            let it = parse(inner)?;
            let it = text_map(&it)?;
            let Value::Integer(id) = get(&it, "digestID")? else {
                return Err(malformed("digest_id"));
            };
            let id = *id;
            if !seen_ids.insert(i128::from(id)) {
                return Err(policy("duplicate_digest_id"));
            }
            if as_bytes(get(&it, "random")?)?.len() < MIN_RANDOM {
                return Err(policy("salt_too_short"));
            }
            let name = as_text(get(&it, "elementIdentifier")?)?.to_owned();
            let want = digests
                .iter()
                .find(|(k, _)| *k == Value::Integer(id))
                .map(|(_, v)| v)
                .ok_or_else(|| policy("digest_id_not_in_mso"))?;
            // digest is over the tag-24 encoded IssuerSignedItemBytes
            let got = digest(
                &dig_alg,
                &enc(&Value::Tag(24, Box::new(Value::Bytes(inner.to_vec())))),
            )?;
            if as_bytes(want)? != got.as_slice() {
                return Err(Error::Integrity("element_digest".into()));
            }
            let value = get(&it, "elementValue")?.clone();
            if out.insert(name, value).is_some() {
                return Err(policy("duplicate_element"));
            }
        }
    }

    // --- DeviceAuth
    let ds = text_map(get(&doc, "deviceSigned")?)?;
    only(&ds, &["nameSpaces", "deviceAuth"])?;
    let dns = get(&ds, "nameSpaces")?;
    let dns_bytes = tag24(dns)?.to_vec();
    let da = text_map(get(&ds, "deviceAuth")?)?;
    let transcript = tag24(&parse(p.session_transcript_bytes)?)?.to_vec();
    // DeviceAuthenticationBytes = #6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes])
    // The transcript is spliced in as raw bytes so it is not re-encoded.
    let mut da_inner = vec![0x84];
    da_inner.extend(enc(&Value::Text("DeviceAuthentication".into())));
    da_inner.extend(&transcript);
    da_inner.extend(enc(&Value::Text(doc_type.clone())));
    da_inner.extend(enc(&Value::Tag(24, Box::new(Value::Bytes(dns_bytes)))));
    let da_bytes = enc(&Value::Tag(24, Box::new(Value::Bytes(da_inner))));

    match (da.get("deviceSignature"), da.get("deviceMac"), da.len()) {
        (Some(sig), None, 1) => {
            let a = as_array(sig)?;
            if a.len() != 4 || !matches!(a[2], Value::Null) {
                return Err(malformed("device_signature_shape"));
            }
            empty_map(&a[1])?;
            let prot = as_bytes(&a[0])?;
            if protected_alg(prot)?.alg != -7 {
                return Err(policy("device_alg_not_es256"));
            }
            let vk = VerifyingKey::from(&device_key);
            verify_es256(
                &vk,
                &sig_structure("Signature1", prot, &da_bytes),
                as_bytes(&a[3])?,
            )?;
        }
        (None, Some(mac), 1) => {
            let DeviceKeyAuth::Mac { ereader } = &p.device_auth else {
                return Err(policy("device_mac_not_accepted"));
            };
            let a = as_array(mac)?;
            if a.len() != 4 || !matches!(a[2], Value::Null) {
                return Err(malformed("device_mac_shape"));
            }
            empty_map(&a[1])?;
            let prot = as_bytes(&a[0])?;
            if protected_alg(prot)?.alg != 5 {
                return Err(policy("device_mac_alg_not_hmac256"));
            }
            let z = diffie_hellman(ereader.to_nonzero_scalar(), device_key.as_affine());
            let salt = Sha256::digest(p.session_transcript_bytes);
            let hk = Hkdf::<Sha256>::new(Some(&salt), z.raw_secret_bytes());
            let mut k = zeroize::Zeroizing::new([0u8; 32]);
            hk.expand(b"EMacKey", &mut *k)
                .map_err(|_| Error::Crypto("hkdf".into()))?;
            let tbm = enc(&Value::Array(vec![
                Value::Text("MAC0".into()),
                Value::Bytes(prot.to_vec()),
                Value::Bytes(vec![]),
                Value::Bytes(da_bytes),
            ]));
            use hmac::{Hmac, KeyInit, Mac};
            let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&*k)
                .map_err(|_| Error::Crypto("hmac key".into()))?;
            m.update(&tbm);
            m.verify_slice(as_bytes(&a[3])?)
                .map_err(|_| Error::Integrity("device_mac".into()))?;
        }
        _ => return Err(policy("device_auth_shape")),
    }

    Ok(MdocVerified {
        doc_type,
        elements,
        issuer: MdocIssuer { x5c_der: chain },
        validity,
        device_key,
    })
}
