#!/usr/bin/env python3
"""Mutation check: disable one security check at a time and require a test to fail.

A surviving mutant means a check is not covered by a test that would notice it
being removed. Usage: scripts/mutate.py  (run from the crate root)
"""
import subprocess, sys, pathlib

F = {"sd": "src/sdjwt.rs", "vp": "src/oid4vp.rs", "md": "src/mdoc.rs", "mr": "src/mdoc_request.rs", "ms": "src/mdoc_session.rs", "rc": "src/receipt.rs", "tb": "tunnelbana-plugin/src/lib.rs", "tf": "tunnelbana-plugin/src/flow.rs", "js": "src/json_strict.rs", "ss": "src/session_seal.rs", "fi": "ffi/src/lib.rs", "sl": "src/status_list.rs"}
M = [
 ("sd", 'if kbc.get("sd_hash").and_then(Value::as_str) != Some(expected.as_str()) {', 'if false {', "KB sd_hash"),
 ("sd", 'if w.used.len() != count {', 'if false {', "unreferenced disclosure"),
 ("sd", 'if top && NOT_DISCLOSABLE.contains(&name.as_str()) {', 'if false {', "non-disclosable claims"),
 ("sd", 'if !self.seen.insert(d.to_owned()) {', 'if false {', "duplicate digest"),
 ("sd", 'if out.contains_key(&name) {', 'if false {', "claim name collision"),
 ("sd", 'if alg.eq_ignore_ascii_case("none") || !allowed.contains(&alg) {', 'if false {', "alg allowlist"),
 ("sd", 'other => return Err(policy(format!("unexpected typ {other:?}"))),', '_ => {}', "typ check"),
 ("sd", 'if kbc.get("aud").and_then(Value::as_str) != Some(*aud) {', 'if false {', "KB aud"),
 ("sd", 'if kbc.get("nonce").and_then(Value::as_str) != Some(*nonce) {', 'if false {', "KB nonce"),
 ("sd", 'if p.now >= exp + p.leeway_secs {', 'if false {', "exp"),
 ("sd", 'if p.now + p.leeway_secs < nbf {', 'if false {', "nbf"),
 ("sd", 'if iat > p.now + p.leeway_secs {\n            return Err(policy("credential issued in the future"));', 'if false {\n            return Err(policy("credential issued in the future"));', "iat future"),
 ("sd", 'if jwk.d.is_some() || jwk.k.is_some() {', 'if false {', "cnf private key"),
 ("sd", '(HolderBinding::NotRequired, Some(_)) => return Err(policy("unexpected key-binding JWT")),', '(HolderBinding::NotRequired, Some(_)) => {}', "unexpected KB"),
 ("sd", '(HolderBinding::Required { .. }, None) => return Err(policy("key-binding JWT required")),', '(HolderBinding::Required { .. }, None) => {}', "KB required"),
 ("sd", 'if depth > MAX_DEPTH {', 'if false {', "depth limit"),
 ("sd", 'if raw_disclosures.len() > MAX_DISCLOSURES {', 'if false {', "disclosure count limit"),
 ("sd", 'if by_digest.insert(digest, d).is_some() {', 'if false {', "duplicate disclosure"),
 ("sd", 'if name == "_sd" || name == "..." {', 'if false {', "reserved disclosure names"),
 ("sd", 'if iat > p.now + p.leeway_secs || iat < p.now - max_age_secs - p.leeway_secs {', 'if false {', "KB iat window"),
 ("sd", 'if kb_header.typ.as_deref() != Some("kb+jwt") {', 'if false {', "KB typ"),
 ("sd", 'if m.len() != 1 {', 'if false {', "array digest object extra members"),
 ("vp", 'if now >= session.expires_at {', 'if false {', "session expiry"),
 ("vp", 'if protected.kid.as_deref() != session.enc_key.kid.as_deref() {', 'if false {', "response kid"),
 ("vp", 'if body.get("state").and_then(Value::as_str) != Some(session.state.as_str()) {', 'if false {', "state"),
 ("vp", 'if find(id).is_none() {', 'if false {', "unrequested credential id"),
 ("vp", 'if list.is_empty() || (!multiple && list.len() != 1) {', 'if false {', "presentation count"),
 ("vp", 'if !vals.iter().any(|x| x.as_str() == Some(v.vct.as_str())) {', 'if false {', "vct_values"),
 ("vp", 'if !current.iter().any(|value| vals.contains(value)) {', 'if false {', "claim values"),
 ("vp", '_ => return Err(policy("only dc+sd-jwt and mso_mdoc are supported")),', '_ => {}', "format"),
 ("vp", 'if session.dcql_query.get("credential_sets").is_some() {', 'if false {', "credential_sets fail-closed"),
 ("vp", 'object.insert("wallet_nonce".into(), json!(wallet_nonce));', 'object.insert("wallet_nonce".into(), json!("wrong"));', "request wallet nonce binding"),
 ("fi", 'if role.trim().is_empty() || role.trim() != role || role.chars().any(char::is_control) {', 'if false {', "ffi issuer role validation"),
 ("fi", 'if let Some(policy) = request_policy {', 'if let Some(policy) = None::<RequestPolicy> {', "ffi retained request policy"),
 ("vp", 'if let Some(err) = body.get("error") {', 'if let Some(err) = None::<&Value> {', "wallet error"),
 ("vp", 'if jwe.len() > MAX_RESPONSE_JWE {', 'if false {', "response JWE size limit"),
 ("vp", 'if parts.len() != 5 {', 'if false {', "response JWE parts"),
 ("vp", 'if !parts[1].is_empty() {', 'if false {', "response empty encrypted key"),
 ("vp", 'if header.alg != "ECDH-ES" {', 'if false {', "response alg ECDH-ES"),
 ("vp", 'if !matches!(enc, "A128GCM" | "A256GCM") {', 'if false {', "response enc policy"),
 ("vp", 'if header.crit.is_some() || header.extra.contains_key("zip") {', 'if false {', "response zip/crit"),
 ("vp", 'if ciphertext.len() > MAX_RESPONSE_PLAINTEXT {', 'if false {', "response ciphertext limit"),
 ("md", 'if !s.is_ascii()\n        || b.len() != 20', 'if b.len() != 20', "mdoc non-ascii date"),
 ("md", 'if protected_alg(protected)?.alg != -7 {', 'if false {', "mdoc issuer alg"),
 ("md", 'verify_es256(\n        &key,\n        &sig_structure("Signature1", protected, payload),\n        as_bytes(&ia[3])?,\n    )?;', '', "mdoc issuer signature"),
 ("md", 'if as_text(get(&mso, "docType")?)? != doc_type {', 'if false {', "mdoc doctype binding"),
 ("md", 'if p.now < validity.valid_from {', 'if false {', "mdoc not before"),
 ("md", 'if p.now >= validity.valid_until {', 'if false {', "mdoc expiry"),
 ("md", 'if !seen_ids.insert(i128::from(id)) {', 'if false {', "mdoc duplicate digest id"),
 ("md", 'if as_bytes(get(&it, "random")?)?.len() < MIN_RANDOM {', 'if false {', "mdoc salt length"),
 ("md", 'if as_bytes(want)? != got.as_slice() {', 'if false {', "mdoc element digest"),
 ("md", 'if out.insert(name, value).is_some() {', 'if false {', "mdoc duplicate element"),
 ("md", '.ok_or_else(|| policy("namespace_not_in_mso"))?', '.or(value_digests.values().next()).ok_or_else(|| policy("namespace_not_in_mso"))?', "mdoc namespace binding"),
 ("md", 'verify_es256(\n                &vk,\n                &sig_structure("Signature1", prot, &da_bytes),\n                as_bytes(&a[3])?,\n            )?;', '', "mdoc device signature"),
 ("md", 'm.verify_slice(as_bytes(&a[3])?)\n                .map_err(|_| Error::Integrity("device_mac".into()))?;', '', "mdoc device mac"),
 ("md", 'if !allowed.contains(&doc_type.as_str()) {', 'if false {', "mdoc requested doctype"),
 ("md", 'if *get(&root, "status")? != Value::Integer(0.into()) {', 'if false {', "mdoc status"),
 ("md", 'only(&root, &["version", "documents", "documentErrors", "status"])?;', '', "mdoc strict root"),
 ("md", 'if docs.is_empty() || docs.len() > MAX_DOCS {', 'if false {', "mdoc doc count"),
 ("md", 'if !cur.is_empty() {', 'if false {', "mdoc trailing bytes"),
 ("md", 'return Err(malformed("duplicate_map_key"));', '', "mdoc duplicate map key"),
 ("md", '-4 => return Err(policy("cose_key_has_private_part")),', '-4 => {}', "mdoc cose key private"),
 ("md", 'if total > MAX_ITEMS {', 'if false {', "mdoc item limit"),
 ("mr", 'if documents.is_empty() {', 'if false {', "request empty documents"),
 ("mr", 'if duplicate(document.namespaces.iter().map(|ns| ns.namespace.as_str())) {', 'if false {', "request duplicate namespace"),
 ("mr", 'if duplicate(\n            namespace\n                .elements\n                .iter()\n                .map(|element| element.identifier.as_str()),\n        ) {', 'if false {', "request duplicate element"),
 ("mr", 'if params.signer.algorithm()\n        != (SignatureAlgorithm::Ecdsa(EcCurve::P256, HashAlgorithm::Sha256))', 'if false', "reader auth algorithm"),
 ("mr", 'verify_es256(&leaf_key(leaf)?, &signing_input, &signature)?;', '', "reader auth signature"),
 ("ms", 'if select.is_empty() || request.is_some_and(|message| message.is_empty()) {', 'if false {', "handover empty NDEF"),
 ("ms", 'Some(Value::Text(v)) if v == "1.0" || v == "1.1" => {}', 'Some(Value::Text(_)) => {}', "handshake engagement version"),
 ("ms", 'if sec.len() != 2 || sec[0] != Value::Integer(1.into()) {', 'if sec.len() != 2 {', "handshake cipher suite"),
 ("ms", 'let Value::Tag(24, inner) = &sec[1] else', 'let inner = &sec[1]; let Value::Tag(_, inner) = inner else', "handshake device key tag24"),
 ("ms", 'validate_handover_cbor(handover)?;', '', "handshake handover validated"),
 ("ms", 'if !cur.is_empty() {\n        return Err(Error::Malformed(format!("{what}_trailing_bytes")));', 'if false {\n        return Err(Error::Malformed(format!("{what}_trailing_bytes")));', "handshake trailing bytes"),
 ("ms", 'if self.sent != 0 {\n            return Err(Error::Policy("already_established".into()));', 'if false {\n            return Err(Error::Policy("already_established".into()));', "handshake establishment once"),
 ("ms", 'if self.sent == 0 {\n            return Err(Error::Policy("not_established".into()));', 'if false {\n            return Err(Error::Policy("not_established".into()));', "handshake data before establishment"),
 ("ms", 'st.extend_from_slice(handover);', 'st.push(0xf6);', "handshake handover in transcript"),
 ("ms", 'if self.poisoned {', 'if false {', "session poison"),
 ("ms", 'b"SKReader")?', 'b"SKDevice")?', "session key separation"),
 ("ms", '(Value::Text(k), Value::Bytes(b)) if k == "data" && data.is_none() => {\n                    data = Some(b)\n                }', '(Value::Text(k), Value::Bytes(b)) if k == "data" => data = Some(b),', "session duplicate data"),
 ("rc", 'a.encode_utf16().cmp(b.encode_utf16())', 'a.cmp(b)', "receipt utf16 key order"),
 ("rc", 'if exp <= now {', 'if false {', "receipt stale trust data"),
 ("rc", 'exp = exp.min(nu);', '', "receipt next_update clamp"),
 ("rc", 'pol.deny_ttl.min(pol.max_ttl)', 'pol.deny_ttl', "receipt tenant ceiling on denials"),
 ("rc", 'None => return Err(policy("canonical_json_float")),', 'None => out.push_str("0"),', "receipt float refusal"),
 ("rc", 'Some(_) => return Err(policy("canonical_json_integer_range")),', 'Some(i) => out.push_str(&i.to_string()),', "receipt i64 range"),
 ("rc", 'None if n.as_u64().is_some() => return Err(policy("canonical_json_integer_range")),', '', "receipt u64 range"),
 ("rc", 'if jws.len() > MAX_JWS {', 'if false {', "receipt size limit"),
 ("rc", 'if parts.len() != 3 {', 'if false {', "receipt parts"),
 ("rc", 'if let Some(bad) = h\n            .keys()\n            .find(|k| !["alg", "typ", "kid"].contains(&k.as_str()))\n        {', 'if let Some(bad) = None::<&String> {', "receipt header members"),
 ("rc", 'if h.get("alg").and_then(Value::as_str) != Some("ES256") {', 'if false {', "receipt alg"),
 ("rc", 'if h.get("typ").and_then(Value::as_str) != Some(TYP) {', 'if false {', "receipt typ"),
 ("rc", 'if str_claim(&c, "iss")? != self.iss {', 'if false {', "receipt iss"),
 ("rc", 'if str_claim(&c, "aud")? != self.aud {', 'if false {', "receipt aud"),
 ("rc", 'if str_claim(&c, "req_sha256")? != req_sha256(request)? {', 'if false {', "receipt request binding"),
 ("rc", 'if now + self.skew < nbf {', 'if false {', "receipt nbf"),
 ("rc", 'if now > exp {', 'if false {', "receipt exp"),
 ("rc", 'Ok(r) if now >= r.refresh_after => Ok(Lookup::Stale(r)),', 'Ok(r) if false => Ok(Lookup::Stale(r)),', "receipt refresh_after"),
 ("rc", 'self.entries.remove(&k);', '', "receipt cache eviction"),
 ("rc", 'if self.high != i64::MIN && now < self.high - self.skew {', 'if false {', "receipt clock rollback"),
 ("rc", 'self.high = self.high.max(now);', 'self.high = now;', "receipt high-water mark"),
 ("tf", 'if !matches!(flow.outcome, Outcome::Pending) {', 'if false {', "plugin replay guard"),
 ("tf", 'flow.outcome = Outcome::Processing(claim_id.to_owned());', 'flow.outcome = Outcome::Pending;', "plugin mark responded"),
 ("tf", 'if !matches!(&flow.outcome, Outcome::Processing(current) if current == claim_id) {', 'if false {', "plugin finish CAS"),
 ("tf", 'flow.outcome = Outcome::Collected;', 'flow.outcome = Outcome::Pending;', "plugin collect once"),
 ("tb", 'Response::text(403, "issuer not trusted"),', 'Response::text(200, "issuer not trusted"),', "plugin deny on untrusted issuer"),
 ("tb", 'Response::text(503, "trust evaluation unavailable"),', 'Response::text(200, "trust evaluation unavailable"),', "plugin fail closed on pdp error"),
 ("tb", 'Err(_) if fallback.is_some() => Ok(fallback.expect("checked").decision),', 'Err(_) if false => Ok(fallback.expect("checked").decision),', "plugin stale receipt fallback"),
 ("tf", 'matches!(self.outcome, Outcome::Pending) && now >= self.expires_at', 'false', "plugin pending expiry"),
 ("tb", "if id.len() < 16\n            || id.len() > 64\n            || !id\n                .bytes()\n                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')\n        {", 'if false {', "plugin flow id validation"),
 ("tb", 'if ctx.request.method != "POST" {', 'if false {', "plugin POST only"),
 ("sl", 'if claims_object.get(name).is_some_and(|value| !value.is_i64()) {', 'if false {', "status time types"),
 ("tb", 'if status != 0 {', 'if false {', "status revoked enforcement"),
 ("tb", 'if let oid4vp::VerifiedCredential::SdJwt(credential) = &p.verified {', 'if let Some(credential) = None::<&Box<CryptoVerified>> {', "status issuer ordering"),
 ("tb", 'if !matches!(ctx.request.method.as_str(), "GET" | "POST") {', 'if false {', "request method allowed"),
 ("tb", 'if pair_count != 1 || nonce.is_none() {', 'if false {', "request wallet nonce validation"),
 ("tb", 'if cfg.request_ttl_secs <= 0 || cfg.request_ttl_secs > 900 {', 'if false {', "plugin ttl bounds"),
 ("tb", "if !p.is_empty() && !p.starts_with('/') {", 'if false {', "plugin pointer validation"),
 ("tb", 'd.requester = requester.clone();', '', "plugin requester carried"),
 ("tb", '.ok_or("subject_claim_missing")?;', '.unwrap_or(&Value::Null);', "plugin subject required"),
 ("tb", 'let decision = v\n        .get("decision")\n        .and_then(Value::as_bool)\n        .ok_or("pdp_decision_missing")?;', 'let decision = v.get("decision").and_then(Value::as_bool).unwrap_or(true);', "plugin decision strictness"),
 ("tb", 'Some(Value::String(s)) if !s.is_empty() => s.clone(),', 'Some(Value::String(s)) => s.clone(),', "plugin empty decision id"),
 ("tb", 'Some(_) => return Err("pdp_context_id_invalid".into()),', 'Some(_) => "x".into(),', "plugin invalid decision id"),
 ("tb", 'max_ttl: if answer.trust_data.is_empty() {\n                self.max_ttl.min(self.no_freshness_ttl)\n            } else {\n                self.max_ttl\n            },', 'max_ttl: self.max_ttl,', "plugin no-freshness lifetime cap"),
 ("tb", 'if url.scheme() != "https" && !(url.scheme() == "http" && (loopback || allow_http)) {', 'if false {', "plugin pdp scheme"),
 ("tb", 'let loopback = matches!(\n            url.host_str(),\n            Some("127.0.0.1") | Some("localhost") | Some("[::1]")\n        );', 'let loopback = true;', "plugin pdp loopback only"),
 ("tb", '.timeout(timeout)\n            .redirect(reqwest::redirect::Policy::none())', '.timeout(timeout)\n            .redirect(reqwest::redirect::Policy::limited(10))', "plugin pdp no redirects"),
 ("tb", 'if !resp.status().is_success() {', 'if false {', "plugin pdp status"),
 ("tb", 'rb = rb.bearer_auth(b);', '', "plugin pdp bearer"),
 ("tb", '.is_some_and(|length| length > limit as u64)', '.is_some_and(|_| false)', "plugin pdp declared size limit"),
 ("tb", '.filter(|length| *length <= limit)', '.filter(|length| *length <= usize::MAX)', "plugin pdp size limit"),
 ("tb", 'if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {', 'if false {', "status uri userinfo"),
 ("tb", 'if !is_public_ip(ip) {', 'if false {', "status public ipv4 policy"),
 ("tb", 'if NAT64_WKP.contains(&ip) {', 'if false {', "status nat64 ipv4 policy"),
 ("tb", 'public_addresses_only: !allow_invalid_certificates,', 'public_addresses_only: true,', "status local conformance egress"),
 ("tb", '.filter(|address| is_public_ip(address.ip()))', '.filter(|_| true)', "status public dns policy"),
 ("tb", '.with_header("cache-control", "no-store")', '', "plugin request object no-store"),
 ("tb", 'Lookup::Fresh(r) => return Ok(r.decision),', 'Lookup::Fresh(_) => None,', "plugin fresh receipt used"),
 ("vp", 'crate::json_strict::from_slice(&protected_bytes)?;', '', "response duplicate JSON members"),
 ("js", 'if !seen.insert(key.clone()) {', 'if seen.insert(key.clone()) && false {', "strict JSON duplicate member"),
 ("ss", 'if master.len() < MIN_MASTER {', 'if false {', "session weak master"),
 ("ss", 'format!("siros-verifier session seal v1:{tenant}")', '"siros-verifier session seal v1".to_string()', "session tenant separation"),
 ("ss", 'Payload { msg: &plain, aad }', 'Payload { msg: &plain, aad: &[] }', "session flow binding"),
 ("ss", 'getrandom::fill(&mut nonce).expect("OS randomness");', 'nonce.fill(0);', "session fresh nonce"),
 ("ss", 'if token.len() > MAX_SEALED {', 'if false {', "sealed session size limit"),
 ("ss", '.strip_prefix(VERSION)', '.strip_prefix("v2")', "sealed session version"),
]

ONLY = set(sys.argv[1:])
if ONLY: M = [x for x in M if x[0] in ONLY]
def cwd_for(key):
    if F[key].startswith("tunnelbana-plugin"): return "tunnelbana-plugin"
    if F[key].startswith("ffi/"): return "ffi"
    return "."
ENV = dict(__import__("os").environ, CARGO_NET_GIT_FETCH_WITH_CLI="true")
def cargo(key, *a): return subprocess.run(["cargo", "test", "--quiet", "--all-features", *a], capture_output=True, text=True, cwd=cwd_for(key), env=ENV)
base = cargo(next(iter(ONLY or {"sd"})))
if base.returncode != 0:
    print("baseline tests fail; mutation results would be meaningless\n" + base.stdout[-2000:] + base.stderr[-2000:])
    sys.exit(2)
survivors, missing = [], []
for key, old, new, name in M:
    p = pathlib.Path(F[key]); orig = p.read_text()
    if old not in orig:
        missing.append(name); continue
    try:
        p.write_text(orig.replace(old, new, 1))
        b = cargo(key, "--no-run")
        if b.returncode != 0:
            # a mutant that does not compile proves nothing; do not count it as killed
            print("BROKEN   " + name, flush=True); survivors.append(name + " (mutant does not compile)"); continue
        r = cargo(key)
        killed = r.returncode != 0
        print(("KILLED   " if killed else "SURVIVED ") + name, flush=True)
        if not killed: survivors.append(name)
    finally:
        p.write_text(orig)
print("\nsurvivors:", survivors or "none"); print("snippet not found:", missing or "none")
sys.exit(1 if survivors or missing else 0)
