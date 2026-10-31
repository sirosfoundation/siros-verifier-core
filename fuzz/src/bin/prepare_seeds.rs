use std::error::Error;
use std::fs;
use std::path::Path;

use jose_rs::algorithm::{JweAlgorithm, JweEncryption};
use jose_rs::jwe::compact as jwe_compact;
use jose_rs::JoseHeader;
use siros_verifier_core::mdoc_session::{Incoming, ReaderSession};
use siros_verifier_fuzz::{go, hex, iso, vc};

fn put(target: &str, name: &str, data: impl AsRef<[u8]>) -> Result<(), Box<dyn Error>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus").join(target);
    fs::create_dir_all(&dir)?;
    fs::write(dir.join(name), data)?;
    Ok(())
}

fn encrypted_seed(body: &str) -> Result<String, Box<dyn Error>> {
    let fixture = go();
    let mut header = JoseHeader::for_jwe(JweAlgorithm::EcdhEs, JweEncryption::A128GCM);
    header.kid = fixture.session.enc_key.kid.clone();
    Ok(jwe_compact::encrypt_with_jwk_header(
        &fixture.session.enc_key.to_public_jwk(),
        header,
        body.as_bytes(),
        JweEncryption::A128GCM,
    )?)
}

fn main() -> Result<(), Box<dyn Error>> {
    let fixture = iso();
    let mut session = ReaderSession::new(
        &fixture.ereader,
        &fixture.edevice,
        &fixture.transcript,
    )?;
    let Incoming::Data { plaintext, .. } = session.decrypt(&fixture.session_data)? else {
        return Err("Annex D.5 session data was not a data message".into());
    };
    put("mdoc_response", "annex_d5", &plaintext)?;
    put("mdoc_response", "empty_map", [0xa0])?;
    put("mdoc_response", "truncated", &plaintext[..plaintext.len() / 2])?;

    put("mdoc_session", "annex_d5", &fixture.session_data)?;
    put("mdoc_session", "termination", hex("a16673746174757314"))?;
    put(
        "mdoc_session",
        "duplicate_data",
        hex("a2646461746140646461746140"),
    )?;

    let vc = vc();
    put("sdjwt", "vc_presentation", vc.presentation.as_bytes())?;
    put("sdjwt", "minimal", "~")?;
    put(
        "sdjwt",
        "no_kb",
        format!("{}~", vc.presentation.split('~').next().unwrap()),
    )?;

    let go = go();
    for (enc, token) in &go.vectors {
        put("oid4vp_jwe", enc, token)?;
    }
    put("oid4vp_jwe", "bad_compact", "a..c")?;
    put(
        "oid4vp_jwe",
        "wrong_state",
        encrypted_seed(r#"{"vp_token":{"pid":["x"]},"state":"wrong"}"#)?,
    )?;
    put(
        "oid4vp_jwe",
        "bad_vp_token",
        encrypted_seed(r#"{"vp_token":"not-object","state":"s-from-go"}"#)?,
    )?;
    println!("wrote fuzz seed corpora");
    Ok(())
}
