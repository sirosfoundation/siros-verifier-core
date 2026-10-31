#![no_main]

use libfuzzer_sys::fuzz_target;
use siros_verifier_core::oid4vp::process_response;
use siros_verifier_fuzz::{go, MAX_INPUT};

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let Ok(jwe) = std::str::from_utf8(data) else {
        return;
    };
    let fixture = go();
    let _ = process_response(&fixture.session, jwe, 0, &fixture.resolver);
});
