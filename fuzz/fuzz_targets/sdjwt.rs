#![no_main]

use libfuzzer_sys::fuzz_target;
use siros_verifier_core::sdjwt::{verify, HolderBinding, VerifyParams};
use siros_verifier_fuzz::{vc, MAX_INPUT};

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let Ok(presentation) = std::str::from_utf8(data) else {
        return;
    };
    let fixture = vc();
    let params = VerifyParams::new(
        fixture.now,
        HolderBinding::Required {
            aud: &fixture.aud,
            nonce: &fixture.nonce,
            max_age_secs: 300,
        },
    );
    let _ = verify(presentation, &fixture.resolver, &params);
});
