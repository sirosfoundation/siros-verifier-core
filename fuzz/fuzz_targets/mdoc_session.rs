#![no_main]

use libfuzzer_sys::fuzz_target;
use siros_verifier_core::mdoc_session::ReaderSession;
use siros_verifier_fuzz::{iso, MAX_INPUT};

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let fixture = iso();
    let mut session = ReaderSession::new(
        &fixture.ereader,
        &fixture.edevice,
        &fixture.transcript,
    )
    .unwrap();
    let _ = session.decrypt(data);
});
