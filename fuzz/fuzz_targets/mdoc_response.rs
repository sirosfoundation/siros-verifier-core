#![no_main]

use libfuzzer_sys::fuzz_target;
use siros_verifier_core::mdoc::{verify_device_response, DeviceKeyAuth, Params};
use siros_verifier_fuzz::{iso, MAX_INPUT};

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let fixture = iso();
    let params = Params {
        session_transcript_bytes: &fixture.transcript,
        now: 1_610_000_000,
        device_auth: DeviceKeyAuth::Mac {
            ereader: &fixture.ereader,
        },
        expected_doc_types: None,
    };
    let _ = verify_device_response(data, &params);
});
