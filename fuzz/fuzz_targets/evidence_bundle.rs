#![no_main]

use libfuzzer_sys::fuzz_target;
use nix_signature_policy::evidence::{EvidenceVerificationOptions, parse_bundle, verify_bundle};

fuzz_target!(|data: &[u8]| {
    if let Ok(bundle) = parse_bundle(data) {
        let _ = verify_bundle(&bundle, EvidenceVerificationOptions::default());
    }
});
