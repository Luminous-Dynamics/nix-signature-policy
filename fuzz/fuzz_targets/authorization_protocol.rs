#![no_main]

use libfuzzer_sys::fuzz_target;
use nix_signature_policy::protocol::decode_and_authorize;

fuzz_target!(|data: &[u8]| {
    let _ = decode_and_authorize(data);
});
