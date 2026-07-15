#![no_main]

use libfuzzer_sys::fuzz_target;
use nix_signature_policy::raw_protocol::{
    MAX_RAW_AUTHORIZATION_REQUEST_BYTES, decode_and_authorize_raw,
};

fuzz_target!(|data: &[u8]| {
    // Mirrors narinfo_parse.rs's / the crate's own established pattern of
    // bounding fuzz input to the real production limit rather than letting
    // libfuzzer generate arbitrarily large inputs the real caller could
    // never actually send.
    if data.len() > MAX_RAW_AUTHORIZATION_REQUEST_BYTES {
        return;
    }

    let first = decode_and_authorize_raw(data);
    // Determinism: identical bytes must always produce an identical
    // outcome (either the same structured AuthorizationResponse or the
    // same structured RawProtocolErrorResponse) -- never flaky, never
    // order/timing/allocation dependent.
    let second = decode_and_authorize_raw(data);
    assert_eq!(
        first, second,
        "decode_and_authorize_raw must be deterministic for identical input"
    );
});
