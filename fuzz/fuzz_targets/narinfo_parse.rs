#![no_main]

use libfuzzer_sys::fuzz_target;
use nix_signature_policy::narinfo::{MAX_NARINFO_BYTES, NarInfo};

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_NARINFO_BYTES {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(info) = NarInfo::parse(text) else {
        return;
    };

    let canonical = info.to_text();
    if canonical.len() > MAX_NARINFO_BYTES {
        return;
    }
    let reparsed = NarInfo::parse(&canonical).expect("serialized narinfo must parse");
    assert_eq!(reparsed.to_text(), canonical);
    if let (Ok(left), Ok(right)) = (info.fingerprint(), reparsed.fingerprint()) {
        assert_eq!(left, right);
    }
});
