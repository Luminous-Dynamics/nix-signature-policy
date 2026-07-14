#![no_main]

use libfuzzer_sys::fuzz_target;
use nix_signature_policy::{keys, narinfo};

fuzz_target!(|data: &[u8]| {
    if data.len() > narinfo::MAX_SIGNATURE_ENTRY_BYTES {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = narinfo::parse_sig_entry(text);
    let _ = keys::parse_named_pubkey(text);
    let _ = keys::validate_key_name(text);

    if let Ok((name, _algorithm, signature)) = keys::decode_sig_pqc(text) {
        let encoded = keys::encode_sig_pqc(&name, &signature);
        let (decoded_name, decoded_algorithm, decoded_signature) =
            keys::decode_sig_pqc(&encoded).expect("re-encoded Sig-PQC must decode");
        assert_eq!(decoded_name, name);
        assert_eq!(decoded_algorithm, keys::SigPqcAlgorithm::MlDsa65);
        assert_eq!(decoded_signature, signature);
    }
});
