#![no_main]

use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;
use nix_pqc_cache_proxy::policy::{TrustedKey, VerificationOutcome};
use nix_pqc_cache_proxy::policy_adapters::{
    AlgorithmTaggedSignature, ConformanceInput, NamedSignature, SemanticSignature, SigPqcSignature,
};

fn outcome(byte: u8) -> VerificationOutcome {
    match byte % 3 {
        0 => VerificationOutcome::Valid,
        1 => VerificationOutcome::Invalid,
        _ => VerificationOutcome::Malformed,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    let trusted = vec![
        TrustedKey {
            key_id: "ed".into(),
            key_name: "cache".into(),
            signer_identity: "owner".into(),
            algorithm: "ed25519".into(),
            roles: BTreeSet::from(["cache-signing".into()]),
            authority: "cache-owner".into(),
            custody_domain: "cache-ed".into(),
            revoked: false,
            valid_from: None,
            valid_until: None,
        },
        TrustedKey {
            key_id: "pq".into(),
            key_name: "cache".into(),
            signer_identity: "owner".into(),
            algorithm: "ml-dsa-65".into(),
            roles: BTreeSet::from(["cache-signing".into()]),
            authority: "cache-owner".into(),
            custody_domain: "cache-pq".into(),
            revoked: false,
            valid_from: None,
            valid_until: None,
        },
    ];

    let mut semantic = Vec::new();
    let mut classical = Vec::new();
    let mut pqc = Vec::new();
    let mut tagged = Vec::new();
    for (index, byte) in data.iter().copied().take(128).enumerate() {
        let is_pq = byte & 1 == 1;
        let verification = outcome(byte >> 1);
        let signature_id = format!("sig-{index}-{}", byte % 16);
        semantic.push(SemanticSignature {
            key_id: if is_pq { "pq" } else { "ed" }.into(),
            signature_id: signature_id.clone(),
            verification,
        });
        if is_pq {
            pqc.push(SigPqcSignature {
                key_name: "cache".into(),
                algorithm_tag: "ml-dsa-65".into(),
                signature_id: signature_id.clone(),
                verification,
            });
        } else {
            classical.push(NamedSignature {
                key_name: "cache".into(),
                signature_id: signature_id.clone(),
                verification,
            });
        }
        tagged.push(AlgorithmTaggedSignature {
            key_name: "cache".into(),
            algorithm: if is_pq { "ml-dsa-65" } else { "ed25519" }.into(),
            signature_id,
            verification,
        });
    }

    let semantic = ConformanceInput::Semantic {
        signatures: semantic,
    }
    .normalize(&trusted);
    let sig_pqc = ConformanceInput::SigPqc {
        sig: classical,
        sig_pqc: pqc,
    }
    .normalize(&trusted);
    let tagged = ConformanceInput::AlgorithmTagged { signatures: tagged }.normalize(&trusted);
    assert_eq!(semantic, sig_pqc);
    assert_eq!(semantic, tagged);
});
