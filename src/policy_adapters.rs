//! Transport adapters for the representation-neutral policy evaluator.
//!
//! The adapters consume fixture observations, not untrusted production bytes.
//! Production wire parsers remain responsible for syntax, size limits, and
//! cryptographic verification before creating equivalent observations.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::policy::{SignatureCandidate, TrustedKey, VerificationOutcome};

/// Input variants supported by the conformance harness.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "adapter", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ConformanceInput {
    /// Direct semantic reference to a trusted-key fixture ID.
    Semantic { signatures: Vec<SemanticSignature> },
    /// Historical prototype representation: Ed25519 `Sig:` observations and
    /// ML-DSA observations from the separate `Sig-PQC:` field.
    SigPqc {
        sig: Vec<NamedSignature>,
        sig_pqc: Vec<SigPqcSignature>,
    },
    /// Ordinary signature collection where every entry carries its algorithm.
    AlgorithmTagged {
        signatures: Vec<AlgorithmTaggedSignature>,
    },
}

impl ConformanceInput {
    pub fn adapter_name(&self) -> &'static str {
        match self {
            Self::Semantic { .. } => "semantic",
            Self::SigPqc { .. } => "sig-pqc",
            Self::AlgorithmTagged { .. } => "algorithm-tagged",
        }
    }

    /// Normalize this representation into policy candidates.
    pub fn normalize(&self, trusted_keys: &[TrustedKey]) -> Vec<SignatureCandidate> {
        let mut candidates = match self {
            Self::Semantic { signatures } => normalize_semantic(signatures, trusted_keys),
            Self::SigPqc { sig, sig_pqc } => normalize_sig_pqc(sig, sig_pqc),
            Self::AlgorithmTagged { signatures } => signatures
                .iter()
                .map(|signature| SignatureCandidate {
                    key_name: signature.key_name.clone(),
                    algorithm: signature.algorithm.clone(),
                    signature_id: signature.signature_id.clone(),
                    verification: signature.verification,
                })
                .collect(),
        };
        // Transports differ in how they order or separate signature fields.
        // Canonicalize observations before policy evaluation so representation
        // layout cannot affect decision evidence.
        candidates.sort_by(|left, right| {
            (
                left.key_name.as_str(),
                left.algorithm.as_str(),
                left.signature_id.as_str(),
                left.verification,
            )
                .cmp(&(
                    right.key_name.as_str(),
                    right.algorithm.as_str(),
                    right.signature_id.as_str(),
                    right.verification,
                ))
        });
        candidates
    }
}

/// Signature fixture that names a semantic trusted-key record directly.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SemanticSignature {
    pub key_id: String,
    pub signature_id: String,
    pub verification: VerificationOutcome,
}

/// Classical `Sig:` fixture observation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamedSignature {
    pub key_name: String,
    pub signature_id: String,
    pub verification: VerificationOutcome,
}

/// Historical `Sig-PQC:` fixture observation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SigPqcSignature {
    pub key_name: String,
    pub algorithm_tag: String,
    pub signature_id: String,
    pub verification: VerificationOutcome,
}

/// Ordinary algorithm-tagged signature fixture observation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AlgorithmTaggedSignature {
    pub key_name: String,
    pub algorithm: String,
    pub signature_id: String,
    pub verification: VerificationOutcome,
}

fn normalize_semantic(
    signatures: &[SemanticSignature],
    trusted_keys: &[TrustedKey],
) -> Vec<SignatureCandidate> {
    let keys: HashMap<&str, &TrustedKey> = trusted_keys
        .iter()
        .map(|key| (key.key_id.as_str(), key))
        .collect();

    signatures
        .iter()
        .map(|signature| {
            if let Some(key) = keys.get(signature.key_id.as_str()) {
                SignatureCandidate {
                    key_name: key.key_name.clone(),
                    algorithm: key.algorithm.clone(),
                    signature_id: signature.signature_id.clone(),
                    verification: signature.verification,
                }
            } else {
                // Preserve an unknown semantic reference as an unknown wire
                // identity instead of treating fixture lookup failure as a
                // harness crash. This lets vectors exercise fail-closed
                // unknown-key behavior.
                SignatureCandidate {
                    key_name: signature.key_id.clone(),
                    algorithm: "unknown".into(),
                    signature_id: signature.signature_id.clone(),
                    verification: signature.verification,
                }
            }
        })
        .collect()
}

fn normalize_sig_pqc(
    classical: &[NamedSignature],
    pqc: &[SigPqcSignature],
) -> Vec<SignatureCandidate> {
    let mut normalized = Vec::with_capacity(classical.len() + pqc.len());
    normalized.extend(classical.iter().map(|signature| SignatureCandidate {
        key_name: signature.key_name.clone(),
        algorithm: "ed25519".into(),
        signature_id: signature.signature_id.clone(),
        verification: signature.verification,
    }));
    normalized.extend(pqc.iter().map(|signature| SignatureCandidate {
        key_name: signature.key_name.clone(),
        algorithm: signature.algorithm_tag.clone(),
        signature_id: signature.signature_id.clone(),
        verification: signature.verification,
    }));
    normalized
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn trusted_keys() -> Vec<TrustedKey> {
        vec![
            TrustedKey {
                key_id: "cache-ed".into(),
                key_name: "cache".into(),
                signer_identity: "cache-owner".into(),
                algorithm: "ed25519".into(),
                roles: BTreeSet::from(["cache-signing".into()]),
                authority: "cache-owner".into(),
                custody_domain: "cache-ed".into(),
                revoked: false,
                valid_from: None,
                valid_until: None,
            },
            TrustedKey {
                key_id: "cache-pq".into(),
                key_name: "cache".into(),
                signer_identity: "cache-owner".into(),
                algorithm: "ml-dsa-65".into(),
                roles: BTreeSet::from(["cache-signing".into()]),
                authority: "cache-owner".into(),
                custody_domain: "cache-pq".into(),
                revoked: false,
                valid_from: None,
                valid_until: None,
            },
        ]
    }

    #[test]
    fn three_adapters_normalize_to_equivalent_candidates() {
        let semantic = ConformanceInput::Semantic {
            signatures: vec![
                SemanticSignature {
                    key_id: "cache-ed".into(),
                    signature_id: "ed-sig".into(),
                    verification: VerificationOutcome::Valid,
                },
                SemanticSignature {
                    key_id: "cache-pq".into(),
                    signature_id: "pq-sig".into(),
                    verification: VerificationOutcome::Valid,
                },
            ],
        };
        let sig_pqc = ConformanceInput::SigPqc {
            sig: vec![NamedSignature {
                key_name: "cache".into(),
                signature_id: "ed-sig".into(),
                verification: VerificationOutcome::Valid,
            }],
            sig_pqc: vec![SigPqcSignature {
                key_name: "cache".into(),
                algorithm_tag: "ml-dsa-65".into(),
                signature_id: "pq-sig".into(),
                verification: VerificationOutcome::Valid,
            }],
        };
        let algorithm_tagged = ConformanceInput::AlgorithmTagged {
            signatures: vec![
                AlgorithmTaggedSignature {
                    key_name: "cache".into(),
                    algorithm: "ed25519".into(),
                    signature_id: "ed-sig".into(),
                    verification: VerificationOutcome::Valid,
                },
                AlgorithmTaggedSignature {
                    key_name: "cache".into(),
                    algorithm: "ml-dsa-65".into(),
                    signature_id: "pq-sig".into(),
                    verification: VerificationOutcome::Valid,
                },
            ],
        };

        let trusted = trusted_keys();
        let expected = semantic.normalize(&trusted);
        assert_eq!(sig_pqc.normalize(&trusted), expected);
        assert_eq!(algorithm_tagged.normalize(&trusted), expected);
    }
}
