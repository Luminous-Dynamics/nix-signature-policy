//! Domain-separated SHA-256 commitments for security-relevant canonical objects.
//!
//! The framing prevents a byte-identical policy, registry, receipt payload, trust-state payload, or
//! transition from sharing the same commitment across object types.

use sha2::{Digest, Sha256};

/// Version of the commitment framing defined in this module.
pub const COMMITMENT_FORMAT_VERSION: u32 = 1;
const COMMITMENT_MAGIC: &[u8] = b"nix-signature-policy\0";

/// Security domain committed by one digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentDomain {
    Policy,
    Registry,
    ReceiptPayload,
    TrustStatePayload,
    Transition,
}

impl CommitmentDomain {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Policy => b"policy",
            Self::Registry => b"registry",
            Self::ReceiptPayload => b"receipt-payload",
            Self::TrustStatePayload => b"trust-state-payload",
            Self::Transition => b"transition",
        }
    }
}

/// Compute `SHA-256(magic || domain || 0 || version_be || len_be || payload)`.
pub fn commitment_sha256(domain: CommitmentDomain, payload: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(COMMITMENT_MAGIC);
    digest.update(domain.label());
    digest.update([0]);
    digest.update(COMMITMENT_FORMAT_VERSION.to_be_bytes());
    digest.update((payload.len() as u64).to_be_bytes());
    digest.update(payload);
    format!("{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer_vectors_are_stable() {
        assert_eq!(
            commitment_sha256(CommitmentDomain::Policy, b"{}"),
            "e7c4dac3f20b6a3f7cff17b9c0635a68f1c57725c894e8fd560bf0de81038eee"
        );
        assert_eq!(
            commitment_sha256(CommitmentDomain::Registry, b"{}"),
            "d7910f5b128fa9b5af07fcc710c02228fa0ead0f93977ccc0a03e66bd0761bb2"
        );
        assert_eq!(
            commitment_sha256(CommitmentDomain::ReceiptPayload, b"{}"),
            "a252e2183fdcefdce1cfa6e93a061daae52e7532b74353beaa0f0eb9398c3105"
        );
        assert_eq!(
            commitment_sha256(CommitmentDomain::TrustStatePayload, b"{}"),
            "281b643774053132dba697b3819e26584d8bbe7138e051f579b9a03e8f260d21"
        );
        assert_eq!(
            commitment_sha256(CommitmentDomain::Transition, b"{}"),
            "1c61c9a3b15cd7402a7fc84d3009ac58dcc9b568f4de87a150c4b05dd5677fa7"
        );
    }

    #[test]
    fn domains_are_not_interchangeable() {
        let payload = b"same canonical bytes";
        let policy = commitment_sha256(CommitmentDomain::Policy, payload);
        let registry = commitment_sha256(CommitmentDomain::Registry, payload);
        let receipt = commitment_sha256(CommitmentDomain::ReceiptPayload, payload);
        let state = commitment_sha256(CommitmentDomain::TrustStatePayload, payload);
        let transition = commitment_sha256(CommitmentDomain::Transition, payload);
        let values =
            std::collections::BTreeSet::from([policy, registry, receipt, state, transition]);
        assert_eq!(values.len(), 5);
    }
}
