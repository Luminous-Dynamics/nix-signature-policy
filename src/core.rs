//! Stable descriptor for the minimal composable-authorization interoperability core.
//!
//! `core-v1` freezes semantic expectations, not a particular wire encoding or
//! implementation language. Implementations remain free to expose richer policy
//! features, but claims of `core-v1` conformance are tied to these identifiers,
//! limits, and the manifest-backed vector profile.

use serde::{Deserialize, Serialize};

use crate::commitment::COMMITMENT_FORMAT_VERSION;
use crate::integration::INTEGRATION_CONTRACT_VERSION;
use crate::policy::{
    MAX_CANDIDATE_DIAGNOSTICS, MAX_CONFIGURABLE_SIGNATURE_CANDIDATES,
    MAX_CONFIGURABLE_SIGNATURE_OBSERVATIONS, POLICY_VECTOR_SCHEMA_VERSION,
};

/// Stable interoperability profile identifier.
pub const CORE_PROFILE_ID: &str = "core-v1";
/// Stable profile version.
pub const CORE_PROFILE_VERSION: u32 = 1;
/// Revision of the normative core specification exercised by this profile.
pub const CORE_NORMATIVE_SPEC_REVISION: u32 = 1;
/// Version of the canonical policy commitment format used by this profile.
pub const CORE_COMMITMENT_FORMAT_VERSION: u32 = COMMITMENT_FORMAT_VERSION;

/// Machine-readable descriptor published by the reference implementation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoreProfileDescriptor {
    pub profile_id: String,
    pub profile_version: u32,
    pub normative_spec_revision: u32,
    pub policy_vector_schema_version: u32,
    pub integration_contract_version: u32,
    pub commitment_format_version: u32,
    pub max_configurable_signature_observations: usize,
    pub max_configurable_signature_candidates: usize,
    pub max_candidate_diagnostics: usize,
}

/// Return the exact descriptor implemented by this crate.
pub fn core_v1_descriptor() -> CoreProfileDescriptor {
    CoreProfileDescriptor {
        profile_id: CORE_PROFILE_ID.into(),
        profile_version: CORE_PROFILE_VERSION,
        normative_spec_revision: CORE_NORMATIVE_SPEC_REVISION,
        policy_vector_schema_version: POLICY_VECTOR_SCHEMA_VERSION,
        integration_contract_version: INTEGRATION_CONTRACT_VERSION,
        commitment_format_version: CORE_COMMITMENT_FORMAT_VERSION,
        max_configurable_signature_observations: MAX_CONFIGURABLE_SIGNATURE_OBSERVATIONS,
        max_configurable_signature_candidates: MAX_CONFIGURABLE_SIGNATURE_CANDIDATES,
        max_candidate_diagnostics: MAX_CANDIDATE_DIAGNOSTICS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_is_stable_and_nonzero() {
        let descriptor = core_v1_descriptor();
        assert_eq!(descriptor.profile_id, "core-v1");
        assert_eq!(descriptor.profile_version, 1);
        assert_eq!(descriptor.normative_spec_revision, 1);
        assert!(descriptor.max_configurable_signature_observations > 0);
        assert!(descriptor.max_configurable_signature_candidates > 0);
        assert!(
            descriptor.max_configurable_signature_observations
                >= descriptor.max_configurable_signature_candidates
        );
        assert_eq!(descriptor.max_candidate_diagnostics, 256);
    }
}
