//! Bounded JSON process protocol for the raw-evidence adapter
//! ([`crate::raw_evidence`]).
//!
//! Unlike [`crate::protocol`] -- which carries normalized,
//! already-**verified** observations and explicitly does not parse narinfo
//! signature syntax or perform cryptographic verification -- this protocol
//! does both: it accepts literal narinfo `Sig:` entries plus a
//! verification-key registry, verifies each signature itself, and only
//! then hands the resulting [`crate::policy::SignatureCandidate`]s to the
//! exact same, unmodified `authorize()` used by the classical protocol.
//!
//! Deliberately a **separate binary and separate request type**
//! ([`RawAuthorizationRequest`], not a mode flag added to
//! [`crate::integration::AuthorizationRequest`]) so the
//! verified-observation vs. raw-evidence distinction stays structurally
//! visible rather than a runtime flag someone could miss.

use serde::{Deserialize, Serialize};

use crate::integration::{
    AuthorizationResponse, BuiltInDecision, EnforcementMode, SerializableEvaluationContext,
    authorize,
};
use crate::policy::SignaturePolicy;
use crate::raw_evidence::{
    RawEvidenceError, RawSignatureEntry, VerificationKeyEntry, verify_raw_evidence,
};
use crate::registry::TrustRegistry;

/// Stable process-protocol identifier.
pub const RAW_AUTHORIZATION_PROTOCOL_ID: &str = "nix-signature-authorization-raw-json-v1";
/// Version of the process envelope, independent from the integration contract.
pub const RAW_AUTHORIZATION_PROTOCOL_VERSION: u32 = 1;
/// Maximum accepted request size before JSON parsing.
pub const MAX_RAW_AUTHORIZATION_REQUEST_BYTES: usize = 1_048_576;
/// Maximum emitted response size after deterministic serialization.
pub const MAX_RAW_AUTHORIZATION_RESPONSE_BYTES: usize = 2_097_152;
/// Maximum accepted fingerprint length. Real narinfo fingerprints
/// (`"1;<store path>;<hash>;<size>;<refs>"`) are a few hundred bytes at
/// most; bounded here defensively ahead of any hashing/verification work.
pub const MAX_FINGERPRINT_BYTES: usize = 16 * 1024;

/// Stable protocol error classification.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RawProtocolErrorCode {
    RequestTooLarge,
    InvalidRequestJson,
    FingerprintTooLarge,
    TooManySignatureEntries,
    TooManyVerificationKeys,
    DuplicateVerificationKeyName,
    ResponseTooLarge,
    ResponseSerializationFailed,
}

/// Closed error response emitted instead of a partial authorization response.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawProtocolErrorResponse {
    pub protocol_id: String,
    pub protocol_version: u32,
    pub error_code: RawProtocolErrorCode,
    /// Set only for `DuplicateVerificationKeyName`, naming the offending
    /// key. Absent for every other error code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl RawProtocolErrorResponse {
    pub fn new(error_code: RawProtocolErrorCode) -> Self {
        Self {
            protocol_id: RAW_AUTHORIZATION_PROTOCOL_ID.into(),
            protocol_version: RAW_AUTHORIZATION_PROTOCOL_VERSION,
            error_code,
            detail: None,
        }
    }

    pub fn with_detail(error_code: RawProtocolErrorCode, detail: String) -> Self {
        Self {
            detail: Some(detail),
            ..Self::new(error_code)
        }
    }
}

/// The raw-evidence request envelope: identical to
/// [`crate::integration::AuthorizationRequest`] except `candidates:
/// Vec<SignatureCandidate>` (pre-verified) is replaced by `fingerprint` +
/// `signatures` (literal `"keyname:base64"` narinfo `Sig:` entries) +
/// `verification_keys` (the trusted registry that resolves each claimed
/// key name to an algorithm and public key -- see
/// [`crate::raw_evidence`]'s module doc for why the wire entries
/// themselves never carry an algorithm).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawAuthorizationRequest {
    pub contract_version: u32,
    pub enforcement_mode: EnforcementMode,
    pub built_in_decision: BuiltInDecision,
    pub evaluation_context: SerializableEvaluationContext,
    pub policy: SignaturePolicy,
    pub trust_registry: TrustRegistry,
    pub fingerprint: String,
    pub signatures: Vec<RawSignatureEntry>,
    pub verification_keys: Vec<VerificationKeyEntry>,
}

/// Decode one bounded raw-evidence request, verify every signature entry,
/// and evaluate the same authorization contract the classical protocol
/// uses. Never trusts a `verification` value from the input -- every
/// outcome is computed here or in [`crate::raw_evidence`].
pub fn decode_and_authorize_raw(
    request_bytes: &[u8],
) -> Result<AuthorizationResponse, RawProtocolErrorResponse> {
    if request_bytes.len() > MAX_RAW_AUTHORIZATION_REQUEST_BYTES {
        return Err(RawProtocolErrorResponse::new(
            RawProtocolErrorCode::RequestTooLarge,
        ));
    }
    let request: RawAuthorizationRequest = serde_json::from_slice(request_bytes)
        .map_err(|_| RawProtocolErrorResponse::new(RawProtocolErrorCode::InvalidRequestJson))?;

    if request.fingerprint.len() > MAX_FINGERPRINT_BYTES {
        return Err(RawProtocolErrorResponse::new(
            RawProtocolErrorCode::FingerprintTooLarge,
        ));
    }

    let candidates = verify_raw_evidence(
        request.fingerprint.as_bytes(),
        &request.signatures,
        &request.verification_keys,
    )
    .map_err(|error| match error {
        RawEvidenceError::TooManyEntries => {
            RawProtocolErrorResponse::new(RawProtocolErrorCode::TooManySignatureEntries)
        }
        RawEvidenceError::TooManyVerificationKeys => {
            RawProtocolErrorResponse::new(RawProtocolErrorCode::TooManyVerificationKeys)
        }
        RawEvidenceError::DuplicateVerificationKeyName(name) => {
            RawProtocolErrorResponse::with_detail(
                RawProtocolErrorCode::DuplicateVerificationKeyName,
                name,
            )
        }
    })?;

    let inner_request = crate::integration::AuthorizationRequest {
        contract_version: request.contract_version,
        enforcement_mode: request.enforcement_mode,
        built_in_decision: request.built_in_decision,
        evaluation_context: request.evaluation_context,
        policy: request.policy,
        trust_registry: request.trust_registry,
        candidates,
    };
    Ok(authorize(&inner_request))
}

/// Serialize one authorization response with an explicit output bound.
pub fn encode_raw_authorization_response(
    response: &AuthorizationResponse,
    pretty: bool,
) -> Result<Vec<u8>, RawProtocolErrorResponse> {
    let mut encoded = if pretty {
        serde_json::to_vec_pretty(response)
    } else {
        serde_json::to_vec(response)
    }
    .map_err(|_| {
        RawProtocolErrorResponse::new(RawProtocolErrorCode::ResponseSerializationFailed)
    })?;
    if encoded.len().saturating_add(1) > MAX_RAW_AUTHORIZATION_RESPONSE_BYTES {
        return Err(RawProtocolErrorResponse::new(
            RawProtocolErrorCode::ResponseTooLarge,
        ));
    }
    encoded.push(b'\n');
    Ok(encoded)
}

/// Serialize a protocol error. This representation is intentionally tiny
/// and cannot exceed the configured response limit.
pub fn encode_raw_protocol_error(error: &RawProtocolErrorResponse, pretty: bool) -> Vec<u8> {
    let mut encoded = if pretty {
        serde_json::to_vec_pretty(error)
    } else {
        serde_json::to_vec(error)
    }
    .expect("serializing closed protocol error cannot fail");
    encoded.push(b'\n');
    encoded
}

/// Suggested process exit status for one successful protocol response.
/// Identical semantics to [`crate::protocol::authorization_exit_code`]
/// (same [`AuthorizationResponse`] type) -- re-exported under this name so
/// callers of the raw binary don't need to reach into the other protocol
/// module for it.
pub fn raw_authorization_exit_code(response: &AuthorizationResponse) -> u8 {
    crate::protocol::authorization_exit_code(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_request_is_rejected_before_parsing() {
        let request = vec![b' '; MAX_RAW_AUTHORIZATION_REQUEST_BYTES + 1];
        let error = decode_and_authorize_raw(&request).unwrap_err();
        assert_eq!(error.error_code, RawProtocolErrorCode::RequestTooLarge);
    }

    #[test]
    fn malformed_request_has_closed_error_code() {
        let error = decode_and_authorize_raw(br#"{"#).unwrap_err();
        assert_eq!(error.error_code, RawProtocolErrorCode::InvalidRequestJson);
    }

    #[test]
    fn protocol_error_encoding_is_bounded_and_newline_terminated() {
        let error = RawProtocolErrorResponse::new(RawProtocolErrorCode::InvalidRequestJson);
        let encoded = encode_raw_protocol_error(&error, false);
        assert!(encoded.len() < MAX_RAW_AUTHORIZATION_RESPONSE_BYTES);
        assert_eq!(encoded.last(), Some(&b'\n'));
    }

    fn empty_policy() -> SignaturePolicy {
        SignaturePolicy {
            policy_id: "test-policy".to_string(),
            version: 1,
            epoch: 0,
            previous_policy_hash: None,
            active_from: None,
            expires_at: None,
            max_signature_observations: 16,
            max_signature_candidates: 16,
            family_registry: Vec::new(),
            algorithm_registry: Vec::new(),
            group_definitions: Vec::new(),
            accept_if_any: Vec::new(),
        }
    }

    #[test]
    fn duplicate_verification_key_name_surfaces_as_closed_error_with_detail() {
        let request = RawAuthorizationRequest {
            contract_version: crate::integration::INTEGRATION_CONTRACT_VERSION,
            enforcement_mode: EnforcementMode::Supplemental,
            built_in_decision: BuiltInDecision::Refuse,
            evaluation_context: SerializableEvaluationContext {
                evaluation_time: 0,
                minimum_policy_epoch: 0,
                minimum_registry_epoch: 0,
            },
            policy: empty_policy(),
            trust_registry: TrustRegistry {
                registry_id: "r".to_string(),
                epoch: 0,
                previous_registry_hash: None,
                trusted_keys: Vec::new(),
            },
            fingerprint: "1;/nix/store/x;sha256:y;1;".to_string(),
            signatures: Vec::new(),
            verification_keys: vec![
                VerificationKeyEntry {
                    key_name: "dup".to_string(),
                    algorithm: "ed25519".to_string(),
                    encoding: crate::raw_evidence::PublicKeyEncoding::Raw,
                    public_key_base64: "AA==".to_string(),
                },
                VerificationKeyEntry {
                    key_name: "dup".to_string(),
                    algorithm: "ml-dsa-65".to_string(),
                    encoding: crate::raw_evidence::PublicKeyEncoding::SpkiDer,
                    public_key_base64: "AA==".to_string(),
                },
            ],
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let error = decode_and_authorize_raw(&bytes).unwrap_err();
        assert_eq!(
            error.error_code,
            RawProtocolErrorCode::DuplicateVerificationKeyName
        );
        assert_eq!(error.detail.as_deref(), Some("dup"));
    }
}
