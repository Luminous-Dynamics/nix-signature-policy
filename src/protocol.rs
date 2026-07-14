//! Bounded JSON process protocol for external signature-authorization hooks.
//!
//! The protocol deliberately carries normalized, already-verified observations.
//! It does not parse narinfo signature syntax and does not perform cryptographic
//! verification. Its purpose is to make the authoritative admission boundary
//! testable across process and implementation boundaries.

use serde::{Deserialize, Serialize};

use crate::integration::{
    AdmissionDecision, AuthorizationRequest, AuthorizationResponse, authorize,
};

/// Stable process-protocol identifier.
pub const AUTHORIZATION_PROTOCOL_ID: &str = "nix-signature-authorization-json-v1";
/// Version of the process envelope, independent from the integration contract.
pub const AUTHORIZATION_PROTOCOL_VERSION: u32 = 1;
/// Maximum accepted request size before JSON parsing.
pub const MAX_AUTHORIZATION_REQUEST_BYTES: usize = 1_048_576;
/// Maximum emitted response size after deterministic serialization.
pub const MAX_AUTHORIZATION_RESPONSE_BYTES: usize = 2_097_152;

/// Stable protocol error classification.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolErrorCode {
    RequestTooLarge,
    InvalidRequestJson,
    ResponseTooLarge,
    ResponseSerializationFailed,
}

/// Closed error response emitted instead of a partial authorization response.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtocolErrorResponse {
    pub protocol_id: String,
    pub protocol_version: u32,
    pub error_code: ProtocolErrorCode,
}

impl ProtocolErrorResponse {
    pub fn new(error_code: ProtocolErrorCode) -> Self {
        Self {
            protocol_id: AUTHORIZATION_PROTOCOL_ID.into(),
            protocol_version: AUTHORIZATION_PROTOCOL_VERSION,
            error_code,
        }
    }
}

/// Decode one bounded request and evaluate the authorization contract.
pub fn decode_and_authorize(
    request_bytes: &[u8],
) -> Result<AuthorizationResponse, ProtocolErrorResponse> {
    if request_bytes.len() > MAX_AUTHORIZATION_REQUEST_BYTES {
        return Err(ProtocolErrorResponse::new(
            ProtocolErrorCode::RequestTooLarge,
        ));
    }
    let request: AuthorizationRequest = serde_json::from_slice(request_bytes)
        .map_err(|_| ProtocolErrorResponse::new(ProtocolErrorCode::InvalidRequestJson))?;
    Ok(authorize(&request))
}

/// Serialize one authorization response with an explicit output bound.
pub fn encode_authorization_response(
    response: &AuthorizationResponse,
    pretty: bool,
) -> Result<Vec<u8>, ProtocolErrorResponse> {
    let mut encoded = if pretty {
        serde_json::to_vec_pretty(response)
    } else {
        serde_json::to_vec(response)
    }
    .map_err(|_| ProtocolErrorResponse::new(ProtocolErrorCode::ResponseSerializationFailed))?;
    if encoded.len().saturating_add(1) > MAX_AUTHORIZATION_RESPONSE_BYTES {
        return Err(ProtocolErrorResponse::new(
            ProtocolErrorCode::ResponseTooLarge,
        ));
    }
    encoded.push(b'\n');
    Ok(encoded)
}

/// Serialize a protocol error. This representation is intentionally tiny and
/// cannot exceed the configured response limit.
pub fn encode_protocol_error(error: &ProtocolErrorResponse, pretty: bool) -> Vec<u8> {
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
pub fn authorization_exit_code(response: &AuthorizationResponse) -> u8 {
    match response.decision {
        AdmissionDecision::Accept => 0,
        AdmissionDecision::Refuse => 10,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_request_is_rejected_before_parsing() {
        let request = vec![b' '; MAX_AUTHORIZATION_REQUEST_BYTES + 1];
        let error = decode_and_authorize(&request).unwrap_err();
        assert_eq!(error.error_code, ProtocolErrorCode::RequestTooLarge);
    }

    #[test]
    fn malformed_request_has_closed_error_code() {
        let error = decode_and_authorize(br#"{"#).unwrap_err();
        assert_eq!(error.error_code, ProtocolErrorCode::InvalidRequestJson);
    }

    #[test]
    fn protocol_error_encoding_is_bounded_and_newline_terminated() {
        let error = ProtocolErrorResponse::new(ProtocolErrorCode::InvalidRequestJson);
        let encoded = encode_protocol_error(&error, false);
        assert!(encoded.len() < MAX_AUTHORIZATION_RESPONSE_BYTES);
        assert_eq!(encoded.last(), Some(&b'\n'));
    }
}
