//! Deterministic hybrid attestations for arbitrary release artifacts.
//!
//! The intended use is to sign a small deterministic release statement
//! which, in turn, binds a source archive and its file manifest.
//! The attestation does not claim that the artifact is safe or correct; it
//! proves that the named hybrid key signed the exact canonical payload and
//! that the supplied artifact still matches the recorded SHA-256 and size.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hybrid::{
    ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, HybridSignature, HybridVerifyingKeys,
    ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};
use crate::keys::{PublicKey, SecretKey};

pub const ARTIFACT_ATTESTATION_SCHEMA_VERSION: u32 = 1;
pub const MAX_ARTIFACT_ATTESTATION_BYTES: u64 = 1024 * 1024;
// Stable legacy domain retained so existing prototype attestations are not reinterpreted.
const ATTESTATION_DOMAIN: &[u8] = b"nix-pqc-cache-proxy/artifact-attestation/v1\0";
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPayload {
    pub schema_version: u32,
    pub domain: String,
    pub identifier: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAttestation {
    pub algorithm: String,
    pub key_name: String,
    pub ed25519_public_key_base64: String,
    pub ml_dsa_65_public_key_base64: String,
    pub ed25519_signature_base64: String,
    pub ml_dsa_65_signature_base64: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAttestationBundle {
    pub bundle_schema_version: u32,
    pub payload_sha256: String,
    pub payload: ArtifactPayload,
    pub attestation: ArtifactAttestation,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactVerificationFailure {
    UnsupportedSchema,
    InvalidPayloadStructure,
    InvalidPayloadDigest,
    ArtifactIdentifierMismatch,
    ArtifactMismatch,
    InvalidAttestation,
    UntrustedAttestation,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactVerificationReport {
    pub report_schema_version: u32,
    pub success: bool,
    pub payload_structure_valid: bool,
    pub payload_digest_valid: bool,
    pub artifact_identifier_valid: bool,
    pub artifact_binding_valid: bool,
    pub attestation_valid: bool,
    pub trusted_key_matches: bool,
    pub failure_codes: BTreeSet<ArtifactVerificationFailure>,
}

pub fn attest_artifact(
    artifact_path: &Path,
    identifier: impl Into<String>,
    signing_key: &SecretKey,
) -> Result<ArtifactAttestationBundle> {
    let (sha256, size_bytes) = hash_file(artifact_path)?;
    let payload = ArtifactPayload {
        schema_version: ARTIFACT_ATTESTATION_SCHEMA_VERSION,
        domain: "release_statement".into(),
        identifier: identifier.into(),
        sha256,
        size_bytes,
    };
    validate_payload(&payload)?;
    let canonical = canonical_payload_bytes(&payload)?;
    let payload_sha256 = sha256_hex(&canonical);
    let message = attestation_message(&signing_key.name, &canonical);
    let signature = signing_key.signer.sign(&message);
    let public = signing_key.public();

    Ok(ArtifactAttestationBundle {
        bundle_schema_version: ARTIFACT_ATTESTATION_SCHEMA_VERSION,
        payload_sha256,
        payload,
        attestation: ArtifactAttestation {
            algorithm: "ed25519+ml-dsa-65".into(),
            key_name: public.name,
            ed25519_public_key_base64: B64.encode(public.keys.ed25519),
            ml_dsa_65_public_key_base64: B64.encode(public.keys.ml_dsa),
            ed25519_signature_base64: B64.encode(signature.ed25519),
            ml_dsa_65_signature_base64: B64.encode(signature.ml_dsa),
        },
    })
}

pub fn verify_artifact_attestation(
    artifact_path: &Path,
    bundle: &ArtifactAttestationBundle,
    trusted_key: &PublicKey,
) -> ArtifactVerificationReport {
    let mut failure_codes = BTreeSet::new();
    let schema_valid = bundle.bundle_schema_version == ARTIFACT_ATTESTATION_SCHEMA_VERSION
        && bundle.payload.schema_version == ARTIFACT_ATTESTATION_SCHEMA_VERSION;
    if !schema_valid {
        failure_codes.insert(ArtifactVerificationFailure::UnsupportedSchema);
    }

    let payload_structure_valid = validate_payload(&bundle.payload).is_ok();
    if !payload_structure_valid {
        failure_codes.insert(ArtifactVerificationFailure::InvalidPayloadStructure);
    }

    let canonical = payload_structure_valid
        .then(|| canonical_payload_bytes(&bundle.payload))
        .transpose()
        .ok()
        .flatten();
    let payload_digest_valid = canonical
        .as_ref()
        .is_some_and(|bytes| sha256_hex(bytes) == bundle.payload_sha256);
    if !payload_digest_valid {
        failure_codes.insert(ArtifactVerificationFailure::InvalidPayloadDigest);
    }

    let artifact_identifier_valid = artifact_path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == bundle.payload.identifier);
    if !artifact_identifier_valid {
        failure_codes.insert(ArtifactVerificationFailure::ArtifactIdentifierMismatch);
    }

    let artifact_binding_valid = hash_file(artifact_path).is_ok_and(|(sha256, size)| {
        sha256 == bundle.payload.sha256 && size == bundle.payload.size_bytes
    });
    if !artifact_binding_valid {
        failure_codes.insert(ArtifactVerificationFailure::ArtifactMismatch);
    }

    let embedded = decode_embedded_key(&bundle.attestation).ok();
    let trusted_key_matches = embedded.as_ref().is_some_and(|keys| {
        bundle.attestation.key_name == trusted_key.name
            && keys.ed25519 == trusted_key.keys.ed25519
            && keys.ml_dsa == trusted_key.keys.ml_dsa
    });
    if !trusted_key_matches {
        failure_codes.insert(ArtifactVerificationFailure::UntrustedAttestation);
    }

    let attestation_valid =
        canonical
            .as_ref()
            .zip(embedded.as_ref())
            .is_some_and(|(canonical, keys)| {
                decode_signature(&bundle.attestation).is_ok_and(|signature| {
                    crate::hybrid::verify(
                        keys,
                        &attestation_message(&bundle.attestation.key_name, canonical),
                        &signature,
                    )
                    .is_ok()
                })
            });
    if !attestation_valid {
        failure_codes.insert(ArtifactVerificationFailure::InvalidAttestation);
    }

    ArtifactVerificationReport {
        report_schema_version: ARTIFACT_ATTESTATION_SCHEMA_VERSION,
        success: schema_valid
            && payload_structure_valid
            && payload_digest_valid
            && artifact_identifier_valid
            && artifact_binding_valid
            && trusted_key_matches
            && attestation_valid,
        payload_structure_valid,
        payload_digest_valid,
        artifact_identifier_valid,
        artifact_binding_valid,
        attestation_valid,
        trusted_key_matches,
        failure_codes,
    }
}

pub fn load_bundle(path: &Path) -> Result<ArtifactAttestationBundle> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading artifact attestation metadata {path:?}"))?;
    if metadata.len() > MAX_ARTIFACT_ATTESTATION_BYTES {
        bail!(
            "artifact attestation {path:?} is {} bytes, limit is {MAX_ARTIFACT_ATTESTATION_BYTES}",
            metadata.len()
        );
    }
    let bytes = fs::read(path).with_context(|| format!("reading artifact attestation {path:?}"))?;
    parse_bundle(&bytes)
}

pub fn parse_bundle(bytes: &[u8]) -> Result<ArtifactAttestationBundle> {
    if bytes.len() > MAX_ARTIFACT_ATTESTATION_BYTES as usize {
        bail!(
            "artifact attestation is {} bytes, limit is {MAX_ARTIFACT_ATTESTATION_BYTES}",
            bytes.len()
        );
    }
    serde_json::from_slice(bytes).context("parsing artifact attestation JSON")
}

pub fn to_pretty_json(bundle: &ArtifactAttestationBundle) -> Result<String> {
    let mut text = serde_json::to_string_pretty(bundle)?;
    text.push('\n');
    Ok(text)
}

fn validate_payload(payload: &ArtifactPayload) -> Result<()> {
    if payload.schema_version != ARTIFACT_ATTESTATION_SCHEMA_VERSION {
        bail!("unsupported artifact payload schema version");
    }
    if payload.domain != "release_statement" {
        bail!("unsupported artifact attestation domain");
    }
    if payload.identifier.is_empty() || payload.identifier.len() > 512 {
        bail!("artifact identifier must contain 1..=512 characters");
    }
    if payload
        .identifier
        .chars()
        .any(|character| matches!(character, '/' | '\\'))
        || matches!(payload.identifier.as_str(), "." | "..")
    {
        bail!("artifact identifier must be one filename, not a path");
    }
    if payload
        .identifier
        .chars()
        .any(|character| matches!(character, '\r' | '\n' | '\0'))
    {
        bail!("artifact identifier contains a forbidden control character");
    }
    if payload.sha256.len() != 64
        || !payload
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("artifact SHA-256 must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn canonical_payload_bytes(payload: &ArtifactPayload) -> Result<Vec<u8>> {
    validate_payload(payload)?;
    serde_json::to_vec(payload).context("serializing canonical artifact payload")
}

fn decode_embedded_key(attestation: &ArtifactAttestation) -> Result<HybridVerifyingKeys> {
    if attestation.algorithm != "ed25519+ml-dsa-65" {
        bail!("unsupported artifact attestation algorithm");
    }
    let ed_bytes = B64
        .decode(&attestation.ed25519_public_key_base64)
        .context("decoding embedded Ed25519 public key")?;
    let ed25519: [u8; ED25519_PUBLIC_KEY_LEN] = ed_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("embedded Ed25519 public key has the wrong length"))?;
    let ml_dsa = B64
        .decode(&attestation.ml_dsa_65_public_key_base64)
        .context("decoding embedded ML-DSA-65 public key")?;
    if ml_dsa.len() != ML_DSA_65_PUBLIC_KEY_LEN {
        bail!("embedded ML-DSA-65 public key has the wrong length");
    }
    Ok(HybridVerifyingKeys { ed25519, ml_dsa })
}

fn decode_signature(attestation: &ArtifactAttestation) -> Result<HybridSignature> {
    let ed_bytes = B64
        .decode(&attestation.ed25519_signature_base64)
        .context("decoding Ed25519 artifact signature")?;
    let ed25519: [u8; ED25519_SIGNATURE_LEN] = ed_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("Ed25519 artifact signature has the wrong length"))?;
    let ml_dsa = B64
        .decode(&attestation.ml_dsa_65_signature_base64)
        .context("decoding ML-DSA-65 artifact signature")?;
    if ml_dsa.len() != ML_DSA_65_SIGNATURE_LEN {
        bail!("ML-DSA-65 artifact signature has the wrong length");
    }
    Ok(HybridSignature { ed25519, ml_dsa })
}

fn hash_file(path: &Path) -> Result<(String, u64)> {
    use std::io::Read;

    let mut file = fs::File::open(path).with_context(|| format!("opening artifact {path:?}"))?;
    let mut digest = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("reading artifact {path:?}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("artifact size overflow"))?;
    }
    Ok((encode_hex(&digest.finalize()), size))
}

fn attestation_message(key_name: &str, canonical_payload: &[u8]) -> Vec<u8> {
    let name = key_name.as_bytes();
    let mut message = Vec::with_capacity(
        ATTESTATION_DOMAIN.len()
            + std::mem::size_of::<u64>()
            + name.len()
            + canonical_payload.len(),
    );
    message.extend_from_slice(ATTESTATION_DOMAIN);
    message.extend_from_slice(&(name.len() as u64).to_be_bytes());
    message.extend_from_slice(name);
    message.extend_from_slice(canonical_payload);
    message
}

fn sha256_hex(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trip_and_tamper_detection() {
        let dir = tempdir().unwrap();
        let artifact = dir.path().join("release.json");
        fs::write(&artifact, b"release statement\n").unwrap();
        let key = SecretKey::generate("release-1");
        let bundle = attest_artifact(&artifact, "release.json", &key).unwrap();
        let report = verify_artifact_attestation(&artifact, &bundle, &key.public());
        assert!(report.success);

        fs::write(&artifact, b"tampered\n").unwrap();
        let report = verify_artifact_attestation(&artifact, &bundle, &key.public());
        assert!(!report.success);
        assert!(
            report
                .failure_codes
                .contains(&ArtifactVerificationFailure::ArtifactMismatch)
        );
    }

    #[test]
    fn artifact_filename_is_bound() {
        let dir = tempdir().unwrap();
        let artifact = dir.path().join("release.json");
        let renamed = dir.path().join("other.json");
        fs::write(&artifact, b"release statement\n").unwrap();
        fs::copy(&artifact, &renamed).unwrap();
        let key = SecretKey::generate("release-1");
        let bundle = attest_artifact(&artifact, "release.json", &key).unwrap();
        let report = verify_artifact_attestation(&renamed, &bundle, &key.public());
        assert!(!report.success);
        assert!(
            report
                .failure_codes
                .contains(&ArtifactVerificationFailure::ArtifactIdentifierMismatch)
        );
    }

    #[test]
    fn attestation_key_name_is_signed() {
        let dir = tempdir().unwrap();
        let artifact = dir.path().join("release.json");
        fs::write(&artifact, b"release statement\n").unwrap();
        let key = SecretKey::generate("release-1");
        let mut bundle = attest_artifact(&artifact, "release.json", &key).unwrap();
        bundle.attestation.key_name = "release-2".into();
        let report = verify_artifact_attestation(&artifact, &bundle, &key.public());
        assert!(!report.success);
        assert!(
            report
                .failure_codes
                .contains(&ArtifactVerificationFailure::InvalidAttestation)
        );
    }

    #[test]
    fn wrong_trust_anchor_is_refused() {
        let dir = tempdir().unwrap();
        let artifact = dir.path().join("release.json");
        fs::write(&artifact, b"release statement\n").unwrap();
        let signer = SecretKey::generate("release-1");
        let other = SecretKey::generate("release-2");
        let bundle = attest_artifact(&artifact, "release.json", &signer).unwrap();
        let report = verify_artifact_attestation(&artifact, &bundle, &other.public());
        assert!(!report.success);
        assert!(
            report
                .failure_codes
                .contains(&ArtifactVerificationFailure::UntrustedAttestation)
        );
    }
}
