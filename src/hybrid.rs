//! Hybrid Ed25519 + ML-DSA-65 signing/verification, using `ed25519-dalek`
//! and RustCrypto's `ml-dsa` directly.
//!
//! Vendored (same author, same AGPL-3.0-or-later license) from
//! `mycelix-crypto::hybrid_sig` in this monorepo, rather than depended on
//! via a path dependency, so this crate has **zero private-monorepo path
//! dependencies** and builds from a fresh clone. `mycelix-crypto` is part
//! of a separate, larger PQC roadmap with its own audit/publish timeline
//! (see `mycelix-workspace/PQC_ROADMAP_2026-07-07.md`); vendoring keeps
//! that roadmap's schedule independent of this prototype's needs, and puts
//! the entire construction this RFC relies on in one directly-auditable
//! place.
//!
//! A hybrid signature is a pair `(ed25519_sig, ml_dsa65_sig)` over the
//! *same* message; verification requires **both** to pass. Forgery
//! therefore requires producing valid signatures under both schemes, so
//! the hybrid remains unforgeable as long as at least one component
//! signature scheme remains unforgeable, assuming independent keys and
//! correct composition (this is not an informal claim of "adds the two
//! security levels together" — it is the standard AND-composition
//! argument for hybrid signatures).
//!
//! # Stability
//! EXPERIMENTAL, unaudited. Fine to reuse for this exploratory prototype,
//! not a claim of production readiness — see README.md's scope notes.

use anyhow::{Result, anyhow, bail};
use ed25519_dalek::{
    Signature as EdSignature, Signer as _, SigningKey as EdSigningKey, Verifier as _,
    VerifyingKey as EdVerifyingKey,
};
use ml_dsa::signature::{Keypair as _, Signer as MlSigner, Verifier as MlVerifier};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Generate as _, KeyExport as _, KeyInit as _, MlDsa65,
    Signature as MlSignature, SigningKey as MlSigningKey, VerifyingKey as MlVerifyingKey,
};
use rand::RngCore;

/// Fixed byte length of an Ed25519 signature.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// Fixed byte length of an Ed25519 public key.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Fixed byte length of an Ed25519 secret key seed. Numerically identical
/// to `ED25519_PUBLIC_KEY_LEN` but kept as a distinct constant since the
/// two mean different things at call sites.
pub const ED25519_SECRET_KEY_LEN: usize = 32;
/// Fixed byte length of an ML-DSA-65 public key (FIPS 204), verified
/// empirically against this crate's own generated keys.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
/// Fixed byte length of an ML-DSA-65 signature (FIPS 204), verified
/// empirically against this crate's own generated signatures.
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;
/// Fixed byte length of the ML-DSA-65 secret-key seed this crate persists
/// (the compact seed form, not the expanded signing key), verified
/// empirically against this crate's own generated keys.
pub const ML_DSA_65_SECRET_SEED_LEN: usize = 32;
/// Total persisted secret-signer length: `ed25519_secret(32) || ML-DSA-65 seed(32)`.
pub const HYBRID_SECRET_KEY_LEN: usize = ED25519_SECRET_KEY_LEN + ML_DSA_65_SECRET_SEED_LEN;

/// Hybrid signer holding both secret keys. Persist with
/// [`to_bytes`](HybridSigner::to_bytes) / restore with
/// [`from_bytes`](HybridSigner::from_bytes).
pub struct HybridSigner {
    ed: EdSigningKey,
    ml_dsa: MlSigningKey<MlDsa65>,
}

/// Publishable hybrid verifying keys.
#[derive(Clone, Debug)]
pub struct HybridVerifyingKeys {
    /// Ed25519 verifying key (32 bytes).
    pub ed25519: [u8; ED25519_PUBLIC_KEY_LEN],
    /// ML-DSA-65 verifying key (1952 bytes).
    pub ml_dsa: Vec<u8>,
}

/// A hybrid signature: Ed25519 (64 bytes) + ML-DSA-65 (3309 bytes).
#[derive(Clone, Debug)]
pub struct HybridSignature {
    /// Ed25519 signature (64 bytes).
    pub ed25519: [u8; ED25519_SIGNATURE_LEN],
    /// ML-DSA-65 signature.
    pub ml_dsa: Vec<u8>,
}

impl HybridSigner {
    /// Generate a fresh hybrid keypair.
    pub fn generate() -> Self {
        // Deliberately not `EdSigningKey::generate(&mut OsRng)` (which needs
        // ed25519-dalek's "rand_core" feature) -- raw OS random bytes +
        // `from_bytes` needs no extra feature flags on our direct dependency.
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self {
            ed: EdSigningKey::from_bytes(&seed),
            ml_dsa: MlSigningKey::<MlDsa65>::generate(),
        }
    }

    /// Verifying keys to publish so others can [`verify`] this signer.
    pub fn verifying_keys(&self) -> HybridVerifyingKeys {
        HybridVerifyingKeys {
            ed25519: self.ed.verifying_key().to_bytes(),
            ml_dsa: self.ml_dsa.verifying_key().encode().as_slice().to_vec(),
        }
    }

    /// Sign `message` with both algorithms over the identical bytes.
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        let ed = self.ed.sign(message).to_bytes();
        let ml_dsa = self.ml_dsa.sign(message).encode().as_slice().to_vec();
        HybridSignature {
            ed25519: ed,
            ml_dsa,
        }
    }

    /// Serialize the secret signer for persistence:
    /// `ed25519_secret(32) || ML-DSA-65 seed(32)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.ed.to_bytes());
        out.extend_from_slice(self.ml_dsa.to_bytes().as_slice());
        out
    }

    /// Reconstruct a signer from [`to_bytes`](Self::to_bytes) output.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HYBRID_SECRET_KEY_LEN {
            bail!(
                "signer bytes are {} bytes, expected exactly {HYBRID_SECRET_KEY_LEN}",
                bytes.len()
            );
        }
        let ed_sk: [u8; ED25519_SECRET_KEY_LEN] = bytes[..ED25519_SECRET_KEY_LEN]
            .try_into()
            .expect("length already checked above");
        let ed = EdSigningKey::from_bytes(&ed_sk);
        let ml_dsa = MlSigningKey::<MlDsa65>::new_from_slice(&bytes[ED25519_SECRET_KEY_LEN..])
            .map_err(|_| anyhow!("invalid ML-DSA signing key"))?;
        Ok(Self { ed, ml_dsa })
    }
}

/// Verify a hybrid signature. **Both** halves must verify against `message`.
pub fn verify(keys: &HybridVerifyingKeys, message: &[u8], sig: &HybridSignature) -> Result<()> {
    // --- Ed25519 (classical) ---
    let ed_vk = EdVerifyingKey::from_bytes(&keys.ed25519)
        .map_err(|e| anyhow!("invalid Ed25519 verifying key: {e}"))?;
    let ed_sig = EdSignature::from_bytes(&sig.ed25519);
    ed_vk
        .verify(message, &ed_sig)
        .map_err(|e| anyhow!("Ed25519 signature verification failed: {e}"))?;

    // --- ML-DSA-65 (post-quantum) ---
    let ml_encoded_vk = EncodedVerifyingKey::<MlDsa65>::try_from(keys.ml_dsa.as_slice())
        .map_err(|_| anyhow!("invalid ML-DSA verifying key length"))?;
    let ml_vk = MlVerifyingKey::<MlDsa65>::decode(&ml_encoded_vk);
    let ml_encoded_sig = EncodedSignature::<MlDsa65>::try_from(sig.ml_dsa.as_slice())
        .map_err(|_| anyhow!("invalid ML-DSA signature length"))?;
    let ml_sig = MlSignature::<MlDsa65>::decode(&ml_encoded_sig)
        .ok_or_else(|| anyhow!("undecodable ML-DSA signature"))?;
    ml_vk
        .verify(message, &ml_sig)
        .map_err(|e| anyhow!("ML-DSA signature verification failed: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_have_expected_lengths() {
        let signer = HybridSigner::generate();
        let keys = signer.verifying_keys();
        assert_eq!(keys.ed25519.len(), ED25519_PUBLIC_KEY_LEN);
        assert_eq!(keys.ml_dsa.len(), ML_DSA_65_PUBLIC_KEY_LEN);
        let sig = signer.sign(b"length check");
        assert_eq!(sig.ed25519.len(), ED25519_SIGNATURE_LEN);
        assert_eq!(sig.ml_dsa.len(), ML_DSA_65_SIGNATURE_LEN);
    }

    #[test]
    fn signer_serialization_round_trip() {
        let signer = HybridSigner::generate();
        let bytes = signer.to_bytes();
        let restored = HybridSigner::from_bytes(&bytes).expect("from_bytes");

        let msg = b"persisted signer still works";
        let sig = restored.sign(msg);
        assert!(verify(&signer.verifying_keys(), msg, &sig).is_ok());
        assert_eq!(
            signer.verifying_keys().ml_dsa,
            restored.verifying_keys().ml_dsa
        );
        assert_eq!(
            signer.verifying_keys().ed25519,
            restored.verifying_keys().ed25519
        );
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(HybridSigner::from_bytes(&[0u8; HYBRID_SECRET_KEY_LEN - 1]).is_err());
        assert!(HybridSigner::from_bytes(&[0u8; HYBRID_SECRET_KEY_LEN + 1]).is_err());
        assert!(HybridSigner::from_bytes(&[]).is_err());
    }

    #[test]
    fn sign_verify_round_trip() {
        let signer = HybridSigner::generate();
        let keys = signer.verifying_keys();
        let msg = b"nix-pqc-cache-proxy";
        let sig = signer.sign(msg);
        assert!(verify(&keys, msg, &sig).is_ok());
    }

    #[test]
    fn tampered_message_is_rejected() {
        let signer = HybridSigner::generate();
        let keys = signer.verifying_keys();
        let sig = signer.sign(b"authentic message");
        assert!(verify(&keys, b"forged message", &sig).is_err());
    }

    #[test]
    fn wrong_signer_is_rejected() {
        let alice = HybridSigner::generate();
        let mallory = HybridSigner::generate();
        let msg = b"from alice";
        let sig = alice.sign(msg);
        assert!(verify(&mallory.verifying_keys(), msg, &sig).is_err());
    }

    #[test]
    fn forged_ml_dsa_half_is_rejected() {
        let signer = HybridSigner::generate();
        let keys = signer.verifying_keys();
        let msg = b"needs both halves";
        let mut sig = signer.sign(msg);
        sig.ml_dsa[0] ^= 0x01;
        assert!(
            verify(&keys, msg, &sig).is_err(),
            "a broken ML-DSA half must fail the whole verify"
        );
    }

    #[test]
    fn forged_ed25519_half_is_rejected() {
        let signer = HybridSigner::generate();
        let keys = signer.verifying_keys();
        let msg = b"needs both halves";
        let mut sig = signer.sign(msg);
        sig.ed25519[0] ^= 0x01;
        assert!(
            verify(&keys, msg, &sig).is_err(),
            "a broken Ed25519 half must fail the whole verify"
        );
    }
}
