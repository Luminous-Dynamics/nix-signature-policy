//! Key generation/storage and the `Sig-PQC` wire encoding, built on top of
//! `mycelix_crypto::hybrid_sig` (Ed25519 + ML-DSA-65, both halves required).
//!
//! `mycelix_crypto`'s `hybrid-rc` construction is EXPERIMENTAL and pending a
//! crypto audit (see `mycelix-workspace/PQC_ROADMAP_2026-07-07.md`) — fine to
//! reuse for this exploratory prototype, not a claim of production readiness.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use mycelix_crypto::hybrid_sig::{HybridSignature, HybridSigner, HybridVerifyingKeys};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// A named hybrid signing key, persisted as `<name>\n<base64 secret bytes>\n`.
pub struct SecretKey {
    pub name: String,
    pub signer: HybridSigner,
}

impl SecretKey {
    pub fn generate(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            signer: HybridSigner::generate(),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let body = format!("{}\n{}\n", self.name, B64.encode(self.signer.to_bytes()));
        fs::write(path, body).with_context(|| format!("writing secret key to {path:?}"))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text =
            fs::read_to_string(path).with_context(|| format!("reading secret key {path:?}"))?;
        let mut lines = text.lines();
        let name = lines
            .next()
            .ok_or_else(|| anyhow!("empty secret key file"))?
            .to_string();
        let b64 = lines
            .next()
            .ok_or_else(|| anyhow!("secret key file missing key material line"))?;
        let bytes = B64.decode(b64).context("base64 decode secret key")?;
        let signer =
            HybridSigner::from_bytes(&bytes).map_err(|e| anyhow!("bad secret key: {e}"))?;
        Ok(Self { name, signer })
    }

    pub fn public(&self) -> PublicKey {
        PublicKey {
            name: self.name.clone(),
            keys: self.signer.verifying_keys(),
        }
    }
}

/// Publishable hybrid verifying keys, persisted as:
/// ```text
/// <name>
/// ed25519:<base64 32B>
/// ml-dsa-65:<base64 ~1952B>
/// ```
pub struct PublicKey {
    pub name: String,
    pub keys: HybridVerifyingKeys,
}

impl PublicKey {
    pub fn save(&self, path: &Path) -> Result<()> {
        let body = format!(
            "{}\ned25519:{}\nml-dsa-65:{}\n",
            self.name,
            B64.encode(self.keys.ed25519),
            B64.encode(&self.keys.ml_dsa),
        );
        fs::write(path, body).with_context(|| format!("writing public key to {path:?}"))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text =
            fs::read_to_string(path).with_context(|| format!("reading public key {path:?}"))?;
        let mut lines = text.lines();
        let name = lines
            .next()
            .ok_or_else(|| anyhow!("empty public key file"))?
            .to_string();
        let ed_line = lines
            .next()
            .ok_or_else(|| anyhow!("public key file missing ed25519 line"))?;
        let ml_line = lines
            .next()
            .ok_or_else(|| anyhow!("public key file missing ml-dsa-65 line"))?;
        let ed_b64 = ed_line
            .strip_prefix("ed25519:")
            .ok_or_else(|| anyhow!("expected 'ed25519:' prefix"))?;
        let ml_b64 = ml_line
            .strip_prefix("ml-dsa-65:")
            .ok_or_else(|| anyhow!("expected 'ml-dsa-65:' prefix"))?;
        let ed_bytes = B64.decode(ed_b64).context("base64 decode ed25519 pubkey")?;
        let ed25519: [u8; 32] = ed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("ed25519 public key is not 32 bytes"))?;
        let ml_dsa = B64.decode(ml_b64).context("base64 decode ml-dsa pubkey")?;
        Ok(Self {
            name,
            keys: HybridVerifyingKeys { ed25519, ml_dsa },
        })
    }
}

/// Strip an optional `name:` prefix from a key string, so `--upstream-pubkey`
/// accepts either a bare base64 key or a `nix.conf`-style `name:base64` entry.
pub fn strip_key_name(s: &str) -> &str {
    s.rsplit_once(':').map(|(_, b)| b).unwrap_or(s)
}

/// Which PQC construction a `Sig-PQC:` entry uses. A single variant today,
/// but giving the wire format an explicit tag means a future ML-DSA-87 or
/// Falcon variant is a new enum arm, not a format rewrite — and an entry
/// tagged with an algorithm this build doesn't understand is rejected
/// cleanly instead of being silently misparsed as if it were this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SigPqcAlgorithm {
    /// Ed25519 (64B) || ML-DSA-65 (~3309B), both halves required to verify.
    HybridEd25519MlDsa65 = 1,
}

impl SigPqcAlgorithm {
    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::HybridEd25519MlDsa65),
            other => bail!(
                "unknown Sig-PQC algorithm tag {other}; this build only understands \
                 HybridEd25519MlDsa65 (tag 1)"
            ),
        }
    }
}

/// Encode a hybrid signature for a narinfo `Sig-PQC:` line:
/// `<name>:<base64(alg_tag(1B) || ed25519(64B) || ml_dsa)>`.
pub fn encode_sig_pqc(name: &str, sig: &HybridSignature) -> String {
    let mut buf = Vec::with_capacity(1 + 64 + sig.ml_dsa.len());
    buf.push(SigPqcAlgorithm::HybridEd25519MlDsa65 as u8);
    buf.extend_from_slice(&sig.ed25519);
    buf.extend_from_slice(&sig.ml_dsa);
    format!("{name}:{}", B64.encode(buf))
}

/// Decode a `Sig-PQC:` line's value back into `(name, algorithm, HybridSignature)`.
pub fn decode_sig_pqc(entry: &str) -> Result<(String, SigPqcAlgorithm, HybridSignature)> {
    let (name, bytes) = crate::narinfo::parse_sig_entry(entry)?;
    let (&tag, rest) = bytes
        .split_first()
        .ok_or_else(|| anyhow!("empty Sig-PQC entry"))?;
    let algorithm = SigPqcAlgorithm::from_tag(tag)?;
    if rest.len() < 64 {
        bail!("Sig-PQC entry shorter than the Ed25519 half alone");
    }
    let ed25519: [u8; 64] = rest[..64]
        .try_into()
        .expect("slice of len 64 always converts");
    let ml_dsa = rest[64..].to_vec();
    Ok((name, algorithm, HybridSignature { ed25519, ml_dsa }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn secret_key_round_trips_through_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("demo.secret");
        let key = SecretKey::generate("demo-1");
        key.save(&path).unwrap();
        let loaded = SecretKey::load(&path).unwrap();
        assert_eq!(loaded.name, "demo-1");
        assert_eq!(loaded.public().keys.ed25519, key.public().keys.ed25519);
    }

    #[test]
    fn public_key_round_trips_through_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("demo.pub");
        let key = SecretKey::generate("demo-1");
        key.public().save(&path).unwrap();
        let loaded = PublicKey::load(&path).unwrap();
        assert_eq!(loaded.name, "demo-1");
        assert_eq!(loaded.keys.ed25519, key.public().keys.ed25519);
        assert_eq!(loaded.keys.ml_dsa, key.public().keys.ml_dsa);
    }

    #[test]
    fn sig_pqc_encode_decode_round_trip_and_verifies() {
        let key = SecretKey::generate("demo-1");
        let msg = b"1;/nix/store/xxx-demo;sha256:abc;123;";
        let sig = key.signer.sign(msg);
        let entry = encode_sig_pqc(&key.name, &sig);
        let (name, algorithm, decoded) = decode_sig_pqc(&entry).unwrap();
        assert_eq!(name, "demo-1");
        assert_eq!(algorithm, SigPqcAlgorithm::HybridEd25519MlDsa65);
        mycelix_crypto::hybrid_sig::verify(&key.public().keys, msg, &decoded)
            .expect("decoded hybrid signature must verify");
    }

    #[test]
    fn corrupted_ml_dsa_half_is_rejected() {
        let key = SecretKey::generate("demo-1");
        let msg = b"needs both halves";
        let sig = key.signer.sign(msg);
        let mut entry = encode_sig_pqc(&key.name, &sig);
        // Flip a base64 character deep in the string (well past the tag byte
        // and 64-byte ed25519 prefix once decoded) to corrupt only the ML-DSA half.
        let mid = entry.len() - 10;
        let bytes = unsafe { entry.as_bytes_mut() };
        bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
        let (_name, _algorithm, decoded) = decode_sig_pqc(&entry).unwrap();
        assert!(mycelix_crypto::hybrid_sig::verify(&key.public().keys, msg, &decoded).is_err());
    }

    #[test]
    fn unknown_algorithm_tag_is_rejected() {
        let key = SecretKey::generate("demo-1");
        let sig = key.signer.sign(b"whatever");
        let entry = encode_sig_pqc(&key.name, &sig);
        // Corrupt just the leading algorithm-tag byte (base64 char 0) to an
        // encoding of a tag this build doesn't recognize.
        let (name, b64) = entry.split_once(':').unwrap();
        let mut raw = B64.decode(b64).unwrap();
        raw[0] = 99; // no such algorithm
        let corrupted = format!("{name}:{}", B64.encode(&raw));
        let err = decode_sig_pqc(&corrupted).unwrap_err();
        assert!(err.to_string().contains("unknown Sig-PQC algorithm tag"));
    }
}
