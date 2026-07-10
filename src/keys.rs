//! Key generation/storage and the `Sig-PQC` wire encoding, built on top of
//! `crate::hybrid` (Ed25519 + ML-DSA-65, both halves required).
//!
//! `Sig-PQC:` carries ONLY the ML-DSA signature — it deliberately does not
//! duplicate the Ed25519 bytes already present in the same-keyname `Sig:`
//! line. [`verify_hybrid`] is where the two get paired back together by
//! keyname to reconstruct the full hybrid check; see
//! `rfc/0000-hybrid-binary-cache-signatures.md`'s "Wire format" section for
//! why this is safe (the classical `Sig:` line must already survive
//! unmodified for backward compatibility, so there's nothing gained by
//! also embedding a copy of it inside `Sig-PQC:`).
//!
//! `crate::hybrid`'s construction is EXPERIMENTAL and unaudited — fine to
//! reuse for this exploratory prototype, not a claim of production readiness.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;

use crate::hybrid::{
    self, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, HybridSignature, HybridSigner,
    HybridVerifyingKeys, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};
use crate::narinfo::{self, NarInfo};

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
/// ml-dsa-65:<base64 1952B>
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
        let ed25519: [u8; ED25519_PUBLIC_KEY_LEN] = ed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("ed25519 public key is not {ED25519_PUBLIC_KEY_LEN} bytes"))?;
        let ml_dsa = B64.decode(ml_b64).context("base64 decode ml-dsa pubkey")?;
        if ml_dsa.len() != ML_DSA_65_PUBLIC_KEY_LEN {
            bail!(
                "ML-DSA-65 public key is {} bytes, expected exactly {ML_DSA_65_PUBLIC_KEY_LEN}",
                ml_dsa.len()
            );
        }
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
    /// ML-DSA-65 (3309B) alone. The Ed25519 half lives in the same-keyname
    /// `Sig:` line, not here — see [`verify_hybrid`].
    MlDsa65 = 1,
}

impl SigPqcAlgorithm {
    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::MlDsa65),
            other => bail!(
                "unknown Sig-PQC algorithm tag {other}; this build only understands \
                 MlDsa65 (tag 1)"
            ),
        }
    }
}

/// Encode a narinfo `Sig-PQC:` line: `<name>:<base64(alg_tag(1B) || ml_dsa_sig)>`.
/// Carries only the ML-DSA signature — see the module docs for why the
/// Ed25519 half is deliberately not duplicated here.
pub fn encode_sig_pqc(name: &str, ml_dsa_sig: &[u8]) -> String {
    let mut buf = Vec::with_capacity(1 + ml_dsa_sig.len());
    buf.push(SigPqcAlgorithm::MlDsa65 as u8);
    buf.extend_from_slice(ml_dsa_sig);
    format!("{name}:{}", B64.encode(buf))
}

/// Decode a `Sig-PQC:` line's value into `(name, algorithm, ml_dsa_sig_bytes)`.
/// Enforces the exact expected signature length for the decoded algorithm at
/// this codec boundary, rather than deferring entirely to the crypto
/// backend — a wrong-length payload is rejected here, cleanly, with a
/// specific error.
pub fn decode_sig_pqc(entry: &str) -> Result<(String, SigPqcAlgorithm, Vec<u8>)> {
    let (name, bytes) = narinfo::parse_sig_entry(entry)?;
    let (&tag, rest) = bytes
        .split_first()
        .ok_or_else(|| anyhow!("empty Sig-PQC entry"))?;
    let algorithm = SigPqcAlgorithm::from_tag(tag)?;
    match algorithm {
        SigPqcAlgorithm::MlDsa65 => {
            if rest.len() != ML_DSA_65_SIGNATURE_LEN {
                bail!(
                    "Sig-PQC ML-DSA-65 signature is {} bytes, expected exactly {ML_DSA_65_SIGNATURE_LEN}",
                    rest.len()
                );
            }
        }
    }
    Ok((name, algorithm, rest.to_vec()))
}

/// Verify a hybrid signature for `keyname` on `info`.
///
/// Tries **every** same-keyname classical `Sig:` candidate paired with
/// **every** same-keyname `Sig-PQC:` candidate, and succeeds if **any**
/// pairing verifies — matching Nix's own any-of-N-signatures trust model
/// (`ValidPathInfo::checkSignatures` counts *any* good signature among
/// possibly-many) rather than assuming exactly one of each ever appears.
/// A malformed or unrecognized-algorithm `Sig-PQC:` candidate, or a
/// wrong-length `Sig:` candidate, is treated as a failed candidate and
/// skipped — never a hard abort that would block a different, valid
/// same-keyname pairing elsewhere in the narinfo from being tried.
pub fn verify_hybrid(
    info: &NarInfo,
    fingerprint: &str,
    keyname: &str,
    keys: &HybridVerifyingKeys,
) -> Result<()> {
    let prefix = format!("{keyname}:");

    let ed_candidates: Vec<[u8; ED25519_SIGNATURE_LEN]> = info
        .sigs
        .iter()
        .filter(|s| s.starts_with(&prefix))
        .filter_map(|s| narinfo::parse_sig_entry(s).ok())
        .filter_map(|(_name, bytes)| bytes.as_slice().try_into().ok())
        .collect();
    if ed_candidates.is_empty() {
        bail!("no valid Sig: candidate for key '{keyname}' to pair with Sig-PQC");
    }

    let pqc_candidates: Vec<Vec<u8>> = info
        .sig_pqc
        .iter()
        .filter(|s| s.starts_with(&prefix))
        .filter_map(|s| decode_sig_pqc(s).ok())
        .map(|(_name, _algorithm, ml_dsa)| ml_dsa)
        .collect();
    if pqc_candidates.is_empty() {
        bail!("no valid Sig-PQC: candidate for key '{keyname}'");
    }

    for ed25519 in &ed_candidates {
        for ml_dsa in &pqc_candidates {
            let sig = HybridSignature {
                ed25519: *ed25519,
                ml_dsa: ml_dsa.clone(),
            };
            if hybrid::verify(keys, fingerprint.as_bytes(), &sig).is_ok() {
                return Ok(());
            }
        }
    }

    Err(anyhow!(
        "no Sig:/Sig-PQC: pair for key '{keyname}' verified ({} classical x {} PQC candidates tried)",
        ed_candidates.len(),
        pqc_candidates.len()
    ))
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
    fn public_key_load_rejects_wrong_length_ml_dsa_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.pub");
        fs::write(
            &path,
            format!(
                "demo-1\ned25519:{}\nml-dsa-65:{}\n",
                B64.encode([0u8; ED25519_PUBLIC_KEY_LEN]),
                B64.encode([0u8; 100]), // nowhere near 1952 bytes
            ),
        )
        .unwrap();
        assert!(PublicKey::load(&path).is_err());
    }

    #[test]
    fn sig_pqc_encode_decode_round_trip() {
        let key = SecretKey::generate("demo-1");
        let msg = b"1;/nix/store/xxx-demo;sha256:abc;123;";
        let sig = key.signer.sign(msg);
        let entry = encode_sig_pqc(&key.name, &sig.ml_dsa);
        let (name, algorithm, ml_dsa) = decode_sig_pqc(&entry).unwrap();
        assert_eq!(name, "demo-1");
        assert_eq!(algorithm, SigPqcAlgorithm::MlDsa65);
        assert_eq!(ml_dsa, sig.ml_dsa);
    }

    #[test]
    fn decode_sig_pqc_rejects_wrong_length_ml_dsa_signature() {
        let key = SecretKey::generate("demo-1");
        let sig = key.signer.sign(b"whatever");
        let mut truncated = sig.ml_dsa.clone();
        truncated.truncate(100); // nowhere near ML_DSA_65_SIGNATURE_LEN
        let entry = encode_sig_pqc(&key.name, &truncated);
        let err = decode_sig_pqc(&entry).unwrap_err();
        assert!(err.to_string().contains("expected exactly"));
    }

    fn narinfo_with(keyname: &str, sig: &HybridSignature) -> NarInfo {
        let ed_b64 = B64.encode(sig.ed25519);
        let mut info = NarInfo {
            store_path: "/nix/store/xxx-demo".to_string(),
            nar_hash: "sha256:abc".to_string(),
            nar_size: 123,
            ..Default::default()
        };
        info.sigs.push(format!("{keyname}:{ed_b64}"));
        info.sig_pqc.push(encode_sig_pqc(keyname, &sig.ml_dsa));
        info
    }

    #[test]
    fn verify_hybrid_passes_with_both_halves_present_and_valid() {
        let key = SecretKey::generate("demo-1");
        let fingerprint = "1;/nix/store/xxx-demo;sha256:abc;123;";
        let sig = key.signer.sign(fingerprint.as_bytes());
        let info = narinfo_with("demo-1", &sig);

        verify_hybrid(&info, fingerprint, "demo-1", &key.public().keys)
            .expect("both halves present and valid must verify");
    }

    #[test]
    fn verify_hybrid_fails_without_matching_sig_line() {
        let key = SecretKey::generate("demo-1");
        let fingerprint = "1;/nix/store/xxx-demo;sha256:abc;123;";
        let sig = key.signer.sign(fingerprint.as_bytes());
        let mut info = NarInfo::default();
        info.sig_pqc.push(encode_sig_pqc("demo-1", &sig.ml_dsa));

        assert!(verify_hybrid(&info, fingerprint, "demo-1", &key.public().keys).is_err());
    }

    #[test]
    fn verify_hybrid_fails_without_matching_sig_pqc_line() {
        let key = SecretKey::generate("demo-1");
        let fingerprint = "1;/nix/store/xxx-demo;sha256:abc;123;";
        let sig = key.signer.sign(fingerprint.as_bytes());
        let ed_b64 = B64.encode(sig.ed25519);
        let mut info = NarInfo::default();
        info.sigs.push(format!("demo-1:{ed_b64}"));

        assert!(verify_hybrid(&info, fingerprint, "demo-1", &key.public().keys).is_err());
    }

    #[test]
    fn corrupted_ml_dsa_half_is_rejected() {
        let key = SecretKey::generate("demo-1");
        let fingerprint = "1;/nix/store/xxx-demo;sha256:abc;123;";
        let sig = key.signer.sign(fingerprint.as_bytes());
        let mut info = narinfo_with("demo-1", &sig);

        // Flip a base64 character deep in the Sig-PQC value (preserves
        // decoded length, so this exercises the crypto check, not the
        // length check) to corrupt the ML-DSA half while leaving the
        // classical Sig: line untouched.
        let entry = &mut info.sig_pqc[0];
        let mid = entry.len() - 10;
        let bytes = unsafe { entry.as_bytes_mut() };
        bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };

        assert!(verify_hybrid(&info, fingerprint, "demo-1", &key.public().keys).is_err());
    }

    #[test]
    fn unknown_algorithm_tag_is_rejected() {
        let key = SecretKey::generate("demo-1");
        let sig = key.signer.sign(b"whatever");
        let entry = encode_sig_pqc(&key.name, &sig.ml_dsa);
        // Corrupt just the leading algorithm-tag byte (base64 char 0) to an
        // encoding of a tag this build doesn't recognize.
        let (name, b64) = entry.split_once(':').unwrap();
        let mut raw = B64.decode(b64).unwrap();
        raw[0] = 99; // no such algorithm
        let corrupted = format!("{name}:{}", B64.encode(&raw));
        let err = decode_sig_pqc(&corrupted).unwrap_err();
        assert!(err.to_string().contains("unknown Sig-PQC algorithm tag"));
    }

    #[test]
    fn any_valid_pair_verifies_when_an_earlier_sig_pqc_candidate_is_invalid() {
        // Two Sig-PQC entries under the SAME keyname: the first is corrupted
        // garbage, the second is genuinely valid. A first-match-only
        // implementation would wrongly reject this; verify_hybrid must try
        // both and succeed on the second.
        let key = SecretKey::generate("demo-1");
        let fingerprint = "1;/nix/store/xxx-demo;sha256:abc;123;";
        let sig = key.signer.sign(fingerprint.as_bytes());
        let ed_b64 = B64.encode(sig.ed25519);

        let mut bad_entry = encode_sig_pqc("demo-1", &sig.ml_dsa);
        {
            let mid = bad_entry.len() - 10;
            let bytes = unsafe { bad_entry.as_bytes_mut() };
            bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
        }
        let good_entry = encode_sig_pqc("demo-1", &sig.ml_dsa);

        let mut info = NarInfo::default();
        info.sigs.push(format!("demo-1:{ed_b64}"));
        info.sig_pqc.push(bad_entry);
        info.sig_pqc.push(good_entry);

        verify_hybrid(&info, fingerprint, "demo-1", &key.public().keys)
            .expect("a later valid Sig-PQC candidate must still verify");
    }

    #[test]
    fn any_valid_pair_verifies_when_an_earlier_sig_candidate_is_invalid() {
        // Mirror case: two Sig: entries under the same keyname, first
        // corrupted, second genuinely valid.
        let key = SecretKey::generate("demo-1");
        let fingerprint = "1;/nix/store/xxx-demo;sha256:abc;123;";
        let sig = key.signer.sign(fingerprint.as_bytes());

        let mut bad_ed = sig.ed25519;
        bad_ed[0] ^= 0xFF;
        let bad_sig_line = format!("demo-1:{}", B64.encode(bad_ed));
        let good_sig_line = format!("demo-1:{}", B64.encode(sig.ed25519));

        let mut info = NarInfo::default();
        info.sigs.push(bad_sig_line);
        info.sigs.push(good_sig_line);
        info.sig_pqc.push(encode_sig_pqc("demo-1", &sig.ml_dsa));

        verify_hybrid(&info, fingerprint, "demo-1", &key.public().keys)
            .expect("a later valid Sig candidate must still verify");
    }

    #[test]
    fn unknown_tag_sig_pqc_candidate_does_not_block_a_later_valid_one() {
        let key = SecretKey::generate("demo-1");
        let fingerprint = "1;/nix/store/xxx-demo;sha256:abc;123;";
        let sig = key.signer.sign(fingerprint.as_bytes());
        let ed_b64 = B64.encode(sig.ed25519);

        let good_entry = encode_sig_pqc("demo-1", &sig.ml_dsa);
        let unknown_tag_entry = {
            let (name, b64) = good_entry.split_once(':').unwrap();
            let mut raw = B64.decode(b64).unwrap();
            raw[0] = 250; // unrecognized future algorithm tag
            format!("{name}:{}", B64.encode(&raw))
        };

        let mut info = NarInfo::default();
        info.sigs.push(format!("demo-1:{ed_b64}"));
        info.sig_pqc.push(unknown_tag_entry);
        info.sig_pqc.push(good_entry);

        verify_hybrid(&info, fingerprint, "demo-1", &key.public().keys)
            .expect("an unrecognized-tag candidate must not block a later valid one");
    }
}
