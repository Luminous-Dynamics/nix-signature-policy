//! Parse/serialize the Nix `.narinfo` text format and compute the v1 signing
//! fingerprint, matching `nix::NarInfo::fingerprint()` bit-for-bit.
//!
//! Deliberately hand-rolled rather than pulling in an external nix-compat-style
//! crate: the format is a handful of `Key: value` lines and this is a security
//! tool, so we keep the trust footprint minimal.

use std::collections::HashSet;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;

/// Maximum accepted metadata body. The proxy already enforces this at the
/// network boundary; the parser repeats the limit so direct library callers
/// and fuzz targets receive the same bounded behavior.
pub const MAX_NARINFO_BYTES: usize = 64 * 1024;
/// Defensive line-count bound within a metadata body.
pub const MAX_NARINFO_LINES: usize = 1024;
/// Defensive bound for any individual metadata line.
pub const MAX_NARINFO_LINE_BYTES: usize = 16 * 1024;
/// Maximum number of references accepted from one `References:` field.
pub const MAX_NARINFO_REFERENCES: usize = 4096;
/// Maximum number of signature fields retained per representation.
pub const MAX_NARINFO_SIGNATURE_FIELDS: usize = 256;
/// Maximum number of unmodeled metadata fields retained.
pub const MAX_NARINFO_EXTRA_FIELDS: usize = 256;
/// Maximum size of one `name:base64` signature entry.
pub const MAX_SIGNATURE_ENTRY_BYTES: usize = 16 * 1024;

/// A parsed `.narinfo` document. `Sig-PQC` is our own prototype field, not a
/// real Nix field — real `nix` ignores unrecognized lines, which is exactly
/// what makes the hybrid format backward compatible.
#[derive(Debug, Clone, Default)]
pub struct NarInfo {
    pub store_path: String,
    pub url: String,
    pub compression: String,
    pub file_hash: Option<String>,
    pub file_size: Option<u64>,
    pub nar_hash: String,
    pub nar_size: u64,
    pub references: Vec<String>,
    pub deriver: Option<String>,
    pub system: Option<String>,
    /// Raw `name:base64` entries from `Sig:` lines (classical Ed25519).
    pub sigs: Vec<String>,
    /// Raw `name:base64` entries from `Sig-PQC:` lines (our hybrid field).
    pub sig_pqc: Vec<String>,
    /// Any other recognized-by-Nix-but-not-modeled-here lines, preserved verbatim in order.
    pub extra: Vec<(String, String)>,
}

impl NarInfo {
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > MAX_NARINFO_BYTES {
            bail!(
                "narinfo is {} bytes, limit is {MAX_NARINFO_BYTES}",
                text.len()
            );
        }

        let mut info = NarInfo::default();
        for (line_index, line) in text.lines().enumerate() {
            if line_index >= MAX_NARINFO_LINES {
                bail!("narinfo has more than {MAX_NARINFO_LINES} lines");
            }
            if line.len() > MAX_NARINFO_LINE_BYTES {
                bail!(
                    "narinfo line {} is {} bytes, limit is {MAX_NARINFO_LINE_BYTES}",
                    line_index + 1,
                    line.len()
                );
            }
            // Only strip a defensive trailing \r (CRLF) — NOT trailing spaces:
            // a real narinfo emits e.g. "References: " (trailing space, empty
            // value) for a zero-reference path, and blindly trim_end()-ing
            // the line eats that separator space and breaks parsing.
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            // Normal case: "Key: value" (value may be empty after the space).
            // Fallback: a bare "Key:" with no trailing space at all.
            let (key, value) = match line.split_once(": ") {
                Some(kv) => kv,
                None => match line.strip_suffix(':') {
                    Some(key) => (key, ""),
                    None => bail!("malformed narinfo line: {line:?}"),
                },
            };
            match key {
                "StorePath" => info.store_path = value.to_string(),
                "URL" => info.url = value.to_string(),
                "Compression" => info.compression = value.to_string(),
                "FileHash" => info.file_hash = Some(value.to_string()),
                "FileSize" => info.file_size = Some(value.parse().context("FileSize")?),
                "NarHash" => info.nar_hash = value.to_string(),
                "NarSize" => info.nar_size = value.parse().context("NarSize")?,
                "References" => {
                    // Real Nix parses references as a set of store paths. Use
                    // token semantics rather than splitting on one literal
                    // space so repeated/leading/trailing whitespace cannot
                    // manufacture empty references.
                    info.references = value.split_whitespace().map(String::from).collect();
                    if info.references.len() > MAX_NARINFO_REFERENCES {
                        bail!(
                            "narinfo has {} references, limit is {MAX_NARINFO_REFERENCES}",
                            info.references.len()
                        );
                    }
                }
                "Deriver" => info.deriver = Some(value.to_string()),
                "System" => info.system = Some(value.to_string()),
                "Sig" => {
                    if info.sigs.len() == MAX_NARINFO_SIGNATURE_FIELDS {
                        bail!("narinfo has more than {MAX_NARINFO_SIGNATURE_FIELDS} Sig fields");
                    }
                    info.sigs.push(value.to_string());
                }
                "Sig-PQC" => {
                    if info.sig_pqc.len() == MAX_NARINFO_SIGNATURE_FIELDS {
                        bail!(
                            "narinfo has more than {MAX_NARINFO_SIGNATURE_FIELDS} Sig-PQC fields"
                        );
                    }
                    info.sig_pqc.push(value.to_string());
                }
                other => {
                    if info.extra.len() == MAX_NARINFO_EXTRA_FIELDS {
                        bail!("narinfo has more than {MAX_NARINFO_EXTRA_FIELDS} unmodeled fields");
                    }
                    info.extra.push((other.to_string(), value.to_string()));
                }
            }
        }
        if info.store_path.is_empty() {
            bail!("narinfo missing StorePath");
        }
        if info.nar_hash.is_empty() {
            bail!("narinfo missing NarHash");
        }
        Ok(info)
    }

    /// Serialize back to `.narinfo` text. This preserves **verification
    /// semantics** (the fields that feed `fingerprint()`, and every
    /// existing `Sig:`/new `Sig-PQC:` line), not the original narinfo's
    /// exact byte layout — field order matches real Nix output for easy
    /// hand-diffing, but any `extra` fields we don't model are re-emitted
    /// in their original relative order rather than at their original
    /// absolute position, and `Sig-PQC` lines are always appended last
    /// since ordinary `nix` never looks for them. The proxy and `sign`
    /// subcommand both rely on this being semantically faithful, not
    /// byte-identical to whatever bytes were originally served.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("StorePath: {}\n", self.store_path));
        out.push_str(&format!("URL: {}\n", self.url));
        out.push_str(&format!("Compression: {}\n", self.compression));
        if let Some(fh) = &self.file_hash {
            out.push_str(&format!("FileHash: {fh}\n"));
        }
        if let Some(fs) = &self.file_size {
            out.push_str(&format!("FileSize: {fs}\n"));
        }
        out.push_str(&format!("NarHash: {}\n", self.nar_hash));
        out.push_str(&format!("NarSize: {}\n", self.nar_size));
        out.push_str(&format!(
            "References: {}\n",
            self.canonical_references().join(" ")
        ));
        if let Some(d) = &self.deriver {
            out.push_str(&format!("Deriver: {d}\n"));
        }
        if let Some(s) = &self.system {
            out.push_str(&format!("System: {s}\n"));
        }
        for (k, v) in &self.extra {
            out.push_str(&format!("{k}: {v}\n"));
        }
        for s in &self.sigs {
            out.push_str(&format!("Sig: {s}\n"));
        }
        for s in &self.sig_pqc {
            out.push_str(&format!("Sig-PQC: {s}\n"));
        }
        out
    }

    /// Replace this key name's classical and PQ signature entries atomically
    /// in the in-memory representation. Repeated signing is therefore
    /// idempotent and cannot grow duplicate same-key entries.
    pub fn replace_signature_pair(
        &mut self,
        key_name: &str,
        classical_entry: String,
        pqc_entry: String,
    ) -> Result<()> {
        if key_name.is_empty() || key_name.contains(':') || key_name.chars().any(char::is_control) {
            bail!("invalid signature key name {key_name:?}");
        }
        let prefix = format!("{key_name}:");
        if !classical_entry.starts_with(&prefix) {
            bail!("classical signature entry does not belong to key {key_name:?}");
        }
        if !pqc_entry.starts_with(&prefix) {
            bail!("PQC signature entry does not belong to key {key_name:?}");
        }

        self.sigs.retain(|entry| !entry.starts_with(&prefix));
        self.sig_pqc.retain(|entry| !entry.starts_with(&prefix));
        self.sigs.push(classical_entry);
        self.sig_pqc.push(pqc_entry);
        Ok(())
    }

    /// The store directory (e.g. `/nix/store`), derived from `store_path`.
    pub fn store_dir(&self) -> Result<&str> {
        let idx = self
            .store_path
            .rfind('/')
            .ok_or_else(|| anyhow!("StorePath has no '/'"))?;
        Ok(&self.store_path[..idx])
    }

    /// Return references with the same ordering and duplicate-elimination
    /// semantics as Nix's `StorePathSet`.
    fn canonical_references(&self) -> Vec<&str> {
        let mut references: Vec<&str> = self.references.iter().map(String::as_str).collect();
        references.sort_unstable();
        references.dedup();
        references
    }

    /// The Nix v1 signing fingerprint:
    /// `1;<store_path>;<nar_hash>;<nar_size>;<comma-joined full reference paths>`.
    pub fn fingerprint(&self) -> Result<String> {
        let store_dir = self.store_dir()?;
        // Real Nix stores references in a `StorePathSet` (`std::set<StorePath>`),
        // so both order and multiplicity in the incoming text are irrelevant.
        let refs = self
            .canonical_references()
            .into_iter()
            .map(|r| format!("{store_dir}/{r}"))
            .collect::<Vec<_>>()
            .join(",");
        Ok(format!(
            "1;{};{};{};{}",
            self.store_path, self.nar_hash, self.nar_size, refs
        ))
    }
}

/// Parse a `name:base64` narinfo signature entry into `(name, raw_bytes)`.
pub fn parse_sig_entry(entry: &str) -> Result<(String, Vec<u8>)> {
    if entry.len() > MAX_SIGNATURE_ENTRY_BYTES {
        bail!(
            "signature entry is {} bytes, limit is {MAX_SIGNATURE_ENTRY_BYTES}",
            entry.len()
        );
    }
    let (name, b64) = entry
        .split_once(':')
        .ok_or_else(|| anyhow!("malformed sig entry: {entry:?}"))?;
    if name.is_empty() || name.chars().any(char::is_control) {
        bail!("signature entry has an invalid key name");
    }
    if b64.is_empty() {
        bail!("signature entry has empty base64 payload");
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("base64 decode sig")?;
    Ok((name.to_string(), bytes))
}

/// Maximum number of distinct, correctly encoded signatures considered for a
/// single trusted key. Exceeding the cap is an explicit policy error rather
/// than an order-dependent "no valid signature" result.
pub const MAX_SIGNATURE_CANDIDATES: usize = 32;

/// Verify that at least one distinct, correctly encoded Ed25519 signature for
/// `expected_name` validates `fingerprint` under `pubkey_b64`.
///
/// Malformed and wrong-name entries are ignored so a valid later signature is
/// still considered. More than [`MAX_SIGNATURE_CANDIDATES`] distinct matching
/// candidates is rejected explicitly before cryptographic verification.
pub fn verify_any_ed25519_sig(
    fingerprint: &str,
    sig_entries: &[String],
    expected_name: Option<&str>,
    pubkey_b64: &str,
) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let pk_bytes = base64::engine::general_purpose::STANDARD
        .decode(pubkey_b64)
        .context("base64 decode pubkey")?;
    let pk_bytes: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("ed25519 public key is not 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| anyhow!("bad verifying key: {e}"))?;

    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for entry in sig_entries {
        let Ok((name, bytes)) = parse_sig_entry(entry) else {
            continue;
        };
        if expected_name.is_some_and(|expected| name != expected) {
            continue;
        }
        let Ok(sig_bytes) = <[u8; 64]>::try_from(bytes.as_slice()) else {
            continue;
        };
        if !seen.insert(sig_bytes) {
            continue;
        }
        if candidates.len() == MAX_SIGNATURE_CANDIDATES {
            bail!(
                "too many distinct Sig: candidates for key {:?}: limit is {MAX_SIGNATURE_CANDIDATES}",
                expected_name.unwrap_or("<any>")
            );
        }
        candidates.push(sig_bytes);
    }

    if candidates.is_empty() {
        bail!(
            "no validly encoded Sig: candidate found for key {:?}",
            expected_name.unwrap_or("<any>")
        );
    }
    if candidates.iter().any(|bytes| {
        vk.verify(fingerprint.as_bytes(), &Signature::from_bytes(bytes))
            .is_ok()
    }) {
        return Ok(());
    }

    bail!(
        "no Sig: candidate for key {:?} verified ({} candidate(s) tried)",
        expected_name.unwrap_or("<any>"),
        candidates.len()
    )
}

/// Verify a raw Ed25519 `Sig:` entry against a known base64-encoded (32-byte)
/// public key, mimicking exactly what real `nix` does for `trusted-public-keys`
/// — including name-first lookup: when `expected_name` is `Some`, the entry's
/// own embedded name must match it before any crypto is even attempted (real
/// Nix only tries a signature at all if its name is in the trusted set).
/// `expected_name: None` skips that check, matching an unnamed configured
/// key — real Nix's `trusted-public-keys` is always `name:base64`, so this
/// escape hatch only exists for callers that haven't (yet) been given a name.
pub fn verify_ed25519_sig(
    fingerprint: &str,
    sig_entry: &str,
    expected_name: Option<&str>,
    pubkey_b64: &str,
) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let (name, sig_bytes) = parse_sig_entry(sig_entry)?;
    if let Some(expected) = expected_name {
        if name != expected {
            bail!("Sig: key name {name:?} does not match expected {expected:?}");
        }
    }
    let sig_bytes: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("ed25519 signature is not 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_bytes);

    let pk_bytes = base64::engine::general_purpose::STANDARD
        .decode(pubkey_b64)
        .context("base64 decode pubkey")?;
    let pk_bytes: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("ed25519 public key is not 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| anyhow!("bad verifying key: {e}"))?;

    vk.verify(fingerprint.as_bytes(), &sig)
        .map_err(|e| anyhow!("ed25519 signature verification failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real narinfo fetched 2026-07-10 from https://cache.nixos.org for a
    // store path present on this machine (bash-5.2p37). Frozen as a fixture
    // so this test is deterministic and network-free; `verify_ed25519_sig`
    // is exercised against the REAL `cache.nixos.org-1` public key from
    // /etc/nix/nix.conf, proving our fingerprint/parsing logic is
    // bit-compatible with real Nix, not just internally self-consistent.
    const SAMPLE: &str = "\
StorePath: /nix/store/00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37
URL: nar/08lg95m879r3yarkg6ndjg3db9an3bzg5ha9iba2vd8hfrw06q93.nar.xz
Compression: xz
FileHash: sha256:08lg95m879r3yarkg6ndjg3db9an3bzg5ha9iba2vd8hfrw06q93
FileSize: 448312
NarHash: sha256:0hbgkq56i09xjh7jkm3z1lwgbrhwazkyab7mw108m0fp0f59dj48
NarSize: 1654112
References: 00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37 q4wq65gl3r8fy746v9bbwgx4gzn0r2kl-glibc-2.40-66
Deriver: c8dsr967ap3j1l01l565w926bahlxpmc-bash-5.2p37.drv
Sig: cache.nixos.org-1:DCeO+o0Q4DlnCPr8TeBZE77GhRlm11H9x609XtU7rUS69am2qkhX4zTsK4URTHG/vEMX4avP8HVcIHwXHq3+CQ==
";

    const CACHE_NIXOS_ORG_PUBKEY: &str = "6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=";

    #[test]
    fn parses_real_narinfo() {
        let info = NarInfo::parse(SAMPLE).unwrap();
        assert_eq!(
            info.store_path,
            "/nix/store/00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37"
        );
        assert_eq!(info.nar_size, 1654112);
        assert_eq!(info.references.len(), 2);
        assert_eq!(info.sigs.len(), 1);
        assert!(info.sig_pqc.is_empty());
    }

    #[test]
    fn round_trips_through_to_text() {
        let info = NarInfo::parse(SAMPLE).unwrap();
        let reparsed = NarInfo::parse(&info.to_text()).unwrap();
        assert_eq!(info.store_path, reparsed.store_path);
        assert_eq!(info.fingerprint().unwrap(), reparsed.fingerprint().unwrap());
        assert_eq!(info.sigs, reparsed.sigs);
    }

    #[test]
    fn fingerprint_matches_expected_v1_format() {
        let info = NarInfo::parse(SAMPLE).unwrap();
        let fp = info.fingerprint().unwrap();
        assert_eq!(
            fp,
            "1;/nix/store/00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37;\
             sha256:0hbgkq56i09xjh7jkm3z1lwgbrhwazkyab7mw108m0fp0f59dj48;1654112;\
             /nix/store/00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37,\
             /nix/store/q4wq65gl3r8fy746v9bbwgx4gzn0r2kl-glibc-2.40-66"
        );
    }

    /// Real Nix stores references in a `std::set<StorePath>` and always
    /// computes the fingerprint from that canonical (sorted) order — it
    /// never trusts the narinfo text's order. A shuffled References: line
    /// (whether from a non-Nix tool, manual editing, or an adversary) must
    /// still produce the SAME fingerprint as the canonically-ordered one,
    /// or verification against a real Nix-issued signature would spuriously
    /// fail. This was a real, previously-untested gap: every fixture this
    /// crate had used happened to already be canonically ordered.
    #[test]
    fn fingerprint_is_invariant_to_reference_order_in_text() {
        let shuffled = SAMPLE.replace(
            "References: 00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37 q4wq65gl3r8fy746v9bbwgx4gzn0r2kl-glibc-2.40-66",
            "References: q4wq65gl3r8fy746v9bbwgx4gzn0r2kl-glibc-2.40-66 00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37",
        );
        assert_ne!(shuffled, SAMPLE, "the replace must actually have matched");

        let canonical_fp = NarInfo::parse(SAMPLE).unwrap().fingerprint().unwrap();
        let shuffled_fp = NarInfo::parse(&shuffled).unwrap().fingerprint().unwrap();
        assert_eq!(
            canonical_fp, shuffled_fp,
            "fingerprint must be invariant to References: text order"
        );
    }

    #[test]
    fn references_are_set_equivalent_for_fingerprint_and_serialization() {
        let irregular = SAMPLE.replace(
            "References: 00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37 q4wq65gl3r8fy746v9bbwgx4gzn0r2kl-glibc-2.40-66",
            "References:   q4wq65gl3r8fy746v9bbwgx4gzn0r2kl-glibc-2.40-66   00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37  q4wq65gl3r8fy746v9bbwgx4gzn0r2kl-glibc-2.40-66   ",
        );
        let canonical = NarInfo::parse(SAMPLE).unwrap();
        let parsed = NarInfo::parse(&irregular).unwrap();

        assert_eq!(
            canonical.fingerprint().unwrap(),
            parsed.fingerprint().unwrap()
        );
        assert_eq!(
            parsed
                .to_text()
                .lines()
                .find(|line| line.starts_with("References:"))
                .unwrap(),
            "References: 00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37 q4wq65gl3r8fy746v9bbwgx4gzn0r2kl-glibc-2.40-66"
        );
    }

    #[test]
    fn excessive_signature_candidates_fail_explicitly() {
        let info = NarInfo::parse(SAMPLE).unwrap();
        let fp = info.fingerprint().unwrap();
        let mut sigs = Vec::new();
        for i in 0..=MAX_SIGNATURE_CANDIDATES {
            let mut bytes = [0u8; 64];
            bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
            sigs.push(format!(
                "cache.nixos.org-1:{}",
                base64::engine::general_purpose::STANDARD.encode(bytes)
            ));
        }
        let err = verify_any_ed25519_sig(
            &fp,
            &sigs,
            Some("cache.nixos.org-1"),
            CACHE_NIXOS_ORG_PUBKEY,
        )
        .unwrap_err();
        assert!(err.to_string().contains("too many distinct Sig:"));
    }

    /// The real proof: our computed fingerprint + parsing verifies against
    /// the REAL cache.nixos.org Ed25519 signature and public key.
    #[test]
    fn real_signature_verifies_against_real_pubkey() {
        let info = NarInfo::parse(SAMPLE).unwrap();
        let fp = info.fingerprint().unwrap();
        verify_ed25519_sig(
            &fp,
            &info.sigs[0],
            Some("cache.nixos.org-1"),
            CACHE_NIXOS_ORG_PUBKEY,
        )
        .expect("real cache.nixos.org signature must verify");
    }

    #[test]
    fn tampered_fingerprint_is_rejected() {
        let info = NarInfo::parse(SAMPLE).unwrap();
        let fp = info.fingerprint().unwrap();
        let tampered = fp.replace("1654112", "1654113");
        assert!(
            verify_ed25519_sig(
                &tampered,
                &info.sigs[0],
                Some("cache.nixos.org-1"),
                CACHE_NIXOS_ORG_PUBKEY
            )
            .is_err()
        );
    }

    #[test]
    fn mismatched_expected_name_is_rejected_even_with_correct_key() {
        let info = NarInfo::parse(SAMPLE).unwrap();
        let fp = info.fingerprint().unwrap();
        let err = verify_ed25519_sig(
            &fp,
            &info.sigs[0],
            Some("some-other-name"),
            CACHE_NIXOS_ORG_PUBKEY,
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not match expected"));
    }

    #[test]
    fn unnamed_expectation_skips_name_check() {
        let info = NarInfo::parse(SAMPLE).unwrap();
        let fp = info.fingerprint().unwrap();
        verify_ed25519_sig(&fp, &info.sigs[0], None, CACHE_NIXOS_ORG_PUBKEY)
            .expect("None expected_name must not enforce a name match");
    }

    #[test]
    fn sig_pqc_round_trips() {
        let mut info = NarInfo::parse(SAMPLE).unwrap();
        info.sig_pqc.push("demo-1:deadbeef==".to_string());
        let text = info.to_text();
        assert!(text.contains("Sig-PQC: demo-1:deadbeef==\n"));
        let reparsed = NarInfo::parse(&text).unwrap();
        assert_eq!(reparsed.sig_pqc, vec!["demo-1:deadbeef==".to_string()]);
    }
}
