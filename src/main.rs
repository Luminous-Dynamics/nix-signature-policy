use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use nix_signature_policy::keys::{self, PublicKey, SecretKey};
use nix_signature_policy::narinfo::{self, NarInfo};
use nix_signature_policy::proxy;

/// Prototype: hybrid Ed25519+ML-DSA-65 signing/verification for Nix binary
/// caches, plus a local trust-translating reverse proxy.
///
/// EXPLORATORY PROTOTYPE — does not and cannot secure cache.nixos.org itself
/// (upstream doesn't sign PQC and we don't hold their key). See README.md.
#[derive(Parser)]
#[command(name = "nix-pqc-cache-proxy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a hybrid Ed25519+ML-DSA-65 signing key: writes `<name>.secret` and `<name>.pub`
    Keygen {
        /// Key name, e.g. "my-cache-1" (mirrors Nix's `<hostname>-N` convention)
        name: String,
        /// Output directory for the key files
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
    },
    /// Dual-sign every .narinfo file in a local binary-cache directory
    Sign {
        /// Directory containing .narinfo files (e.g. a `nix copy --to file://...` cache)
        cache_dir: PathBuf,
        /// Path to the secret key file produced by `keygen`
        #[arg(long)]
        key: PathBuf,
    },
    /// Verify one .narinfo file's classical Sig and (optionally required) Sig-PQC
    Verify {
        narinfo: PathBuf,
        /// Base64 Ed25519 public key to check classical Sig: lines against
        #[arg(long)]
        pubkey: Option<String>,
        /// Path to a .pub file (from keygen). Supplying this requires a valid
        /// same-keyname Ed25519+ML-DSA hybrid signature.
        #[arg(long)]
        pqc_pubkey: Option<PathBuf>,
        /// Require hybrid verification. This flag also requires --pqc-pubkey.
        #[arg(long)]
        require_pqc: bool,
    },
    /// Run the local trust-translating reverse proxy
    Proxy {
        /// Upstream binary cache base URL
        #[arg(long, default_value = "https://cache.nixos.org")]
        upstream: String,
        /// Upstream's base64 Ed25519 public key (e.g. cache.nixos.org's)
        #[arg(long)]
        upstream_pubkey: String,
        /// Our hybrid secret key file (from keygen), used to re-sign narinfo
        #[arg(long)]
        key: PathBuf,
        /// Address to listen on
        #[arg(long, default_value = "127.0.0.1:8443")]
        listen: String,
        /// Maximum admitted handlers/streams before bounded queueing begins.
        #[arg(long, default_value_t = 128)]
        max_in_flight: usize,
        /// Maximum queue wait before returning 503 Service Unavailable.
        #[arg(long, default_value_t = 1_000)]
        queue_timeout_ms: u64,
        /// Upstream TCP/TLS connection deadline.
        #[arg(long, default_value_t = 10)]
        connect_timeout_secs: u64,
        /// Whole-request deadline for small metadata responses.
        #[arg(long, default_value_t = 30)]
        metadata_timeout_secs: u64,
        /// Deadline for upstream NAR response headers.
        #[arg(long, default_value_t = 30)]
        nar_header_timeout_secs: u64,
        /// Maximum idle interval between streamed NAR chunks.
        #[arg(long, default_value_t = 30)]
        nar_idle_timeout_secs: u64,
        /// Optional maximum NAR body size in bytes; omitted means unlimited.
        #[arg(long)]
        max_nar_bytes: Option<u64>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen { name, out_dir } => cmd_keygen(&name, &out_dir),
        Command::Sign { cache_dir, key } => cmd_sign(&cache_dir, &key),
        Command::Verify {
            narinfo,
            pubkey,
            pqc_pubkey,
            require_pqc,
        } => cmd_verify(
            &narinfo,
            pubkey.as_deref(),
            pqc_pubkey.as_deref(),
            require_pqc,
        ),
        Command::Proxy {
            upstream,
            upstream_pubkey,
            key,
            listen,
            max_in_flight,
            queue_timeout_ms,
            connect_timeout_secs,
            metadata_timeout_secs,
            nar_header_timeout_secs,
            nar_idle_timeout_secs,
            max_nar_bytes,
        } => {
            let config = proxy::ProxyConfig {
                max_in_flight,
                queue_timeout: Duration::from_millis(queue_timeout_ms),
                connect_timeout: Duration::from_secs(connect_timeout_secs),
                metadata_total_timeout: Duration::from_secs(metadata_timeout_secs),
                nar_header_timeout: Duration::from_secs(nar_header_timeout_secs),
                nar_chunk_idle_timeout: Duration::from_secs(nar_idle_timeout_secs),
                max_nar_bytes,
            };
            proxy::run_with_config(upstream, upstream_pubkey, key, listen, config).await
        }
    }
}

fn cmd_keygen(name: &str, out_dir: &Path) -> Result<()> {
    keys::validate_key_name(name)?;
    std::fs::create_dir_all(out_dir)?;
    let secret = SecretKey::generate(name);
    let secret_path = out_dir.join(format!("{name}.secret"));
    let pub_path = out_dir.join(format!("{name}.pub"));
    secret.save(&secret_path)?;
    secret.public().save(&pub_path)?;
    println!("wrote {}", secret_path.display());
    println!("wrote {}", pub_path.display());
    println!(
        "ed25519 public key (base64, 32B): {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            secret.public().keys.ed25519
        )
    );
    println!(
        "ml-dsa-65 public key length: {}B",
        secret.public().keys.ml_dsa.len()
    );
    Ok(())
}

fn cmd_sign(cache_dir: &Path, key_path: &Path) -> Result<()> {
    let secret = SecretKey::load(key_path)?;
    let mut count = 0usize;
    for entry in
        std::fs::read_dir(cache_dir).with_context(|| format!("reading cache dir {cache_dir:?}"))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("narinfo") {
            continue;
        }
        let text = std::fs::read_to_string(&path)?;
        let mut info = NarInfo::parse(&text).with_context(|| format!("parsing {path:?}"))?;
        let fingerprint = info.fingerprint()?;
        let sig = secret.signer.sign(fingerprint.as_bytes());

        // Classical Sig: is signed with the SAME Ed25519 half — ordinary
        // `nix` stays fully backward compatible and needs no awareness of
        // Sig-PQC. The shared replacement helper makes repeated signing
        // idempotent across both the CLI and proxy paths.
        let ed_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.ed25519);
        info.replace_signature_pair(
            &secret.name,
            format!("{}:{}", secret.name, ed_b64),
            keys::encode_sig_pqc(&secret.name, &sig.ml_dsa),
        )?;

        keys::write_atomic_overwrite(&path, &info.to_text())?;
        count += 1;
    }
    println!(
        "dual-signed {count} narinfo file(s) in {}",
        cache_dir.display()
    );
    Ok(())
}

fn cmd_verify(
    narinfo_path: &Path,
    pubkey_b64: Option<&str>,
    pqc_pubkey_path: Option<&Path>,
    require_pqc: bool,
) -> Result<()> {
    // An empty verification policy (neither flag given) must never silently
    // report success -- automation could easily read exit code 0 as "this
    // narinfo is authenticated" when nothing was actually checked.
    if pubkey_b64.is_none() && pqc_pubkey_path.is_none() {
        bail!(
            "no verification requested: pass --pubkey and/or --pqc-pubkey \
             (verify with neither would otherwise report success without checking anything)"
        );
    }

    if require_pqc && pqc_pubkey_path.is_none() {
        bail!("--require-pqc requires --pqc-pubkey so a hybrid key is available");
    }

    let text = std::fs::read_to_string(narinfo_path)?;
    let info = NarInfo::parse(&text)?;
    let fingerprint = info.fingerprint()?;

    if let Some(pubkey_arg) = pubkey_b64 {
        let (expected_name, pubkey_b64) = keys::parse_named_pubkey(pubkey_arg);
        if expected_name.is_none() {
            eprintln!(
                "warning: --pubkey has no 'name:' prefix; matching any Sig: entry's name \
                 (not enforcing key-name identity, unlike real Nix's trusted-public-keys)"
            );
        }
        narinfo::verify_any_ed25519_sig(&fingerprint, &info.sigs, expected_name, pubkey_b64)
            .context("classical Ed25519 verification failed")?;
        println!("classical Ed25519 Sig: OK");
    }

    if let Some(pqc_pubkey_path) = pqc_pubkey_path {
        let pk = PublicKey::load(pqc_pubkey_path)?;
        // Supplying a hybrid key is an explicit verification request, not an
        // opportunistic hint: a missing or invalid Sig-PQC must fail even when
        // --require-pqc was omitted. Otherwise `verify --pqc-pubkey ...`
        // could exit 0 without authenticating anything.
        keys::verify_hybrid(&info, &fingerprint, &pk.name, &pk.keys).with_context(|| {
            format!(
                "hybrid Sig-PQC verification failed for configured key {:?}",
                pk.name
            )
        })?;
        println!("hybrid Sig-PQC (Ed25519+ML-DSA-65): OK");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use tempfile::tempdir;

    fn unsigned_info() -> NarInfo {
        NarInfo {
            store_path: "/nix/store/00000000000000000000000000000000-demo".to_string(),
            url: "nar/demo.nar".to_string(),
            compression: "none".to_string(),
            nar_hash: "sha256:0000000000000000000000000000000000000000000000000000".to_string(),
            nar_size: 1,
            ..Default::default()
        }
    }

    #[test]
    fn verify_with_pqc_key_fails_when_hybrid_signature_is_missing() {
        let dir = tempdir().unwrap();
        let narinfo_path = dir.path().join("demo.narinfo");
        let key_path = dir.path().join("demo.pub");
        let key = SecretKey::generate("demo-1");
        key.public().save(&key_path).unwrap();
        std::fs::write(&narinfo_path, unsigned_info().to_text()).unwrap();

        let err = cmd_verify(&narinfo_path, None, Some(&key_path), false).unwrap_err();
        assert!(
            err.to_string()
                .contains("hybrid Sig-PQC verification failed")
        );
    }

    #[test]
    fn require_pqc_without_a_hybrid_key_is_rejected() {
        let dir = tempdir().unwrap();
        let narinfo_path = dir.path().join("demo.narinfo");
        std::fs::write(&narinfo_path, unsigned_info().to_text()).unwrap();

        let err = cmd_verify(&narinfo_path, Some("AAAA"), None, true).unwrap_err();
        assert!(
            err.to_string()
                .contains("--require-pqc requires --pqc-pubkey")
        );
    }

    #[test]
    fn explicit_hybrid_verification_succeeds_only_with_both_halves() {
        let dir = tempdir().unwrap();
        let narinfo_path = dir.path().join("demo.narinfo");
        let key_path = dir.path().join("demo.pub");
        let key = SecretKey::generate("demo-1");
        key.public().save(&key_path).unwrap();

        let mut info = unsigned_info();
        let fingerprint = info.fingerprint().unwrap();
        let sig = key.signer.sign(fingerprint.as_bytes());
        info.sigs.push(format!(
            "demo-1:{}",
            base64::engine::general_purpose::STANDARD.encode(sig.ed25519)
        ));
        info.sig_pqc
            .push(keys::encode_sig_pqc("demo-1", &sig.ml_dsa));
        std::fs::write(&narinfo_path, info.to_text()).unwrap();

        cmd_verify(&narinfo_path, None, Some(&key_path), false).unwrap();
    }
}
