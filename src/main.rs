use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use nix_pqc_cache_proxy::keys::{self, PublicKey, SecretKey};
use nix_pqc_cache_proxy::narinfo::{self, NarInfo};
use nix_pqc_cache_proxy::proxy;

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
    /// Generate a hybrid Ed25519+ML-DSA-65 signing key: writes <name>.secret and <name>.pub
    Keygen {
        /// Key name, e.g. "my-cache-1" (mirrors Nix's "<hostname>-N" convention)
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
        /// Path to a .pub file (from keygen) to check Sig-PQC: lines against
        #[arg(long)]
        pqc_pubkey: Option<PathBuf>,
        /// Fail if no valid Sig-PQC is found, even if the classical Sig is fine
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
        } => proxy::run(upstream, upstream_pubkey, key, listen).await,
    }
}

fn cmd_keygen(name: &str, out_dir: &Path) -> Result<()> {
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

        // Classical Sig:, signed with the SAME Ed25519 half — ordinary `nix`
        // stays fully backward compatible and needs no awareness of Sig-PQC.
        let ed_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.ed25519);
        info.sigs.push(format!("{}:{}", secret.name, ed_b64));
        info.sig_pqc
            .push(keys::encode_sig_pqc(&secret.name, &sig.ml_dsa));

        std::fs::write(&path, info.to_text())?;
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
    let text = std::fs::read_to_string(narinfo_path)?;
    let info = NarInfo::parse(&text)?;
    let fingerprint = info.fingerprint()?;

    if let Some(pubkey_b64) = pubkey_b64 {
        let pubkey_b64 = keys::strip_key_name(pubkey_b64);
        let ok = info
            .sigs
            .iter()
            .any(|s| narinfo::verify_ed25519_sig(&fingerprint, s, pubkey_b64).is_ok());
        if !ok {
            bail!("no Sig: line verified against the given classical public key");
        }
        println!("classical Ed25519 Sig: OK");
    }

    let mut pqc_ok = false;
    if let Some(pqc_pubkey_path) = pqc_pubkey_path {
        let pk = PublicKey::load(pqc_pubkey_path)?;
        for entry in &info.sig_pqc {
            // A malformed or unrecognized-algorithm entry is a failed
            // candidate, not a reason to abort checking the rest of the
            // list -- one bad Sig-PQC line must never block a different,
            // valid one elsewhere in the same narinfo.
            let name = match keys::decode_sig_pqc(entry) {
                Ok((name, _algorithm, _ml_dsa)) => name,
                Err(_) => continue,
            };
            if keys::verify_hybrid(&info, &fingerprint, &name, &pk.keys).is_ok() {
                pqc_ok = true;
                break;
            }
        }
        if pqc_ok {
            println!("hybrid Sig-PQC (Ed25519+ML-DSA-65): OK");
        } else if require_pqc || !info.sig_pqc.is_empty() {
            bail!("no Sig-PQC: line verified against the given hybrid public key");
        }
    }

    if require_pqc && !pqc_ok {
        bail!("--require-pqc set but no valid Sig-PQC was found");
    }

    Ok(())
}
