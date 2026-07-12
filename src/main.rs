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

        // Re-signing an already-signed narinfo must REPLACE this key's prior
        // entries, not accumulate duplicates alongside them -- `sign` is
        // meant to be safely re-runnable on the same cache dir.
        let prefix = format!("{}:", secret.name);
        info.sigs.retain(|s| !s.starts_with(&prefix));
        info.sig_pqc.retain(|s| !s.starts_with(&prefix));

        // Classical Sig:, signed with the SAME Ed25519 half — ordinary `nix`
        // stays fully backward compatible and needs no awareness of Sig-PQC.
        let ed_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.ed25519);
        info.sigs.push(format!("{}:{}", secret.name, ed_b64));
        info.sig_pqc
            .push(keys::encode_sig_pqc(&secret.name, &sig.ml_dsa));

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
        let ok = info.sigs.iter().any(|s| {
            narinfo::verify_ed25519_sig(&fingerprint, s, expected_name, pubkey_b64).is_ok()
        });
        if !ok {
            bail!("no Sig: line verified against the given classical public key");
        }
        println!("classical Ed25519 Sig: OK");
    }

    let mut pqc_ok = false;
    if let Some(pqc_pubkey_path) = pqc_pubkey_path {
        let pk = PublicKey::load(pqc_pubkey_path)?;
        // Uses the loaded key's OWN name as the expected keyname -- not
        // whatever name a Sig-PQC: entry happens to claim -- matching real
        // Nix's name-first trusted-key lookup rather than trusting
        // attacker-controlled narinfo text to say which key it's using.
        pqc_ok = keys::verify_hybrid(&info, &fingerprint, &pk.name, &pk.keys).is_ok();
        if pqc_ok {
            println!("hybrid Sig-PQC (Ed25519+ML-DSA-65): OK");
        } else if require_pqc || !info.sig_pqc.is_empty() {
            bail!(
                "no Sig-PQC: line verified against the given hybrid public key (name {:?})",
                pk.name
            );
        }
    }

    if require_pqc && !pqc_ok {
        bail!("--require-pqc set but no valid Sig-PQC was found");
    }

    Ok(())
}
