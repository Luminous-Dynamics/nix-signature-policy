//! Create and verify hybrid attestations over deterministic release statements.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use nix_pqc_cache_proxy::artifact_attestation::{
    attest_artifact, load_bundle, to_pretty_json, verify_artifact_attestation,
};
use nix_pqc_cache_proxy::keys::{PublicKey, SecretKey, write_atomic_overwrite};

#[derive(Parser, Debug)]
#[command(about = "Create or verify an Ed25519+ML-DSA-65 artifact attestation")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Attest one release statement with a named hybrid signing key.
    Attest {
        artifact: PathBuf,
        #[arg(long)]
        identifier: Option<String>,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify the artifact binding and hybrid signature against a trusted key.
    Verify {
        artifact: PathBuf,
        attestation: PathBuf,
        #[arg(long)]
        trusted_key: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Pretty)]
        format: OutputFormat,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Pretty,
    Json,
}

fn main() -> Result<()> {
    match Args::parse().command {
        Command::Attest {
            artifact,
            identifier,
            key,
            out,
        } => attest(&artifact, identifier, &key, &out),
        Command::Verify {
            artifact,
            attestation,
            trusted_key,
            format,
        } => verify(&artifact, &attestation, &trusted_key, format),
    }
}

fn attest(artifact: &Path, identifier: Option<String>, key_path: &Path, out: &Path) -> Result<()> {
    let key = SecretKey::load(key_path)?;
    let identifier = identifier.unwrap_or_else(|| {
        artifact
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("artifact")
            .to_string()
    });
    let bundle = attest_artifact(artifact, identifier, &key)?;
    write_atomic_overwrite(out, &to_pretty_json(&bundle)?)?;
    println!("wrote {}", out.display());
    println!("payload sha256: {}", bundle.payload_sha256);
    println!("attestation key: {}", bundle.attestation.key_name);
    Ok(())
}

fn verify(
    artifact: &Path,
    attestation_path: &Path,
    trusted_key_path: &Path,
    format: OutputFormat,
) -> Result<()> {
    let bundle = load_bundle(attestation_path)?;
    let trusted_key = PublicKey::load(trusted_key_path)?;
    let report = verify_artifact_attestation(artifact, &bundle, &trusted_key);
    match format {
        OutputFormat::Pretty => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Json => println!("{}", serde_json::to_string(&report)?),
    }
    if !report.success {
        bail!("artifact attestation verification failed");
    }
    Ok(())
}
