//! Export and verify deterministic policy-decision evidence bundles.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use nix_signature_policy::conformance::load_case;
use nix_signature_policy::evidence::{
    EvidenceVerificationOptions, bundle_from_conformance_case, load_bundle, to_pretty_json,
    verify_bundle,
};
use nix_signature_policy::keys::{PublicKey, SecretKey, write_atomic_overwrite};

#[derive(Parser, Debug)]
#[command(about = "Export and verify deterministic signature-policy evidence")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Export one conformance vector as a deterministic policy evidence bundle.
    ExportVector {
        /// JSON conformance vector to normalize and evaluate.
        case: PathBuf,
        /// Destination evidence JSON file.
        #[arg(long)]
        out: PathBuf,
        /// Optional hybrid key used to attest the canonical payload digest.
        #[arg(long)]
        signing_key: Option<PathBuf>,
    },
    /// Recompute and verify one evidence bundle offline.
    Verify {
        /// Evidence JSON file to verify.
        bundle: PathBuf,
        /// Optional trusted public key. When supplied, the bundle must carry a
        /// valid attestation from exactly this key.
        #[arg(long)]
        trusted_key: Option<PathBuf>,
        /// Optional original source artifact used to check the recorded source
        /// size and SHA-256 binding.
        #[arg(long)]
        source: Option<PathBuf>,
        /// Refuse unsigned evidence even when no trusted key was supplied.
        #[arg(long)]
        require_attestation: bool,
        /// Refuse verification unless --source is supplied and matches.
        #[arg(long)]
        require_source: bool,
        /// Report encoding written to stdout.
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
    let args = Args::parse();
    match args.command {
        Command::ExportVector {
            case,
            out,
            signing_key,
        } => export_vector(&case, &out, signing_key.as_deref()),
        Command::Verify {
            bundle,
            trusted_key,
            source,
            require_attestation,
            require_source,
            format,
        } => verify_evidence(
            &bundle,
            trusted_key.as_deref(),
            source.as_deref(),
            require_attestation,
            require_source,
            format,
        ),
    }
}

fn export_vector(case_path: &Path, out: &Path, signing_key_path: Option<&Path>) -> Result<()> {
    let source_bytes =
        fs::read(case_path).with_context(|| format!("reading conformance source {case_path:?}"))?;
    let case = load_case(case_path)?;
    let signing_key = signing_key_path.map(SecretKey::load).transpose()?;
    let identifier = case_path.to_string_lossy().replace('\\', "/");
    let bundle =
        bundle_from_conformance_case(&case, identifier, &source_bytes, signing_key.as_ref())?;
    write_atomic_overwrite(out, &to_pretty_json(&bundle)?)?;
    println!("wrote {}", out.display());
    println!("payload sha256: {}", bundle.payload_sha256);
    println!(
        "attestation: {}",
        bundle
            .attestation
            .as_ref()
            .map(|attestation| attestation.key_name.as_str())
            .unwrap_or("none")
    );
    Ok(())
}

fn verify_evidence(
    bundle_path: &Path,
    trusted_key_path: Option<&Path>,
    source_path: Option<&Path>,
    require_attestation: bool,
    require_source: bool,
    format: OutputFormat,
) -> Result<()> {
    let bundle = load_bundle(bundle_path)?;
    let trusted_key = trusted_key_path.map(PublicKey::load).transpose()?;
    let source_bytes = source_path
        .map(|path| fs::read(path).with_context(|| format!("reading source artifact {path:?}")))
        .transpose()?;
    let report = verify_bundle(
        &bundle,
        EvidenceVerificationOptions {
            trusted_attestation_key: trusted_key.as_ref(),
            source_artifact: source_bytes.as_deref(),
            require_attestation,
            require_source_artifact: require_source,
        },
    );

    match format {
        OutputFormat::Pretty => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Json => println!("{}", serde_json::to_string(&report)?),
    }
    if !report.success {
        bail!("evidence verification failed");
    }
    Ok(())
}
