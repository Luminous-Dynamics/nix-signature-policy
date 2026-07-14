use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nix_pqc_cache_proxy::integration::AuthorizationRequest;
use nix_pqc_cache_proxy::receipt::{
    ReceiptArtifact, build_trust_receipt, explain_trust_receipt, parse_trust_receipt,
    to_pretty_json, verify_trust_receipt,
};

#[derive(Parser)]
#[command(about = "Create, verify, and explain compact Nix trust receipts")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Create {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        artifact_id: String,
        #[arg(long)]
        canonical_fingerprint_sha256: String,
        #[arg(long)]
        nar_hash: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    Verify {
        #[arg(long)]
        receipt: PathBuf,
    },
    Explain {
        #[arg(long)]
        receipt: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Create {
            request,
            artifact_id,
            canonical_fingerprint_sha256,
            nar_hash,
            output,
        } => {
            let bytes = fs::read(&request)
                .with_context(|| format!("reading authorization request {request:?}"))?;
            let request: AuthorizationRequest = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing authorization request {request:?}"))?;
            let receipt = build_trust_receipt(
                &request,
                ReceiptArtifact {
                    identifier: artifact_id,
                    canonical_fingerprint_sha256,
                    nar_hash,
                },
            )?;
            fs::write(&output, to_pretty_json(&receipt)?)
                .with_context(|| format!("writing trust receipt {output:?}"))?;
            println!("{}", receipt.payload_sha256);
        }
        Command::Verify { receipt } => {
            let bytes =
                fs::read(&receipt).with_context(|| format!("reading trust receipt {receipt:?}"))?;
            let receipt = parse_trust_receipt(&bytes)?;
            verify_trust_receipt(&receipt)?;
            println!("valid trust receipt: {}", receipt.payload_sha256);
        }
        Command::Explain { receipt } => {
            let bytes =
                fs::read(&receipt).with_context(|| format!("reading trust receipt {receipt:?}"))?;
            let receipt = parse_trust_receipt(&bytes)?;
            println!("{}", explain_trust_receipt(&receipt)?);
        }
    }
    Ok(())
}
