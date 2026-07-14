//! Run the representation-neutral policy conformance vectors.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use nix_pqc_cache_proxy::conformance::run_directory;

#[derive(Parser, Debug)]
#[command(about = "Run adversarial signature-policy conformance vectors")]
struct Args {
    /// Root directory containing JSON vectors.
    #[arg(long, default_value = "policy-vectors")]
    vectors: PathBuf,

    /// Report encoding written to stdout.
    #[arg(long, value_enum, default_value_t = OutputFormat::Pretty)]
    format: OutputFormat,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Pretty,
    Json,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let report = run_directory(&args.vectors)?;
    match args.format {
        OutputFormat::Pretty => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Json => println!("{}", serde_json::to_string(&report)?),
    }
    if !report.is_success() {
        std::process::exit(1);
    }
    Ok(())
}
