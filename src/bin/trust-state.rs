use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use nix_pqc_cache_proxy::integration::AuthorizationRequest;
use nix_pqc_cache_proxy::state::{
    advance_trust_state, apply_trust_state, initialize_trust_state, parse_trust_state,
    trust_state_to_pretty_json, verify_trust_state,
};

#[derive(Parser, Debug)]
#[command(about = "Manage local rollback-resistant Nix trust checkpoints")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Init {
        #[arg(long)]
        domain: String,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Advance {
        #[arg(long)]
        domain: String,
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Apply {
        #[arg(long)]
        domain: String,
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Verify {
        #[arg(long)]
        state: PathBuf,
    },
    Show {
        #[arg(long)]
        state: PathBuf,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Init {
            domain,
            request,
            out,
        } => {
            let request = read_request(&request)?;
            let state = initialize_trust_state(&domain, &request)?;
            write_atomic(&out, trust_state_to_pretty_json(&state)?.as_bytes())?;
        }
        Command::Advance {
            domain,
            state,
            request,
            out,
        } => {
            let state = read_state(&state)?;
            let request = read_request(&request)?;
            let advanced = advance_trust_state(&state, &domain, &request)?;
            write_atomic(&out, trust_state_to_pretty_json(&advanced)?.as_bytes())?;
        }
        Command::Apply {
            domain,
            state,
            request,
            out,
        } => {
            let state = read_state(&state)?;
            let mut request = read_request(&request)?;
            apply_trust_state(&state, &domain, &mut request)?;
            let mut text = serde_json::to_string_pretty(&request)?;
            text.push('\n');
            write_atomic(&out, text.as_bytes())?;
        }
        Command::Verify { state } => {
            let state = read_state(&state)?;
            verify_trust_state(&state)?;
            println!("trust state verified");
        }
        Command::Show { state } => {
            let state = read_state(&state)?;
            print!("{}", trust_state_to_pretty_json(&state)?);
        }
    }
    Ok(())
}

fn read_request(path: &Path) -> Result<AuthorizationRequest> {
    let bytes = fs::read(path).with_context(|| format!("reading request {path:?}"))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing request {path:?}"))
}

fn read_state(path: &Path) -> Result<nix_pqc_cache_proxy::state::TrustStateFile> {
    let bytes = fs::read(path).with_context(|| format!("reading trust state {path:?}"))?;
    parse_trust_state(&bytes).with_context(|| format!("parsing trust state {path:?}"))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("creating {parent:?}"))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("output path has no UTF-8 file name"))?;
    let temporary = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    if temporary == path {
        bail!("temporary output path collides with destination");
    }
    fs::write(&temporary, bytes).with_context(|| format!("writing {temporary:?}"))?;
    fs::rename(&temporary, path).with_context(|| format!("renaming {temporary:?} to {path:?}"))?;
    Ok(())
}
