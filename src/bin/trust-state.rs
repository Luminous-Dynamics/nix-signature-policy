use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nix_signature_policy::atomic_file::{CommitMode, write_via_temp};
use nix_signature_policy::integration::AuthorizationRequest;
use nix_signature_policy::state::{
    advance_trust_state, apply_trust_state, initialize_trust_state, parse_trust_state,
    trust_state_to_pretty_json, verify_trust_state,
};

/// Trust-state files aren't secret, but they are integrity-critical
/// rollback-resistance checkpoints -- an explicit mode is set rather
/// than inheriting whatever the process umask happens to produce.
const TRUST_STATE_FILE_MODE: u32 = 0o644;

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
            // A checkpoint is a new rollback-chain root -- never allowed
            // to silently replace whatever (if anything) is already at
            // `out`. See the module-level note on write_checkpoint().
            write_checkpoint(&out, trust_state_to_pretty_json(&state)?.as_bytes())?;
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
            // Same reasoning as Init: two concurrent `advance` invocations
            // both starting from the same checkpoint must not be able to
            // race to the same `out` path and have the last rename win,
            // silently discarding one advance. Committing via CreateNew
            // makes the second writer fail loudly instead.
            write_checkpoint(&out, trust_state_to_pretty_json(&advanced)?.as_bytes())?;
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
            // Unlike a checkpoint, a guarded request is a disposable,
            // per-invocation output that doesn't feed the rollback
            // chain -- intentional overwrite (e.g. re-running the same
            // apply) is fine here.
            write_via_temp(
                &out,
                text.as_bytes(),
                TRUST_STATE_FILE_MODE,
                CommitMode::Replace,
            )?;
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

fn read_state(path: &Path) -> Result<nix_signature_policy::state::TrustStateFile> {
    let bytes = fs::read(path).with_context(|| format!("reading trust state {path:?}"))?;
    parse_trust_state(&bytes).with_context(|| format!("parsing trust state {path:?}"))
}

/// Commit a new rollback-chain checkpoint (`init`/`advance`'s `--out`).
/// Uses `CommitMode::CreateNew`: the commit fails, atomically, if `out`
/// already exists, rather than silently replacing it. This is the fix
/// for a review-found race -- a prior version of this file's local
/// `write_atomic()` always used rename-style replacement, so two
/// concurrent `advance` invocations reading the same starting state
/// could both compute a next checkpoint and both write it to the same
/// `out` path, with the last rename silently winning and the other
/// advance's result vanishing with no error. A checkpoint file is not a
/// disposable scratch output like `apply`'s guarded request -- it feeds
/// future `advance`/`apply` calls, so losing one silently is exactly the
/// rollback-resistance property this tool exists to protect.
fn write_checkpoint(path: &Path, bytes: &[u8]) -> Result<()> {
    write_via_temp(path, bytes, TRUST_STATE_FILE_MODE, CommitMode::CreateNew)
}
