//! Model S ("persistent sandboxed observation service") from the
//! admission-boundary architecture comparison
//! (see docs/CANDIDATE_ARCHITECTURES.md, docs/PROCESS_VS_PROVIDER_RESULTS.md).
//!
//! A prototype, not a production daemon -- deliberately scoped, matching
//! this project's narrow-scope discipline for each new model. Reuses
//! `verify_raw_evidence()` directly, the same R -> O function
//! `nix-signature-verify-raw` (Model O-process's real verifier) uses, so
//! this is a fair transport-only comparison: identical verification
//! logic and wire shape, the only difference is that the registry is
//! loaded once at process start and each request is served over a
//! long-lived Unix-domain socket connection instead of a fresh
//! fork+exec per decision.
//!
//! Explicitly out of scope for this prototype (per the architecture
//! comparison's own Model S write-up: "daemon lifecycle/authentication/
//! caching/invalidation would each need their own real design"):
//! - No authentication beyond Unix socket file permissions (0600,
//!   owner-only) and directory placement -- a real deployment would need
//!   a real access-control story, not assumed here.
//! - No supervision/systemd integration -- run in the foreground,
//!   manually, for measurement purposes.
//! - No caching of verification results -- every request is verified
//!   fresh via the same `verify_raw_evidence()` call Model O-process
//!   makes; only process-startup cost is amortized, never a security
//!   decision (matching this project's explicit "do not build caching"
//!   stance in docs/CACHE_DECISION_QUESTIONS.md).
//! - No registry hot-reload -- the registry is loaded once at startup;
//!   changing trusted keys requires restarting the daemon (a real
//!   limitation, stated plainly, not hidden).
//!
//! Concurrency: thread-per-connection, matching the coarse-grained
//! model every other transport in this comparison uses (one OS-level
//! unit of work per admission decision) rather than introducing an
//! async runtime dependency for a prototype.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use nix_signature_policy::policy::SignatureCandidate;
use nix_signature_policy::raw_evidence::{
    RawSignatureEntry, VerificationKeyEntry, verify_raw_evidence,
};

const MAX_REQUEST_BYTES: usize = 1_048_576;

#[derive(serde::Deserialize)]
struct VerifyRawRequest {
    fingerprint: String,
    signatures: Vec<RawSignatureEntry>,
}

#[derive(serde::Serialize)]
struct VerifyRawResponse {
    candidates: Vec<SignatureCandidate>,
}

#[derive(serde::Serialize)]
struct VerifyRawErrorResponse {
    error: String,
}

#[derive(Parser, Debug)]
#[command(
    about = "Model S prototype: persistent Unix-socket R -> O verification service. See docs/CANDIDATE_ARCHITECTURES.md."
)]
struct Args {
    /// Unix-domain socket path to listen on. Must not already exist
    /// (removed if a stale socket file is found, matching common daemon
    /// practice -- a real deployment would want a lock file or
    /// liveness check first; not implemented in this prototype).
    #[arg(long)]
    socket: PathBuf,
    /// Verification-key registry, loaded once at startup. Same JSON
    /// shape as nix-signature-verify-raw's --registry.
    #[arg(long)]
    registry: PathBuf,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let registry_bytes = match fs::read(&args.registry) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("cannot read --registry '{}': {e}", args.registry.display());
            return ExitCode::from(64);
        }
    };
    let verification_keys: Vec<VerificationKeyEntry> = match serde_json::from_slice(&registry_bytes)
    {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("invalid --registry JSON: {e}");
            return ExitCode::from(64);
        }
    };
    let verification_keys = Arc::new(verification_keys);

    if args.socket.exists() {
        if let Err(e) = fs::remove_file(&args.socket) {
            eprintln!(
                "cannot remove stale socket '{}': {e}",
                args.socket.display()
            );
            return ExitCode::from(74);
        }
    }

    let listener = match UnixListener::bind(&args.socket) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("cannot bind socket '{}': {e}", args.socket.display());
            return ExitCode::from(74);
        }
    };

    // Owner-only. The socket's containing directory's own permissions
    // are the caller's responsibility -- a prototype cannot enforce
    // that its parent directory isn't world-writable.
    if let Err(e) = fs::set_permissions(&args.socket, fs::Permissions::from_mode(0o600)) {
        eprintln!("cannot set socket permissions: {e}");
        return ExitCode::from(74);
    }

    eprintln!(
        "nix-signature-verify-raw-daemon: listening on {}, {} registry keys loaded",
        args.socket.display(),
        verification_keys.len()
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let keys = Arc::clone(&verification_keys);
                std::thread::spawn(move || handle_connection(stream, &keys));
            }
            Err(e) => {
                eprintln!("accept error: {e}");
            }
        }
    }

    ExitCode::SUCCESS
}

fn handle_connection(mut stream: UnixStream, verification_keys: &[VerificationKeyEntry]) {
    let mut bytes = Vec::new();
    let read_result = (&mut stream)
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes);
    if read_result.is_err() {
        write_error(&mut stream, "failed to read request");
        return;
    }
    if bytes.len() > MAX_REQUEST_BYTES {
        write_error(&mut stream, "request too large");
        return;
    }

    let request: VerifyRawRequest = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(_) => {
            write_error(&mut stream, "invalid request JSON");
            return;
        }
    };

    let candidates = match verify_raw_evidence(
        request.fingerprint.as_bytes(),
        &request.signatures,
        verification_keys,
    ) {
        Ok(candidates) => candidates,
        Err(e) => {
            write_error(&mut stream, &format!("{e:?}"));
            return;
        }
    };

    let response = VerifyRawResponse { candidates };
    match serde_json::to_vec(&response) {
        Ok(encoded) => {
            let _ = stream.write_all(&encoded);
        }
        Err(_) => write_error(&mut stream, "failed to encode response"),
    }
}

fn write_error(stream: &mut UnixStream, message: &str) {
    let response = VerifyRawErrorResponse {
        error: message.to_string(),
    };
    if let Ok(encoded) = serde_json::to_vec(&response) {
        let _ = stream.write_all(&encoded);
    }
}
