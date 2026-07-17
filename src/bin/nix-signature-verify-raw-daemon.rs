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
//!
//! Wire framing: newline-delimited JSON (one request per line, one
//! response per line), so a single connection can serve many
//! sequential requests -- added specifically so the Nix-side caller
//! can cache and reuse a connection across a closure's multiple
//! admission decisions instead of connecting fresh per decision (see
//! docs/PROCESS_VS_PROVIDER_RESULTS.md's "Model S prototype" section
//! for why the original connect-per-decision design didn't amortize
//! as well as hoped). Safe with compact JSON output, which always
//! escapes literal newline bytes inside string values as `\n` (two
//! characters), never emits one raw. Not a robustness feature: an
//! oversized or malformed line is treated the same as any other
//! failure (connection closed), and a single very long line is read
//! in full before that check runs, bounded only by available memory
//! -- an accepted limitation given this is a local, same-user Unix
//! socket (0600), matching every other model's trust boundary in this
//! comparison, not a service exposed to untrusted peers.

use std::fs;
use std::io::{BufRead, BufReader, Write};
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

/// Batch variant added to test the batching hypothesis directly (see
/// docs/PROCESS_VS_PROVIDER_RESULTS.md's Model S connection-reuse
/// correction): does amortizing *decisions per round trip* -- not
/// process-per-decision (O-process) or even connection-per-decision
/// (Model S's original design) -- actually eliminate the per-decision
/// floor found there? One request line carries every decision a
/// closure needs; one response line carries every result, in the same
/// order. Distinguished from the single-decision `VerifyRawRequest` by
/// its `decisions` field (untagged enum, tried in declaration order).
#[derive(serde::Deserialize)]
struct VerifyRawBatchRequest {
    decisions: Vec<VerifyRawRequest>,
}

#[derive(serde::Serialize)]
struct VerifyRawBatchResponse {
    results: Vec<VerifyRawResponse>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum IncomingRequest {
    Batch(VerifyRawBatchRequest),
    Single(VerifyRawRequest),
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

    let connection_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let keys = Arc::clone(&verification_keys);
                let n = connection_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                eprintln!("accepted connection #{n}");
                std::thread::spawn(move || handle_connection(stream, &keys));
            }
            Err(e) => {
                eprintln!("accept error: {e}");
            }
        }
    }

    ExitCode::SUCCESS
}

fn handle_connection(stream: UnixStream, verification_keys: &[VerificationKeyEntry]) {
    let read_half = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            // EOF: the client closed its write side (or the whole
            // connection). Normal end of a session, not an error.
            Ok(0) => return,
            Ok(_) => {}
            Err(_) => return,
        }
        let trimmed = line.trim_end_matches('\n');
        if trimmed.len() > MAX_REQUEST_BYTES {
            write_error_line(&mut writer, "request too large");
            return;
        }

        let incoming: IncomingRequest = match serde_json::from_str(trimmed) {
            Ok(request) => request,
            Err(_) => {
                write_error_line(&mut writer, "invalid request JSON");
                return;
            }
        };

        let encoded = match incoming {
            IncomingRequest::Single(request) => {
                let candidates = match verify_one(&request, verification_keys) {
                    Ok(candidates) => candidates,
                    Err(e) => {
                        write_error_line(&mut writer, &e);
                        return;
                    }
                };
                serde_json::to_vec(&VerifyRawResponse { candidates })
            }
            IncomingRequest::Batch(batch) => {
                let mut results = Vec::with_capacity(batch.decisions.len());
                let mut failed = false;
                for decision in &batch.decisions {
                    match verify_one(decision, verification_keys) {
                        Ok(candidates) => results.push(VerifyRawResponse { candidates }),
                        Err(_) => {
                            failed = true;
                            break;
                        }
                    }
                }
                if failed {
                    write_error_line(&mut writer, "one or more decisions in the batch failed");
                    return;
                }
                serde_json::to_vec(&VerifyRawBatchResponse { results })
            }
        };

        match encoded {
            Ok(mut encoded) => {
                encoded.push(b'\n');
                if writer.write_all(&encoded).is_err() {
                    return;
                }
            }
            Err(_) => {
                write_error_line(&mut writer, "failed to encode response");
                return;
            }
        }
        // Loop back and read the next request on this same connection.
    }
}

/// Verify one decision's evidence against the loaded registry. Shared by
/// both the single-decision and batch paths so they run through
/// identical logic -- the only difference between them is how many
/// times this is called per request line and how the results are framed
/// back to the caller.
fn verify_one(
    request: &VerifyRawRequest,
    verification_keys: &[VerificationKeyEntry],
) -> Result<Vec<SignatureCandidate>, String> {
    verify_raw_evidence(
        request.fingerprint.as_bytes(),
        &request.signatures,
        verification_keys,
    )
    .map_err(|e| format!("{e:?}"))
}

fn write_error_line(stream: &mut UnixStream, message: &str) {
    let response = VerifyRawErrorResponse {
        error: message.to_string(),
    };
    if let Ok(mut encoded) = serde_json::to_vec(&response) {
        encoded.push(b'\n');
        let _ = stream.write_all(&encoded);
    }
}
