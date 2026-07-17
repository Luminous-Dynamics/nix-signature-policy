//! Model O ("external verifier returns O; Nix owns native narrow policy")
//! from the admission-boundary architecture comparison
//! (see nix-authorization-boundary-experiments-*/measurement/).
//!
//! Deliberately narrower than `nix-signature-authorize-raw`: this binary
//! performs *only* R -> O, raw signature verification with no policy
//! evaluation at all -- reusing `verify_raw_evidence()` directly, the
//! same function the raw-evidence adapter uses for the R -> O half of its
//! own pipeline. It never constructs a `SignaturePolicy` or
//! `TrustRegistry`, and never calls `core-v1`'s `authorize()`. The
//! caller (Nix itself, for Model O) is responsible for evaluating policy
//! over the returned observations.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

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
    verification_keys: Vec<VerificationKeyEntry>,
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
    about = "R -> O only: verify raw narinfo Sig: entries against a verification-key registry and emit observations. No policy is evaluated. See measurement/ in the admission-boundary comparison."
)]
struct Args {
    /// Read the request from this file instead of standard input.
    #[arg(long)]
    request: Option<PathBuf>,
    /// Emit indented JSON rather than compact JSON.
    #[arg(long)]
    pretty: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let bytes = match read_bounded(args.request.as_deref()) {
        Ok(bytes) => bytes,
        Err(message) => return fail(&message, args.pretty),
    };

    let request: VerifyRawRequest = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(_) => return fail("invalid request JSON", args.pretty),
    };

    let candidates = match verify_raw_evidence(
        request.fingerprint.as_bytes(),
        &request.signatures,
        &request.verification_keys,
    ) {
        Ok(candidates) => candidates,
        Err(error) => return fail(&format!("{error:?}"), args.pretty),
    };

    let response = VerifyRawResponse { candidates };
    let encoded = if args.pretty {
        serde_json::to_vec_pretty(&response)
    } else {
        serde_json::to_vec(&response)
    };
    match encoded {
        Ok(encoded) => {
            if io::stdout().write_all(&encoded).is_err() {
                return ExitCode::from(74);
            }
            ExitCode::SUCCESS
        }
        Err(_) => fail("failed to encode response", args.pretty),
    }
}

fn fail(message: &str, pretty: bool) -> ExitCode {
    let response = VerifyRawErrorResponse {
        error: message.to_string(),
    };
    let encoded = if pretty {
        serde_json::to_vec_pretty(&response)
    } else {
        serde_json::to_vec(&response)
    }
    .unwrap_or_else(|_| b"{\"error\":\"internal error encoding error response\"}".to_vec());
    let _ = io::stdout().write_all(&encoded);
    ExitCode::from(64)
}

fn read_bounded(path: Option<&Path>) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    match path {
        Some(path) => {
            if fs::metadata(path)
                .map(|metadata| metadata.len() > MAX_REQUEST_BYTES as u64)
                .unwrap_or(false)
            {
                return Err("request too large".to_string());
            }
            let file = fs::File::open(path).map_err(|_| "cannot open request file".to_string())?;
            file.take((MAX_REQUEST_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| "failed to read request file".to_string())?;
        }
        None => {
            io::stdin()
                .take((MAX_REQUEST_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| "failed to read stdin".to_string())?;
        }
    }
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err("request too large".to_string());
    }
    Ok(bytes)
}
