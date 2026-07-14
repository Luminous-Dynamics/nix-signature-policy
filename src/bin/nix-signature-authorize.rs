use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use nix_signature_policy::protocol::{
    MAX_AUTHORIZATION_REQUEST_BYTES, ProtocolErrorCode, ProtocolErrorResponse,
    authorization_exit_code, decode_and_authorize, encode_authorization_response,
    encode_protocol_error,
};

#[derive(Parser, Debug)]
#[command(about = "Evaluate one bounded normalized Nix signature-authorization request")]
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
    let request = match read_bounded(args.request.as_deref()) {
        Ok(bytes) => bytes,
        Err(error) => {
            let _ = io::stdout().write_all(&encode_protocol_error(&error, args.pretty));
            return ExitCode::from(64);
        }
    };

    let response = match decode_and_authorize(&request) {
        Ok(response) => response,
        Err(error) => {
            let _ = io::stdout().write_all(&encode_protocol_error(&error, args.pretty));
            return ExitCode::from(64);
        }
    };
    let exit = authorization_exit_code(&response);
    match encode_authorization_response(&response, args.pretty) {
        Ok(encoded) => {
            if io::stdout().write_all(&encoded).is_err() {
                return ExitCode::from(74);
            }
            ExitCode::from(exit)
        }
        Err(error) => {
            let _ = io::stdout().write_all(&encode_protocol_error(&error, args.pretty));
            ExitCode::from(70)
        }
    }
}

fn read_bounded(path: Option<&Path>) -> Result<Vec<u8>, ProtocolErrorResponse> {
    let mut bytes = Vec::new();
    match path {
        Some(path) => {
            if fs::metadata(path)
                .map(|metadata| metadata.len() > MAX_AUTHORIZATION_REQUEST_BYTES as u64)
                .unwrap_or(false)
            {
                return Err(request_too_large());
            }
            let file = fs::File::open(path).map_err(|_| invalid_request())?;
            file.take((MAX_AUTHORIZATION_REQUEST_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| invalid_request())?;
        }
        None => {
            io::stdin()
                .take((MAX_AUTHORIZATION_REQUEST_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| invalid_request())?;
        }
    }
    if bytes.len() > MAX_AUTHORIZATION_REQUEST_BYTES {
        return Err(request_too_large());
    }
    Ok(bytes)
}

fn request_too_large() -> ProtocolErrorResponse {
    ProtocolErrorResponse::new(ProtocolErrorCode::RequestTooLarge)
}

fn invalid_request() -> ProtocolErrorResponse {
    ProtocolErrorResponse::new(ProtocolErrorCode::InvalidRequestJson)
}
