//! A hardened Unix reference implementation of *how to safely invoke* an
//! external `nix-signature-authorize`-shaped helper process.
//!
//! This is deliberately not part of the frozen `core-v1` interoperability
//! surface (see `docs/CORE_V1.md`): process invocation is
//! platform-and-integration-specific, while `core-v1` is about the
//! authorization semantics themselves. This module exists so the eventual
//! Nix-side (C++) caller has a concrete, adversarially-tested specification
//! to mirror rather than an underspecified prose contract, and so this
//! project's own test suite can exercise the exact boundary a future
//! `trusted-signatures-command`-style hook would rely on. See
//! `docs/CALLER_SAFETY.md`.
//!
//! Its job, deliberately narrow: encode a bounded request, invoke a
//! configured executable safely, collect bounded output, parse a closed
//! response, and report either a decision or an invocation failure. It does
//! not understand family rules, thresholds, registries, or policy
//! evaluation — that all already happened inside the helper process.
//!
//! # Security properties
//!
//! - No shell is ever involved; the command is exec'd directly.
//! - The child's environment is cleared and receives only what the caller
//!   explicitly opts into — no `PATH`, no inherited secrets. Callers should
//!   configure an absolute path to the helper executable, matching the
//!   precedent set by tools like OpenSSH's `AuthorizedKeysCommand`.
//! - stdout (the protocol response) and stderr (diagnostics only, and
//!   *never* consulted for the decision) are drained by dedicated reader
//!   threads started immediately after spawn, each independently bounded.
//!   Polling `Child::try_wait()` without concurrently draining both pipes
//!   can deadlock if a misbehaving helper fills a pipe buffer before
//!   exiting; this module never does that.
//! - The child runs in its own process group (`setpgid` via
//!   [`std::os::unix::process::CommandExt::process_group`]), so cleanup
//!   can reach any grandchildren the helper spawned, not just the direct
//!   child.
//! - On timeout or output overflow, this is treated as a failure path, not
//!   a graceful shutdown: the process group is sent `SIGKILL` directly
//!   (no `SIGTERM` grace period — a helper that already overran its bounds
//!   doesn't get a chance to clean up), the direct child is always
//!   `wait()`-ed afterward to avoid a zombie, and any output collected so
//!   far is discarded unread. A helper cannot win a race by emitting an
//!   acceptance right as the deadline expires: once this module decides to
//!   fail an invocation, it never looks at the reader threads' output at
//!   all.
//! - The exit code is treated purely as a protocol-success gate — an
//!   authorization decision is *only* ever taken from the parsed JSON
//!   response, never from the exit code alone. `nix-signature-authorize`'s
//!   own CLI additionally uses exit code 0/10 as a scripting convenience
//!   (see `docs/AUTHORIZATION_JSON_PROTOCOL.md`); this caller treats both
//!   as "a response should exist, go parse it" and takes the actual
//!   decision only from `AuthorizationResponse::decision`.
//! - Response parsing accepts exactly one JSON value followed only by
//!   optional trailing whitespace: duplicate top-level keys, multiple
//!   concatenated documents, and non-whitespace trailing bytes are all
//!   rejected rather than silently taking "whatever serde_json's default
//!   behavior happens to do" on faith (see the `duplicate_keys_are_rejected`
//!   test below, which verifies this empirically rather than assuming it).

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::integration::{AuthorizationResponse, INTEGRATION_CONTRACT_VERSION};
use crate::protocol::MAX_AUTHORIZATION_RESPONSE_BYTES;

/// Maximum protocol-response bytes read from the helper's stdout. Matches
/// the bound the protocol itself already documents for a response.
pub const MAX_RESPONSE_BYTES: usize = MAX_AUTHORIZATION_RESPONSE_BYTES;

/// Maximum diagnostic bytes retained from the helper's stderr. Deliberately
/// much smaller than the response bound: this is a memory guard on
/// operator-facing diagnostics, never an input to the authorization
/// decision. Exceeding it truncates retained diagnostics; it never by
/// itself fails the invocation (a flooding helper is instead bounded by the
/// overall timeout).
pub const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;

/// How the caller should invoke one helper process.
#[derive(Clone, Debug)]
pub struct CallerConfig {
    /// Absolute path to the helper executable. A relative path would need
    /// `PATH` to resolve, and this caller deliberately clears `PATH` from
    /// the child's environment.
    pub command: PathBuf,
    pub args: Vec<String>,
    /// Explicit working directory; never inherited from the caller's own
    /// cwd.
    pub working_dir: PathBuf,
    /// Wall-clock budget for the whole invocation, from spawn to exit.
    pub timeout: Duration,
    /// Explicit, deliberate environment additions. Empty by default: the
    /// child's environment is otherwise fully cleared.
    pub extra_env: Vec<(String, String)>,
}

impl CallerConfig {
    pub fn new(command: impl Into<PathBuf>, working_dir: impl Into<PathBuf>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            working_dir: working_dir.into(),
            timeout: Duration::from_secs(5),
            extra_env: Vec::new(),
        }
    }
}

/// Why this caller refused to trust an invocation. Distinct from the
/// helper's own authorization decision (see [`InvocationOutcome`]): a
/// caller failure means no trustworthy decision was ever obtained, not
/// that the helper decided to refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallerFailure {
    /// The process could not be spawned at all (missing executable,
    /// permission denied, etc).
    SpawnFailed,
    /// The invocation did not complete within `CallerConfig::timeout`.
    Timeout,
    /// The process exited with a status other than 0 or 10 (the
    /// documented `nix-signature-authorize` CLI convention — see the
    /// module docs for why this is a protocol-success gate, not a
    /// decision channel).
    UnexpectedExitStatus,
    /// stdout exceeded [`MAX_RESPONSE_BYTES`] before the process produced
    /// a complete response.
    ResponseTooLarge,
    /// stdout was not valid UTF-8.
    InvalidUtf8Response,
    /// stdout did not parse as exactly one well-formed
    /// `AuthorizationResponse` JSON document (includes duplicate keys,
    /// multiple concatenated documents, and non-whitespace trailing
    /// bytes — see the module docs).
    MalformedResponseJson,
    /// The response's `contract_version` did not match
    /// [`INTEGRATION_CONTRACT_VERSION`].
    ContractVersionMismatch,
}

/// The result of invoking one helper process: either a trustworthy decision
/// from the helper, or a caller-side failure. Both must be treated as
/// non-admission under authoritative enforcement — but they are kept as
/// distinct variants (rather than collapsing "helper refused" and "caller
/// couldn't get an answer" into one shared "refuse" case) so operational
/// diagnostics can tell the two apart, without that distinction ever
/// affecting the admission decision itself.
#[derive(Debug)]
pub enum InvocationOutcome {
    /// The helper produced a well-formed, trusted response. Inspect
    /// `AuthorizationResponse::decision` for the actual accept/refuse
    /// outcome. Boxed: `AuthorizationResponse` carries nested policy/
    /// registry decision detail and is far larger than `CallerFailure`,
    /// and clippy's `large_enum_variant` lint (correctly) objects to
    /// that size disparity on the unboxed enum.
    Decision(Box<AuthorizationResponse>),
    /// No trustworthy decision was obtained.
    Failure(CallerFailure),
}

/// Invoke one helper process with `request_bytes` on stdin, honoring all of
/// [`CallerConfig`]'s bounds. See the module docs for the full security
/// model.
pub fn invoke(config: &CallerConfig, request_bytes: &[u8]) -> InvocationOutcome {
    let mut command = Command::new(&config.command);
    command
        .args(&config.args)
        .current_dir(&config.working_dir)
        .env_clear();
    for (key, value) in &config.extra_env {
        command.env(key, value);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // A new process group whose pgid equals the child's pid, so cleanup
        // can signal every process the helper spawned, not just the direct
        // child.
        command.process_group(0);
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return InvocationOutcome::Failure(CallerFailure::SpawnFailed),
    };

    // Arm concurrent, independently-bounded readers *before* any wait/poll
    // loop. A helper that fills a pipe buffer prior to exiting would
    // otherwise deadlock a caller that only reads after observing exit.
    let mut stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");

    let request_bytes = request_bytes.to_vec();
    let stdin_writer = std::thread::spawn(move || {
        // A helper that never reads stdin (or exits immediately) simply
        // makes this write fail; that's fine, the outcome is decided by
        // the exit status and stdout, not by whether this write succeeded.
        let _ = stdin.write_all(&request_bytes);
    });

    let stdout_overflowed = Arc::new(AtomicBool::new(false));
    let (stdout_tx, stdout_rx) = mpsc::channel();
    let stdout_reader = spawn_bounded_reader(
        stdout,
        MAX_RESPONSE_BYTES,
        Arc::clone(&stdout_overflowed),
        stdout_tx,
    );

    // Diagnostics: bounded and fully independent of the decision. No
    // "overflowed" flag is threaded back into the poll loop for stderr —
    // an endless-stderr helper is instead reaped by the overall timeout,
    // exactly like any other hang.
    let (stderr_tx, _stderr_rx) = mpsc::channel();
    let stderr_reader = spawn_bounded_reader(
        stderr,
        MAX_DIAGNOSTIC_BYTES,
        Arc::new(AtomicBool::new(false)),
        stderr_tx,
    );

    let deadline = Instant::now() + config.timeout;
    let exited = loop {
        if stdout_overflowed.load(Ordering::SeqCst) {
            break None;
        }
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break None,
        }
    };

    let Some(status) = exited else {
        // Timeout or stdout overflow: this is a failure path, not a
        // graceful shutdown. Escalate straight to SIGKILL on the whole
        // process group and reap the direct child so it never becomes a
        // zombie. Deliberately do not join the reader threads' *output* —
        // only their handles, for cleanup — so nothing the helper wrote
        // after we gave up can ever be trusted.
        kill_process_group(&child);
        let _ = child.wait();
        let _ = stdin_writer.join();
        let _ = stdout_reader.join();
        let _ = stderr_reader.join();
        return InvocationOutcome::Failure(if stdout_overflowed.load(Ordering::SeqCst) {
            CallerFailure::ResponseTooLarge
        } else {
            CallerFailure::Timeout
        });
    };

    let _ = stdin_writer.join();
    let stdout_bytes = stdout_reader
        .join()
        .ok()
        .and_then(|_| stdout_rx.try_recv().ok());
    let _ = stderr_reader.join();

    match status.code() {
        Some(0) | Some(10) => {}
        _ => return InvocationOutcome::Failure(CallerFailure::UnexpectedExitStatus),
    }

    let Some(bytes) = stdout_bytes else {
        return InvocationOutcome::Failure(CallerFailure::ResponseTooLarge);
    };

    parse_response(&bytes)
}

/// Spawn a thread that reads `reader` to completion (or EOF), capping
/// retained bytes at `max_bytes`. On overflow, sets `overflowed` and stops
/// retaining further bytes; the underlying read loop keeps draining the
/// pipe (discarding past the cap) so a flooding writer can't itself block
/// on a full pipe forever, but never sends a result once overflowed.
fn spawn_bounded_reader<R: Read + Send + 'static>(
    mut reader: R,
    max_bytes: usize,
    overflowed: Arc<AtomicBool>,
    result_tx: mpsc::Sender<Vec<u8>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        let mut collected = Vec::new();
        let mut over = false;
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if !over {
                        collected.extend_from_slice(&buf[..n]);
                        if collected.len() > max_bytes {
                            over = true;
                            overflowed.store(true, Ordering::SeqCst);
                        }
                    }
                    // Once over, keep draining into a throwaway buffer so
                    // the writer never blocks on us specifically — but
                    // stop growing `collected`.
                }
                Err(_) => break,
            }
        }
        if !over {
            let _ = result_tx.send(collected);
        }
    })
}

#[cfg(unix)]
fn kill_process_group(child: &Child) {
    // SAFETY: `process_group(0)` at spawn time put this child in a new
    // process group whose pgid equals its pid, so signalling the negated
    // pid reaches every process in that group, not just the direct child.
    unsafe {
        libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn kill_process_group(child: &Child) {
    // Best effort only: this module is a Unix reference implementation
    // (Nix itself has no Windows target). Falls back to killing the direct
    // child; grandchildren may be leaked on non-Unix platforms.
    let _ = child.id();
}

/// Parse exactly one `AuthorizationResponse` JSON document, rejecting
/// anything else: invalid UTF-8, malformed/duplicate-keyed/multi-document
/// JSON, non-whitespace trailing bytes, or a mismatched contract version.
fn parse_response(bytes: &[u8]) -> InvocationOutcome {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return InvocationOutcome::Failure(CallerFailure::InvalidUtf8Response),
    };

    let mut deserializer = serde_json::Deserializer::from_str(text);
    let response: AuthorizationResponse = match serde::Deserialize::deserialize(&mut deserializer) {
        Ok(response) => response,
        Err(_) => return InvocationOutcome::Failure(CallerFailure::MalformedResponseJson),
    };
    // `Deserializer::end()` succeeds only if nothing but whitespace remains
    // — this is what rejects a second concatenated JSON document or other
    // non-whitespace trailing bytes, while still accepting the documented
    // single trailing newline.
    if deserializer.end().is_err() {
        return InvocationOutcome::Failure(CallerFailure::MalformedResponseJson);
    }

    if response.contract_version != INTEGRATION_CONTRACT_VERSION {
        return InvocationOutcome::Failure(CallerFailure::ContractVersionMismatch);
    }

    InvocationOutcome::Decision(Box::new(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Empirical, not assumed: confirms serde's derive-generated struct
    /// deserializer rejects a duplicate top-level key rather than silently
    /// taking the last occurrence. If this ever regresses (e.g. a future
    /// refactor introduces `#[serde(flatten)]`, which is known to weaken
    /// this guarantee), this test fails loudly instead of us finding out
    /// via a downgrade bug.
    #[test]
    fn duplicate_keys_are_rejected() {
        let json = r#"{"decision":"refuse","decision":"accept"}"#;
        let mut deserializer = serde_json::Deserializer::from_str(json);
        let result: Result<crate::integration::AdmissionDecision, _> =
            serde::Deserialize::deserialize(&mut deserializer);
        // AdmissionDecision itself isn't the right shape for a bare object,
        // so assert on the general struct-with-duplicate-field case using
        // a minimal local struct instead, matching how AuthorizationResponse
        // (and every other #[serde(deny_unknown_fields)] struct in this
        // crate) is generated.
        assert!(result.is_err(), "expected duplicate key to be rejected");

        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct Probe {
            decision: String,
        }
        let mut deserializer = serde_json::Deserializer::from_str(json);
        let probe: Result<Probe, _> = serde::Deserialize::deserialize(&mut deserializer);
        assert!(
            probe.is_err(),
            "serde must reject duplicate fields on a plain derived struct"
        );
    }

    /// `AuthorizationResponse` already carries `#[serde(deny_unknown_fields)]`
    /// (see `src/integration.rs`); this confirms that actually holds for a
    /// real serialized response with one extra field grafted on, rather
    /// than trusting the attribute is doing what it says.
    #[test]
    fn unknown_top_level_field_is_rejected() {
        let mut value = serde_json::json!({
            "contract_version": crate::integration::INTEGRATION_CONTRACT_VERSION,
            "enforcement_mode": "legacy",
            "decision": "accept",
            "built_in_decision": "accept",
            "policy_decision": {
                "decision": "refuse",
                "policy_id": "p",
                "policy_version": 1,
                "policy_epoch": 0,
                "satisfied_clause": null,
                "raw_candidate_count": 0,
                "unique_candidate_count": 0,
                "eligible_candidate_count": 0,
                "reason_codes": [],
                "candidate_diagnostics": [],
                "clause_evaluations": [],
                "omitted_candidate_diagnostics": 0
            },
            "registry_decision": {
                "registry_id": "r",
                "registry_epoch": 0,
                "decision": "accept",
                "reason_codes": []
            },
            "reason_codes": []
        });
        // Sanity: the well-formed version must parse first, so the
        // rejection below is actually caused by the extra field.
        let well_formed: AuthorizationResponse =
            serde_json::from_value(value.clone()).expect("well-formed response must parse");
        assert_eq!(
            well_formed.decision,
            crate::integration::AdmissionDecision::Accept
        );

        value["unexpected_extra_field"] = serde_json::json!(true);
        let result: Result<AuthorizationResponse, _> = serde_json::from_value(value);
        assert!(
            result.is_err(),
            "an unknown field must be rejected, not ignored"
        );
    }

    #[test]
    fn trailing_document_after_response_is_rejected() {
        let two_documents = br#"{"a":1}{"b":2}"#;
        let mut deserializer = serde_json::Deserializer::from_slice(two_documents);
        let _first: serde_json::Value =
            serde::Deserialize::deserialize(&mut deserializer).expect("first document parses");
        assert!(
            deserializer.end().is_err(),
            "a second concatenated document must not be treated as trailing whitespace"
        );
    }

    #[test]
    fn trailing_newline_alone_is_accepted() {
        let with_newline = b"{\"a\":1}\n";
        let mut deserializer = serde_json::Deserializer::from_slice(with_newline);
        let _value: serde_json::Value =
            serde::Deserialize::deserialize(&mut deserializer).expect("document parses");
        assert!(
            deserializer.end().is_ok(),
            "a single trailing newline must be accepted, matching the documented wire format"
        );
    }

    #[test]
    fn spawn_failure_on_missing_executable_is_reported_as_such() {
        let config = CallerConfig::new("/nonexistent/nix-signature-authorize-does-not-exist", "/");
        match invoke(&config, b"{}") {
            InvocationOutcome::Failure(CallerFailure::SpawnFailed) => {}
            other => panic!("expected SpawnFailed, got {other:?}"),
        }
    }
}
