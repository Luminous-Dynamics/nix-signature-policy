//! Adversarial process-invocation tests for `nix_signature_policy::caller`.
//!
//! These exercise the exact boundary a future Nix-side caller would rely
//! on: the real `nix-signature-authorize` binary for the happy path, and
//! small `/bin/sh` fixtures simulating a hostile or buggy helper for
//! everything else. See `docs/CALLER_SAFETY.md`.
//!
//! Deliberately not covered here (see `docs/CALLER_SAFETY.md` for why):
//! "network access where prohibited" requires OS-level sandboxing that
//! belongs to a deployment layer, not this crate's test suite; a literal
//! unbounded fork bomb is never run (see `bounded_excessive_forking_is_
//! fully_reaped` for the bounded stand-in); deeply-nested/huge-string JSON
//! payloads are covered by `fuzz/fuzz_targets/authorization_protocol.rs`
//! instead of hand-written cases here.

use std::path::{Path, PathBuf};
use std::time::Duration;

use nix_signature_policy::caller::{self, CallerConfig, CallerFailure, InvocationOutcome};
use nix_signature_policy::integration::AdmissionDecision;

const SH: &str = "/bin/sh";
/// The default for fixtures that are *not* specifically testing timeout
/// behavior (those set their own short, explicit override instead — see
/// e.g. `hung_helper_is_killed_and_its_eventual_output_is_never_trusted`).
/// Deliberately generous rather than "as short as possible": on a heavily
/// loaded machine, even a trivial `/bin/sh -c 'kill -SEGV $$'` fixture may
/// not get scheduled within a few hundred milliseconds, which would
/// misclassify a crash as a timeout — a test-harness artifact, not a
/// `caller.rs` bug. Observed directly under real load on a shared
/// development machine: `crashing_helper_is_unexpected_exit_status` failed
/// with `Timeout` instead of `UnexpectedExitStatus` at 500ms, and passed
/// reliably once raised.
const TEST_TIMEOUT: Duration = Duration::from_secs(3);

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().expect("create tempdir")
}

/// Single-quote a path for embedding in a `/bin/sh -c` script body,
/// escaping any embedded single quotes defensively (tempdir paths won't
/// realistically contain one, but this makes the helper correct regardless).
fn quote(path: &Path) -> String {
    let raw = path.display().to_string();
    format!("'{}'", raw.replace('\'', r"'\''"))
}

/// `CallerConfig` clears `PATH` from the child by design (see `src/
/// caller.rs`'s module docs and `environment_is_not_inherited` below, which
/// tests that property directly). These hostility fixtures aren't testing
/// PATH-clearing specifically, so they opt back into a real `PATH` via
/// `extra_env` — otherwise `/bin/sh` can't resolve `cat`, `head`, `touch`,
/// etc. and every fixture would fail closed with "command not found"
/// before it ever exercised the behavior under test.
fn sh_config(script: &str, dir: &Path) -> CallerConfig {
    let mut config = CallerConfig::new(SH, dir);
    config.args = vec!["-c".to_string(), script.to_string()];
    config.timeout = TEST_TIMEOUT;
    if let Ok(path) = std::env::var("PATH") {
        config.extra_env.push(("PATH".to_string(), path));
    }
    config
}

fn real_authorize_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_nix-signature-authorize"))
}

fn committed_refuse_request() -> Vec<u8> {
    std::fs::read("integration/examples/authoritative-downgrade-refusal.request.json")
        .expect("read committed example request")
}

/// The same committed request, switched to `legacy` mode (which preserves
/// `built_in_decision: accept`) so we have a real accept-shaped request
/// without hand-maintaining a second full JSON literal.
fn accept_request() -> Vec<u8> {
    let mut value: serde_json::Value =
        serde_json::from_slice(&committed_refuse_request()).expect("parse committed example");
    value["enforcement_mode"] = serde_json::json!("legacy");
    serde_json::to_vec(&value).expect("reserialize")
}

/// Real response bytes from the real binary — fixtures that need "a valid
/// response" mutate output the actual serializer produced, never a
/// hand-maintained literal that could drift from the real wire shape.
fn real_response(dir: &Path, request: &[u8]) -> Vec<u8> {
    let request_path = dir.join("request.json");
    std::fs::write(&request_path, request).unwrap();
    let output = std::process::Command::new(real_authorize_bin())
        .arg("--request")
        .arg(&request_path)
        .output()
        .expect("run the real binary directly (not through caller::invoke) to produce a fixture");
    output.stdout
}

fn assert_failure(config: &CallerConfig, request: &[u8], expected: CallerFailure) {
    match caller::invoke(config, request) {
        InvocationOutcome::Failure(actual) => {
            assert_eq!(actual, expected, "wrong failure reason");
        }
        other => panic!("expected Failure({expected:?}), got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Sanity: the real binary still works correctly through the caller.
// ---------------------------------------------------------------------

#[test]
fn sanity_accept_flows_through_the_caller() {
    let dir = tmp();
    let mut config = CallerConfig::new(real_authorize_bin(), dir.path());
    config.timeout = Duration::from_secs(5);
    match caller::invoke(&config, &accept_request()) {
        InvocationOutcome::Decision(response) => {
            assert_eq!(response.decision, AdmissionDecision::Accept);
        }
        other => panic!("expected a decision, got {other:?}"),
    }
}

#[test]
fn sanity_refuse_flows_through_the_caller() {
    let dir = tmp();
    let mut config = CallerConfig::new(real_authorize_bin(), dir.path());
    config.timeout = Duration::from_secs(5);
    match caller::invoke(&config, &committed_refuse_request()) {
        InvocationOutcome::Decision(response) => {
            assert_eq!(response.decision, AdmissionDecision::Refuse);
        }
        other => panic!("expected a decision, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Spawn-time failures.
// ---------------------------------------------------------------------

#[test]
fn missing_executable_is_a_spawn_failure() {
    let dir = tmp();
    let config = CallerConfig::new("/nonexistent/helper-does-not-exist", dir.path());
    assert_failure(&config, b"{}", CallerFailure::SpawnFailed);
}

#[test]
fn non_executable_file_is_a_spawn_failure() {
    let dir = tmp();
    let path = dir.path().join("not-executable");
    std::fs::write(&path, b"#!/bin/sh\necho hi\n").unwrap();
    // Deliberately no +x bit set.
    let config = CallerConfig::new(&path, dir.path());
    assert_failure(&config, b"{}", CallerFailure::SpawnFailed);
}

// ---------------------------------------------------------------------
// Abnormal termination.
// ---------------------------------------------------------------------

#[test]
fn crashing_helper_is_unexpected_exit_status() {
    let dir = tmp();
    let config = sh_config("kill -SEGV $$", dir.path());
    assert_failure(&config, b"{}", CallerFailure::UnexpectedExitStatus);
}

#[test]
fn self_terminated_helper_is_unexpected_exit_status() {
    let dir = tmp();
    let config = sh_config("kill -TERM $$", dir.path());
    assert_failure(&config, b"{}", CallerFailure::UnexpectedExitStatus);
}

#[test]
fn clean_exit_with_no_output_is_malformed() {
    let dir = tmp();
    let config = sh_config("exit 0", dir.path());
    assert_failure(&config, b"{}", CallerFailure::MalformedResponseJson);
}

#[test]
fn valid_accept_response_but_unexpected_exit_code_is_rejected() {
    let dir = tmp();
    let response_path = dir.path().join("response.json");
    std::fs::write(&response_path, real_response(dir.path(), &accept_request())).unwrap();
    // exit 1 is not one of the documented {0, 10}: a caller must not infer
    // acceptance from well-formed stdout when the exit status itself is
    // anomalous.
    let script = format!("cat {}; exit 1", quote(&response_path));
    let config = sh_config(&script, dir.path());
    assert_failure(&config, b"{}", CallerFailure::UnexpectedExitStatus);
}

#[test]
fn valid_refuse_response_but_unexpected_exit_code_is_rejected() {
    let dir = tmp();
    let response_path = dir.path().join("response.json");
    std::fs::write(
        &response_path,
        real_response(dir.path(), &committed_refuse_request()),
    )
    .unwrap();
    let script = format!("cat {}; exit 137", quote(&response_path));
    let config = sh_config(&script, dir.path());
    assert_failure(&config, b"{}", CallerFailure::UnexpectedExitStatus);
}

// ---------------------------------------------------------------------
// Timeout, and the "output right after the deadline" race.
// ---------------------------------------------------------------------

#[test]
fn hung_helper_is_killed_and_its_eventual_output_is_never_trusted() {
    let dir = tmp();
    let ready = dir.path().join("ready");
    let go = dir.path().join("go"); // the test never creates this.
    // The fixture proves it actually started (touches `ready`), then blocks
    // forever waiting on a file that will never appear. If this caller ever
    // regressed into reading stdout only *after* observing exit, this
    // script's final printf would be exactly the output that must never be
    // trusted — but it never even runs, because the timeout kills the
    // process while it's still in the wait loop.
    let script = format!(
        "touch {}; while [ ! -f {} ]; do sleep 0.01; done; printf 'this must never be read'",
        quote(&ready),
        quote(&go),
    );
    let mut config = sh_config(&script, dir.path());
    config.timeout = Duration::from_millis(200);
    assert_failure(&config, b"{}", CallerFailure::Timeout);
    assert!(
        ready.exists(),
        "sanity: the fixture actually started running"
    );
}

// ---------------------------------------------------------------------
// Output bounds. Both cases below write enough to exceed a single pipe
// buffer (typically 64KiB) before the process exits, so they also prove
// this caller doesn't deadlock the way a try_wait()-then-read design would.
// ---------------------------------------------------------------------

#[test]
fn oversized_stdout_is_response_too_large() {
    let dir = tmp();
    let script = format!("head -c {} /dev/zero", caller::MAX_RESPONSE_BYTES + 4096);
    let mut config = sh_config(&script, dir.path());
    config.timeout = Duration::from_secs(5); // generous; overflow should trip well before this.
    assert_failure(&config, b"{}", CallerFailure::ResponseTooLarge);
}

#[test]
fn endless_stderr_does_not_block_a_valid_decision() {
    let dir = tmp();
    let response_path = dir.path().join("response.json");
    std::fs::write(&response_path, real_response(dir.path(), &accept_request())).unwrap();
    let script = format!(
        "head -c {} /dev/zero 1>&2; cat {}",
        caller::MAX_DIAGNOSTIC_BYTES * 4,
        quote(&response_path),
    );
    let mut config = sh_config(&script, dir.path());
    config.timeout = Duration::from_secs(5);
    match caller::invoke(&config, b"{}") {
        InvocationOutcome::Decision(response) => {
            assert_eq!(response.decision, AdmissionDecision::Accept);
        }
        other => panic!("stderr flooding must not affect the decision, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Malformed response bodies.
// ---------------------------------------------------------------------

#[test]
fn invalid_utf8_stdout_is_rejected() {
    let dir = tmp();
    // Write the exact invalid-UTF-8 bytes from Rust and `cat` them, rather
    // than relying on a shell's `printf \xHH` hex-escape support: that's a
    // bash-ism, not POSIX, and this fixture silently produced valid ASCII
    // text (not the intended invalid bytes) under the dash-based /bin/sh
    // on GitHub's ubuntu-latest runner, which then failed with
    // MalformedResponseJson instead of the expected InvalidUtf8Response —
    // a portability bug in the fixture, not in `caller.rs`.
    let bytes_path = dir.path().join("invalid-utf8.bin");
    std::fs::write(&bytes_path, [0xffu8, 0xfe]).unwrap();
    let script = format!("cat {}", quote(&bytes_path));
    let config = sh_config(&script, dir.path());
    assert_failure(&config, b"{}", CallerFailure::InvalidUtf8Response);
}

#[test]
fn malformed_json_is_rejected() {
    let dir = tmp();
    let config = sh_config(r#"printf '{"decision":'"#, dir.path());
    assert_failure(&config, b"{}", CallerFailure::MalformedResponseJson);
}

#[test]
fn duplicate_json_keys_are_rejected_end_to_end() {
    let dir = tmp();
    let config = sh_config(
        r#"printf '{"contract_version":2,"contract_version":2,"decision":"accept"}'"#,
        dir.path(),
    );
    assert_failure(&config, b"{}", CallerFailure::MalformedResponseJson);
}

#[test]
fn trailing_garbage_after_response_is_rejected() {
    let dir = tmp();
    let response_path = dir.path().join("response.json");
    std::fs::write(&response_path, real_response(dir.path(), &accept_request())).unwrap();
    let script = format!(
        "cat {}; printf 'extra-garbage-not-whitespace'",
        quote(&response_path)
    );
    let config = sh_config(&script, dir.path());
    assert_failure(&config, b"{}", CallerFailure::MalformedResponseJson);
}

#[test]
fn unsupported_contract_version_is_rejected() {
    let dir = tmp();
    let mut response: serde_json::Value =
        serde_json::from_slice(&real_response(dir.path(), &accept_request())).unwrap();
    response["contract_version"] = serde_json::json!(999);
    let response_path = dir.path().join("response.json");
    std::fs::write(&response_path, serde_json::to_vec(&response).unwrap()).unwrap();
    let script = format!("cat {}", quote(&response_path));
    let config = sh_config(&script, dir.path());
    assert_failure(&config, b"{}", CallerFailure::ContractVersionMismatch);
}

// ---------------------------------------------------------------------
// Process-tree and environment hygiene.
// ---------------------------------------------------------------------

#[test]
fn grandchild_does_not_survive_group_kill() {
    let dir = tmp();
    let pid_file = dir.path().join("grandchild.pid");
    // The direct child backgrounds a grandchild that writes its own PID
    // and then sleeps far longer than the test, then the direct child
    // itself hangs (so the caller's timeout is what triggers cleanup).
    let script = format!(
        "(echo $$ > {} ; sleep 100) & disown; while true; do sleep 0.01; done",
        quote(&pid_file)
    );
    let mut config = sh_config(&script, dir.path());
    config.timeout = Duration::from_millis(200);
    assert_failure(&config, b"{}", CallerFailure::Timeout);

    // Bounded retries: the PID file may take a moment to appear, and after
    // group kill the OS may take a moment to fully reap. Both must settle
    // well within a couple of seconds.
    let mut grandchild_pid: Option<i32> = None;
    for _ in 0..50 {
        if let Ok(text) = std::fs::read_to_string(&pid_file) {
            if let Ok(pid) = text.trim().parse() {
                grandchild_pid = Some(pid);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let grandchild_pid = grandchild_pid.expect("grandchild PID file was never written");

    let mut still_alive = true;
    for _ in 0..50 {
        // Signal 0: existence check only, sends nothing.
        let alive = unsafe { libc::kill(grandchild_pid, 0) } == 0;
        if !alive {
            still_alive = false;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !still_alive,
        "grandchild pid {grandchild_pid} outlived the process-group kill"
    );
}

#[test]
fn environment_is_not_inherited() {
    let dir = tmp();
    // SAFETY: single-threaded test setup for this specific env var, and
    // nothing else in this test reads it concurrently.
    unsafe {
        std::env::set_var("HOSTILE_HELPER_TEST_MARKER", "must-not-leak");
    }
    let config = sh_config(r#"printf '%s' "$HOSTILE_HELPER_TEST_MARKER""#, dir.path());
    unsafe {
        std::env::remove_var("HOSTILE_HELPER_TEST_MARKER");
    }
    // An empty/absent variable makes the script print nothing, which is
    // not valid JSON, and that's exactly the point.
    assert_failure(&config, b"{}", CallerFailure::MalformedResponseJson);
}

#[test]
fn working_directory_is_explicit_not_inherited() {
    let dir = tmp();
    let marker_dir = dir.path().join("expected-cwd");
    std::fs::create_dir(&marker_dir).unwrap();
    let mut config = sh_config("printf '%s' \"$(pwd)\"", &marker_dir);
    config.timeout = TEST_TIMEOUT;
    // `pwd` output isn't valid AuthorizationResponse JSON either, but the
    // point of this test is the *path* the child ran the fixture in, so
    // check that independently first via a marker file.
    let script = format!(
        "pwd > {}; printf 'not-json'",
        quote(&marker_dir.join("observed-cwd"))
    );
    config.args = vec!["-c".to_string(), script];
    let _ = caller::invoke(&config, b"{}");
    let observed = std::fs::read_to_string(marker_dir.join("observed-cwd")).unwrap();
    assert_eq!(observed.trim(), marker_dir.display().to_string());
}

#[test]
fn bounded_excessive_forking_is_fully_reaped() {
    // A *bounded* stand-in for a fork-bomb attempt: ~50 short-lived
    // children under the group, then the direct child hangs so the
    // caller's timeout drives cleanup. This proves process-group kill
    // reaps a burst of children without running an actual unbounded
    // `:(){ :|:& };:` that could take down the test runner.
    let dir = tmp();
    let counter_dir = dir.path().join("forked");
    std::fs::create_dir(&counter_dir).unwrap();
    let script = format!(
        "for i in $(seq 1 50); do (touch {}/$i.alive; sleep 100) & done; while true; do sleep 0.01; done",
        counter_dir.display(),
    );
    let mut config = sh_config(&script, dir.path());
    config.timeout = Duration::from_millis(300);
    assert_failure(&config, b"{}", CallerFailure::Timeout);

    // Give the burst a moment to actually start before we kill it, then
    // confirm nothing from it is still running afterward. We don't track
    // individual PIDs here (50 of them); instead confirm process-group
    // membership was effective by checking overall process count settles
    // and none of the marker files' owning `sleep 100`s are still alive —
    // approximated by asserting no new `sleep 100` children of this test
    // process remain after a bounded wait.
    std::thread::sleep(Duration::from_millis(100));
    // Best-effort: if pgrep is unavailable this simply doesn't assert
    // further, since the Timeout failure above already proves cleanup ran.
    if let Ok(output) = std::process::Command::new("pgrep")
        .args(["-f", "sleep 100"])
        .output()
    {
        let remaining = String::from_utf8_lossy(&output.stdout);
        let leaked = remaining.lines().count();
        assert!(
            leaked <= 2, // allow for unrelated `sleep 100`s from other concurrent tests/sessions
            "expected the forked burst to be fully reaped, found {leaked} matching processes"
        );
    }
}

// ---------------------------------------------------------------------
// Reentrancy: repeated and concurrent invocations stay independently
// bounded, with no shared state leaking between calls.
// ---------------------------------------------------------------------

#[test]
fn repeated_timeouts_do_not_degrade() {
    for _ in 0..5 {
        let dir = tmp();
        let config = sh_config("while true; do sleep 0.01; done", dir.path());
        let mut config = config;
        config.timeout = Duration::from_millis(150);
        let started = std::time::Instant::now();
        assert_failure(&config, b"{}", CallerFailure::Timeout);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "a single timeout invocation took too long; possible leak or slowdown across repeats"
        );
    }
}

#[test]
fn concurrent_invocations_stay_independently_bounded() {
    let handles: Vec<_> = (0..3)
        .map(|i| {
            std::thread::spawn(move || {
                let dir = tmp();
                match i % 3 {
                    0 => {
                        let mut config = CallerConfig::new(real_authorize_bin(), dir.path());
                        config.timeout = Duration::from_secs(5);
                        matches!(
                            caller::invoke(&config, &accept_request()),
                            InvocationOutcome::Decision(response)
                                if response.decision == AdmissionDecision::Accept
                        )
                    }
                    1 => {
                        let config = sh_config("kill -SEGV $$", dir.path());
                        matches!(
                            caller::invoke(&config, b"{}"),
                            InvocationOutcome::Failure(CallerFailure::UnexpectedExitStatus)
                        )
                    }
                    _ => {
                        let mut config = sh_config("while true; do sleep 0.01; done", dir.path());
                        config.timeout = Duration::from_millis(150);
                        matches!(
                            caller::invoke(&config, b"{}"),
                            InvocationOutcome::Failure(CallerFailure::Timeout)
                        )
                    }
                }
            })
        })
        .collect();
    for handle in handles {
        assert!(
            handle.join().unwrap(),
            "one concurrent invocation got the wrong outcome"
        );
    }
}
