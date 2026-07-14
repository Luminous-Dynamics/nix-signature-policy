//! Codifies the manual end-to-end proof this crate was built against: select
//! a real package store path, dual-sign it, serve it through our real proxy, and prove
//! via `nix store verify` — Nix's own trust logic, not ours — that an
//! unmodified `nix` trusts the hybrid-signed narinfo when only our key is
//! trusted, and correctly refuses it when no key is trusted.
//!
//! `#[ignore]`d: needs a real `nix` binary and `python3` (to serve the local
//! cache directory over HTTP, exactly as a human running the README's manual
//! steps would). By default it resolves `nixpkgs#hello`; the reproducible flake
//! apps instead set `NIX_PQC_E2E_STORE_PATH` to an already-built, pinned store
//! path, avoiding registry and package-resolution drift. Run explicitly with:
//!
//! ```text
//! cargo test --test real_nix_e2e -- --ignored --nocapture
//! ```

use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use nix_pqc_cache_proxy::keys::PublicKey;

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_until_up(addr: &str) {
    for _ in 0..100 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("nothing came up on {addr} in time");
}

fn run(cmd: &mut Command) -> String {
    let output = cmd.output().expect("failed to spawn command");
    if !output.status.success() {
        panic!(
            "command failed ({:?}):\nstdout: {}\nstderr: {}",
            cmd,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
#[ignore = "needs a real `nix` binary and python3 — see module docs"]
fn real_nix_trusts_our_hybrid_resigned_narinfo() {
    if Command::new("nix").arg("--version").output().is_err() {
        eprintln!("SKIP: no `nix` binary on PATH");
        return;
    }
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("SKIP: no `python3` on PATH (used to serve the local demo cache)");
        return;
    }

    let bin = env!("CARGO_BIN_EXE_nix-pqc-cache-proxy");
    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    let key_dir = tmp.path().join("keys");
    let dest_dir = tmp.path().join("dest");
    std::fs::create_dir_all(&cache_dir).unwrap();
    std::fs::create_dir_all(&key_dir).unwrap();
    std::fs::create_dir_all(&dest_dir).unwrap();

    // 1. Select a real store path and push it into a local, unsigned file://
    // cache. Flake apps supply an already-built path from the pinned nixpkgs
    // input. Manual runs retain the convenient nixpkgs#hello fallback.
    let store_path = match std::env::var("NIX_PQC_E2E_STORE_PATH") {
        Ok(path) => {
            assert!(
                path.starts_with("/nix/store/"),
                "NIX_PQC_E2E_STORE_PATH must name a /nix/store path, got {path:?}"
            );
            assert!(
                std::path::Path::new(&path).exists(),
                "NIX_PQC_E2E_STORE_PATH does not exist: {path}"
            );
            path
        }
        Err(_) => run(Command::new("nix").args([
            "build",
            "--no-link",
            "--print-out-paths",
            "nixpkgs#hello",
        ]))
        .trim()
        .to_string(),
    };
    run(Command::new("nix").args([
        "copy",
        "--to",
        &format!("file://{}", cache_dir.display()),
        &store_path,
    ]));

    // 2. keygen + dual-sign the local cache with our CLI.
    run(Command::new(bin)
        .args(["keygen", "demo-1", "--out-dir"])
        .arg(&key_dir));
    run(Command::new(bin)
        .args(["sign"])
        .arg(&cache_dir)
        .args(["--key"])
        .arg(key_dir.join("demo-1.secret")));

    let our_pubkey = PublicKey::load(&key_dir.join("demo-1.pub")).unwrap();
    let our_pubkey_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        our_pubkey.keys.ed25519,
    );

    // 3. Serve the now-dual-signed cache over plain HTTP (matches the
    // README's manual steps: a real substituter is HTTP, not file://).
    let http_port = pick_free_port();
    let http_server = KillOnDrop(
        Command::new("python3")
            .args(["-m", "http.server", &http_port.to_string()])
            .current_dir(&cache_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_until_up(&format!("127.0.0.1:{http_port}"));

    // 4. Run our real proxy in front of it, verifying upstream = our OWN
    // demo-1 signature this time (since that's what's actually on the
    // narinfo now — realistic "upstream already dual-signed by someone"
    // scenario, distinct from the hermetic tests' from-scratch fake upstream).
    let proxy_port = pick_free_port();
    let proxy = KillOnDrop(
        Command::new(bin)
            .args(["proxy", "--upstream"])
            .arg(format!("http://127.0.0.1:{http_port}"))
            .args(["--upstream-pubkey", &format!("demo-1:{our_pubkey_b64}")])
            .args(["--key"])
            .arg(key_dir.join("demo-1.secret"))
            .args(["--listen", &format!("127.0.0.1:{proxy_port}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_until_up(&format!("127.0.0.1:{proxy_port}"));

    // 5. A real, unmodified `nix copy` pulls the closure through our proxy.
    run(Command::new("nix").args([
        "copy",
        "--from",
        &format!("http://127.0.0.1:{proxy_port}"),
        "--to",
        &format!("file://{}", dest_dir.display()),
        &store_path,
    ]));

    // 6. The actual proof: `nix store verify` — Nix's own trust logic —
    // trusts the path when ONLY our key is trusted...
    run(Command::new("nix").args([
        "store",
        "verify",
        "--store",
        &format!("file://{}", dest_dir.display()),
        "--option",
        "trusted-public-keys",
        &format!("demo-1:{our_pubkey_b64}"),
        &store_path,
    ]));

    // ...and correctly refuses it when NO key is trusted.
    let output = Command::new("nix")
        .args([
            "store",
            "verify",
            "--store",
            &format!("file://{}", dest_dir.display()),
            "--option",
            "trusted-public-keys",
            "",
            &store_path,
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "nix store verify must fail when no key is trusted"
    );
    // Nix's convention for which of stdout/stderr carries this message isn't
    // load-bearing for us — check both rather than assume one.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("untrusted"),
        "expected an 'untrusted' message, got: {combined}"
    );

    drop(proxy);
    drop(http_server);
    println!("real-nix end-to-end proof: PASSED");
}

fn pick_free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}
