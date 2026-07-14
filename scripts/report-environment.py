#!/usr/bin/env python3
"""Emit reproducibility metadata for a nix-pqc-cache-proxy checkout.

Uses only the Python standard library so it can run in the locked Nix shell and
in ordinary CI. The report is intentionally JSON for easy attachment to test,
benchmark, or RFC evidence.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def command_version(*argv: str) -> str | None:
    try:
        proc = subprocess.run(
            argv,
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    return proc.stdout.strip()


def direct_dependency_versions(cargo_toml: dict[str, Any], cargo_lock: dict[str, Any]) -> dict[str, str]:
    direct = set(cargo_toml.get("dependencies", {})) | set(cargo_toml.get("dev-dependencies", {}))
    locked: dict[str, list[str]] = {}
    for package in cargo_lock.get("package", []):
        name = package.get("name")
        version = package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            locked.setdefault(name, []).append(version)

    result: dict[str, str] = {}
    for name in sorted(direct):
        versions = sorted(set(locked.get(name, [])))
        result[name] = ",".join(versions) if versions else "not-found-in-lock"
    return result


def policy_vector_manifest() -> dict[str, Any]:
    vector_root = ROOT / "policy-vectors"
    paths = sorted(path for path in vector_root.rglob("*") if path.is_file())
    digest = hashlib.sha256()
    vector_count = 0
    for path in paths:
        relative = path.relative_to(ROOT).as_posix().encode("utf-8")
        contents = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
        if path.suffix == ".json" and path.name != "schema-v1.json":
            vector_count += 1
    return {
        "schema_version": 1,
        "vector_count": vector_count,
        "manifest_sha256": digest.hexdigest(),
    }



def evidence_manifest() -> dict[str, Any]:
    evidence_root = ROOT / "evidence"
    schema_path = evidence_root / "schema-v1.json"
    schema_contents = schema_path.read_bytes()
    schema = json.loads(schema_contents)
    paths = sorted(path for path in evidence_root.rglob("*") if path.is_file())
    digest = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(ROOT).as_posix().encode("utf-8")
        contents = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return {
        "schema_version": schema["properties"]["bundle_schema_version"]["const"],
        "schema_sha256": hashlib.sha256(schema_contents).hexdigest(),
        "example_count": len(list((evidence_root / "examples").glob("*.json"))),
        "manifest_sha256": digest.hexdigest(),
    }


def release_manifest() -> dict[str, Any]:
    schema_path = ROOT / "release/schema-v1.json"
    schema_contents = schema_path.read_bytes()
    schema = json.loads(schema_contents)
    paths = sorted(
        path
        for path in (ROOT / "release").rglob("*")
        if path.is_file()
    )
    digest = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(ROOT).as_posix().encode("utf-8")
        contents = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return {
        "schema_version": schema["properties"]["schema_version"]["const"],
        "schema_sha256": hashlib.sha256(schema_contents).hexdigest(),
        "manifest_sha256": digest.hexdigest(),
    }


def fuzz_manifest() -> dict[str, Any]:
    fuzz_root = ROOT / "fuzz"
    paths = sorted(
        path
        for path in fuzz_root.rglob("*")
        if path.is_file()
        and "target" not in path.parts
        and "artifacts" not in path.parts
        and "coverage" not in path.parts
    )
    digest = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(ROOT).as_posix().encode("utf-8")
        contents = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return {
        "target_count": len(list((fuzz_root / "fuzz_targets").glob("*.rs"))),
        "corpus_seed_count": len(
            [path for path in (fuzz_root / "corpus").rglob("*") if path.is_file()]
        ),
        "manifest_sha256": digest.hexdigest(),
    }

def main() -> int:
    cargo_toml = tomllib.loads((ROOT / "Cargo.toml").read_text())
    cargo_lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    rust_toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())
    fuzz_toolchain = tomllib.loads((ROOT / "fuzz/rust-toolchain.toml").read_text())
    flake_lock = json.loads((ROOT / "flake.lock").read_text())

    locked_inputs = {}
    for name, node in sorted(flake_lock.get("nodes", {}).items()):
        locked = node.get("locked")
        if not isinstance(locked, dict):
            continue
        locked_inputs[name] = {
            key: locked[key]
            for key in ("type", "owner", "repo", "rev", "narHash", "lastModified")
            if key in locked
        }

    report = {
        "schema": "nix-pqc-cache-proxy-environment-v1",
        "project": {
            "name": cargo_toml["package"]["name"],
            "version": cargo_toml["package"]["version"],
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "tools": {
            "rust_toolchain_pin": rust_toolchain["toolchain"]["channel"],
            "fuzz_toolchain_pin": fuzz_toolchain["toolchain"]["channel"],
            "rustc": command_version("rustc", "--version", "--verbose"),
            "cargo": command_version("cargo", "--version", "--verbose"),
            "nix": command_version("nix", "--version"),
            "python": sys.version.split()[0],
        },
        "transport_tls": {
            "reqwest_features": cargo_toml["dependencies"]["reqwest"].get("features", []),
            "reqwest_default_features": cargo_toml["dependencies"]["reqwest"].get(
                "default-features", True
            ),
            "openssl_required_by_direct_configuration": False,
        },
        "operational_profile": {
            "schema_version": 1,
            "default_max_in_flight": 128,
            "default_queue_timeout_ms": 1000,
            "default_connect_timeout_secs": 10,
            "default_metadata_timeout_secs": 30,
            "default_nar_header_timeout_secs": 30,
            "default_nar_idle_timeout_secs": 30,
            "default_max_nar_bytes": None,
            "health_endpoint": "/healthz",
            "readiness_endpoint": "/readyz",
            "metrics_endpoint": "/metrics",
        },
        "direct_cargo_dependencies": direct_dependency_versions(cargo_toml, cargo_lock),
        "policy_vectors": policy_vector_manifest(),
        "evidence": evidence_manifest(),
        "release_engineering": release_manifest(),
        "fuzzing": fuzz_manifest(),
        "flake_inputs": locked_inputs,
    }
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
