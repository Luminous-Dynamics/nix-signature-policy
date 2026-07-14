#!/usr/bin/env python3
"""Verify a deterministic source release, manifest, and optional attestation."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = 1
MAX_RELEASE_STATEMENT_BYTES = 1024 * 1024
MAX_SOURCE_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_SOURCE_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_SOURCE_FILES = 10000
MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 1024 * 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        raise SystemExit(f"{context}: expected keys {sorted(expected)}, got {sorted(actual)}")


def safe_basename(value: str, context: str) -> str:
    pure = PurePosixPath(value)
    if pure.is_absolute() or len(pure.parts) != 1 or pure.name in ("", ".", ".."):
        raise SystemExit(f"{context}: unsafe artifact path {value!r}")
    return pure.name


def verify_artifact_record(base: Path, record: dict[str, Any]) -> Path:
    require_exact_keys(record, {"kind", "path", "sha256", "size_bytes"}, "artifact record")
    path = base / safe_basename(record["path"], "artifact record")
    if not path.is_file():
        raise SystemExit(f"missing release artifact: {path}")
    if path.stat().st_size != record["size_bytes"]:
        raise SystemExit(f"artifact size mismatch: {path}")
    if sha256_file(path) != record["sha256"]:
        raise SystemExit(f"artifact SHA-256 mismatch: {path}")
    return path


def verify_archive(archive: Path, manifest: dict[str, Any]) -> None:
    if archive.stat().st_size > MAX_SOURCE_ARCHIVE_BYTES:
        raise SystemExit("source archive exceeds the verifier size limit")
    with archive.open("rb") as handle:
        raw_header = handle.read(10)
    if len(raw_header) < 10 or raw_header[:2] != b"\x1f\x8b":
        raise SystemExit("source archive is not a gzip stream")
    gzip_mtime = int.from_bytes(raw_header[4:8], "little")
    if gzip_mtime != manifest["source_date_epoch"]:
        raise SystemExit("gzip timestamp does not match source_date_epoch")

    expected_files = {entry["path"]: entry for entry in manifest["files"]}
    observed_files: dict[str, dict[str, Any]] = {}
    observed_members: set[str] = set()
    observed_total = 0
    archive_root = manifest["archive_root"]
    with tarfile.open(archive, mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.name in observed_members:
                raise SystemExit(f"duplicate tar member: {member.name!r}")
            observed_members.add(member.name)
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts or not pure.parts:
                raise SystemExit(f"unsafe tar member: {member.name!r}")
            if pure.parts[0] != archive_root:
                raise SystemExit(f"tar member escapes declared archive root: {member.name!r}")
            if member.uid != 0 or member.gid != 0 or member.uname != "root" or member.gname != "root":
                raise SystemExit(f"non-normalized tar ownership: {member.name!r}")
            if member.mtime != manifest["source_date_epoch"]:
                raise SystemExit(f"non-normalized tar timestamp: {member.name!r}")
            if member.isdir():
                if member.mode != 0o755:
                    raise SystemExit(f"non-normalized directory mode: {member.name!r}")
                continue
            if not member.isfile():
                raise SystemExit(f"source archive contains non-regular member: {member.name!r}")
            relative = PurePosixPath(*pure.parts[1:]).as_posix()
            if relative in observed_files:
                raise SystemExit(f"duplicate source file member: {relative!r}")
            if relative not in expected_files:
                raise SystemExit(f"unmanifested source file: {relative!r}")
            extracted = tar.extractfile(member)
            if extracted is None:
                raise SystemExit(f"could not read source member: {relative!r}")
            entry = expected_files[relative]
            if member.size > MAX_SOURCE_FILE_BYTES or entry["size_bytes"] > MAX_SOURCE_FILE_BYTES:
                raise SystemExit(f"source file exceeds verifier size limit: {relative!r}")
            observed_total += member.size
            if observed_total > MAX_SOURCE_TOTAL_BYTES:
                raise SystemExit("source archive exceeds the uncompressed verifier limit")
            contents = extracted.read(MAX_SOURCE_FILE_BYTES + 1)
            if len(contents) > MAX_SOURCE_FILE_BYTES:
                raise SystemExit(f"source file exceeds verifier size limit: {relative!r}")
            mode = int(entry["mode"], 8)
            if member.mode != mode:
                raise SystemExit(f"mode mismatch for {relative!r}")
            if len(contents) != entry["size_bytes"] or member.size != entry["size_bytes"]:
                raise SystemExit(f"size mismatch for {relative!r}")
            if hashlib.sha256(contents).hexdigest() != entry["sha256"]:
                raise SystemExit(f"content hash mismatch for {relative!r}")
            observed_files[relative] = entry
    if set(observed_files) != set(expected_files):
        missing = sorted(set(expected_files) - set(observed_files))
        raise SystemExit(f"source archive is missing manifested files: {missing}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("release", type=Path)
    parser.add_argument("--attestation", type=Path)
    parser.add_argument("--trusted-key", type=Path)
    parser.add_argument("--attestation-binary", default="artifact-attestation")
    args = parser.parse_args()

    release_path = args.release.resolve()
    if release_path.stat().st_size > MAX_RELEASE_STATEMENT_BYTES:
        raise SystemExit("release statement exceeds the verifier size limit")
    release = json.loads(release_path.read_text())
    require_exact_keys(release, {"schema_version", "project", "source", "artifacts", "inputs"}, "release statement")
    if release["schema_version"] != SCHEMA_VERSION:
        raise SystemExit("unsupported release statement schema")
    require_exact_keys(release["project"], {"name", "version"}, "release project")
    require_exact_keys(release["source"], {"git_commit", "source_date_epoch", "tree_state"}, "release source")
    if release["source"]["tree_state"] != "clean":
        raise SystemExit("release statement was not produced from a clean tree")
    require_exact_keys(
        release["inputs"],
        {
            "cargo_lock_sha256",
            "flake_lock_sha256",
            "policy_vectors_manifest_sha256",
            "evidence_manifest_sha256",
            "fuzz_manifest_sha256",
        },
        "release inputs",
    )

    base = release_path.parent
    by_kind: dict[str, Path] = {}
    for record in release["artifacts"]:
        path = verify_artifact_record(base, record)
        kind = record["kind"]
        if kind in by_kind:
            raise SystemExit(f"duplicate release artifact kind: {kind!r}")
        by_kind[kind] = path
    if set(by_kind) != {"source_archive", "source_manifest"}:
        raise SystemExit(f"unexpected release artifact kinds: {sorted(by_kind)}")

    if by_kind["source_manifest"].stat().st_size > MAX_SOURCE_MANIFEST_BYTES:
        raise SystemExit("source manifest exceeds the verifier size limit")
    manifest = json.loads(by_kind["source_manifest"].read_text())
    require_exact_keys(
        manifest,
        {"schema_version", "project", "version", "git_commit", "source_date_epoch", "archive_root", "files"},
        "source manifest",
    )
    if manifest["schema_version"] != SCHEMA_VERSION:
        raise SystemExit("unsupported source manifest schema")
    if manifest["project"] != release["project"]["name"] or manifest["version"] != release["project"]["version"]:
        raise SystemExit("source manifest project/version mismatch")
    if manifest["git_commit"] != release["source"]["git_commit"]:
        raise SystemExit("source manifest commit mismatch")
    if manifest["source_date_epoch"] != release["source"]["source_date_epoch"]:
        raise SystemExit("source manifest epoch mismatch")
    if not isinstance(manifest["files"], list) or len(manifest["files"]) > MAX_SOURCE_FILES:
        raise SystemExit("source manifest contains too many files")
    paths: set[str] = set()
    for entry in manifest["files"]:
        require_exact_keys(entry, {"path", "mode", "size_bytes", "sha256"}, "manifest file")
        path = PurePosixPath(entry["path"])
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise SystemExit(f"unsafe manifest file path: {entry['path']!r}")
        if entry["path"] in paths:
            raise SystemExit(f"duplicate manifest file path: {entry['path']!r}")
        if entry["mode"] not in ("0644", "0755"):
            raise SystemExit(f"unsupported source file mode: {entry['mode']!r}")
        if len(entry["sha256"]) != 64 or any(character not in "0123456789abcdef" for character in entry["sha256"]):
            raise SystemExit(f"invalid source file SHA-256: {entry['path']!r}")
        paths.add(entry["path"])
    verify_archive(by_kind["source_archive"], manifest)

    if (args.attestation is None) != (args.trusted_key is None):
        raise SystemExit("--attestation and --trusted-key must be supplied together")
    if args.attestation is not None:
        subprocess.run(
            [
                args.attestation_binary,
                "verify",
                str(release_path),
                str(args.attestation),
                "--trusted-key",
                str(args.trusted_key),
                "--format",
                "json",
            ],
            check=True,
        )

    print(f"release verification passed: {release_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
