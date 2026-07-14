#!/usr/bin/env python3
"""Build a deterministic, source-only release bundle from a clean Git tree."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = 1


def run_git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def framed_tree_digest(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        relative = path.relative_to(ROOT).as_posix().encode("utf-8")
        contents = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return digest.hexdigest()


def tracked_files() -> list[tuple[str, int]]:
    raw = run_git("ls-files", "--stage", "-z")
    result: list[tuple[str, int]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode_text = metadata.split(b" ", 1)[0]
        path = raw_path.decode("utf-8", "strict")
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts or not pure.parts:
            raise SystemExit(f"refusing unsafe tracked path: {path!r}")
        if any(ord(character) < 32 or ord(character) == 127 for character in path):
            raise SystemExit(f"refusing tracked path with control characters: {path!r}")
        git_mode = int(mode_text, 8)
        if git_mode not in (0o100644, 0o100755):
            raise SystemExit(
                f"source releases accept only regular tracked files; {path!r} has Git mode {mode_text.decode()}"
            )
        result.append((path, 0o755 if git_mode == 0o100755 else 0o644))
    if not result:
        raise SystemExit("Git reported no tracked source files")
    return sorted(result)


def add_directory(tar: tarfile.TarFile, name: str, epoch: int) -> None:
    info = tarfile.TarInfo(name=name.rstrip("/") + "/")
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = epoch
    info.size = 0
    tar.addfile(info)


def build_archive(
    archive_path: Path,
    archive_root: str,
    files: list[tuple[str, int]],
    epoch: int,
) -> list[dict[str, Any]]:
    manifest_files: list[dict[str, Any]] = []
    directory_names = {archive_root}
    for relative, _mode in files:
        parent = PurePosixPath(archive_root, relative).parent
        while str(parent) not in (".", ""):
            directory_names.add(parent.as_posix())
            if parent.as_posix() == archive_root:
                break
            parent = parent.parent

    with tempfile.NamedTemporaryFile(dir=archive_path.parent, delete=False) as temp_tar:
        temp_tar_path = Path(temp_tar.name)
    try:
        with tarfile.open(temp_tar_path, mode="w", format=tarfile.GNU_FORMAT) as tar:
            for directory in sorted(directory_names, key=lambda value: (value.count("/"), value)):
                add_directory(tar, directory, epoch)
            for relative, mode in files:
                source = ROOT / relative
                contents = source.read_bytes()
                info = tarfile.TarInfo(name=f"{archive_root}/{relative}")
                info.type = tarfile.REGTYPE
                info.mode = mode
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                info.mtime = epoch
                info.size = len(contents)
                import io

                tar.addfile(info, io.BytesIO(contents))
                manifest_files.append(
                    {
                        "path": relative,
                        "mode": format(mode, "04o"),
                        "size_bytes": len(contents),
                        "sha256": hashlib.sha256(contents).hexdigest(),
                    }
                )

        with temp_tar_path.open("rb") as source, archive_path.open("wb") as raw_output:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw_output,
                mtime=epoch,
            ) as compressed:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    compressed.write(chunk)
    finally:
        temp_tar_path.unlink(missing_ok=True)
    return manifest_files


def artifact_record(kind: str, path: Path) -> dict[str, Any]:
    return {
        "kind": kind,
        "path": path.name,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, default=ROOT / "dist")
    parser.add_argument("--version")
    parser.add_argument("--source-date-epoch", type=int)
    parser.add_argument("--signing-key", type=Path)
    parser.add_argument(
        "--attestation-binary",
        default="artifact-attestation",
        help="binary used only when --signing-key is supplied",
    )
    args = parser.parse_args()

    if run_git("status", "--porcelain=v1", "--untracked-files=all").strip():
        raise SystemExit("source release requires a clean Git working tree")

    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
    project = cargo["package"]["name"]
    version = args.version or cargo["package"]["version"]
    if not version or any(character not in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._-" for character in version):
        raise SystemExit(f"unsafe release version: {version!r}")

    commit = run_git("rev-parse", "HEAD").decode().strip()
    epoch = args.source_date_epoch
    if epoch is None:
        epoch = int(run_git("show", "-s", "--format=%ct", "HEAD").decode().strip())
    if epoch < 0 or epoch > 0xFFFFFFFF:
        raise SystemExit("source date epoch must fit the portable gzip timestamp field")

    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    archive_root = f"{project}-{version}"
    prefix = f"{project}-{version}-source"
    archive_path = out_dir / f"{prefix}.tar.gz"
    manifest_path = out_dir / f"{prefix}.manifest.json"
    release_path = out_dir / f"{project}-{version}.release.json"
    environment_path = out_dir / f"{project}-{version}.environment.json"
    attestation_path = out_dir / f"{project}-{version}.release.attestation.json"

    files = tracked_files()
    manifest_files = build_archive(archive_path, archive_root, files, epoch)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "project": project,
        "version": version,
        "git_commit": commit,
        "source_date_epoch": epoch,
        "archive_root": archive_root,
        "files": manifest_files,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    release_statement = {
        "schema_version": SCHEMA_VERSION,
        "project": {"name": project, "version": version},
        "source": {
            "git_commit": commit,
            "source_date_epoch": epoch,
            "tree_state": "clean",
        },
        "artifacts": [
            artifact_record("source_archive", archive_path),
            artifact_record("source_manifest", manifest_path),
        ],
        "inputs": {
            "cargo_lock_sha256": sha256_file(ROOT / "Cargo.lock"),
            "flake_lock_sha256": sha256_file(ROOT / "flake.lock"),
            "policy_vectors_manifest_sha256": framed_tree_digest(
                [path for path in (ROOT / "policy-vectors").rglob("*") if path.is_file()]
            ),
            "evidence_manifest_sha256": framed_tree_digest(
                [path for path in (ROOT / "evidence").rglob("*") if path.is_file()]
            ),
            "fuzz_manifest_sha256": framed_tree_digest(
                [
                    path
                    for path in (ROOT / "fuzz").rglob("*")
                    if path.is_file()
                    and "target" not in path.parts
                    and "artifacts" not in path.parts
                    and "coverage" not in path.parts
                ]
            ),
        },
    }
    release_path.write_text(json.dumps(release_statement, indent=2, sort_keys=True) + "\n")

    environment = subprocess.check_output(
        [sys.executable, str(ROOT / "scripts/report-environment.py")], cwd=ROOT
    )
    environment_path.write_bytes(environment)

    if args.signing_key is not None:
        subprocess.run(
            [
                args.attestation_binary,
                "attest",
                str(release_path),
                "--identifier",
                release_path.name,
                "--key",
                str(args.signing_key),
                "--out",
                str(attestation_path),
            ],
            cwd=ROOT,
            check=True,
        )

    for path in (archive_path, manifest_path, release_path, environment_path):
        print(f"{sha256_file(path)}  {path}")
    if attestation_path.exists():
        print(f"{sha256_file(attestation_path)}  {attestation_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
