//! Hardened same-directory temp-file-then-commit writer, shared by every
//! writer in this crate that produces a file another process or a later
//! invocation of this one will read back and trust (signing keys in
//! [`crate::keys`], local rollback-resistant trust checkpoints in
//! `src/bin/trust-state.rs`).
//!
//! Extracted from a prior copy of this logic that lived only in
//! `crate::keys` after an external review found `src/bin/trust-state.rs`
//! had grown its own, much weaker, local `write_atomic()`: a predictable
//! PID-only temporary filename (no randomness -- guessable, and prone to
//! a pre-created-file/symlink race in a writable-by-others directory),
//! `fs::write()` instead of an exclusive `create_new` open (so a
//! pre-existing file or symlink at the temp path is silently followed
//! and truncated rather than rejected), no `sync_all()` before commit
//! (data may not be durable across a crash before the rename lands), no
//! parent-directory sync after the rename (the directory-entry update
//! itself may not be durable across a crash even once the file's own
//! bytes are), and no explicit file mode (whatever the process umask
//! happens to produce). This module fixes all of that once, so nothing
//! in this crate needs its own weaker copy again.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use rand::RngCore;

/// Whether a write must fail if `path` already exists, or is allowed to
/// intentionally replace it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitMode {
    /// Commit fails (atomically, no race window) if `path` already
    /// exists. Use for anything that must never silently clobber an
    /// existing file -- e.g. a newly generated key, or a new rollback
    /// checkpoint that a concurrent writer may have already produced.
    CreateNew,
    /// Intentionally replace `path` if it already exists. Use only when
    /// overwriting is part of the operation's own contract (e.g.
    /// re-signing an existing file, or regenerating a disposable,
    /// non-chained scratch output).
    Replace,
}

/// Write `contents` to `path` via a same-directory temporary file with a
/// randomized name, `fsync`ed before commit, then either hard-linked
/// (`CommitMode::CreateNew`) or renamed (`CommitMode::Replace`) into
/// place, followed by an `fsync` of the parent directory so the commit
/// itself survives a crash. `file_mode` sets the temporary (and thus
/// final) file's Unix permissions explicitly -- pass the mode the caller
/// actually wants (e.g. `0o600` for secret material, `0o644` for
/// non-secret data that still shouldn't inherit an unreviewed umask).
///
/// `CreateNew` uses `hard_link` rather than `rename` deliberately: a
/// hard-link commit fails atomically if `path` already exists (no
/// separate existence check, so no TOCTOU race between checking and
/// committing), which is exactly the property needed to make two
/// concurrent writers targeting the same new path fail one of them
/// loudly instead of letting the last rename silently win.
pub fn write_via_temp(
    path: &Path,
    contents: &[u8],
    file_mode: u32,
    mode: CommitMode,
) -> Result<()> {
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).with_context(|| format!("creating {dir:?}"))?;

    let mut rng = rand::rngs::OsRng;
    let tmp_name = format!(
        ".{}.tmp-{}-{:016x}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file"),
        std::process::id(),
        rng.next_u64()
    );
    let tmp_path = dir.join(tmp_name);

    let result = (|| -> Result<()> {
        use std::io::Write;

        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(file_mode);
        }
        let mut file = options
            .open(&tmp_path)
            .with_context(|| format!("creating {tmp_path:?}"))?;
        file.write_all(contents)
            .with_context(|| format!("writing {tmp_path:?}"))?;
        file.sync_all()
            .with_context(|| format!("syncing {tmp_path:?}"))?;
        drop(file);

        match mode {
            CommitMode::CreateNew => {
                fs::hard_link(&tmp_path, path).with_context(|| {
                    format!(
                        "committing new file {path:?} without replacement (it may already exist)"
                    )
                })?;
                // The destination is committed once hard_link succeeds. A
                // failure to remove the temporary name must not report the
                // whole write as failed after the durable destination
                // already exists; leave cleanup as best effort.
                let _ = fs::remove_file(&tmp_path);
            }
            CommitMode::Replace => {
                fs::rename(&tmp_path, path)
                    .with_context(|| format!("renaming {tmp_path:?} -> {path:?}"))?;
            }
        }

        sync_parent_directory(dir)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

fn sync_parent_directory(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(dir)
            .with_context(|| format!("opening parent directory {dir:?} for sync"))?
            .sync_all()
            .with_context(|| format!("syncing parent directory {dir:?}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_new_fails_when_destination_already_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("checkpoint.json");
        write_via_temp(&path, b"first", 0o644, CommitMode::CreateNew).expect("first write");
        let second = write_via_temp(&path, b"second", 0o644, CommitMode::CreateNew);
        assert!(
            second.is_err(),
            "a second CreateNew commit to the same path must fail, not silently win"
        );
        assert_eq!(
            fs::read(&path).expect("read"),
            b"first",
            "the losing writer must not have clobbered the winner's content"
        );
    }

    #[test]
    fn create_new_succeeds_for_a_fresh_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("checkpoint.json");
        write_via_temp(&path, b"contents", 0o644, CommitMode::CreateNew).expect("write");
        assert_eq!(fs::read(&path).expect("read"), b"contents");
    }

    #[test]
    fn replace_overwrites_an_existing_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scratch.json");
        write_via_temp(&path, b"first", 0o644, CommitMode::Replace).expect("first write");
        write_via_temp(&path, b"second", 0o644, CommitMode::Replace).expect("second write");
        assert_eq!(fs::read(&path).expect("read"), b"second");
    }

    #[test]
    fn no_temporary_file_survives_a_successful_commit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        write_via_temp(&path, b"contents", 0o644, CommitMode::CreateNew).expect("write");
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name() != "state.json")
            .collect();
        assert!(
            leftovers.is_empty(),
            "expected no leftover temp files, found {leftovers:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn explicit_file_mode_is_applied() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.json");
        write_via_temp(&path, b"contents", 0o600, CommitMode::CreateNew).expect("write");
        let permissions = fs::metadata(&path).expect("metadata").permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }
}
