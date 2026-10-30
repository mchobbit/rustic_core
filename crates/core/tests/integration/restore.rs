use std::{fs, path::PathBuf, str::FromStr};

#[cfg(not(windows))]
use std::{
    fs::File,
    io::{Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};

use anyhow::Result;
use pretty_assertions::assert_eq;
use rstest::rstest;
use tempfile::tempdir;

use rustic_core::{
    BackupOptions, LocalDestination, LsOptions, RestoreOptions, repofile::SnapshotFile,
};

use super::{RepoOpen, TestSource, set_up_repo, tar_gz_testdata};

#[rstest]
#[cfg(not(windows))]
fn test_restore_preserves_hardlinks(
    tar_gz_testdata: Result<TestSource>,
    set_up_repo: Result<RepoOpen>,
) -> Result<()> {
    let (source, repo) = (tar_gz_testdata?, set_up_repo?.to_indexed_ids()?);

    let opts = BackupOptions::default().as_path(PathBuf::from_str("test")?);
    let _snapshot = repo.backup(&opts, &source.path_list(), SnapshotFile::default())?;

    let repo = repo.to_indexed()?;
    let node = repo.node_from_snapshot_path("latest", |_| true)?;
    let ls_opts = LsOptions::default();
    let ls = repo.ls(&node, &ls_opts)?;

    let restore_dir = tempdir()?;
    let dest = LocalDestination::new(
        restore_dir
            .path()
            .to_str()
            .expect("restore path is valid utf-8"),
        true,
        !node.is_dir(),
    )?;
    let restore_opts = RestoreOptions::default();
    let plan = repo.prepare_restore(&restore_opts, ls.clone(), &dest, false)?;
    repo.restore(plan, &restore_opts, ls, &dest)?;

    let hardlink = restore_dir.path().join("test/0/tests/testfile-hardlink");
    let linked = restore_dir.path().join("test/0/tests/testfile");
    let symlink = restore_dir.path().join("test/0/tests/testfile-symlink");

    let hardlink_meta = fs::metadata(&hardlink)?;
    let linked_meta = fs::metadata(&linked)?;
    assert_eq!(hardlink_meta.dev(), linked_meta.dev());
    assert_eq!(hardlink_meta.ino(), linked_meta.ino());
    assert_eq!(hardlink_meta.nlink(), 2);
    assert_eq!(linked_meta.nlink(), 2);
    assert_eq!(fs::read_to_string(&hardlink)?, fs::read_to_string(&linked)?);
    assert_eq!(fs::read_link(&symlink)?, PathBuf::from("testfile"));

    Ok(())
}

/// BackOtter: a file with holes is marked (`unix.sparse`) and comes back
/// with holes, and one with the same contents written out comes back
/// allocated, zeros and all.
#[rstest]
#[cfg(not(windows))]
fn test_restore_sparse(set_up_repo: Result<RepoOpen>) -> Result<()> {
    let allocated = |path: &Path| -> Result<bool> {
        let m = fs::metadata(path)?;
        Ok(m.blocks() * 512 >= m.len())
    };
    // Data around 8 MiB of zeros, which the chunker cuts into zero chunks.
    let data = vec![1_u8; 1 << 20];
    let zeros = vec![0_u8; 8 << 20];
    let source = tempdir()?;
    let mut f = File::create(source.path().join("sparse"))?;
    f.write_all(&data)?;
    _ = f.seek(SeekFrom::Current(i64::try_from(zeros.len())?))?;
    f.write_all(&data)?;
    f.sync_all()?;
    let mut f = File::create(source.path().join("full"))?;
    for part in [&data, &zeros, &data] {
        f.write_all(part)?;
    }
    f.sync_all()?;
    if allocated(&source.path().join("sparse"))? || !allocated(&source.path().join("full"))? {
        // A file system without holes, or one that compresses.
        return Ok(());
    }

    let repo = set_up_repo?.to_indexed_ids()?;
    let opts = BackupOptions::default().as_path(PathBuf::from_str("test")?);
    let paths = rustic_core::PathList::from_iter(Some(source.path().to_path_buf()));
    let _snapshot = repo.backup(&opts, &paths, SnapshotFile::default())?;

    let repo = repo.to_indexed()?;
    let node = repo.node_from_snapshot_path("latest", |_| true)?;
    let ls_opts = LsOptions::default();
    let mut sparse_marks = Vec::new();
    for item in repo.ls(&node, &ls_opts)? {
        let (path, node) = item?;
        sparse_marks.push((path, node.meta.generic_attributes.is_true("unix.sparse")));
    }
    assert_eq!(
        sparse_marks,
        [
            (PathBuf::from("test"), false),
            (PathBuf::from("test/full"), false),
            (PathBuf::from("test/sparse"), true),
        ]
    );

    let restore_dir = tempdir()?;
    let dest = LocalDestination::new(
        restore_dir
            .path()
            .to_str()
            .expect("restore path is valid utf-8"),
        true,
        !node.is_dir(),
    )?;
    let ls = repo.ls(&node, &ls_opts)?;
    let restore_opts = RestoreOptions::default();
    let plan = repo.prepare_restore(&restore_opts, ls.clone(), &dest, false)?;
    repo.restore(plan, &restore_opts, ls, &dest)?;

    let expected = [data.as_slice(), &zeros, &data].concat();
    for name in ["sparse", "full"] {
        let path = restore_dir.path().join("test").join(name);
        assert!(fs::read(&path)? == expected, "{name}: contents differ");
        assert_eq!(allocated(&path)?, name == "full", "{name}");
    }

    Ok(())
}
