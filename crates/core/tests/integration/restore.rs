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
    BackupOptions, LocalDestination, LsOptions, RestoreOptions, SnapshotOrigin,
    repofile::SnapshotFile,
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

    // BackOtter: again, over the complete earlier restore, where the link is
    // already, and over one where another file has its name, and a file the
    // symlink's.
    restore_to(&repo, restore_dir.path(), restore_opts)?;
    assert_eq!(fs::read_link(&symlink)?, PathBuf::from("testfile"));
    fs::remove_file(&hardlink)?;
    fs::write(&hardlink, "another file")?;
    fs::remove_file(&symlink)?;
    fs::write(&symlink, "a file")?;
    restore_to(&repo, restore_dir.path(), restore_opts)?;
    assert_eq!(fs::read_link(&symlink)?, PathBuf::from("testfile"));
    let hardlink_meta = fs::metadata(&hardlink)?;
    let linked_meta = fs::metadata(&linked)?;
    assert_eq!(hardlink_meta.ino(), linked_meta.ino());
    assert_eq!(linked_meta.nlink(), 2);
    assert_eq!(fs::read_to_string(&hardlink)?, fs::read_to_string(&linked)?);

    Ok(())
}

/// BackOtter: restores what the repository's latest snapshot holds into
/// `dir`, with `opts` and the snapshot's origin, as rustic's restore does.
#[cfg(not(windows))]
fn restore_to(
    repo: &rustic_core::Repository<impl rustic_core::IndexedFull>,
    dir: &Path,
    opts: RestoreOptions,
) -> Result<()> {
    let snap = repo.get_snapshot_from_str("latest", |_| true)?;
    restore_with(repo, dir, opts.origin(SnapshotOrigin::of(&snap)), |node| node)
}

/// BackOtter: restores what the repository's latest snapshot holds into
/// `dir`, with `opts` as they are, each node changed by `change` first (to
/// make it as another program would have written it).
#[cfg(not(windows))]
fn restore_with(
    repo: &rustic_core::Repository<impl rustic_core::IndexedFull>,
    dir: &Path,
    opts: RestoreOptions,
    change: impl Fn(rustic_core::repofile::Node) -> rustic_core::repofile::Node + Copy,
) -> Result<()> {
    let node = repo.node_from_snapshot_path("latest", |_| true)?;
    let ls_opts = LsOptions::default();
    let dest = LocalDestination::new(
        dir.to_str().expect("restore path is valid utf-8"),
        true,
        !node.is_dir(),
    )?;
    let ls = repo.ls(&node, &ls_opts)?.map(move |item| item.map(|(p, n)| (p, change(n))));
    let plan = repo.prepare_restore(&opts, ls.clone(), &dest, false)?;
    repo.restore(plan, &opts, ls, &dest)?;
    Ok(())
}

/// BackOtter: whether the file at `path` has all its blocks.
#[cfg(not(windows))]
fn allocated(path: &Path) -> Result<bool> {
    let m = fs::metadata(path)?;
    Ok(m.blocks() * 512 >= m.len())
}

/// BackOtter: a file with holes is marked (`unix.sparse`) and comes back
/// with holes into a new file; any other file, or one restored over an
/// existing file, comes back allocated, zeros and all.
#[rstest]
#[cfg(not(windows))]
#[allow(clippy::too_many_lines)]
fn test_restore_sparse(set_up_repo: Result<RepoOpen>) -> Result<()> {
    use rustic_core::SparseRestore;

    // Data around 8 MiB of zeros, which the chunker cuts into zero chunks.
    let data = vec![1_u8; 1 << 20];
    let zeros = vec![0_u8; 8 << 20];
    let source = tempdir()?;
    let write_sparse = |path: &Path| -> Result<()> {
        let mut f = File::create(path)?;
        f.write_all(&data)?;
        _ = f.seek(SeekFrom::Current(i64::try_from(zeros.len())?))?;
        f.write_all(&data)?;
        f.sync_all()?;
        Ok(())
    };
    let write_full = |path: &Path, parts: &[&[u8]]| -> Result<()> {
        let mut f = File::create(path)?;
        for part in parts {
            f.write_all(part)?;
        }
        f.sync_all()?;
        Ok(())
    };
    write_sparse(&source.path().join("sparse"))?;
    write_full(&source.path().join("full"), &[&data, &zeros, &data])?;
    write_full(&source.path().join("zeros"), &[&zeros])?;
    write_full(&source.path().join("trailing"), &[&data, &zeros])?;
    fs::create_dir(source.path().join("linked"))?;
    write_sparse(&source.path().join("linked/a"))?;
    fs::hard_link(source.path().join("linked/a"), source.path().join("linked/b"))?;
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
    let mut contents = std::collections::BTreeMap::new();
    for item in repo.ls(&node, &ls_opts)? {
        let (path, node) = item?;
        sparse_marks.push((path.clone(), node.meta.generic_attributes.is_true("unix.sparse")));
        _ = contents.insert(path, node.content);
    }
    // The file read by its data extents has the blobs of the same bytes read
    // plainly.
    let blobs = |name: &str| contents[&PathBuf::from("test").join(name)].clone();
    assert!(blobs("full").is_some_and(|blobs| blobs.len() > 1));
    assert_eq!(blobs("sparse"), blobs("full"));
    assert_eq!(blobs("linked/a"), blobs("full"));
    assert_eq!(
        sparse_marks,
        [
            (PathBuf::from("test"), false),
            (PathBuf::from("test/full"), false),
            (PathBuf::from("test/linked"), false),
            (PathBuf::from("test/linked/a"), true),
            (PathBuf::from("test/linked/b"), true),
            (PathBuf::from("test/sparse"), true),
            (PathBuf::from("test/trailing"), false),
            (PathBuf::from("test/zeros"), false),
        ]
    );
    let sparse_data = [data.as_slice(), &zeros, &data].concat();
    let expected = |name: &str| -> Vec<u8> {
        match name {
            "zeros" => zeros.clone(),
            "trailing" => [data.as_slice(), &zeros].concat(),
            _ => sparse_data.clone(),
        }
    };
    let names = ["sparse", "full", "zeros", "trailing", "linked/a", "linked/b"];
    // Allocation is only certain where the restore can allocate (Linux).
    // Those in neither list have holes and data.
    let check = |dir: &Path, sparse: &[&str], dense: &[&str]| -> Result<()> {
        for name in names {
            let path = dir.join("test").join(name);
            assert!(fs::read(&path)? == expected(name), "{name}: contents differ");
            if sparse.contains(&name) {
                assert!(!allocated(&path)?, "{name}: allocated");
            } else if cfg!(target_os = "linux") && dense.contains(&name) {
                assert!(allocated(&path)?, "{name}: not allocated");
            }
        }
        Ok(())
    };

    // Into new files: those that had holes get them back, the hard links
    // too, and the rest are allocated.
    let restore_dir = tempdir()?;
    restore_to(&repo, restore_dir.path(), RestoreOptions::default())?;
    check(
        restore_dir.path(),
        &["sparse", "linked/a", "linked/b"],
        &["full", "zeros", "trailing"],
    )?;
    let a = fs::metadata(restore_dir.path().join("test/linked/a"))?;
    let b = fs::metadata(restore_dir.path().join("test/linked/b"))?;
    assert_eq!((a.dev(), a.ino()), (b.dev(), b.ino()));

    // --sparse by-content: zeros as holes in every new file.
    let restore_dir = tempdir()?;
    let by_content = RestoreOptions::default().sparse(SparseRestore::ByContent);
    restore_to(&repo, restore_dir.path(), by_content)?;
    check(
        restore_dir.path(),
        &["sparse", "full", "zeros", "linked/a", "linked/b"],
        &[],
    )?;
    // trailing: its zeros are a hole too, but its data takes room.
    assert!(fs::metadata(restore_dir.path().join("test/trailing"))?.blocks() * 512 < 4 << 20);

    // Over existing files: a marked file over one of another content of the
    // same size comes back whole and allocated, and so does an unmarked one
    // over a file of holes, of the same size, and one of the same contents
    // (zeros) left as it is.
    let restore_dir = tempdir()?;
    let test = restore_dir.path().join("test");
    fs::create_dir(&test)?;
    fs::write(test.join("sparse"), vec![0xaa_u8; sparse_data.len()])?;
    File::create(test.join("full"))?.set_len(u64::try_from(sparse_data.len())?)?;
    File::create(test.join("zeros"))?.set_len(u64::try_from(zeros.len())?)?;
    restore_to(&repo, restore_dir.path(), RestoreOptions::default())?;
    check(
        restore_dir.path(),
        &["linked/a", "linked/b"],
        &["sparse", "full", "zeros", "trailing"],
    )?;

    // The same file of holes, left as it is, from a snapshot not
    // BackOtter's (stock rustic's, which marks no file): it keeps its holes,
    // as in stock rustic, which can't tell it had none.
    let restore_dir = tempdir()?;
    let test = restore_dir.path().join("test");
    fs::create_dir(&test)?;
    File::create(test.join("zeros"))?.set_len(u64::try_from(zeros.len())?)?;
    restore_with(&repo, restore_dir.path(), RestoreOptions::default(), |node| node)?;
    assert!(fs::read(test.join("zeros"))? == zeros, "zeros: contents differ");
    assert!(!allocated(&test.join("zeros"))?, "zeros: allocated");

    // Over a symlink where the snapshot has a directory: the symlink is
    // replaced by the directory, as BackOtter's restic does, and nothing is
    // written where it points. The files in it are new, so those marked get
    // their holes.
    let restore_dir = tempdir()?;
    let real = restore_dir.path().join("real");
    fs::create_dir(&real)?;
    let other = vec![0xaa_u8; sparse_data.len()];
    fs::write(real.join("sparse"), &other)?;
    std::os::unix::fs::symlink("real", restore_dir.path().join("test"))?;
    restore_to(&repo, restore_dir.path(), RestoreOptions::default())?;
    assert!(fs::symlink_metadata(restore_dir.path().join("test"))?.is_dir());
    assert!(fs::read(real.join("sparse"))? == other, "written through the symlink");
    assert_eq!(fs::read_dir(&real)?.count(), 1);
    check(
        restore_dir.path(),
        &["sparse", "linked/a", "linked/b"],
        &["full", "zeros", "trailing"],
    )?;

    Ok(())
}

/// BackOtter: a regular file without a mode keeps the mode it is created
/// with (as in stock rustic) where the snapshot doesn't say it had 0: one
/// read from stdin (no inode number), or any in a stock rustic snapshot. A
/// file a restic snapshot has without a mode (restic leaves 0 out) is
/// restored with permissions 0000.
#[rstest]
#[cfg(not(windows))]
fn test_restore_missing_mode(set_up_repo: Result<RepoOpen>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    use rustic_core::{CommandInput, PathList};

    let mode = |path: &Path| -> Result<u32> { Ok(fs::metadata(path)?.permissions().mode() & 0o7777) };

    // stdin, in a snapshot of BackOtter's.
    let repo = set_up_repo?.to_indexed_ids()?;
    let cmd: CommandInput = "echo test".parse()?;
    let opts = BackupOptions::default().stdin_filename("dump.sql").stdin_command(cmd);
    let snap = repo.backup(&opts, &PathList::from_string("-")?, SnapshotFile::default())?;
    assert_eq!(SnapshotOrigin::of(&snap), SnapshotOrigin::BackOtter);
    let repo = repo.to_indexed()?;
    let restore_dir = tempdir()?;
    restore_to(&repo, restore_dir.path(), RestoreOptions::default())?;
    let dump = restore_dir.path().join("dump.sql");
    assert_eq!(fs::read(&dump)?, b"test\n");
    assert_ne!(mode(&dump)? & 0o600, 0, "stdin dump restored as {:o}", mode(&dump)?);

    // A file of a Unix file system, its mode left out as restic leaves 0
    // out: 0000 from restic's snapshot, the creation mode from stock
    // rustic's.
    let source = tempdir()?;
    fs::write(source.path().join("shadow"), b"secret")?;
    let repo = repo.to_indexed_ids()?;
    let opts = BackupOptions::default().as_path(PathBuf::from_str("test")?);
    let paths = PathList::from_iter(Some(source.path().to_path_buf()));
    let _snapshot = repo.backup(&opts, &paths, SnapshotFile::default())?;
    let repo = repo.to_indexed()?;
    let no_mode = |mut node: rustic_core::repofile::Node| {
        if node.is_file() {
            node.meta.mode = None;
        }
        node
    };
    let restic = RestoreOptions::default().origin(SnapshotOrigin::Restic);
    let restore_dir = tempdir()?;
    restore_with(&repo, restore_dir.path(), restic, no_mode)?;
    let shadow = restore_dir.path().join("test/shadow");
    assert_eq!(mode(&shadow)?, 0);
    fs::set_permissions(&shadow, fs::Permissions::from_mode(0o600))?;
    assert_eq!(fs::read(&shadow)?, b"secret");

    let restore_dir = tempdir()?;
    restore_with(&repo, restore_dir.path(), RestoreOptions::default(), no_mode)?;
    let shadow = restore_dir.path().join("test/shadow");
    assert_ne!(mode(&shadow)? & 0o600, 0, "restored as {:o}", mode(&shadow)?);
    Ok(())
}
