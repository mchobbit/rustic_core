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
    let restore = || -> Result<()> {
        let plan = repo.prepare_restore(&restore_opts, ls.clone(), &dest, false)?;
        _ = repo.restore(plan, &restore_opts, ls.clone(), &dest)?;
        Ok(())
    };
    restore()?;

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

    restore()?;
    assert_eq!(fs::metadata(&hardlink)?.ino(), linked_meta.ino());

    fs::remove_file(&hardlink)?;
    fs::write(&hardlink, "stale")?;
    restore()?;
    assert_eq!(fs::metadata(&hardlink)?.ino(), linked_meta.ino());

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
    _ = repo.restore(plan, &opts, ls, &dest)?;
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

    // --dry-run over the same file of holes: BackOtter's snapshot would
    // fill them, so it counts as a file to modify (as in BackOtter's
    // restic); a stock rustic snapshot leaves it as it is. Nothing is
    // filled.
    let restore_dir = tempdir()?;
    let test = restore_dir.path().join("test");
    fs::create_dir(&test)?;
    File::create(test.join("zeros"))?.set_len(u64::try_from(zeros.len())?)?;
    let dry_run_modify = |opts: RestoreOptions| -> Result<u64> {
        let node = repo.node_from_snapshot_path("latest", |_| true)?;
        let dest = LocalDestination::new(
            restore_dir.path().to_str().expect("restore path is valid utf-8"),
            true,
            false,
        )?;
        let ls = repo.ls(&node, &LsOptions::default())?;
        Ok(repo.prepare_restore(&opts, ls, &dest, true)?.stats.files.modify)
    };
    let snap = repo.get_snapshot_from_str("latest", |_| true)?;
    let bko = RestoreOptions::default().origin(SnapshotOrigin::of(&snap));
    // Holes are filled on Linux only.
    let fills = u64::from(cfg!(any(target_os = "linux", target_os = "android")));
    assert_eq!(dry_run_modify(bko)?, fills, "BackOtter's snapshot");
    assert_eq!(dry_run_modify(RestoreOptions::default())?, 0, "stock snapshot");
    assert!(!allocated(&test.join("zeros"))?, "zeros: allocated by --dry-run");

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

/// BackOtter: what `--delete` can't remove (an extra directory whose
/// entries it may not remove) is counted in the plan's statistics
/// (`RestoreStats::errors`), as BackOtter's restic counts it as an error
/// (exit 1); the restore itself then fails at nothing
/// (`RestoreOutcome::errors`). A plain restore counts none. Not as root,
/// who may remove it.
#[rstest]
#[cfg(not(windows))]
fn test_restore_counts_what_delete_left(set_up_repo: Result<RepoOpen>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    use rustic_core::PathList;

    if nix::unistd::geteuid().is_root() {
        return Ok(());
    }
    let source = tempdir()?;
    fs::write(source.path().join("a"), "a")?;
    let repo = set_up_repo?.to_indexed_ids()?;
    let opts = BackupOptions::default().as_path(PathBuf::from_str("test")?);
    let paths = PathList::from_iter(Some(source.path().to_path_buf()));
    let _snapshot = repo.backup(&opts, &paths, SnapshotFile::default())?;
    let repo = repo.to_indexed()?;
    let node = repo.node_from_snapshot_path("latest:test", |_| true)?;
    let ls_opts = LsOptions::default();

    let restore = |dir: &Path, opts: RestoreOptions| -> Result<(u64, u64)> {
        let dest = LocalDestination::new(dir.to_str().unwrap(), true, false)?;
        let ls = repo.ls(&node, &ls_opts)?;
        let plan = repo.prepare_restore(&opts, ls.clone(), &dest, false)?;
        let planned = plan.stats.errors;
        let outcome = repo.restore(plan, &opts, ls, &dest)?;
        Ok((planned, outcome.errors))
    };

    let plain = tempdir()?;
    assert_eq!(restore(plain.path(), RestoreOptions::default())?, (0, 0));

    let target = tempdir()?;
    let extra = target.path().join("extra");
    fs::create_dir(&extra)?;
    fs::write(extra.join("x"), "x")?;
    fs::set_permissions(&extra, fs::Permissions::from_mode(0o555))?;
    let result = restore(target.path(), RestoreOptions::default().delete(true));
    fs::set_permissions(&extra, fs::Permissions::from_mode(0o755))?;
    assert_eq!(result?, (1, 0));
    assert_eq!(fs::read_to_string(target.path().join("a"))?, "a");
    Ok(())
}

/// BackOtter: the kept `fsx_xflags` (realtime too) of the file at `path` on
/// XFS, as `xfs_io`'s stat shows them.
#[cfg(target_os = "linux")]
fn xfs_xflags(path: &Path) -> u64 {
    let out = std::process::Command::new("xfs_io").args(["-r", "-c", "stat"]).arg(path).output().unwrap();
    let out = String::from_utf8_lossy(&out.stdout);
    let x = out
        .lines()
        .find_map(|l| l.strip_prefix("fsxattr.xflags = 0x"))
        .and_then(|h| u64::from_str_radix(h.split_whitespace().next()?, 16).ok())
        .unwrap_or_else(|| panic!("no xflags for {}: {out}", path.display()));
    x & 0x1_7d01
}

/// BackOtter: a loop XFS, mounted until dropped.
#[cfg(target_os = "linux")]
struct LoopXfs {
    _scratch: tempfile::TempDir,
    mnt: PathBuf,
}

#[cfg(target_os = "linux")]
impl Drop for LoopXfs {
    fn drop(&mut self) {
        _ = std::process::Command::new("umount").arg(&self.mnt).status();
    }
}

/// BackOtter: whether `cmd` runs and succeeds.
#[cfg(target_os = "linux")]
fn ok(cmd: &mut std::process::Command) -> bool {
    cmd.output().is_ok_and(|o| o.status.success())
}

/// BackOtter: with root, a new loop XFS of 320 MiB; None, with why, where
/// it can't be had.
#[cfg(target_os = "linux")]
fn loop_xfs() -> Result<Option<LoopXfs>> {
    use std::process::Command;

    if !nix::unistd::geteuid().is_root() {
        eprintln!("skipped: needs root, to mount a file system");
        return Ok(None);
    }
    let scratch = tempdir()?;
    let (img, mnt) = (scratch.path().join("fs.img"), scratch.path().join("mnt"));
    File::create(&img)?.set_len(320 << 20)?;
    fs::create_dir(&mnt)?;
    if !ok(Command::new("mkfs.xfs").args(["-q", "-f"]).arg(&img)) {
        eprintln!("skipped: no mkfs.xfs");
        return Ok(None);
    }
    if !ok(Command::new("mount").args(["-o", "loop"]).arg(&img).arg(&mnt)) {
        eprintln!("skipped: mount failed");
        return Ok(None);
    }
    Ok(Some(LoopXfs { _scratch: scratch, mnt }))
}

/// BackOtter: a snapshot ("test") of dir, holding in and sub/f, and plain,
/// holding sub; restored through [`with_xfs_options`], dir has XFS options.
#[cfg(target_os = "linux")]
fn xfs_snapshot(
    set_up_repo: Result<RepoOpen>,
) -> Result<rustic_core::Repository<rustic_core::IndexedFullStatus>> {
    use rustic_core::PathList;

    let source = tempdir()?;
    fs::create_dir_all(source.path().join("dir/sub"))?;
    fs::write(source.path().join("dir/in"), "in")?;
    fs::write(source.path().join("dir/sub/f"), "f")?;
    fs::create_dir_all(source.path().join("plain/sub"))?;
    let repo = set_up_repo?.to_indexed_ids()?;
    let opts = BackupOptions::default().as_path(PathBuf::from_str("test")?);
    let paths = PathList::from_iter(Some(source.path().to_path_buf()));
    let _snapshot = repo.backup(&opts, &paths, SnapshotFile::default())?;
    Ok(repo.to_indexed()?)
}

/// BackOtter: `node` as restic or rustic-bko would back it up from XFS: the
/// directory dir with realtime inheritance, its extent size hint's
/// inheritance and filestream, and a 2 MiB hint.
#[cfg(target_os = "linux")]
fn with_xfs_options(mut node: rustic_core::repofile::Node) -> rustic_core::repofile::Node {
    if node.is_dir() && &*node.name() == std::ffi::OsStr::new("dir") {
        let opts = std::collections::BTreeMap::from([("extsize", 2_u32 << 20), ("xflags", 0x5100)]);
        node.meta.generic_attributes.set("linux.xfs_options", &opts).unwrap();
    }
    node
}

/// BackOtter: with root, on a loop XFS: a directory's XFS options
/// (`linux.xfs_options`, realtime inheritance among them) go on in the last
/// pass, so that the entries restored in it, a file and a directory,
/// inherit none of them; and restoring again over that tree, the entries
/// the restore makes in it inherit none either, as in a new target. A
/// directory whose node has none keeps those it had. As in BackOtter's
/// restic (`TestRestorerXFSOptions`, `TestRestorerXFSOptionsOverExisting`).
#[rstest]
#[cfg(target_os = "linux")]
fn test_restore_xfs_options(set_up_repo: Result<RepoOpen>) -> Result<()> {
    use std::process::Command;

    let Some(xfs) = loop_xfs()? else { return Ok(()) };
    let repo = xfs_snapshot(set_up_repo)?;
    let dst = xfs.mnt.join("dst");
    restore_with(&repo, &dst, RestoreOptions::default(), with_xfs_options)?;
    let t = dst.join("test");
    for (name, want) in [("dir", 0x5100), ("dir/in", 0), ("dir/sub", 0), ("dir/sub/f", 0), ("plain", 0)] {
        assert_eq!(xfs_xflags(&t.join(name)), want, "{name}");
    }

    // Again over that tree, with what it holds made anew, and realtime
    // inheritance on a directory whose node has no XFS options.
    for name in ["dir/in", "dir/sub", "plain/sub"] {
        let p = t.join(name);
        if p.is_dir() { fs::remove_dir_all(p)? } else { fs::remove_file(p)? }
    }
    assert!(ok(Command::new("xfs_io").args(["-c", "chattr +t"]).arg(t.join("plain"))));
    restore_with(&repo, &dst, RestoreOptions::default(), with_xfs_options)?;
    for (name, want) in
        [("dir", 0x5100), ("dir/in", 0), ("dir/sub", 0), ("dir/sub/f", 0), ("plain", 0x100), ("plain/sub", 0)]
    {
        assert_eq!(xfs_xflags(&t.join(name)), want, "again: {name}");
    }
    Ok(())
}

/// BackOtter: with root, on a loop XFS: a restore that stops between
/// planning and the late pass puts back the XFS options planning took off
/// the directories there, also those of a directory whose node has none
/// (plain's realtime inheritance), which the snapshot can't give back: a
/// plan dropped without being restored (`--dry-run-warmup`, an error in
/// `warm_up_wait`), and a restore whose node stream fails. As in
/// BackOtter's restic (`TestRestorerXFSOptionsInterrupted`).
#[rstest]
#[cfg(target_os = "linux")]
fn test_restore_xfs_options_stopped(set_up_repo: Result<RepoOpen>) -> Result<()> {
    use std::process::Command;

    use rustic_core::{ErrorKind, RusticError};

    let Some(xfs) = loop_xfs()? else { return Ok(()) };
    let repo = xfs_snapshot(set_up_repo)?;
    let dst = xfs.mnt.join("dst");
    restore_with(&repo, &dst, RestoreOptions::default(), with_xfs_options)?;
    let t = dst.join("test");
    assert!(ok(Command::new("xfs_io").args(["-c", "chattr +t"]).arg(t.join("plain"))));
    let check = |when: &str| {
        for (name, want) in [("dir", 0x5100), ("plain", 0x100)] {
            assert_eq!(xfs_xflags(&t.join(name)), want, "{when}: {name}");
        }
    };

    let node = repo.node_from_snapshot_path("latest", |_| true)?;
    let dest = LocalDestination::new(dst.to_str().expect("restore path is valid utf-8"), true, false)?;
    let ls = repo.ls(&node, &LsOptions::default())?.map(|item| item.map(|(p, n)| (p, with_xfs_options(n))));
    let opts = RestoreOptions::default();

    // Planned, and not restored.
    let plan = repo.prepare_restore(&opts, ls.clone(), &dest, false)?;
    assert_eq!(xfs_xflags(&t.join("plain")), 0, "planned: plain's cleared");
    drop(plan);
    check("plan dropped");

    // Restored with a node stream that fails after its first two nodes.
    let plan = repo.prepare_restore(&opts, ls.clone(), &dest, false)?;
    let failing = ls
        .take(2)
        .chain(std::iter::once(Err(RusticError::new(ErrorKind::Internal, "stopped by the test"))));
    assert!(repo.restore(plan, &opts, failing, &dest).is_err(), "the failing restore succeeded");
    check("restore failed");

    restore_with(&repo, &dst, opts, with_xfs_options)?;
    check("restored again");
    Ok(())
}

/// BackOtter: with root, on a loop XFS: the destination, which keeps its own
/// metadata (a whole snapshot, which has no node of its own), loses its XFS
/// options while the restore makes entries in it, as any directory there,
/// so that they inherit none of them, and gets them back at the end. As in
/// BackOtter's restic (`TestRestorerXFSOptionsTarget`).
#[rstest]
#[cfg(target_os = "linux")]
fn test_restore_xfs_options_destination(set_up_repo: Result<RepoOpen>) -> Result<()> {
    use std::process::Command;

    let Some(xfs) = loop_xfs()? else { return Ok(()) };
    let repo = xfs_snapshot(set_up_repo)?;
    let dst = xfs.mnt.join("dst");
    fs::create_dir(&dst)?;
    fs::write(dst.join("keep"), "keep")?;
    assert!(ok(Command::new("xfs_io").args(["-c", "extsize 2m", "-c", "chattr +tS"]).arg(&dst)));
    assert_eq!(xfs_xflags(&dst), 0x5100, "the destination before");
    restore_with(&repo, &dst, RestoreOptions::default(), with_xfs_options)?;
    for (name, want) in [
        ("", 0x5100),
        ("test", 0),
        ("test/dir", 0x5100),
        ("test/dir/in", 0),
        ("test/plain", 0),
        ("test/plain/sub", 0),
    ] {
        assert_eq!(xfs_xflags(&dst.join(name)), want, "{name:?}");
    }
    Ok(())
}

/// BackOtter: `--clone-from` with the destination inside the directory
/// cloned from, as bko-holt restores a snapper snapshot: `@/.snapshots/1/snapshot`,
/// seeded from `@` (a btrfs snapshot), restored `--exact` with `@` to clone
/// from. A seeded file of the snapshot's size but other contents is restored
/// with the snapshot's contents, never cloned from itself (which emptied it
/// where the file system clones, btrfs and XFS: a 0-byte file with the
/// snapshot's mtime), and the destination's seed is offered to nothing: a
/// file elsewhere in `@` with those contents is cloned instead. The clone
/// itself needs a file system that clones (`TMPDIR` on btrfs or XFS);
/// elsewhere the files are written and the restore is still checked.
#[rstest]
#[cfg(not(windows))]
fn test_restore_clone_from_holding_the_destination(set_up_repo: Result<RepoOpen>) -> Result<()> {
    use rustic_core::PathList;

    let (live, snap, same) = (&b"live @ content"[..], &b"snapshot 12345"[..], &b"same contents."[..]);
    let (only_live, only_snap) = (&b"live only 1234"[..], &b"in snapshot 99"[..]);
    let source = tempdir()?;
    let (s, ss) = (source.path(), source.path().join(".snapshots/1/snapshot"));
    fs::create_dir_all(&ss)?;
    for (name, at, in_snap) in [("diff", live, snap), ("same", same, same), ("moved", only_live, only_snap)] {
        fs::write(s.join(name), at)?;
        fs::write(ss.join(name), in_snap)?;
    }
    // Elsewhere in @, the contents only the snapshot's "moved" has.
    fs::write(s.join("other"), only_snap)?;
    let repo = set_up_repo?.to_indexed_ids()?;
    let opts = BackupOptions::default().as_path(PathBuf::from_str("test")?);
    let _snapshot = repo.backup(&opts, &PathList::from_iter(Some(s.to_path_buf())), SnapshotFile::default())?;
    let repo = repo.to_indexed()?;

    // @ restored, and the snapshot seeded from it.
    let top = tempdir()?;
    let at = top.path().join("at");
    restore_to(&repo, &at, RestoreOptions::default())?;
    let at = at.join("test");
    let dst = at.join(".snapshots/1/snapshot");
    for name in ["diff", "same", "moved"] {
        _ = fs::copy(at.join(name), dst.join(name))?;
    }

    let from = repo.node_from_snapshot_path("latest:test", |_| true)?;
    let node = repo.node_from_snapshot_path("latest:test/.snapshots/1/snapshot", |_| true)?;
    let ls = repo.ls(&node, &LsOptions::default())?;
    let content = |name: &str| -> Result<Vec<rustic_core::DataId>> {
        let mut found = None;
        for item in ls.clone() {
            let (p, n) = item?;
            if p == Path::new(name) {
                found = n.content;
            }
        }
        Ok(found.expect("the file is in the snapshot"))
    };
    let sources = repo.clone_sources(&from, &at, Some(&dst))?;
    assert_eq!(sources.get(&content("diff")?), None, "the destination's own seed is offered");
    assert_eq!(sources.get(&content("moved")?), Some(at.join("other").as_path()));

    let dest = LocalDestination::new(dst.to_str().expect("restore path is valid utf-8"), true, false)?
        .with_clone_sources(sources);
    let opts = RestoreOptions::default().exact(true);
    let plan = repo.prepare_restore(&opts, ls.clone(), &dest, false)?;
    _ = repo.restore(plan, &opts, ls, &dest)?;
    for (name, want) in [("diff", snap), ("same", same), ("moved", only_snap)] {
        assert_eq!(fs::read(dst.join(name))?, want, "{name}");
    }
    for (name, want) in [("diff", live), ("same", same), ("moved", only_live), ("other", only_snap)] {
        assert_eq!(fs::read(at.join(name))?, want, "@'s {name}");
    }
    Ok(())
}
