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

/// BackOtter: whether the file at `path` has no hole before its end
/// (`SEEK_HOLE` finds none): every byte written or allocated.
#[cfg(target_os = "linux")]
fn no_hole(path: &Path) -> Result<bool> {
    use nix::unistd::{Whence, lseek};

    let f = File::open(path)?;
    let len = f.metadata()?.len();
    Ok(u64::try_from(lseek(&f, 0, Whence::SeekHole)?)? >= len)
}

/// BackOtter: whether the restore allocates the file at `path` (it
/// preallocates what it writes into, and fills the holes of a file left as
/// it is), as the restore decides it (`osattrs::sparse::allocates_on`,
/// `fills_holes_on`): not on btrfs but for a no-copy-on-write file, nor on
/// bcachefs, nor on ZFS. There a file the restore writes into keeps the
/// holes that blobs of zeros matched, and one left as it is its holes.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn restore_allocates(path: &Path) -> Result<bool> {
    use nix::sys::statfs::{BTRFS_SUPER_MAGIC, fstatfs};
    use std::os::fd::AsRawFd;

    const BCACHEFS_SUPER_MAGIC: u32 = 0xca45_1a4e;
    const ZFS_SUPER_MAGIC: u32 = 0x2fc1_2fc1;
    const FS_NOCOW_FL: u32 = 0x0080_0000;
    let f = File::open(path)?;
    let f_type = fstatfs(&f)?.filesystem_type();
    if f_type == BTRFS_SUPER_MAGIC {
        let mut flags: libc::c_int = 0;
        // SAFETY: FS_IOC_GETFLAGS writes an int to the pointer.
        let got = unsafe { libc::ioctl(f.as_raw_fd(), libc::FS_IOC_GETFLAGS, &raw mut flags) };
        return Ok(got == 0 && u32::from_ne_bytes(flags.to_ne_bytes()) & FS_NOCOW_FL != 0);
    }
    // The low 32 bits, as the restore takes them.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let f_type = f_type.0 as u32;
    Ok(f_type != BCACHEFS_SUPER_MAGIC && f_type != ZFS_SUPER_MAGIC)
}

/// BackOtter: a file with holes is marked (`unix.sparse`) and comes back
/// with holes into a new file; any other file, or one restored over an
/// existing file, comes back allocated, zeros and all (over an existing
/// file, only where the restore allocates: `restore_allocates`).
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
    // The files written in full, zeros and all, preallocated or not (btrfs,
    // bcachefs): no hole before the end (`SEEK_HOLE`). Not those that are
    // only preallocated in part: an unwritten extent can count as a hole.
    let written = |dir: &Path, files: &[&str]| -> Result<()> {
        #[cfg(target_os = "linux")]
        for name in files {
            assert!(no_hole(&dir.join("test").join(name))?, "{name}: has a hole");
        }
        _ = (dir, files);
        Ok(())
    };

    // Into new files: those that had holes get them back, the hard links
    // too, and the rest are allocated and written in full.
    let restore_dir = tempdir()?;
    restore_to(&repo, restore_dir.path(), RestoreOptions::default())?;
    check(
        restore_dir.path(),
        &["sparse", "linked/a", "linked/b"],
        &["full", "zeros", "trailing"],
    )?;
    written(restore_dir.path(), &["full", "zeros", "trailing"])?;
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
    // (zeros) left as it is. Where the restore allocates nothing (btrfs but
    // for a no-copy-on-write file, bcachefs, ZFS), those two keep the holes
    // that its zeros matched, as in BackOtter's restic: only what differs
    // is written.
    let restore_dir = tempdir()?;
    let test = restore_dir.path().join("test");
    fs::create_dir(&test)?;
    fs::write(test.join("sparse"), vec![0xaa_u8; sparse_data.len()])?;
    File::create(test.join("full"))?.set_len(u64::try_from(sparse_data.len())?)?;
    File::create(test.join("zeros"))?.set_len(u64::try_from(zeros.len())?)?;
    #[cfg(target_os = "linux")]
    let allocates = restore_allocates(&test.join("full"))?;
    #[cfg(not(target_os = "linux"))]
    let allocates = true;
    restore_to(&repo, restore_dir.path(), RestoreOptions::default())?;
    if allocates {
        check(
            restore_dir.path(),
            &["linked/a", "linked/b"],
            &["sparse", "full", "zeros", "trailing"],
        )?;
    } else {
        check(
            restore_dir.path(),
            &["full", "zeros", "linked/a", "linked/b"],
            &["sparse", "trailing"],
        )?;
    }
    written(restore_dir.path(), &["sparse", "trailing"])?;

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
    // Holes are filled on Linux only, where the restore allocates.
    let fills = u64::from(cfg!(any(target_os = "linux", target_os = "android")) && allocates);
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
    written(restore_dir.path(), &["full", "zeros", "trailing"])?;

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

/// BackOtter: a loop file system, mounted until dropped.
#[cfg(target_os = "linux")]
struct LoopFs {
    _scratch: tempfile::TempDir,
    mnt: PathBuf,
}

#[cfg(target_os = "linux")]
impl Drop for LoopFs {
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
fn loop_xfs() -> Result<Option<LoopFs>> {
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
    Ok(Some(LoopFs { _scratch: scratch, mnt }))
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

    // Planned, and not restored. A directory loses its options only once
    // the restore makes an entry in it (D8): plain gets its sub again.
    fs::remove_dir(t.join("plain/sub"))?;
    let plan = repo.prepare_restore(&opts, ls.clone(), &dest, false)?;
    assert_eq!(xfs_xflags(&t.join("plain")), 0, "planned: plain's cleared");
    drop(plan);
    check("plan dropped");

    // Restored with a node stream that fails after its first two nodes.
    fs::remove_dir(t.join("plain/sub"))?;
    let plan = repo.prepare_restore(&opts, ls.clone(), &dest, false)?;
    assert_eq!(xfs_xflags(&t.join("plain")), 0, "planned again: plain's cleared");
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

/// BackOtter: backs up `source` (as `test`) into `repo`, for the `--exact`
/// tests below.
#[cfg(not(windows))]
fn backed_up(
    repo: RepoOpen,
    source: &Path,
) -> Result<rustic_core::Repository<impl rustic_core::IndexedFull>> {
    let repo = repo.to_indexed_ids()?;
    let opts = BackupOptions::default().as_path(PathBuf::from_str("test")?);
    let paths = rustic_core::PathList::from_iter(Some(source.to_path_buf()));
    let _snapshot = repo.backup(&opts, &paths, SnapshotFile::default())?;
    Ok(repo.to_indexed()?)
}

/// BackOtter: [`restore_to`], returning the errors the plan and the restore
/// counted (`RestoreStats::errors`, `RestoreOutcome::errors`) together.
#[cfg(not(windows))]
fn restore_counting(
    repo: &rustic_core::Repository<impl rustic_core::IndexedFull>,
    dir: &Path,
    opts: RestoreOptions,
) -> Result<u64> {
    let snap = repo.get_snapshot_from_str("latest", |_| true)?;
    let opts = opts.origin(SnapshotOrigin::of(&snap));
    let node = repo.node_from_snapshot_path("latest", |_| true)?;
    let dest = LocalDestination::new(dir.to_str().expect("utf-8"), true, false)?;
    let ls = repo.ls(&node, &LsOptions::default())?;
    let plan = repo.prepare_restore(&opts, ls.clone(), &dest, false)?;
    let planned = plan.stats.errors;
    let outcome = repo.restore(plan, &opts, ls, &dest)?;
    Ok(planned + outcome.errors)
}

/// BackOtter: the inode and change time of every regular file below `dir`,
/// by path. Not directories or symlinks: listing one, or reading its target,
/// moves its atime on a file system mounted `relatime` (TMPDIR's tmpfs)
/// whatever it is, and an `--exact` restore then sets it again (exact-rt.sh
/// mounts noatime); a regular file is read with `O_NOATIME`.
#[cfg(not(windows))]
fn inodes(dir: &Path) -> Result<std::collections::BTreeMap<PathBuf, (u64, i64, i64)>> {
    let mut seen = std::collections::BTreeMap::new();
    for entry in walkdir::WalkDir::new(dir).min_depth(1) {
        let entry = entry?;
        let m = fs::symlink_metadata(entry.path())?;
        if !m.is_file() {
            continue;
        }
        _ = seen.insert(entry.path().to_path_buf(), (m.ino(), m.ctime(), m.ctime_nsec()));
    }
    Ok(seen)
}

/// BackOtter (D4): a second `--exact` restore of the same snapshot changes
/// no file: no inode, no change time, the hard-link group's either (it is
/// already exactly the snapshot's, and keeps its inode). Its atimes are
/// after the restore's change times, which `relatime` (TMPDIR's tmpfs)
/// doesn't move on a read (there is none: `O_NOATIME`). On NetBSD, whose
/// FFS moves them on the reads that verify the contents, they are put back
/// alone, which leaves the change times.
#[rstest]
#[cfg(not(windows))]
fn test_restore_exact_twice_changes_nothing(set_up_repo: Result<RepoOpen>) -> Result<()> {
    let source = tempdir()?;
    let s = source.path();
    fs::create_dir(s.join("d"))?;
    fs::write(s.join("d/a"), "linked")?;
    fs::hard_link(s.join("d/a"), s.join("d/b"))?;
    fs::write(s.join("c"), "c")?;
    fs::write(s.join("e"), "")?;
    std::os::unix::fs::symlink("c", s.join("s"))?;
    let repo = backed_up(set_up_repo?, s)?;
    let target = tempdir()?;
    let exact = RestoreOptions::default().exact(true).numeric_id(true);
    let late_atime = |mut node: rustic_core::repofile::Node| {
        node.meta.atime = Some(jiff::Timestamp::from_second(4_100_000_000).expect("2099"));
        node
    };
    let snap = repo.get_snapshot_from_str("latest", |_| true)?;
    let exact = exact.origin(SnapshotOrigin::of(&snap));
    restore_with(&repo, target.path(), exact, late_atime)?;
    let before = inodes(target.path())?;
    let (a, b) = (target.path().join("test/d/a"), target.path().join("test/d/b"));
    assert_eq!(fs::metadata(&a)?.ino(), fs::metadata(&b)?.ino());
    std::thread::sleep(std::time::Duration::from_millis(20));
    restore_with(&repo, target.path(), exact, late_atime)?;
    assert_eq!(inodes(target.path())?, before);
    assert_eq!(fs::read_to_string(&b)?, "linked");
    Ok(())
}

/// BackOtter (D1): `--exact` breaking a hard link never opens an entry
/// named `.bko-exact-NAME`: a symlink of the snapshot's to a file outside
/// the destination isn't followed (the old fixed temporary name truncated
/// what it pointed at), and a regular file of the snapshot's by that name
/// keeps its contents.
#[rstest]
#[cfg(not(windows))]
fn test_restore_exact_temp_name_is_no_entry(set_up_repo: Result<RepoOpen>) -> Result<()> {
    let outside = tempdir()?;
    let victim = outside.path().join("victim");
    fs::write(&victim, "outside the destination")?;
    let source = tempdir()?;
    let s = source.path();
    fs::write(s.join("foo"), "snapshot foo")?;
    std::os::unix::fs::symlink(&victim, s.join(".bko-exact-foo"))?;
    fs::write(s.join("baz"), "snapshot baz")?;
    fs::write(s.join(".bko-exact-baz"), "a file of the snapshot's")?;
    let repo = backed_up(set_up_repo?, s)?;
    let target = tempdir()?;
    restore_to(&repo, target.path(), RestoreOptions::default())?;
    let t = target.path().join("test");
    // Each file shares its inode with a name outside the destination.
    fs::hard_link(t.join("foo"), outside.path().join("foo"))?;
    fs::hard_link(t.join("baz"), outside.path().join("baz"))?;
    let errors = restore_counting(&repo, target.path(), RestoreOptions::default().exact(true))?;
    assert_eq!(errors, 0);
    assert_eq!(fs::read_to_string(&victim)?, "outside the destination");
    assert_eq!(fs::read_link(t.join(".bko-exact-foo"))?, victim);
    assert_eq!(fs::read_to_string(t.join(".bko-exact-baz"))?, "a file of the snapshot's");
    for name in ["foo", "baz"] {
        assert_eq!(fs::read_to_string(t.join(name))?, format!("snapshot {name}"));
        assert_eq!(fs::read_to_string(outside.path().join(name))?, format!("snapshot {name}"));
        assert_eq!(fs::metadata(t.join(name))?.nlink(), 1, "{name}'s link not broken");
    }
    let names: Vec<_> = fs::read_dir(&t)?.map(|e| e.map(|e| e.file_name())).collect::<Result<_, _>>()?;
    assert_eq!(names.len(), 4, "{names:?}");
    Ok(())
}

/// BackOtter (D2, E1): a file whose hard link `--exact` can't break (its
/// directory refuses the removal, not running as root) is an error and is
/// left exactly as it is, contents and all, which its other names, outside
/// the destination too, share; the snapshot's other name for it isn't
/// linked to it (an error), and the restore goes on: a file after it gets
/// its metadata. Not as root, who may remove it.
#[rstest]
#[cfg(not(windows))]
fn test_restore_exact_unbroken_link_left_alone(set_up_repo: Result<RepoOpen>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if nix::unistd::geteuid().is_root() {
        return Ok(());
    }
    let source = tempdir()?;
    let s = source.path();
    fs::create_dir(s.join("d"))?;
    fs::write(s.join("d/foo"), "snapshot")?;
    fs::hard_link(s.join("d/foo"), s.join("d/foo2"))?;
    fs::write(s.join("z"), "z")?;
    let repo = backed_up(set_up_repo?, s)?;
    let target = tempdir()?;
    restore_to(&repo, target.path(), RestoreOptions::default())?;
    let t = target.path().join("test");
    let outside = tempdir()?;
    fs::remove_file(t.join("d/foo2"))?;
    fs::remove_file(t.join("d/foo"))?;
    fs::write(t.join("d/foo"), "old")?;
    fs::hard_link(t.join("d/foo"), outside.path().join("o"))?;
    let z_mtime = fs::metadata(s.join("z"))?.mtime();
    filetime::set_file_mtime(t.join("z"), filetime::FileTime::from_unix_time(1, 0))?;
    fs::set_permissions(t.join("d"), fs::Permissions::from_mode(0o555))?;
    let result = restore_counting(&repo, target.path(), RestoreOptions::default().exact(true));
    fs::set_permissions(t.join("d"), fs::Permissions::from_mode(0o755))?;
    assert!(result? >= 2, "the link not broken and the name not linked are errors");
    assert_eq!(fs::read_to_string(t.join("d/foo"))?, "old");
    assert_eq!(fs::read_to_string(outside.path().join("o"))?, "old");
    assert!(!t.join("d/foo2").exists());
    assert_eq!(fs::metadata(t.join("z"))?.mtime(), z_mtime);
    Ok(())
}

/// BackOtter (E1): a hard link the metadata pass can't make (its directory
/// refuses it, not running as root) is an error of its own, and the
/// restore goes on: it used to stop there, leaving every entry after it
/// without its metadata and the late flags pass undone.
#[rstest]
#[cfg(not(windows))]
fn test_restore_link_failure_goes_on(set_up_repo: Result<RepoOpen>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if nix::unistd::geteuid().is_root() {
        return Ok(());
    }
    let source = tempdir()?;
    let s = source.path();
    fs::create_dir(s.join("x"))?;
    fs::create_dir(s.join("y"))?;
    fs::write(s.join("x/a"), "a")?;
    fs::hard_link(s.join("x/a"), s.join("y/b"))?;
    fs::write(s.join("z"), "z")?;
    let repo = backed_up(set_up_repo?, s)?;
    let target = tempdir()?;
    restore_to(&repo, target.path(), RestoreOptions::default())?;
    let t = target.path().join("test");
    fs::remove_file(t.join("y/b"))?;
    let z_mtime = fs::metadata(s.join("z"))?.mtime();
    filetime::set_file_mtime(t.join("z"), filetime::FileTime::from_unix_time(1, 0))?;
    fs::set_permissions(t.join("y"), fs::Permissions::from_mode(0o555))?;
    let result = restore_counting(&repo, target.path(), RestoreOptions::default());
    fs::set_permissions(t.join("y"), fs::Permissions::from_mode(0o755))?;
    assert!(result? >= 1);
    assert_eq!(fs::metadata(t.join("z"))?.mtime(), z_mtime);
    Ok(())
}

/// BackOtter: whether `chattr ATTRS path` worked: setting `i` or `a` takes
/// root and a file system with them.
#[cfg(target_os = "linux")]
fn chattr(attrs: &str, path: &Path) -> bool {
    std::process::Command::new("chattr")
        .arg(attrs)
        .arg(path)
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// BackOtter: whether the file at `path` is immutable (`lsattr`).
#[cfg(target_os = "linux")]
fn immutable(path: &Path) -> bool {
    has_attr(path, 'i')
}

/// BackOtter: whether the file at `path` has the flag `attr` (`lsattr`).
#[cfg(target_os = "linux")]
fn has_attr(path: &Path, attr: char) -> bool {
    std::process::Command::new("lsattr")
        .arg("-d")
        .arg(path)
        .output()
        .is_ok_and(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .next()
                .is_some_and(|flags| flags.contains(attr))
        })
}

/// BackOtter (D8): an immutable file and an append-only directory whose
/// contents and metadata already match keep their flags, and the file its
/// inode's change time, through a second `--exact` restore: flags come off
/// only for what the restore changes. Root only, on a file system with
/// flags (TMPDIR).
#[rstest]
#[cfg(target_os = "linux")]
fn test_restore_exact_flags_left_where_nothing_changes(set_up_repo: Result<RepoOpen>) -> Result<()> {
    let source = tempdir()?;
    let s = source.path();
    fs::create_dir(s.join("d"))?;
    fs::write(s.join("d/f"), "f")?;
    if !chattr("+i", &s.join("d/f")) {
        eprintln!("no immutable flag in {}", s.display());
        return Ok(());
    }
    _ = chattr("+a", &s.join("d"));
    let repo = backed_up(set_up_repo?, s);
    _ = chattr("-i", &s.join("d/f"));
    _ = chattr("-a", &s.join("d"));
    let repo = repo?;
    let target = tempdir()?;
    let t = target.path().join("test");
    let exact = RestoreOptions::default().exact(true).numeric_id(true);
    let result = (|| -> Result<_> {
        assert_eq!(restore_counting(&repo, target.path(), exact)?, 0);
        assert!(immutable(&t.join("d/f")));
        let before = inodes(target.path())?;
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(restore_counting(&repo, target.path(), exact)?, 0);
        Ok((before, inodes(target.path())?))
    })();
    let flagged = immutable(&t.join("d/f"));
    let appended = has_attr(&t.join("d"), 'a');
    _ = chattr("-i", &t.join("d/f"));
    _ = chattr("-a", &t.join("d"));
    let (before, after) = result?;
    assert!(flagged, "the second restore lost immutable");
    assert!(appended, "the second restore lost append-only");
    assert_eq!(after, before);
    Ok(())
}

/// BackOtter (D6, D7): `--exact` over an immutable file with other names:
/// the snapshot's name gets a file of its own, the unexpected name in the
/// destination, which sorts before it, is removed all the same (--delete:
/// it is a name of a file the restore replaced a name of), and the name
/// outside the destination keeps the file's flags, which came off held and
/// went back on it. Root only, on a file system with flags (TMPDIR).
#[rstest]
#[cfg(target_os = "linux")]
fn test_restore_exact_flags_back_on_other_names(set_up_repo: Result<RepoOpen>) -> Result<()> {
    let source = tempdir()?;
    let s = source.path();
    fs::create_dir(s.join("d"))?;
    fs::write(s.join("d/b"), "snapshot")?;
    let repo = backed_up(set_up_repo?, s)?;
    let target = tempdir()?;
    let t = target.path().join("test");
    restore_to(&repo, target.path(), RestoreOptions::default())?;
    let outside = tempdir()?;
    let o = outside.path().join("o");
    fs::remove_file(t.join("d/b"))?;
    fs::write(t.join("d/b"), "old")?;
    fs::hard_link(t.join("d/b"), t.join("d/a"))?;
    fs::hard_link(t.join("d/b"), &o)?;
    if !chattr("+i", &o) {
        eprintln!("no immutable flag in {}", outside.path().display());
        return Ok(());
    }
    let result = restore_counting(&repo, target.path(), RestoreOptions::default().exact(true));
    let flagged = immutable(&o);
    _ = chattr("-i", &o);
    _ = chattr("-i", &t.join("d/a"));
    assert_eq!(result?, 0);
    assert!(flagged, "the name outside lost immutable");
    assert_eq!(fs::read_to_string(&o)?, "old");
    assert_eq!(fs::read_to_string(t.join("d/b"))?, "snapshot");
    assert!(!t.join("d/a").exists(), "the unexpected name is still there");
    assert_eq!(fs::metadata(&o)?.nlink(), 1);
    Ok(())
}

/// BackOtter: with root, a new loop ext4 of 64 MiB that can fold case
/// (`-O casefold`); None, with why, where it can't be had.
#[cfg(target_os = "linux")]
fn loop_ext4_casefold() -> Result<Option<LoopFs>> {
    use std::process::Command;

    if !nix::unistd::geteuid().is_root() {
        eprintln!("skipped: needs root, to mount a file system");
        return Ok(None);
    }
    let scratch = tempdir()?;
    let (img, mnt) = (scratch.path().join("fs.img"), scratch.path().join("mnt"));
    File::create(&img)?.set_len(64 << 20)?;
    fs::create_dir(&mnt)?;
    if !ok(Command::new("mkfs.ext4").args(["-q", "-F", "-O", "casefold"]).arg(&img)) {
        eprintln!("skipped: no mkfs.ext4 with casefold");
        return Ok(None);
    }
    if !ok(Command::new("mount").args(["-o", "loop"]).arg(&img).arg(&mnt)) {
        eprintln!("skipped: mount failed");
        return Ok(None);
    }
    Ok(Some(LoopFs { _scratch: scratch, mnt }))
}

/// BackOtter: `size` bytes that don't repeat, the same every time.
#[cfg(not(windows))]
fn noise(size: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..size)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[3]
        })
        .collect()
}

/// BackOtter: `--delete` in a case-insensitive directory (ext4 casefolding)
/// leaves what is the snapshot's entry under another name: `SAME` is the
/// snapshot's `same`, and gets its contents, whichever name sorts first
/// (`snapupper` and `SNAPUPPER` too); in `docs`, the snapshot's `Docs`, only
/// what the snapshot hasn't got goes; a file `KIND` where the snapshot has
/// a directory `kind` is replaced by it, a directory `FLAT` where it has a
/// file `flat` too; and every other file is restored.
/// rustic-bko 0.11.4+backotter.14 removed `SAME` once it had planned
/// `same`, then panicked reading it (exit 134, the rest of the restore not
/// done). The same with `--exact`, over what the first restore left. Root
/// only (a loop ext4).
#[rstest]
#[cfg(target_os = "linux")]
fn test_restore_delete_leaves_a_case_variant(set_up_repo: Result<RepoOpen>) -> Result<()> {
    let Some(loop_fs) = loop_ext4_casefold()? else {
        return Ok(());
    };
    let source = tempdir()?;
    let s = source.path();
    fs::write(s.join("same"), "same")?;
    fs::write(s.join("SNAPUPPER"), "snapshot")?;
    fs::create_dir_all(s.join("Docs/new"))?;
    fs::write(s.join("Docs/x"), "snapshot x")?;
    fs::write(s.join("Docs/new/n"), "n")?;
    fs::create_dir(s.join("kind"))?;
    fs::write(s.join("kind/f"), "f")?;
    fs::write(s.join("flat"), "flat")?;
    let other = noise(3 << 20, 7);
    fs::write(s.join("other"), &other)?;
    let repo = backed_up(set_up_repo?, s)?;
    let dst = loop_fs.mnt.join("dst");
    let t = dst.join("test");
    fs::create_dir_all(&t)?;
    assert!(chattr("+F", &t), "no casefolding on {}", t.display());
    fs::write(t.join("SAME"), "same")?;
    fs::write(t.join("snapupper"), "old")?;
    fs::create_dir(t.join("docs"))?;
    fs::write(t.join("docs/x"), "old x")?;
    fs::write(t.join("docs/y"), "unexpected")?;
    fs::write(t.join("KIND"), "a file where the snapshot has a directory")?;
    fs::create_dir(t.join("FLAT"))?;
    fs::write(t.join("FLAT/junk"), "a directory where the snapshot has a file")?;
    fs::write(t.join("extra"), "unexpected")?;
    for opts in [
        RestoreOptions::default().delete(true),
        RestoreOptions::default().delete(true).exact(true).numeric_id(true),
    ] {
        assert_eq!(restore_counting(&repo, &dst, opts)?, 0, "{opts:?}");
        assert_eq!(fs::read_to_string(t.join("same"))?, "same");
        assert_eq!(fs::read_to_string(t.join("SNAPUPPER"))?, "snapshot");
        assert_eq!(fs::read_to_string(t.join("Docs/x"))?, "snapshot x");
        assert_eq!(fs::read_to_string(t.join("Docs/new/n"))?, "n");
        assert_eq!(fs::read_to_string(t.join("kind/f"))?, "f");
        assert_eq!(fs::read_to_string(t.join("flat"))?, "flat");
        assert!(fs::read(t.join("other"))? == other, "other's contents");
        assert!(!t.join("docs/y").exists(), "the unexpected docs/y is still there");
        assert!(!t.join("extra").exists(), "the unexpected extra is still there");
        let mut names: Vec<_> = fs::read_dir(&t)?
            .map(|e| e.map(|e| e.file_name().to_string_lossy().to_lowercase()))
            .collect::<Result<_, _>>()?;
        names.sort();
        assert_eq!(names, ["docs", "flat", "kind", "other", "same", "snapupper"]);
    }
    Ok(())
}

/// BackOtter: a file the restore planned to take a part of its contents
/// from, gone before the restore read it (a directory there now), leaves the files that were to
/// get that part without their contents, each an error (the restore's
/// error names how many), and the restore goes on: it used to panic (exit
/// 134), the rest of the restore not done.
#[rstest]
#[cfg(not(windows))]
fn test_restore_existing_file_gone_is_no_panic(set_up_repo: Result<RepoOpen>) -> Result<()> {
    let source = tempdir()?;
    let s = source.path();
    let data = noise(8 << 20, 11);
    fs::write(s.join("f"), &data)?;
    fs::write(s.join("g"), &data)?;
    fs::write(s.join("h"), "h")?;
    let repo = backed_up(set_up_repo?, s)?;
    let target = tempdir()?;
    restore_to(&repo, target.path(), RestoreOptions::default())?;
    let t = target.path().join("test");
    // f keeps its first chunks and g is gone: g's chunks are read from f,
    // which is a directory by then (it can't be read, nor made again by
    // f's own writes). h is left as it is: a blob to write that sorts
    // first in the pack would have the pack read whole, f's chunks too
    // (PackInfo::coalesce).
    let mut changed = data.clone();
    let len = changed.len();
    changed[len - 4096..].fill(0x5a);
    fs::write(t.join("f"), &changed)?;
    fs::remove_file(t.join("g"))?;

    let snap = repo.get_snapshot_from_str("latest", |_| true)?;
    let opts = RestoreOptions::default().origin(SnapshotOrigin::of(&snap));
    let node = repo.node_from_snapshot_path("latest", |_| true)?;
    let dest = LocalDestination::new(target.path().to_str().expect("utf-8"), true, false)?;
    let ls = repo.ls(&node, &LsOptions::default())?;
    let plan = repo.prepare_restore(&opts, ls.clone(), &dest, false)?;
    fs::remove_file(t.join("f"))?;
    fs::create_dir(t.join("f"))?;
    // f and g without their contents: the restore's error.
    let err = repo.restore(plan, &opts, ls, &dest).expect_err("contents not restored");
    assert!(err.to_string().contains("could not be restored"), "{err}");
    assert!(fs::read(t.join("g")).ok() != Some(data), "g restored from what?");
    assert_eq!(fs::read_to_string(t.join("h"))?, "h");
    Ok(())
}

/// BackOtter (D7): `--exact --delete` over a hard-linked pair whose names
/// are two immutable files with other names each, unexpected ones: the
/// pair gets a file of its own, and both unexpected names go, the second
/// file's too (its name `b` is in the way of the link, removed early, so
/// that `--delete` knows it: rustic-bko 0.11.4+backotter.14 left
/// `y_extra`, "Operation not permitted"). Root only, on a file system with
/// flags (TMPDIR).
#[rstest]
#[cfg(target_os = "linux")]
fn test_restore_exact_delete_link_group_in_the_way(set_up_repo: Result<RepoOpen>) -> Result<()> {
    let source = tempdir()?;
    let s = source.path();
    fs::create_dir(s.join("d"))?;
    fs::write(s.join("d/a"), "snapshot")?;
    fs::hard_link(s.join("d/a"), s.join("d/b"))?;
    if !chattr("+i", &s.join("d/a")) {
        eprintln!("no immutable flag in {}", s.display());
        return Ok(());
    }
    let repo = backed_up(set_up_repo?, s);
    _ = chattr("-i", &s.join("d/a"));
    let repo = repo?;
    let target = tempdir()?;
    let d = target.path().join("test/d");
    fs::create_dir_all(&d)?;
    fs::write(d.join("a"), "old X")?;
    fs::hard_link(d.join("a"), d.join("x_extra"))?;
    fs::write(d.join("b"), "old Y")?;
    fs::hard_link(d.join("b"), d.join("y_extra"))?;
    assert!(chattr("+i", &d.join("a")) && chattr("+i", &d.join("b")));
    let exact = RestoreOptions::default().exact(true).delete(true).numeric_id(true);
    let result = restore_counting(&repo, target.path(), exact);
    let left: Vec<_> = ["x_extra", "y_extra"].into_iter().filter(|n| d.join(n).exists()).collect();
    let flagged = immutable(&d.join("a")) && immutable(&d.join("b"));
    for entry in fs::read_dir(&d)? {
        _ = chattr("-i", &entry?.path());
    }
    assert_eq!(result?, 0);
    assert!(left.is_empty(), "unexpected names left: {left:?}");
    assert!(flagged, "the pair lost immutable");
    assert_eq!(fs::read_to_string(d.join("a"))?, "snapshot");
    assert_eq!(fs::metadata(d.join("a"))?.ino(), fs::metadata(d.join("b"))?.ino());
    assert_eq!(fs::metadata(d.join("a"))?.nlink(), 2);
    Ok(())
}

/// BackOtter: the directories below `top` named by `names`, one in the
/// other, opened by descriptors (a path that deep is too long for a system
/// call): each one's, `top`'s first.
#[cfg(target_os = "linux")]
fn open_chain(top: &Path, names: &[String]) -> Result<Vec<std::os::fd::OwnedFd>> {
    use nix::fcntl::{OFlag, open, openat};
    use nix::sys::stat::Mode;

    let how = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut fds = vec![open(top, how, Mode::empty())?];
    for name in names {
        let fd = openat(fds.last().unwrap(), name.as_str(), how, Mode::empty())
            .map_err(|err| anyhow::anyhow!("{name}: {err}"))?;
        fds.push(fd);
    }
    Ok(fds)
}

/// BackOtter: the file `name` in the directory `dir`, opened by `how`
/// (`O_NOFOLLOW` too), with `mode` if it is made.
#[cfg(target_os = "linux")]
fn file_at(
    dir: &std::os::fd::OwnedFd,
    name: &str,
    how: nix::fcntl::OFlag,
    mode: u32,
) -> Result<File> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;

    let how = how | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    Ok(File::from(openat(dir, name, how, Mode::from_bits_truncate(mode))?))
}

/// BackOtter (BackShot2's fail-001): a tree deeper than a path a system
/// call takes (`PATH_MAX`, 4096 bytes) is backed up whole, and restored
/// whole, each directory and the file at the bottom with their metadata (a
/// mode, an mtime, an extended attribute) and contents, and a symlink;
/// then restored again over itself, and with `--delete` over an unexpected
/// file at the bottom, which goes. rustic-bko 0.11.4+backotter.16 left out
/// of the backup everything past `PATH_MAX`, with a warning, and exited 0;
/// its restore couldn't make it either (`ENAMETOOLONG`).
#[rstest]
#[cfg(target_os = "linux")]
fn test_backup_restore_past_path_max(set_up_repo: Result<RepoOpen>) -> Result<()> {
    use std::io::Read;
    use std::time::{Duration, SystemTime};

    use nix::fcntl::{AtFlags, OFlag, readlinkat};
    use nix::sys::stat::{FileStat, Mode, fstat, fstatat, mkdirat};
    use rustic_core::PathList;
    use xattr::FileExt;

    let source = tempdir()?;
    let names: Vec<String> = (0..120).map(|i| format!("d{i:03}{}", "x".repeat(36))).collect();
    let deep: PathBuf = names.iter().collect();
    assert!(source.path().join(&deep).as_os_str().len() > 4096);
    // The tree, made through descriptors.
    for (i, name) in names.iter().enumerate() {
        let fds = open_chain(source.path(), &names[..i])?;
        let mode = if i % 2 == 0 { 0o750 } else { 0o705 };
        mkdirat(fds.last().unwrap(), name.as_str(), Mode::from_bits_truncate(mode))?;
    }
    let fds = open_chain(source.path(), &names)?;
    let bottom = fds.last().unwrap();
    let mut leaf = file_at(bottom, "leaf", OFlag::O_WRONLY | OFlag::O_CREAT, 0o640)?;
    leaf.write_all(b"deep down")?;
    if leaf.set_xattr("user.bko", b"otter").is_err() {
        eprintln!("no user xattrs in {}", source.path().display());
        return Ok(());
    }
    let mtime = SystemTime::UNIX_EPOCH + Duration::new(1_600_000_000, 123_456_789);
    leaf.set_times(fs::FileTimes::new().set_modified(mtime).set_accessed(mtime))?;
    drop(leaf);
    nix::unistd::symlinkat("leaf", bottom, "lnk")?;
    let times = |st: &FileStat| (st.st_mode, st.st_mtime, st.st_mtime_nsec);
    let want: Vec<_> = fds.iter().map(|fd| fstat(fd).map(|st| times(&st))).collect::<Result<_, _>>()?;
    let want_leaf = times(&fstatat(bottom, "leaf", AtFlags::AT_SYMLINK_NOFOLLOW)?);
    drop(fds);

    let repo = set_up_repo?.to_indexed_ids()?;
    let opts = BackupOptions::default().as_path(PathBuf::from_str("test")?);
    let paths = PathList::from_iter(Some(source.path().to_path_buf()));
    let snap = repo.backup(&opts, &paths, SnapshotFile::default())?;
    assert_eq!(snap.summary.as_ref().map(|s| s.items_incomplete), Some(0));
    let repo = repo.to_indexed()?;
    let node = repo.node_from_snapshot_path("latest", |_| true)?;
    let listed: Vec<PathBuf> = repo
        .ls(&node, &LsOptions::default())?
        .map(|item| item.map(|(p, _)| p))
        .collect::<Result<_, _>>()?;
    let test = PathBuf::from("test");
    assert!(listed.contains(&test.join(&deep).join("leaf")), "{} entries", listed.len());
    assert!(listed.contains(&test.join(&deep).join("lnk")));

    let target = tempdir()?;
    let check = || -> Result<()> {
        let fds = open_chain(&target.path().join("test"), &names)?;
        for (i, (fd, want)) in fds.iter().zip(&want).enumerate().skip(1) {
            assert_eq!(times(&fstat(fd)?), *want, "mode and mtime of directory {i}");
        }
        let bottom = fds.last().unwrap();
        assert_eq!(times(&fstatat(bottom, "leaf", AtFlags::AT_SYMLINK_NOFOLLOW)?), want_leaf);
        let mut leaf = file_at(bottom, "leaf", OFlag::O_RDONLY, 0)?;
        let mut data = String::new();
        _ = leaf.read_to_string(&mut data)?;
        assert_eq!(data, "deep down");
        assert_eq!(leaf.get_xattr("user.bko")?, Some(b"otter".to_vec()));
        assert_eq!(readlinkat(bottom, "lnk")?, "leaf");
        assert!(fstatat(bottom, "extra", AtFlags::AT_SYMLINK_NOFOLLOW).is_err(), "extra left");
        Ok(())
    };
    assert_eq!(restore_counting(&repo, target.path(), RestoreOptions::default())?, 0);
    check()?;

    // Again over it, as it is.
    assert_eq!(restore_counting(&repo, target.path(), RestoreOptions::default())?, 0);
    check()?;

    // And with --delete, over a file the snapshot hasn't got at the bottom.
    let fds = open_chain(&target.path().join("test"), &names)?;
    drop(file_at(fds.last().unwrap(), "extra", OFlag::O_WRONLY | OFlag::O_CREAT, 0o600)?);
    drop(fds);
    let delete = RestoreOptions::default().delete(true);
    assert_eq!(restore_counting(&repo, target.path(), delete)?, 0);
    check()
}
