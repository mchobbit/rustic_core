//! BackOtter: the temporary directory inside the tree that is backed up or
//! restored to, with paths of `PATH_MAX` bytes or more in that tree. The
//! links such paths are reached through are in a directory of the process's
//! own in `$TMPDIR` (`walkdir::short_path`), which is then an entry of the
//! tree's walk: it is no part of the tree (`walkdir::is_short_path_dir`).
//!
//! A process decides where its links are once, and other tests of this
//! binary shorten paths too, so each test here runs its body in a child
//! process of its own, with `TMPDIR` set (`in_child`).

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::Result;
use nix::fcntl::OFlag;
use nix::sys::stat::{Mode, mkdirat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use rstest::rstest;
use tempfile::tempdir;

use rustic_core::{
    BackupOptions, LocalDestination, LsOptions, PathList, RestoreOptions, SnapshotOrigin,
    repofile::SnapshotFile,
};

use super::restore::{file_at, open_chain};
use super::{RepoOpen, set_up_repo};

/// The variable that names, to the child process, the directory the parent
/// made for it.
const BASE: &str = "BKO_TMPDIR_TEST_BASE";

/// In the child process, the directory its parent made for it. In the
/// parent, `None`, after it ran the test `name` of this module again, alone
/// in a child process whose `TMPDIR` is `tmp` (below a new directory, which
/// is made first and removed afterwards), and checked that it ran and
/// passed.
fn in_child(name: &str, tmp: &str) -> Result<Option<PathBuf>> {
    if let Some(base) = std::env::var_os(BASE) {
        return Ok(Some(PathBuf::from(base)));
    }
    let base = tempdir()?;
    let base_path = fs::canonicalize(base.path())?;
    let tmp = base_path.join(tmp);
    fs::create_dir_all(&tmp)?;
    let child_test = format!("integration::bko_tmpdir::{name}");
    let out = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", &child_test, "--nocapture", "--test-threads=1"])
        .env(BASE, &base_path)
        .env("TMPDIR", &tmp)
        .current_dir(&base_path)
        .output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{text}");
    assert!(text.contains("test result: ok. 1 passed"), "{text}");
    Ok(None)
}

/// 120 directory names of 40 bytes: one in the other, a path of 4.9 KB.
fn deep_names() -> Vec<String> {
    (0..120)
        .map(|i| format!("d{i:03}{}", "x".repeat(36)))
        .collect()
}

/// Makes, in the new directory `source`: `aaa/` + `names`, one in the other
/// (through descriptors: the path is too long for a system call), with a
/// file `leaf` at the bottom, and `tmp/keep` and `tmp/old`.
fn make_source(source: &Path, names: &[String]) -> Result<()> {
    fs::create_dir_all(source.join("aaa"))?;
    fs::create_dir_all(source.join("tmp"))?;
    fs::write(source.join("tmp/keep"), "keep")?;
    fs::write(source.join("tmp/old"), "old")?;
    for (i, name) in names.iter().enumerate() {
        let fds = open_chain(&source.join("aaa"), &names[..i])?;
        mkdirat(
            fds.last().unwrap(),
            name.as_str(),
            Mode::from_bits_truncate(0o755),
        )?;
    }
    let fds = open_chain(&source.join("aaa"), names)?;
    let mut leaf = file_at(
        fds.last().unwrap(),
        "leaf",
        OFlag::O_WRONLY | OFlag::O_CREAT,
        0o644,
    )?;
    leaf.write_all(&[b'l'; 4900])?;
    Ok(())
}

/// The contents of `leaf` at the bottom of `top` + `names`, if it is there.
fn leaf_of(top: &Path, names: &[String]) -> Result<Option<Vec<u8>>> {
    let fds = open_chain(top, names)?;
    let Ok(mut leaf) = file_at(fds.last().unwrap(), "leaf", OFlag::O_RDONLY, 0) else {
        return Ok(None);
    };
    let mut data = Vec::new();
    _ = leaf.read_to_end(&mut data)?;
    Ok(Some(data))
}

/// Removes that `leaf`.
fn unlink_leaf(top: &Path, names: &[String]) -> Result<()> {
    let fds = open_chain(top, names)?;
    unlinkat(fds.last().unwrap(), "leaf", UnlinkatFlags::NoRemoveDir)?;
    Ok(())
}

/// The names in `dir`, in the order a walk of it gives them.
fn listing(dir: &Path) -> Result<Vec<String>> {
    Ok(fs::read_dir(dir)?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<_>>()?)
}

/// The names in `dir`, sorted.
fn names_in(dir: &Path) -> Result<Vec<String>> {
    let mut names = listing(dir)?;
    names.sort();
    Ok(names)
}

/// The entries of `dir`, sorted: each one's name, inode and change time,
/// which an entry removed and made again hasn't kept (after `pause`).
fn entries_of(dir: &Path) -> Result<Vec<(String, u64, i64, i64)>> {
    use std::os::unix::fs::MetadataExt;

    let mut entries = Vec::new();
    for name in names_in(dir)? {
        let m = fs::symlink_metadata(dir.join(&name))?;
        entries.push((name, m.ino(), m.ctime(), m.ctime_nsec()));
    }
    Ok(entries)
}

/// Waits for the clock that change times are taken from to go on: an entry
/// made again in the same tick would keep its change time.
fn pause() {
    std::thread::sleep(std::time::Duration::from_millis(20));
}

/// Restores the latest snapshot to `dir` with `opts`: the errors counted
/// (planning and restoring), and the additional directories and files the
/// plan found there.
fn restore_to(
    repo: &rustic_core::Repository<impl rustic_core::IndexedFull>,
    dir: &Path,
    opts: RestoreOptions,
) -> Result<(u64, u64, u64)> {
    let snap = repo.get_snapshot_from_str("latest", |_| true)?;
    let opts = opts.origin(SnapshotOrigin::of(&snap));
    let node = repo.node_from_snapshot_path("latest", |_| true)?;
    let dest = LocalDestination::new(dir.to_str().expect("utf-8"), true, false)?;
    let ls = repo.ls(&node, &LsOptions::default())?;
    let plan = repo.prepare_restore(&opts, ls.clone(), &dest, false)?;
    let (planned, dirs, files) = (
        plan.stats.errors,
        plan.stats.dirs.additional,
        plan.stats.files.additional,
    );
    let outcome = repo.restore(plan, &opts, ls, &dest)?;
    Ok((planned + outcome.errors, dirs, files))
}

/// BackOtter (ForkAudit1 G7-01): `restore --delete` (and `--exact`) to a
/// destination that holds `$TMPDIR` restores the files past `PATH_MAX`, and
/// leaves the process's own links' directory in `$TMPDIR` alone: no
/// additional entry, nothing removed. rustic-bko 0.12.0+backotter.1 removed
/// it as an extra entry, made the path of each such file again as real
/// directories inside `$TMPDIR`, wrote the file there, removed it all at
/// exit, and reported "restore done." with no error: the file was missing.
///
/// Then with `$TMPDIR` itself an extra entry (a snapshot without it): its
/// contents go, it stays with the links' directory in it, as one error
/// ("Directory not empty"), and the files past `PATH_MAX` are still
/// restored; .1 removed it whole and lost them the same way. The links
/// stay as they are, not removed and made again, and every other entry of
/// `$TMPDIR` goes, those its listing has before the links' directory and
/// those after it: the first fix (8ff6881) removed the links, and left what
/// was listed after the links' directory (on XFS `keep`, so this test
/// failed there, and passed on tmpfs, which lists the other way).
#[rstest]
fn test_restore_delete_with_tmpdir_in_destination(set_up_repo: Result<RepoOpen>) -> Result<()> {
    let name = "test_restore_delete_with_tmpdir_in_destination";
    let Some(base) = in_child(name, "dst/test/tmp")? else {
        return Ok(());
    };
    let names = deep_names();
    let (source, dst) = (base.join("src"), base.join("dst"));
    let tmp = dst.join("test/tmp");
    assert_eq!(std::env::temp_dir(), tmp);
    // The snapshot's `old` in $TMPDIR, there before the links' directory,
    // which the backup makes in it (it reads the path past PATH_MAX);
    // `keep` is made after it, by the restore.
    fs::write(tmp.join("old"), "old")?;
    make_source(&source, &names)?;
    let want = Some(vec![b'l'; 4900]);

    let repo = set_up_repo?.to_indexed_ids()?;
    let opts = BackupOptions::default().as_path(PathBuf::from_str("test")?);
    let paths = PathList::from_iter(Some(source.clone()));
    let snap = repo.backup(&opts, &paths, SnapshotFile::default())?;
    assert_eq!(snap.summary.as_ref().map(|s| s.items_incomplete), Some(0));
    let repo = repo.to_indexed()?;

    // To the destination, new but for $TMPDIR with `old` and the links'
    // directory in it.
    let top = dst.join("test/aaa");
    assert_eq!(
        restore_to(&repo, &dst, RestoreOptions::default())?,
        (0, 0, 0)
    );
    assert_eq!(leaf_of(&top, &names)?, want);
    let in_tmp = names_in(&tmp)?;
    assert_eq!(in_tmp.len(), 3, "{in_tmp:?}");
    assert!(
        in_tmp[0].starts_with(".bko-longpath-") && in_tmp[1..] == ["keep", "old"],
        "{in_tmp:?}"
    );
    let links = tmp.join(&in_tmp[0]);
    assert!(walkdir::is_short_path_dir(&links));
    let made = entries_of(&links)?;
    assert!(!made.is_empty());

    // The file at the bottom gone: --delete, then --exact, restore it, find
    // nothing additional, and leave $TMPDIR as it is.
    let delete = RestoreOptions::default().delete(true);
    let exact = RestoreOptions::default()
        .exact(true)
        .delete(true)
        .numeric_id(true);
    for opts in [delete, exact, RestoreOptions::default()] {
        unlink_leaf(&top, &names)?;
        pause();
        assert_eq!(restore_to(&repo, &dst, opts)?, (0, 0, 0));
        assert_eq!(leaf_of(&top, &names)?, want, "the file past PATH_MAX");
        assert_eq!(names_in(&tmp)?, in_tmp);
        // Links only: nothing real was made in it for the path. The links
        // made first, none made again.
        for entry in fs::read_dir(&links)? {
            assert!(entry?.file_type()?.is_symlink());
        }
        assert_eq!(entries_of(&links)?, made);
    }

    // A snapshot without tmp: --delete removes what is in $TMPDIR but the
    // links' directory, so not $TMPDIR itself (one error), and restores
    // the file.
    fs::remove_dir_all(source.join("tmp"))?;
    let repo = repo.to_indexed_ids()?;
    let _snap = repo.backup(&opts, &paths, SnapshotFile::default())?;
    let repo = repo.to_indexed()?;
    unlink_leaf(&top, &names)?;
    // A directory in $TMPDIR too, and entries on both sides of the links'
    // directory in $TMPDIR's listing, whatever order the file system lists
    // in (by age, one way or the other, as tmpfs and a small XFS directory
    // do: `old` and `keep`; ext4 by a hash of the name: more names).
    fs::create_dir(tmp.join("sub"))?;
    fs::write(tmp.join("sub/file"), "file")?;
    let mut more = 0;
    loop {
        let order = listing(&tmp)?;
        let at = order.iter().position(|n| *n == in_tmp[0]).unwrap();
        if at > 0 && at + 1 < order.len() {
            break;
        }
        assert!(more < 256, "{order:?}");
        fs::write(tmp.join(format!("more-{more}")), "more")?;
        more += 1;
    }
    pause();
    let (errors, dirs, files) = restore_to(&repo, &dst, delete)?;
    assert_eq!(
        leaf_of(&top, &names)?,
        want,
        "the file past PATH_MAX, $TMPDIR extra"
    );
    assert_eq!((errors, dirs, files), (1, 1, 0));
    // Both at once, for a failure to show both: the links as they were
    // made, and nothing else left in $TMPDIR.
    assert_eq!(
        (entries_of(&links)?, names_in(&tmp)?),
        (made, in_tmp[..1].to_vec())
    );
    Ok(())
}

/// BackOtter (ForkAudit1 G7-02): a backup of a source that holds `$TMPDIR`
/// (given by a relative path, where the links' directory's own is
/// canonical), with a path past `PATH_MAX` that sorts before it, leaves the
/// process's own links' directory out, with or without another entry
/// filter (`--exclude-if-present`), and counts nothing as incomplete.
/// rustic-bko 0.12.0+backotter.1 saved `tmp/.bko-longpath-PID-N` and its
/// links, under a name that differs from run to run.
#[rstest]
fn test_backup_with_tmpdir_in_source(set_up_repo: Result<RepoOpen>) -> Result<()> {
    use rustic_core::LocalSourceFilterOptions;

    let name = "test_backup_with_tmpdir_in_source";
    let Some(base) = in_child(name, "src/tmp")? else {
        return Ok(());
    };
    let names = deep_names();
    let deep: PathBuf = names.iter().collect();
    assert_eq!(std::env::current_dir()?, base);
    assert_eq!(std::env::temp_dir(), base.join("src/tmp"));
    let source = Path::new("src");
    make_source(source, &names)?;

    let mut repo = set_up_repo?.to_indexed_ids()?;
    let present =
        LocalSourceFilterOptions::default().exclude_if_present(vec!["no-such".to_string()]);
    for filter in [LocalSourceFilterOptions::default(), present] {
        let opts = BackupOptions::default()
            .as_path(PathBuf::from_str("test")?)
            .ignore_filter_opts(filter);
        let paths = PathList::from_iter(Some(source.to_path_buf()));
        let snap = repo.backup(&opts, &paths, SnapshotFile::default())?;
        assert_eq!(snap.summary.as_ref().map(|s| s.items_incomplete), Some(0));
        // The links' directory is there, beside keep and old, for the walk
        // to find.
        let in_tmp = names_in(&source.join("tmp"))?;
        assert_eq!(in_tmp.len(), 3, "{in_tmp:?}");
        assert!(
            in_tmp[0].starts_with(".bko-longpath-") && in_tmp[1..] == ["keep", "old"],
            "{in_tmp:?}"
        );

        let indexed = repo.to_indexed()?;
        let node = indexed.node_from_snapshot_path("latest", |_| true)?;
        let listed: Vec<PathBuf> = indexed
            .ls(&node, &LsOptions::default())?
            .map(|item| item.map(|(p, _)| p))
            .collect::<Result<_, _>>()?;
        let test = PathBuf::from("test");
        assert!(
            listed.contains(&test.join("aaa").join(&deep).join("leaf")),
            "{} entries",
            listed.len()
        );
        assert!(listed.contains(&test.join("tmp/keep")));
        assert!(listed.contains(&test.join("tmp/old")));
        let own: Vec<_> = listed
            .iter()
            .filter(|p| p.to_string_lossy().contains(".bko-longpath-"))
            .collect();
        assert!(own.is_empty(), "the backup's own links saved: {own:?}");
        assert_eq!(
            listed.iter().filter(|p| p.starts_with("test/tmp")).count(),
            3,
            "tmp, keep and old"
        );
        repo = indexed.to_indexed_ids()?;
    }
    Ok(())
}
