use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::Result;
use insta::Settings;
use pretty_assertions::assert_eq;
use rstest::rstest;

use rustic_core::{
    BackupOptions, CommandInput, Grouped, ParentOptions, PathList, SnapshotGroupCriterion,
    SnapshotOptions, StringList,
    repofile::{PackId, SnapshotFile},
};

use super::{
    RepoOpen, TestSource, assert_with_win, insta_node_redaction, insta_snapshotfile_redaction,
    set_up_repo, tar_gz_testdata,
};

#[rstest]
fn test_backup_with_tar_gz_passes(
    tar_gz_testdata: Result<TestSource>,
    set_up_repo: Result<RepoOpen>,
    insta_snapshotfile_redaction: Settings,
    insta_node_redaction: Settings,
) -> Result<()> {
    // uncomment for logging output
    // SimpleLogger::init(log::LevelFilter::Debug, Config::default())?;

    // Fixtures
    let (source, repo) = (tar_gz_testdata?, set_up_repo?.to_indexed_ids()?);

    let paths = &source.path_list();

    // we use as_path to not depend on the actual tempdir
    let opts = BackupOptions::default().as_path(PathBuf::from_str("test")?);

    // first backup
    let first_snapshot = repo.backup(&opts, paths, SnapshotFile::default())?;

    // We can also bind to scope ( https://docs.rs/insta/latest/insta/struct.Settings.html#method.bind_to_scope )
    // But I think that can get messy with a lot of tests, also checking which settings are currently applied
    // will be probably harder
    insta_snapshotfile_redaction.bind(|| {
        assert_with_win("backup-tar-summary-first", &first_snapshot);
    });

    assert!(first_snapshot.get_parents().is_empty());

    // tree of first backup
    // re-read index
    let repo = repo.to_indexed_ids()?;
    let tree = repo.node_from_path(first_snapshot.tree, Path::new("test/0/tests"))?;
    let tree: rustic_core::repofile::Tree = repo.get_tree(&tree.subtree.expect("Sub tree"))?;

    insta_node_redaction.bind(|| {
        assert_with_win("backup-tar-tree", tree);
    });

    // get all snapshots and check them
    let all_snapshots = repo.get_all_snapshots()?;
    assert_eq!(vec![first_snapshot.clone()], all_snapshots);
    // save list of pack files
    let packs1: Vec<PackId> = repo.list()?.collect();

    // re-read index
    let repo = repo.to_indexed_ids()?;
    // second backup
    let second_snapshot = repo.backup(&opts, paths, SnapshotFile::default())?;

    insta_snapshotfile_redaction.bind(|| {
        assert_with_win("backup-tar-summary-second", &second_snapshot);
    });

    assert_eq!(second_snapshot.get_parents(), &[first_snapshot.id]);
    assert_eq!(first_snapshot.tree, second_snapshot.tree);

    // pack files should be unchanged
    let packs2: Vec<_> = repo.list()?.collect();
    assert_eq!(packs1, packs2);

    // re-read index
    let repo = repo.to_indexed_ids()?;
    // third backup with tags and explicitly given parent
    let snap = SnapshotOptions::default()
        .tags([StringList::from_str("a,b")?])
        .to_snapshot()?;
    let opts =
        opts.parent_opts(ParentOptions::default().parents(vec![second_snapshot.id.to_string()]));
    let third_snapshot = repo.backup(&opts, paths, snap)?;

    insta_snapshotfile_redaction.bind(|| {
        assert_with_win("backup-tar-summary-third", &third_snapshot);
    });
    assert_eq!(third_snapshot.get_parents(), &[second_snapshot.id]);
    assert_eq!(third_snapshot.tree, second_snapshot.tree);

    // get all snapshots and check them
    let mut all_snapshots = repo.get_all_snapshots()?;
    all_snapshots.sort_unstable();
    assert_eq!(
        vec![first_snapshot.clone(), second_snapshot, third_snapshot],
        all_snapshots
    );

    // pack files should be unchanged
    let packs2: Vec<_> = repo.list()?.collect();
    assert_eq!(packs1, packs2);
    let packs3: Vec<_> = repo.list()?.collect();
    assert_eq!(packs1, packs3);

    // Check if snapshots can be retrieved
    let mut ids: Vec<_> = all_snapshots.iter().map(|sn| sn.id.to_string()).collect();
    let snaps = repo.get_snapshots(&ids)?;
    assert_eq!(snaps, all_snapshots);

    // reverse order and add duplicate snapshot - test if update_snapshots works as expected
    all_snapshots.reverse();
    all_snapshots.push(first_snapshot.clone());
    ids.reverse();
    ids.push(first_snapshot.id.to_string());
    let snaps = repo.update_snapshots(snaps, &ids)?;
    assert_eq!(snaps, all_snapshots);

    // get snapshot group
    let group_by = SnapshotGroupCriterion::new().tags(true);
    let mut snapshots = repo.get_all_snapshots()?;

    // sort to get unique result
    snapshots.sort();

    insta_snapshotfile_redaction.bind(|| {
        assert_with_win(
            "backup-tar-groups",
            Grouped::from_items(snapshots, group_by).groups,
        );
    });

    // filter snapshots by tag
    let filter = |snap: &SnapshotFile| snap.tags.contains("a");
    let snaps = repo.get_matching_snapshots(filter)?;
    insta_snapshotfile_redaction.bind(|| {
        assert_with_win("backup-tar-matching-snaps", &snaps);
    });

    Ok(())
}

#[rstest]
fn test_backup_dry_run_with_tar_gz_passes(
    tar_gz_testdata: Result<TestSource>,
    set_up_repo: Result<RepoOpen>,
    insta_snapshotfile_redaction: Settings,
    insta_node_redaction: Settings,
) -> Result<()> {
    // Fixtures
    let (source, repo) = (tar_gz_testdata?, set_up_repo?.to_indexed_ids()?);

    let paths = &source.path_list();

    // we use as_path to not depend on the actual tempdir
    let opts = BackupOptions::default()
        .as_path(PathBuf::from_str("test")?)
        .dry_run(true);

    // dry-run backup
    let snap_dry_run = repo.backup(&opts, paths, SnapshotFile::default())?;

    insta_snapshotfile_redaction.bind(|| {
        assert_with_win("dryrun-tar-summary-first", &snap_dry_run);
    });

    // check that repo is still empty
    let snaps = repo.get_all_snapshots()?;
    assert_eq!(snaps.len(), 0);
    assert_eq!(repo.list::<PackId>()?.count(), 0);
    assert_eq!(repo.list::<PackId>()?.count(), 0);

    // first real backup
    let opts = opts.dry_run(false);
    let first_snapshot = repo.backup(&opts, paths, SnapshotFile::default())?;
    assert_eq!(snap_dry_run.tree, first_snapshot.tree);
    let packs: Vec<_> = repo.list::<PackId>()?.collect();

    // tree of first backup
    // re-read index
    let repo = repo.to_indexed_ids()?;
    let tree = repo.node_from_path(first_snapshot.tree, Path::new("test/0/tests"))?;
    let tree = repo.get_tree(&tree.subtree.expect("Sub tree"))?;

    insta_node_redaction.bind(|| {
        assert_with_win("dryrun-tar-tree", tree);
    });

    // re-read index
    let repo = repo.to_indexed_ids()?;
    // second dry-run backup
    let opts = opts.dry_run(true);
    let snap_dry_run = repo.backup(&opts, paths, SnapshotFile::default())?;

    insta_snapshotfile_redaction.bind(|| {
        assert_with_win("dryrun-tar-summary-second", &snap_dry_run);
    });

    // check that no data has been added
    let snaps = repo.get_all_snapshots()?;
    assert_eq!(snaps, vec![first_snapshot]);
    let packs_dry_run: Vec<PackId> = repo.list()?.collect();
    assert_eq!(packs_dry_run, packs);

    // re-read index
    let repo = repo.to_indexed_ids()?;
    // second real backup
    let opts = opts.dry_run(false);
    let second_snapshot = repo.backup(&opts, paths, SnapshotFile::default())?;
    assert_eq!(snap_dry_run.tree, second_snapshot.tree);
    Ok(())
}

#[rstest]
fn test_backup_stdin_command(
    set_up_repo: Result<RepoOpen>,
    insta_snapshotfile_redaction: Settings,
) -> Result<()> {
    // Fixtures
    let repo = set_up_repo?.to_indexed_ids()?;
    let paths = PathList::from_string("-")?;

    let cmd: CommandInput = "echo test".parse()?;
    let opts = BackupOptions::default()
        .stdin_filename("test")
        .stdin_command(cmd);
    // backup data from cmd
    let snapshot = repo.backup(&opts, &paths, SnapshotFile::default())?;
    insta_snapshotfile_redaction.bind(|| {
        assert_with_win("stdin-command-summary", &snapshot);
    });

    // re-read index
    let repo = repo.to_indexed()?;

    // check content
    let node = repo.node_from_snapshot_path("latest:test", |_| true)?;
    let mut content = Vec::new();
    repo.dump(&node, &mut content)?;
    assert_eq!(content, b"test\n");
    // BackOtter: the size is the bytes read, as restic records it
    assert_eq!(node.meta.size, 5);
    Ok(())
}

#[cfg(not(any(windows, target_os = "openbsd")))]
#[rstest]
fn test_backup_excludes_xattr_entries(set_up_repo: Result<RepoOpen>) -> Result<()> {
    use std::ffi::OsStr;
    use std::fs;

    use rustic_core::{
        LocalSourceFilterOptions, LsOptions, RusticResult,
        repofile::{Metadata, Node, NodeType},
    };

    if !xattr::SUPPORTED_PLATFORM {
        return Ok(());
    }

    let tmp = tempfile::tempdir()?;
    let base = tmp.path();

    fs::write(base.join("keep.txt"), "keep")?;
    fs::create_dir(base.join("keep-dir"))?;
    fs::write(base.join("keep-dir").join("nested.txt"), "nested")?;

    let exclude_file = base.join("exclude.txt");
    fs::write(&exclude_file, "excluded")?;
    xattr::set(&exclude_file, "user.rustic_test_exclude", b"")?;

    let exclude_dir = base.join("exclude-dir");
    fs::create_dir(&exclude_dir)?;
    fs::write(exclude_dir.join("nested.txt"), "nested-excluded")?;
    xattr::set(&exclude_dir, "user.rustic_test_exclude", b"")?;

    let repo = set_up_repo?.to_indexed_ids()?;
    let paths = PathList::from_iter(Some(base.to_path_buf()));

    let filter_opts = LocalSourceFilterOptions::default()
        .exclude_if_xattr(vec!["user.rustic_test_exclude".to_string()]);
    let opts = BackupOptions::default()
        .as_path(PathBuf::from("test"))
        .ignore_filter_opts(filter_opts);

    let snapshot = repo.backup(&opts, &paths, SnapshotFile::default())?;

    let repo = repo.to_indexed_ids()?;
    let mut root_node = Node::new_node(OsStr::new(""), NodeType::Dir, Metadata::default());
    root_node.subtree = Some(snapshot.tree);

    let mut paths: Vec<PathBuf> = repo
        .ls(&root_node, &LsOptions::default())?
        .collect::<RusticResult<Vec<_>>>()?
        .into_iter()
        .map(|(path, _)| path)
        .collect();
    paths.sort();

    assert_with_win("backup-exclude-xattr", &paths);

    Ok(())
}

/// BackOtter: a backup with `--set-atime yes` (as BackOtter runs it) keeps
/// each file's and directory's access time, and leaves them as they were in
/// the source (on Linux, where it can read them without updating them). By
/// default, as in stock rustic, the atime stored is the mtime.
#[rstest]
#[cfg(not(windows))]
fn test_backup_keeps_access_times(set_up_repo: Result<RepoOpen>) -> Result<()> {
    use filetime::{FileTime, set_file_atime};
    use rustic_core::{LocalSourceSaveOptions, TimeOption};

    let source = tempfile::tempdir()?;
    let dir = source.path().join("dir");
    std::fs::create_dir(&dir)?;
    std::fs::write(dir.join("file"), vec![1_u8; 100_000])?;
    let old = FileTime::from_unix_time(1_577_836_800, 0); // 2020-01-01
    set_file_atime(dir.join("file"), old)?;
    set_file_atime(&dir, old)?;

    let repo = set_up_repo?.to_indexed_ids()?;
    let opts = BackupOptions::default()
        .as_path(PathBuf::from_str("test")?)
        .ignore_save_opts(LocalSourceSaveOptions::default().set_atime(TimeOption::Yes));
    let paths = PathList::from_iter(Some(source.path().to_path_buf()));
    let first = repo.backup(&opts, &paths, SnapshotFile::default())?;
    let mtime_opts = BackupOptions::default().as_path(PathBuf::from_str("test")?);
    let by_default = repo.backup(&mtime_opts, &paths, SnapshotFile::default())?;

    let repo = repo.to_indexed()?;
    let times = |snap: &SnapshotFile, path: &str| -> Result<(Option<i64>, Option<i64>)> {
        let node = repo.node_from_snapshot_path(&format!("{}:{path}", snap.id), |_| true)?;
        Ok((
            node.meta.atime.map(jiff::Timestamp::as_second),
            node.meta.mtime.map(jiff::Timestamp::as_second),
        ))
    };
    assert_eq!(times(&first, "test/dir")?.0, Some(old.unix_seconds()));
    assert_eq!(times(&first, "test/dir/file")?.0, Some(old.unix_seconds()));
    for path in ["test/dir", "test/dir/file"] {
        let (atime, mtime) = times(&by_default, path)?;
        assert_eq!(atime, mtime, "{path}");
        assert_ne!(atime, Some(old.unix_seconds()), "{path}");
    }

    // The backup read them; on Linux it leaves their access times as they
    // were, even on a file system that updates them (relatime).
    if cfg!(any(target_os = "linux", target_os = "android")) {
        for path in [dir.join("file"), dir] {
            let m = std::fs::metadata(&path)?;
            assert_eq!(FileTime::from_last_access_time(&m), old, "{}", path.display());
        }
        // So a second backup saves the same trees, even where the file
        // system updates atimes on every access (strictatime).
        let repo = repo.to_indexed_ids()?;
        let second = repo.backup(&opts, &paths, SnapshotFile::default())?;
        assert_eq!(second.tree, first.tree);
    }
    Ok(())
}

/// BackOtter: a backup that leaves out what it can't read (a file it may
/// not open, a directory it may not list) still saves its snapshot, with
/// what it could read, and counts what it left out
/// (`SnapshotSummary::items_incomplete`), as BackOtter's restic counts them
/// toward its exit status 3; a backup of what can all be read counts none.
/// Not as root, who reads them all.
#[rstest]
#[cfg(not(windows))]
fn test_backup_counts_what_it_left_out(set_up_repo: Result<RepoOpen>) -> Result<()> {
    use std::{fs, os::unix::fs::PermissionsExt};

    if nix::unistd::geteuid().is_root() {
        return Ok(());
    }
    let repo = set_up_repo?.to_indexed_ids()?;
    let opts = BackupOptions::default().as_path(PathBuf::from_str("test")?);

    let plain = tempfile::tempdir()?;
    fs::write(plain.path().join("ok"), "ok")?;
    let paths = PathList::from_iter(Some(plain.path().to_path_buf()));
    let snap = repo.backup(&opts, &paths, SnapshotFile::default())?;
    assert_eq!(snap.summary.as_ref().unwrap().items_incomplete, 0);

    let source = tempfile::tempdir()?;
    let base = source.path();
    fs::write(base.join("ok"), "ok")?;
    fs::write(base.join("secret"), "secret")?;
    fs::create_dir(base.join("closed"))?;
    fs::write(base.join("closed").join("inner"), "inner")?;
    let mode = |path: &Path, mode: u32| fs::set_permissions(path, fs::Permissions::from_mode(mode));
    mode(&base.join("secret"), 0o000)?;
    mode(&base.join("closed"), 0o000)?;
    let paths = PathList::from_iter(Some(base.to_path_buf()));
    let result = repo.backup(&opts, &paths, SnapshotFile::default());
    mode(&base.join("closed"), 0o755)?;
    mode(&base.join("secret"), 0o644)?;
    let snap = result?;
    assert!(snap.summary.as_ref().unwrap().items_incomplete >= 2);

    let repo = repo.to_indexed()?;
    let node = repo.node_from_snapshot_path(&format!("{}:test/ok", snap.id), |_| true)?;
    assert!(node.is_file());
    Ok(())
}
