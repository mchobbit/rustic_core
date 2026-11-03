//! BackOtter: what a merged snapshot says wrote it.

use std::{path::PathBuf, str::FromStr};

use anyhow::Result;
use pretty_assertions::assert_eq;
use rstest::rstest;

use rustic_core::{BackupOptions, SnapshotOrigin, last_modified_node, repofile::SnapshotFile};

use super::{RepoOpen, TestSource, set_up_repo, tar_gz_testdata};

/// A merged snapshot is BackOtter's (its program version has `+backotter`,
/// and its nodes' missing attributes were zero) only if every snapshot
/// merged is; one of stock rustic among them makes it stock rustic's
/// (`rustic X.Y.Z`, without `+backotter`).
#[rstest]
fn test_merge_known_bko_only_if_all_are(
    tar_gz_testdata: Result<TestSource>,
    set_up_repo: Result<RepoOpen>,
) -> Result<()> {
    let (source, repo) = (tar_gz_testdata?, set_up_repo?.to_indexed_ids()?);
    let paths = &source.path_list();
    let opts = BackupOptions::default().as_path(PathBuf::from_str("test")?);

    // This fork's own snapshots are BackOtter's.
    let bko = SnapshotFile::default();
    assert!(SnapshotOrigin::of(&bko).known_bko(), "{}", bko.program_version);
    let stock_version = bko.program_version.split("+backotter").next().unwrap().to_string();
    let bko1 = repo.backup(&opts, paths, SnapshotFile::default())?;
    let bko2 = repo.backup(&opts, paths, SnapshotFile::default())?;
    let stock = repo.backup(
        &opts,
        paths,
        SnapshotFile {
            program_version: stock_version.clone(),
            ..SnapshotFile::default()
        },
    )?;
    assert!(!SnapshotOrigin::of(&stock).known_bko());

    let repo = repo.to_indexed()?;
    let merge = |snaps: &[SnapshotFile]| {
        repo.merge_snapshots(snaps, &last_modified_node, SnapshotFile::default())
    };
    let merged = merge(&[bko1.clone(), bko2])?;
    assert_eq!(merged.program_version, bko.program_version);
    assert!(SnapshotOrigin::of(&merged).known_bko());

    let merged = merge(&[bko1, stock])?;
    assert_eq!(merged.program_version, stock_version);
    assert!(!SnapshotOrigin::of(&merged).known_bko());
    // As saved.
    let saved = repo.get_snapshot_from_str(&merged.id.to_string(), |_| true)?;
    assert_eq!(saved.program_version, stock_version);
    Ok(())
}
