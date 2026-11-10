use std::{collections::BTreeMap, ffi::OsStr};
use std::{path::PathBuf, str::FromStr};

use anyhow::Result;
use insta::Settings;
use rstest::rstest;

use rustic_core::{
    BackupOptions, Excludes, LsOptions, RusticResult,
    repofile::{Metadata, Node, SnapshotFile},
};

use super::{
    RepoOpen, TestSource, assert_with_win, insta_node_redaction, set_up_repo, tar_gz_testdata,
};

#[rstest]
fn test_ls(
    tar_gz_testdata: Result<TestSource>,
    set_up_repo: Result<RepoOpen>,
    insta_node_redaction: Settings,
) -> Result<()> {
    // Fixtures
    let (source, repo) = (tar_gz_testdata?, set_up_repo?.to_indexed_ids()?);
    let paths = &source.path_list();

    // we use as_path to not depend on the actual tempdir
    let opts = BackupOptions::default().as_path(PathBuf::from_str("test")?);
    // backup test-data
    let snapshot = repo.backup(&opts, paths, SnapshotFile::default())?;

    // test non-existing entries
    let mut node = Node::new_node(
        OsStr::new(""),
        rustic_core::repofile::NodeType::Dir,
        Metadata::default(),
    );
    node.subtree = Some(snapshot.tree);

    // re-read index
    let repo = repo.to_indexed_ids()?;

    let entries: BTreeMap<_, _> = repo
        .ls(&node, &LsOptions::default())?
        .collect::<RusticResult<_>>()?;

    insta_node_redaction.bind(|| {
        assert_with_win("ls", &entries);
    });

    Ok(())
}

#[rstest]
fn test_ls_dir_without_subtree_does_not_panic(set_up_repo: Result<RepoOpen>) -> Result<()> {
    let repo = set_up_repo?.to_indexed_ids()?;
    let node = Node::new_node(
        OsStr::new("corrupted_dir"),
        rustic_core::repofile::NodeType::Dir,
        Metadata::default(),
    );
    assert!(node.subtree.is_none());

    let entries: Vec<_> = repo
        .ls(&node, &LsOptions::default())?
        .collect::<RusticResult<_>>()?;

    assert_eq!(entries, []);
    Ok(())
}

/// BackOtter: with `with_parents`, the directories above the nodes the
/// globs let through, which they don't let through themselves, come just
/// before the first of them, in order, each once, as a restore needs them;
/// without it only the nodes let through, as in stock rustic.
#[rstest]
fn test_ls_with_parents(
    tar_gz_testdata: Result<TestSource>,
    set_up_repo: Result<RepoOpen>,
) -> Result<()> {
    let (source, repo) = (tar_gz_testdata?, set_up_repo?.to_indexed_ids()?);
    let paths = &source.path_list();
    let opts = BackupOptions::default().as_path(PathBuf::from_str("test")?);
    let snapshot = repo.backup(&opts, paths, SnapshotFile::default())?;
    let mut node = Node::new_node(
        OsStr::new(""),
        rustic_core::repofile::NodeType::Dir,
        Metadata::default(),
    );
    node.subtree = Some(snapshot.tree);
    let repo = repo.to_indexed_ids()?;

    let globs = vec!["test/0/0/9/0".to_string(), "test/0/0/9/1".to_string()];
    let ls_opts = LsOptions::default().excludes(Excludes::default().globs(globs));
    let ls = |ls_opts: &LsOptions| -> Result<Vec<PathBuf>> {
        Ok(repo
            .ls(&node, ls_opts)?
            .map(|item| item.map(|(path, _)| path))
            .collect::<RusticResult<_>>()?)
    };
    let files: Vec<PathBuf> = ["test/0/0/9/0", "test/0/0/9/1"]
        .iter()
        .map(PathBuf::from)
        .collect();
    assert_eq!(ls(&ls_opts)?, files);

    let with_parents = ls(&ls_opts.with_parents(true))?;
    let mut want: Vec<PathBuf> = ["test", "test/0", "test/0/0", "test/0/0/9"]
        .iter()
        .map(PathBuf::from)
        .collect();
    want.extend(files);
    assert_eq!(with_parents, want);
    Ok(())
}
