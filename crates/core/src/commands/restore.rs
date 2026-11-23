//! `restore` subcommand

use derive_setters::Setters;
use jiff::Timestamp;
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use std::{
    cell::Cell,
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
};

use itertools::Itertools;
use rayon::ThreadPoolBuilder;
use walkdir::{DirEntry, WalkDir};

use crate::{
    backend::{
        FileType, ReadBackend,
        decrypt::DecryptReadBackend,
        local_destination::{self, LocalDestination},
        node::{ExtendedAttribute, Node, NodeType, generic_attributes::XfsOptions},
        osattrs::{self, NotRoot},
    },
    blob::{BlobLocation, BlobLocations},
    error::{ErrorKind, RusticError, RusticResult},
    repofile::{SnapshotFile, packfile::PackId},
    repository::{IndexedFull, IndexedTree, Open, Repository},
};

mod exact;
pub use exact::CloneSources;
// BackOtter: one handle per file while it has blobs to come.
mod files_writer;
// BackOtter: our own parts of the restore, in files of ours: whether the
// destination is fresh, the bytes held at once, and what the plan keeps of
// the destination and removes from it.
mod budget;
mod fresh;
mod prepare;
pub use fresh::restore_target_is_fresh;
pub(crate) use prepare::making_entries;
pub use prepare::put_back_xfs_options;
use prepare::{DirChanges, Prepare, Replaced, remove_held};
#[cfg(test)]
mod test_log;

pub(crate) mod constants {
    /// The maximum number of reader threads to use for restoring.
    pub(crate) const MAX_READER_THREADS_NUM: usize = 20;
    /// BackOtter: the reader threads per CPU, up to [`MAX_READER_THREADS_NUM`]:
    /// a small machine gets fewer packs read and written at once.
    pub(crate) const READER_THREADS_PER_CPU: usize = 4;
    /// BackOtter: the most bytes of pack data a restore holds at once, read
    /// and decrypted, until every write of it is done. Without it the 20
    /// readers each held a whole coalesced read (up to 40 MiB) and its
    /// decrypted blobs while their writes queued, and rustic-bko grew to
    /// ~1.7 GB and was killed in the OpenBSD rescue image, which has 3 GiB
    /// and no swap.
    pub(crate) const MAX_RESTORE_BYTES_IN_FLIGHT: u64 = 256 * 1024 * 1024;
}

type Filenames = Vec<PathBuf>;
type RestoreInfo = BTreeMap<(PackId, BlobLocation), SmallVec<[FileLocation; 1]>>;

#[allow(clippy::struct_excessive_bools)]
#[cfg_attr(feature = "clap", derive(clap::Parser))]
#[derive(Debug, Copy, Clone, Default, Setters)]
#[setters(into)]
#[non_exhaustive]
/// Options for the `restore` command
pub struct RestoreOptions {
    /// Remove all files/dirs in destination which are not contained in snapshot.
    ///
    /// # Warning
    ///
    /// * Use with care, maybe first try this with `--dry-run`?
    #[cfg_attr(feature = "clap", clap(long))]
    pub delete: bool,

    /// Use numeric ids instead of user/group when restoring uid/gui
    #[cfg_attr(feature = "clap", clap(long))]
    pub numeric_id: bool,

    // BackOtter: names are the default, as in stock rustic; --by-name (and
    // --ownership-by-name, restic's name for it) says so explicitly.
    /// Look the owners up by user/group name, falling back to the saved uid/gid (the default)
    #[cfg_attr(
        feature = "clap",
        clap(
            long,
            visible_alias = "ownership-by-name",
            conflicts_with = "numeric_id"
        )
    )]
    pub by_name: bool,

    /// Don't restore ownership (user/group)
    #[cfg_attr(
        feature = "clap",
        clap(long, conflicts_with = "numeric_id", conflicts_with = "by_name")
    )]
    pub no_ownership: bool,

    /// Always read and verify existing files (don't trust correct modification time and file size)
    #[cfg_attr(feature = "clap", clap(long))]
    pub verify_existing: bool,

    // BackOtter: for bko-holt's btrfs snapshots, each a snapshot of a tree
    // restored before (commands/restore/exact.rs).
    /// Make the destination exactly the snapshot, writing only what differs: implies --delete and --verify-existing; a file with other names gets a name of its own first; an entry whose metadata already matches is left untouched
    #[cfg_attr(feature = "clap", clap(long))]
    pub exact: bool,

    // BackOtter: new files that had holes ("unix.sparse") are restored
    // sparse anyway, see write_sparse.
    /// Restore sparse files: by-content makes holes for zero runs in every new file [default: only in new files that had holes]
    #[cfg_attr(feature = "clap", clap(long))]
    pub sparse: Option<SparseRestore>,

    // BackOtter: not an option, but what the snapshot says: the caller sets
    // it from the snapshot it restores ([`SnapshotOrigin::of`]).
    /// What wrote the snapshot restored, which says what a node's missing attributes mean
    #[cfg_attr(feature = "clap", clap(skip))]
    pub origin: SnapshotOrigin,
}

/// BackOtter: what wrote the snapshot a restore restores, by its
/// `program_version`, which says what a node's missing attributes mean.
///
/// BackOtter's restic and rustic (`+backotter` in the version) record
/// everything they can, so a missing attribute means zero or none at backup
/// time: no file flags, no project ID, no holes worth keeping. In any other
/// snapshot a missing attribute means unknown, and the restore leaves the
/// destination as it is, as stock rustic does. Stock restic leaves a mode
/// of 0 out (Go's `omitempty`), so a regular file of a Unix file system
/// without a mode had mode 0 there.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SnapshotOrigin {
    /// Stock rustic, or not known: missing attributes are unknown
    #[default]
    Other,
    /// Stock restic: a missing mode is 0, other missing attributes unknown
    Restic,
    /// BackOtter's restic or rustic: missing attributes are zero or none
    BackOtter,
}

impl RestoreOptions {
    /// BackOtter: the options as the restore applies them: `exact` implies
    /// `delete` and `verify_existing`.
    #[must_use]
    pub const fn resolved(mut self) -> Self {
        if self.exact {
            self.delete = true;
            self.verify_existing = true;
        }
        self
    }
}

impl SnapshotOrigin {
    /// The origin of a snapshot written by the program `program_version`
    /// (`restic 0.18.1`, `rustic 0.11.4+backotter.3`). None (empty) is
    /// restic's before 0.16, which wrote none: stock rustic always writes
    /// `rustic VERSION`.
    #[must_use]
    pub fn from_program_version(program_version: &str) -> Self {
        if program_version.contains("+backotter") {
            Self::BackOtter
        } else if program_version.is_empty() || program_version.starts_with("restic ") {
            // restic before 0.16 wrote no program version; rustic always has.
            Self::Restic
        } else {
            Self::Other
        }
    }

    /// The origin of the snapshot `snap`.
    #[must_use]
    pub fn of(snap: &SnapshotFile) -> Self {
        Self::from_program_version(&snap.program_version)
    }

    /// Whether a missing attribute means zero or none at backup time:
    /// a snapshot of BackOtter's restic or rustic.
    #[must_use]
    pub const fn known_bko(self) -> bool {
        matches!(self, Self::BackOtter)
    }

    /// Whether a regular file read from a Unix file system without a mode
    /// had mode 0: restic (any) leaves a mode of 0 out, and so did
    /// BackOtter's rustic before it wrote `"mode":0`.
    #[must_use]
    pub const fn omits_zero_mode(self) -> bool {
        matches!(self, Self::Restic | Self::BackOtter)
    }
}

/// Which files to restore sparse (BackOtter: new files that had holes are,
/// anyway)
#[derive(Serialize, Default, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum SparseRestore {
    /// Only new files that had holes
    #[default]
    No,
    /// Every new file: its zero runs as holes
    ByContent,
}

#[derive(Default, Debug, Clone, Copy)]
#[non_exhaustive]
/// Statistics for files or directories
pub struct FileDirStats {
    /// Number of files or directories to restore
    pub restore: u64,
    /// Number of files or directories which are unchanged (determined by date, but not verified)
    pub unchanged: u64,
    /// Number of files or directories which are verified and unchanged
    pub verified: u64,
    /// Number of files or directories which are modified
    pub modify: u64,
    /// Number of additional entries
    pub additional: u64,
}

#[derive(Default, Debug, Clone, Copy)]
#[non_exhaustive]
/// Restore statistics
pub struct RestoreStats {
    /// file statistics
    pub files: FileDirStats,
    /// directory statistics
    pub dirs: FileDirStats,
    /// BackOtter: failures while collecting and preparing (walking the
    /// destination for `--delete`, removing what `--delete` or a node of
    /// another type wants gone, flags that go on before entries or
    /// contents), warned about each, which BackOtter's restic counts as
    /// errors (exit 1)
    pub errors: u64,
}

#[derive(Default, Debug, Clone, Copy)]
#[non_exhaustive]
/// BackOtter: what restoring a plan couldn't do and only warned about.
///
/// Metadata not set for a reason other than the target not supporting it,
/// and special files not made. BackOtter's restic counts each as an error
/// (exit 1).
pub struct RestoreOutcome {
    /// Number of such failures
    pub errors: u64,
}

/// BackOtter: the failures of setting metadata that the restore warns about
/// and BackOtter's restic counts as errors (exit 1), by the same rules
/// (`osattrs::restore_error_counts`, `LocalDestination::error_counts`).
#[derive(Debug)]
struct RestoreTally {
    /// How many.
    errors: u64,
    /// Whether the restore runs as root.
    root: bool,
}

impl RestoreTally {
    fn new() -> Self {
        Self {
            errors: 0,
            root: osattrs::is_root(),
        }
    }

    /// Warns about `err` restoring the metadata of `path`
    /// (`osattrs::warn_restore`), and counts it if restic would;
    /// `not_root` says whether the step is one restic's restore not
    /// running as root doesn't count a permission refused for.
    fn io(&mut self, path: &Path, err: &std::io::Error, not_root: NotRoot) {
        osattrs::warn_restore(path, err);
        self.count(err, not_root);
    }

    /// Counts `err`, warned about already, if restic would.
    fn count(&mut self, err: &std::io::Error, not_root: NotRoot) {
        if osattrs::restore_error_counts(err, not_root, self.root) {
            self.errors += 1;
        }
    }

    /// Counts `err`, from the destination and warned about already, if
    /// restic would.
    fn dest(&mut self, err: &local_destination::LocalDestinationErrorKind) {
        if LocalDestination::error_counts(err, self.root) {
            self.errors += 1;
        }
    }

    /// Counts a failure restic always counts (a special file not made).
    const fn always(&mut self) {
        self.errors += 1;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct HardlinkKey {
    device_id: u64,
    inode: u64,
}

/// Restore the repository to the given destination.
///
/// # Type Parameters
///
/// * `P` - The progress bar type
/// * `S` - The type of the indexed tree
///
/// # Arguments
///
/// * `file_infos` - The restore information
/// * `repo` - The repository to restore
/// * `opts` - The restore options
/// * `node_streamer` - The node streamer to use
/// * `dest` - The destination to restore to
///
/// # Errors
///
/// * If the restore failed.
///
/// # Returns
///
/// BackOtter: what it couldn't do and only warned about ([`RestoreOutcome`]).
pub(crate) fn restore_repository<S: IndexedTree>(
    file_infos: RestorePlan,
    repo: &Repository<S>,
    opts: RestoreOptions,
    node_streamer: impl Iterator<Item = RusticResult<(PathBuf, Node)>>,
    dest: &LocalDestination,
) -> RusticResult<RestoreOutcome> {
    repo.warm_up_wait(file_infos.to_packs().into_iter())?;
    let failed = restore_contents(
        repo,
        dest,
        &file_infos.names,
        file_infos.file_lengths,
        &file_infos.sparse,
        file_infos.r,
        file_infos.restore_size,
    )?;

    let p = repo.progress_spinner("setting metadata...");
    let errors = restore_metadata(
        without_sockets(node_streamer),
        &file_infos.hardlink_candidates,
        &file_infos.unbroken,
        &failed,
        file_infos.dirs,
        opts,
        dest,
    )?;
    p.finish();

    // BackOtter: files whose contents couldn't be written fail the restore,
    // as in BackOtter's restic (exit 1), once everything else is restored.
    if !failed.is_empty() {
        return Err(RusticError::new(
            ErrorKind::InputOutput,
            "The contents of `{count}` files could not be restored; see the errors above.",
        )
        .attach_context("count", failed.len().to_string()));
    }

    Ok(RestoreOutcome { errors })
}

/// Collect restore information, scan existing files, create needed dirs and remove superfluous files
///
/// # Type Parameters
///
/// * `P` - The progress bar type.
/// * `S` - The type of the indexed tree.
///
/// # Arguments
///
/// * `repo` - The repository to restore.
/// * `node_streamer` - The node streamer to use.
/// * `dest` - The destination to restore to.
/// * `dry_run` - If true, don't actually restore anything, but only print out what would be done.
///
/// # Errors
///
/// * If a directory could not be created.
/// * If the restore information could not be collected.
#[allow(clippy::too_many_lines)]
pub(crate) fn collect_and_prepare<S: IndexedFull>(
    repo: &Repository<S>,
    opts: RestoreOptions,
    node_streamer: impl Iterator<Item = RusticResult<(PathBuf, Node)>>,
    dest: &LocalDestination,
    dry_run: bool,
) -> RusticResult<RestorePlan> {
    let mut node_streamer = without_sockets(node_streamer);
    let p = repo.progress_spinner("collecting file information...");
    let dest_path = dest.path("").map_err(|err| {
        RusticError::with_source(
            ErrorKind::InputOutput,
            "Failed to resolve destination base path.",
            err,
        )
    })?;

    let mut stats = RestoreStats::default();
    let mut restore_infos = RestorePlan::default();
    let mut additional_existing = false;
    // BackOtter: what the plan keeps of our own, and does to the destination
    // that stock rustic doesn't, is in restore/prepare.rs (Prepare), which
    // the closures and the loop below call. What --delete removes is removed
    // once the walk is done, so that every file the restore replaces a name
    // of is known by then (Replaced), whatever order the names come in. The
    // walk's errors that count are counted here: a Cell, as next_entry is
    // used by the loop and by process_existing.
    let mut prep = Prepare::new(opts, dest, &dest_path, dry_run);
    let mut extra = Vec::new();
    let walk_errors = Cell::new(0_u64);

    let next_entry = |walker: &mut walkdir::IntoIter| -> Option<DirEntry> {
        walker
            .inspect(|r| {
                if let Err(err) = r {
                    error!("Error during collection of files: {err:?}");
                    if prepare::walk_error_counts(err, opts.delete) {
                        walk_errors.set(walk_errors.get() + 1);
                    }
                }
            })
            .find_map(Result::ok)
    };

    let mut process_existing =
        |walker: &mut walkdir::IntoIter, entry: &DirEntry| -> RusticResult<Option<DirEntry>> {
            if entry.depth() == 0 {
                // don't process the root dir which should be existing
                return Ok(next_entry(walker));
            }

            // BackOtter: this process's own links' directory (paths past
            // PATH_MAX), there when $TMPDIR is in the destination, is no
            // entry of it: not counted, and never removed (--delete removed
            // it, and the files past PATH_MAX were then written inside
            // $TMPDIR and lost: ForkAudit1 G7-01).
            if entry.file_type().is_dir() && walkdir::is_short_path_dir(entry.path()) {
                walker.skip_current_dir();
                return Ok(next_entry(walker));
            }

            debug!("additional {}", entry.path().display());
            let is_dir = entry.file_type().is_dir();
            if is_dir {
                stats.dirs.additional += 1;
            } else {
                stats.files.additional += 1;
            }
            match (opts.delete, dry_run, is_dir) {
                (true, true, true) => {
                    info!(
                        "would have removed the additional dir: {}",
                        entry.path().display()
                    );
                }
                (true, true, false) => {
                    info!(
                        "would have removed the additional file: {}",
                        entry.path().display()
                    );
                }
                (true, false, _) => extra.push((entry.path().to_path_buf(), is_dir)),
                (false, _, _) => {
                    additional_existing = true;
                }
            }

            // don't descend into extra dirs
            if is_dir {
                walker.skip_current_dir();
            }
            Ok(next_entry(walker))
        };

    let mut process_node = |prep: &mut Prepare<'_>,
                            path: &PathBuf,
                            node: &Node,
                            exists: bool|
     -> RusticResult<_> {
        // BackOtter: the node's path in the destination, checked, and
        // whether it is there under another name (a case-insensitive
        // directory).
        let target = prep.target_of(path)?;
        let exists = prep.found_under_another_name(&target, node, exists);
        match node.node_type {
            NodeType::Dir => {
                if exists {
                    stats.dirs.modify += 1;
                    trace!("existing dir {}", path.display());
                    prep.existing_dir(path, node, &target);
                } else {
                    stats.dirs.restore += 1;
                    debug!("to restore: {}", path.display());
                    if !dry_run {
                        prep.dirs.change_parent(&target);
                        dest.create_dir(path)
                            .map_err(|err| {
                                RusticError::with_source(
                                    ErrorKind::InputOutput,
                                    "Failed to create the directory `{path}`. Please check the path and try again.",
                                    err
                                )
                                .attach_context("path", path.display().to_string())
                            })?;
                        prep.created_dir(path, node, &target);
                    }
                }
            }
            NodeType::File => {
                if let Some(key) = hardlink_key(node) {
                    match restore_infos.hardlink_candidates.entry(key) {
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            trace!("Adding hardlink candidate {}", path.display());
                            _ = entry.insert(path.clone());
                        }
                        // this is a hardlink to an existing candidate, will be processed later while setting metadata
                        std::collections::btree_map::Entry::Occupied(_) => {
                            prep.later_link_name(key, node, target, exists);
                            return Ok(());
                        }
                    }
                }
                // collect blobs needed for restoring
                // BackOtter: upstream's match on what add_file found, with
                // its counts, is Prepare::plan_file.
                prep.plan_node_file(&mut restore_infos, repo, path, node, &target, exists)?;
            }
            _ => {} // nothing to do for symlink, device, etc.
        }
        Ok(())
    };

    let mut walker = WalkDir::new(&dest_path)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter();

    let mut next_dst = next_entry(&mut walker);

    let mut next_node = node_streamer.next().transpose()?;

    loop {
        match (&next_dst, &next_node) {
            (None, None) => break,

            (Some(destination), None) => {
                next_dst = process_existing(&mut walker, destination)?;
            }
            (Some(destination), Some((path, node))) => {
                let target_path = dest.path(path).map_err(|err| {
                    RusticError::with_source(
                        ErrorKind::InputOutput,
                        "Invalid path in snapshot for restore destination: `{path}`.",
                        err,
                    )
                    .attach_context("path", path.display().to_string())
                })?;
                match destination.path().cmp(&target_path) {
                    Ordering::Less => {
                        next_dst = process_existing(&mut walker, destination)?;
                    }
                    Ordering::Equal => {
                        // process existing node
                        // BackOtter: under --exact, a special file that is
                        // already the same (a symlink to the same target)
                        // stays, and so stays shared.
                        let kept_special = node.is_special()
                            && opts.exact
                            && exact::same_type(destination.path(), node);
                        if (node.is_dir() && !destination.file_type().is_dir())
                            || (node.is_file() && !destination.file_type().is_file())
                            || (node.is_special() && !kept_special)
                        {
                            // if types do not match, first remove the existing file
                            // BackOtter: removed as in the way, with or
                            // without --delete (Prepare::replace_existing).
                            let removed;
                            (next_dst, removed) =
                                prep.replace_existing(&mut walker, destination, node, next_entry);
                            process_node(&mut prep, path, node, !removed)?;
                        } else {
                            next_dst = next_entry(&mut walker);
                            process_node(&mut prep, path, node, true)?;
                        }
                        next_node = node_streamer.next().transpose()?;
                    }
                    Ordering::Greater => {
                        process_node(&mut prep, path, node, false)?;
                        next_node = node_streamer.next().transpose()?;
                    }
                }
            }
            (None, Some((path, node))) => {
                process_node(&mut prep, path, node, false)?;
                next_node = node_streamer.next().transpose()?;
            }
        }
    }

    // BackOtter: what waits until the walk has seen every name: --exact's
    // hard-linked files, the later names in the way of their links, and
    // what --delete removes.
    prep.finish(&mut restore_infos, repo, extra)?;

    if additional_existing {
        warn!("Note: additional entries exist in destination");
    }

    // BackOtter: the errors restic counts (RestoreStats::errors) and the
    // files planned, with what the rest of the restore goes on with.
    stats.errors = walk_errors.get();
    prep.into_plan(&mut restore_infos, &mut stats);
    restore_infos.stats = stats;
    p.finish();

    Ok(restore_infos)
}

/// BackOtter: the nodes to restore, without sockets, which restic doesn't
/// restore either. A backup skips them now; older rustic snapshots have them.
fn without_sockets(
    node_streamer: impl Iterator<Item = RusticResult<(PathBuf, Node)>>,
) -> impl Iterator<Item = RusticResult<(PathBuf, Node)>> {
    node_streamer.filter(|item| {
        let Ok((path, node)) = item else { return true };
        let socket = matches!(node.node_type, NodeType::Socket);
        if socket {
            debug!("{} is a socket, not restored", path.display());
        }
        !socket
    })
}

/// Restore the metadata of the files and directories.
///
/// # Arguments
///
/// * `node_streamer` - The node streamer to use
/// * `opts` - The restore options to use
/// * `dest` - The destination to restore to
///
/// # Errors
///
/// * If the restore failed.
///
/// # Returns
///
/// BackOtter: how many failures it warned about that BackOtter's restic
/// counts as errors (exit 1).
#[allow(clippy::too_many_lines)]
fn restore_metadata(
    mut node_streamer: impl Iterator<Item = RusticResult<(PathBuf, Node)>>,
    hardlink_candidates: &BTreeMap<HardlinkKey, PathBuf>,
    unbroken: &BTreeSet<PathBuf>,
    contents_failed: &BTreeSet<PathBuf>,
    dirs: DirChanges,
    opts: RestoreOptions,
    dest: &LocalDestination,
) -> RusticResult<u64> {
    // BackOtter: file flags go on last of all (osattrs), once per file:
    // they belong to the file, not each of its names, and an immutable file
    // (on illumos) refuses having them set again. ZFS's DOS flags (Linux)
    // just before them.
    let mut pass = MetadataPass {
        dirs,
        late: LatePass::default(),
        tally: RestoreTally::new(),
    };
    let how = compared(opts);
    let known_bko = opts.origin.known_bko();
    let finish = |pass: &mut MetadataPass, path: &PathBuf, node: &Node| {
        let MetadataPass { dirs, late, tally } = pass;
        // BackOtter: a directory whose XFS options came off before its
        // entries went in gets those it had back, last, where its node has
        // none, and wherever nothing else is set on it here. It stays in
        // xfs_cleared until the late pass sets them: a restore that stops
        // before puts them back.
        let had_xfs = if node.is_dir() {
            dirs.xfs.had(path)
        } else {
            None
        };
        let only_had_xfs = LateAttrs {
            flags: None,
            dos_flags: None,
            fat_attrs: None,
            xfs_options: had_xfs,
        };
        // BackOtter: under --exact, an entry whose metadata already matches
        // is left untouched, its restricting flags too: setting it again
        // would change its inode (the change time), which a btrfs snapshot
        // then no longer shares. On NetBSD one whose atime alone differs
        // (the restore's own reads moved it) gets it back alone, which
        // leaves its change time.
        let attrs = if opts.exact
            && dest.path(path).is_ok_and(|t| {
                exact::already_matches(&t, node, how) || exact::atime_put_back(&t, node, how)
            }) {
            trace!("metadata already matches: {}", path.display());
            only_had_xfs
        } else {
            let create = !(opts.exact
                && node.is_special()
                && dest.path(path).is_ok_and(|t| exact::same_type(&t, node)));
            // BackOtter: a special file made anew is an entry made in its
            // directory (DirChanges); anything else there loses the flags
            // that would refuse its metadata, where its node says what they
            // are. The late flags pass sets the node's.
            if let Ok(target) = dest.path(path) {
                if create && node.is_special() {
                    dirs.change_parent(&target);
                } else if osattrs::node_sets_flags(node, known_bko) {
                    osattrs::clear_restricting_flags(&target);
                }
            }
            // BackOtter: a file whose contents couldn't be restored, by
            // any of its names (a hard link's later names aren't in the
            // plan: their first name is), gets no times (set_metadata).
            let failed = !contents_failed.is_empty()
                && node.is_file()
                && (contents_failed.contains(path)
                    || hardlink_key(node)
                        .and_then(|key| hardlink_candidates.get(&key))
                        .is_some_and(|first| contents_failed.contains(first)));
            if set_metadata(dest, opts, path, node, create, failed, tally) {
                LateAttrs {
                    flags: osattrs::file_flags(node),
                    dos_flags: osattrs::zfs_dos_flags(node),
                    fat_attrs: osattrs::fat_attrs(node),
                    xfs_options: osattrs::xfs_options(node).or(had_xfs),
                }
            } else {
                only_had_xfs
            }
        };
        if attrs.any() && hardlink_key(node).is_none_or(|key| late.flags_linked.insert(key)) {
            late.file_flags.push((
                path.clone(),
                node.node_type.clone(),
                attrs,
                osattrs::flags_xattrs(node),
            ));
        }
    };

    let mut dir_stack = Vec::new();
    // BackOtter: a failure to read the snapshot's nodes stops the pass, but
    // not the late flags pass, which puts back what came off (E1).
    let mut stream_err = None;
    loop {
        let (path, node) = match node_streamer.next() {
            None => break,
            Some(Ok(item)) => item,
            Some(Err(err)) => {
                stream_err = Some(err);
                break;
            }
        };
        // BackOtter: a file whose hard link --exact couldn't break is left
        // exactly as it is, and the snapshot's other names for it aren't
        // linked to it: an error each.
        if unbroken.contains(&path) {
            continue;
        }
        // Create hardlink directly, if this is one.
        if let Some(key) = hardlink_key(&node)
            && let Some(canonical) = hardlink_candidates.get(&key)
            && canonical != &path
        {
            if unbroken.contains(canonical) {
                error!(
                    "restore {}: not linked to {}, left as it is: its hard link not broken",
                    path.display(),
                    canonical.display()
                );
                pass.tally.always();
                continue;
            }
            // BackOtter: a name already of that file stays.
            if !matches!((dest.path(canonical), dest.path(&path)),
                    (Ok(a), Ok(b)) if exact::same_file(&a, &b))
            {
                debug!(
                    "restoring hardlink {} -> {}",
                    path.display(),
                    canonical.display()
                );
                // BackOtter: one that can't be made is an error of its own,
                // and the restore goes on: the rest gets its metadata, and
                // the late flags pass puts back what came off (E1).
                let sets = osattrs::node_sets_flags(&node, known_bko);
                let linked = link_name(dest, canonical, &path, &node, key, sets, &mut pass);
                if let Err(err) = linked {
                    error!(
                        "restore {}: hard link to {} not made: {err}",
                        path.display(),
                        canonical.display()
                    );
                    pass.tally.always();
                    continue;
                }
            }
        }

        match node.node_type {
            NodeType::Dir => {
                // set metadata for all non-parent paths in stack
                while let Some((stackpath, _)) = dir_stack.last() {
                    if path.starts_with(stackpath) {
                        break;
                    }
                    let (path, node) = dir_stack.pop().unwrap();
                    finish(&mut pass, &path, &node);
                }
                // push current path to the stack
                dir_stack.push((path, node));
            }
            _ => finish(&mut pass, &path, &node),
        }
    }

    // empty dir stack and set metadata
    for (path, node) in dir_stack.into_iter().rev() {
        finish(&mut pass, &path, &node);
    }

    let MetadataPass {
        mut dirs,
        late,
        mut tally,
    } = pass;
    for (path, node_type, late_attrs, xattrs) in late.file_flags {
        // set_metadata made it, so its path is in the destination.
        let Ok(target) = dest.path(&path) else {
            continue;
        };
        // BackOtter: these count as errors as root and not (restic's late
        // flags pass), unless the file system doesn't support them.
        if let Some(attrs) = late_attrs.fat_attrs {
            osattrs::restore_fat_attrs(&target, &node_type, attrs)
                .unwrap_or_else(|err| tally.io(&path, &err, NotRoot::Counted));
        }
        if let Some(xfs) = &late_attrs.xfs_options {
            osattrs::restore_xfs_options(&target, &node_type, xfs)
                .unwrap_or_else(|err| tally.io(&path, &err, NotRoot::Counted));
            // BackOtter: a directory's options, cleared before its entries
            // went in or not, are its node's or those it had now.
            if node_type == NodeType::Dir {
                dirs.xfs.take(&path);
            }
        }
        let (flags, dos_flags) = (late_attrs.flags, late_attrs.dos_flags);
        if let Some(dos_flags) = dos_flags {
            osattrs::restore_zfs_dos_flags(&target, &node_type, dos_flags)
                .unwrap_or_else(|err| tally.io(&path, &err, NotRoot::Counted));
        }
        if let Some(flags) = flags {
            osattrs::restore_file_flags(&target, &node_type, flags, &xattrs)
                .unwrap_or_else(|err| tally.io(&path, &err, NotRoot::Counted));
        }
    }
    // BackOtter: the directories cleared whose options the late pass didn't
    // set (the destination, which keeps its own metadata) get back those
    // they had.
    dirs.xfs
        .put_back(|path, err| tally.io(path, err, NotRoot::Counted));
    // BackOtter: how many files had metadata the file system doesn't
    // support, warned about once; the SELinux labels an active SELinux
    // kept (--exact), one error for them all.
    osattrs::report_unsupported();
    if osattrs::report_labels_kept() {
        tally.always();
    }
    if let Some(err) = stream_err {
        return Err(err);
    }

    Ok(tally.errors)
}

/// BackOtter: what the metadata pass leaves for the late flags pass: each
/// file's late attributes, once per file (`flags_linked`, by its hard-link
/// key).
#[derive(Debug, Default)]
struct LatePass {
    file_flags: Vec<(PathBuf, NodeType, LateAttrs, Vec<ExtendedAttribute>)>,
    flags_linked: BTreeSet<HardlinkKey>,
}

/// BackOtter: what the metadata pass keeps as it goes: the existing
/// directories the restore hasn't changed yet ([`DirChanges`]), what it
/// leaves for the late flags pass, and the failures it counts.
#[derive(Debug)]
struct MetadataPass {
    dirs: DirChanges,
    late: LatePass,
    tally: RestoreTally,
}

/// BackOtter: links the name `path` of the hard-linked file `node` (`key`)
/// to its first name, `canonical`, as the metadata pass does
/// (`LocalDestination::hard_link`): an entry made in its directory
/// ([`DirChanges`]). Where its node says which flags it had, the file loses
/// those that would refuse a link to it (immutable, append-only), which the
/// late flags pass puts back on it, and what is in the way loses those that
/// would refuse its removal, held: its other names get them back once this
/// name is gone ([`remove_held`]).
///
/// # Errors
///
/// * If the link couldn't be made.
fn link_name(
    dest: &LocalDestination,
    canonical: &Path,
    path: &Path,
    node: &Node,
    key: HardlinkKey,
    sets: bool,
    pass: &mut MetadataPass,
) -> std::io::Result<()> {
    let MetadataPass { dirs, late, tally } = pass;
    let (Ok(first), Ok(target)) = (dest.path(canonical), dest.path(path)) else {
        return dest
            .hard_link(canonical, path)
            .map_err(std::io::Error::other);
    };
    dirs.change_parent(&target);
    if sets {
        osattrs::clear_restricting_flags(&first);
        if osattrs::file_flags(node).is_some() && late.flags_linked.insert(key) {
            late.file_flags.push((
                canonical.to_path_buf(),
                node.node_type.clone(),
                LateAttrs {
                    flags: osattrs::file_flags(node),
                    dos_flags: None,
                    fat_attrs: None,
                    xfs_options: None,
                },
                osattrs::flags_xattrs(node),
            ));
        }
    }
    let in_the_way = std::fs::symlink_metadata(walkdir::short_path(&target)).is_ok();
    let mut replaced = Replaced::default();
    let (linked, put_back) = remove_held(&target, sets && in_the_way, &mut replaced, |_, _| {
        dest.hard_link(canonical, path)
            .map_err(std::io::Error::other)
    });
    if let Err(err) = put_back {
        error!(
            "restore {}: restricting flags not put back on its other names: {err}",
            target.display()
        );
        tally.always();
    }
    linked
}

/// BackOtter: the metadata the restore sets last, once every file has
/// everything else: file flags, and before them ZFS's DOS flags, FAT's
/// attributes and XFS's options (Linux).
#[derive(Debug)]
struct LateAttrs {
    flags: Option<u32>,
    dos_flags: Option<u64>,
    fat_attrs: Option<u32>,
    xfs_options: Option<XfsOptions>,
}

impl LateAttrs {
    /// Whether there is any.
    const fn any(&self) -> bool {
        self.flags.is_some()
            || self.dos_flags.is_some()
            || self.fat_attrs.is_some()
            || self.xfs_options.is_some()
    }
}

/// BackOtter: whether to restore the file `node` sparse: one that had holes
/// (`unix.sparse`), or any with `--sparse by-content`, and only into a new,
/// empty file (`fresh`), which the restore sizes without allocating, and
/// where it leaves the all-zero parts of each blob, block by block of the
/// file system, unwritten (`LocalDestination::write_sparse_at`), as
/// BackOtter's restic does. In a
/// file that existed, a hole would keep its old contents. Any other file is
/// allocated in full (preallocated, where the system can) and written out,
/// zeros and all: a swap file, a preallocated file.
fn write_sparse(sparse: Option<SparseRestore>, node: &Node, fresh: bool) -> bool {
    fresh && (sparse == Some(SparseRestore::ByContent) || osattrs::is_sparse(node))
}

/// BackOtter: whether a regular file `node` that the restore leaves as it is
/// (its contents match) gets its holes filled: only in a snapshot of
/// BackOtter's, where a file without `unix.sparse` had no holes at backup,
/// and not with `--sparse by-content`. In any other snapshot no file is
/// marked, and a file with holes there may have had them at backup too: it
/// stays as it is, as in stock rustic.
fn fills_holes(opts: RestoreOptions, node: &Node) -> bool {
    opts.origin.known_bko()
        && opts.sparse != Some(SparseRestore::ByContent)
        && !osattrs::is_sparse(node)
}

/// BackOtter: how a restore sets owners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ownership {
    /// Not at all (`--no-ownership`).
    None,
    /// The saved uid and gid (`--numeric-id`), as restic does.
    Numeric,
    /// By user and group name, falling back to the saved ids (the default,
    /// as in stock rustic; `--by-name`).
    ByName,
}

/// BackOtter: how `opts` say to set owners: by name unless numeric ids are
/// asked for (`--numeric-id`), as in stock rustic.
const fn ownership(opts: RestoreOptions) -> Ownership {
    match (opts.no_ownership, opts.numeric_id) {
        (true, _) => Ownership::None,
        (false, true) => Ownership::Numeric,
        (false, false) => Ownership::ByName,
    }
}

/// BackOtter: how `--exact` compares an entry with its node under `opts`
/// ([`exact::Compared`]): owners only where the restore sets them, which is
/// as root (as BackOtter's restic); not root, it leaves them as they are.
fn compared(opts: RestoreOptions) -> exact::Compared {
    exact::Compared {
        numeric: ownership(opts) == Ownership::Numeric,
        ownership: ownership(opts) != Ownership::None && osattrs::is_root(),
        origin: opts.origin,
    }
}

/// BackOtter: whether the regular file `node`, which has no mode, had mode
/// 0 (permissions `0000`, as /etc/shadow has): when it was read from a Unix
/// file system (it has an inode number; a file read from stdin or made on
/// Windows has none) and the snapshot leaves a mode of 0 out (restic's, or
/// BackOtter's rustic's before it wrote `"mode":0`). Otherwise its mode is
/// unknown, and the file keeps the one it was created with, as in stock
/// rustic.
const fn mode_zero_if_missing(opts: RestoreOptions, node: &Node) -> bool {
    missing_mode_is_zero(opts.origin, node)
}

/// BackOtter: [`mode_zero_if_missing`] by the snapshot's origin, for
/// `--exact`'s comparison too (`exact::same_mode`).
const fn missing_mode_is_zero(origin: SnapshotOrigin, node: &Node) -> bool {
    matches!(node.node_type, NodeType::File)
        && node.meta.mode.is_none()
        && node.meta.inode != 0
        && origin.omits_zero_mode()
}

fn hardlink_key(node: &Node) -> Option<HardlinkKey> {
    (matches!(node.node_type, NodeType::File)
        && node.meta.links > 1
        && node.meta.device_id != 0
        && node.meta.inode != 0)
        .then_some(HardlinkKey {
            device_id: node.meta.device_id,
            inode: node.meta.inode,
        })
}

/// Set the metadata of the given file or directory.
///
/// # Arguments
///
/// * `dest` - The destination to restore to
/// * `opts` - The restore options to use
/// * `path` - The path of the file or directory
/// * `node` - The node information of the file or directory
///
/// # Errors
///
/// If the metadata could not be set.
///
/// # Returns
///
/// BackOtter: false if the node is a special file that couldn't be made,
/// which then gets nothing else, as in BackOtter's restic: one warning for
/// it (restic reports an error), not one more for each step after. Each
/// failure BackOtter's restic counts as an error is counted in `tally`.
///
/// BackOtter: a file whose contents couldn't be restored
/// (`contents_failed`, which the restore's error is for) gets everything
/// but its times, the birth time too (FreeBSD and NetBSD set it as an
/// mtime): with the snapshot's size and mtime the next restore would take
/// it for restored (`RestorePlan::match_file`), leave the wrong contents
/// and report nothing. With another mtime the next restore writes it.
// TODO: Return a result here, introduce errors and get rid of logging.
fn set_metadata(
    dest: &LocalDestination,
    opts: RestoreOptions,
    path: &PathBuf,
    node: &Node,
    create: bool,
    contents_failed: bool,
    tally: &mut RestoreTally,
) -> bool {
    debug!("setting metadata for {}", path.display());
    // BackOtter: not a special file kept as it was (--exact).
    if create && let Err(err) = dest.create_special(path, node) {
        warn!(
            "restore {}: creating special file failed: {err}",
            path.display()
        );
        tally.always();
        return false;
    }
    // create_special refused (and warned of) a path that leaves the
    // destination, so this is one in it.
    let Ok(target) = dest.path(path) else {
        return false;
    };
    // BackOtter: by name, unless numeric ids are asked for (--numeric-id);
    // then on illumos the ids an owner and group that are SIDs have here,
    // before the mode, which a change of owner can clear the setuid bit of.
    // A change of owner refused to a restore not running as root is no
    // warning, as in restic.
    let chown_failed = |what: &str,
                        err: &local_destination::LocalDestinationErrorKind,
                        tally: &mut RestoreTally| {
        if LocalDestination::chown_refused_not_root(err) {
            debug!(
                "not running as root, {} of {} not set: {err}",
                what,
                path.display()
            );
        } else {
            warn_metadata_failed(path, &format!("setting {what}"), err);
            tally.dest(err);
        }
    };
    match ownership(opts) {
        Ownership::None => {}
        Ownership::Numeric => dest
            .set_uid_gid(path, &node.meta)
            .unwrap_or_else(|err| chown_failed("UID/GID", &err, tally)),
        Ownership::ByName => dest
            .set_user_group(path, &node.meta)
            .unwrap_or_else(|err| chown_failed("User/Group", &err, tally)),
    }
    if ownership(opts) != Ownership::None {
        osattrs::restore_owner(&target, node)
            .unwrap_or_else(|err| tally.io(path, &err, NotRoot::Forgiven));
    }
    // BackOtter: the attributes osattrs keeps; ACLs after the mode. One
    // warning naming each attribute not set, and its error.
    let known_bko = opts.origin.known_bko();
    let set_attributes = |tally: &mut RestoreTally| {
        // BackOtter: stock rustic's names on FreeBSD and NetBSD
        // (`user.NAME`) in any snapshot not BackOtter's.
        dest.set_extended_attributes_all(path, &node.meta.extended_attributes, !known_bko, opts.exact)
            .unwrap_or_else(|err| {
                warn!(
                    "restore {}: setting extended attributes failed: {err}",
                    path.display()
                );
                tally.dest(&err);
            });
        osattrs::restore_attributes(&target, node, known_bko, ownership(opts) != Ownership::None)
            .unwrap_or_else(|err| tally.io(path, &err, NotRoot::Forgiven));
    };
    // On Haiku before the mode: BFS wants write access to the file for
    // each attribute it writes, which a restore by a user other than root
    // wouldn't have on a read-only file.
    if cfg!(target_os = "haiku") {
        set_attributes(tally);
    }
    dest.set_permission(path, node, mode_zero_if_missing(opts, node))
        .unwrap_or_else(|err| {
            warn_metadata_failed(path, "chmod", &err);
            tally.dest(&err);
        });
    if node.is_symlink() {
        osattrs::restore_symlink_mode(&target, node).unwrap_or_else(|err| {
            warn!("restore {}: {err}", path.display());
            tally.count(&err, NotRoot::Forgiven);
        });
    }
    if !cfg!(target_os = "haiku") {
        set_attributes(tally);
    }
    osattrs::restore_acls(&target, node, known_bko)
        .unwrap_or_else(|err| tally.io(path, &err, NotRoot::Forgiven));
    if contents_failed {
        debug!(
            "restore {}: times not set, its contents were not restored",
            path.display()
        );
        return true;
    }
    // BackOtter: the birth time just before the times, which on FreeBSD and
    // NetBSD replace the earlier mtime it is set as.
    osattrs::restore_birthtime(&target, node).unwrap_or_else(|err| {
        warn!("restore {}: {err}", path.display());
        tally.count(&err, NotRoot::Forgiven);
    });
    dest.set_times(path, &node.meta).unwrap_or_else(|err| {
        warn_metadata_failed(path, "setting file times", &err);
        tally.dest(&err);
    });
    true
}

/// BackOtter: warns that `what`, a step of setting the metadata of `path`
/// (its owner, mode or times), failed, and why. Two lines: the first is
/// stock rustic's, `restore PATH: WHAT failed.`, as it always was, since
/// bko-holt matches it whole (the root of a FreeBSD msdosfs takes no owner,
/// mode or times, and a restore whose only errors are those passes); the
/// second gives the error, which stock rustic and this left out, so that
/// nothing said what refused it (an immutable file, a read-only file
/// system, a quota).
fn warn_metadata_failed(
    path: &Path,
    what: &str,
    err: &local_destination::LocalDestinationErrorKind,
) {
    warn!("restore {}: {what} failed.", path.display());
    warn!("restore {}: {what}: {err}", path.display());
}

struct PackInfo {
    pack_id: PackId,
    from_file: Option<(usize, u64, u32)>,
    locations: BlobLocations<SmallVec<[(usize, u64); 1]>>,
}

impl PackInfo {
    #[allow(clippy::result_large_err)]
    /// coalesce two `PackInfo` if possible
    fn coalesce(self, other: Self) -> Result<Self, (Self, Self)> {
        if self.pack_id == other.pack_id // if the pack is identical
           && self.from_file.is_none() // and we don't read from a present file
           // and the blobs can be coalesced
           && self.locations.can_coalesce(&other.locations)
        {
            Ok(Self {
                pack_id: self.pack_id,
                from_file: self.from_file,
                locations: self.locations.append(other.locations),
            })
        } else {
            Err((self, other))
        }
    }
}

/// [`restore_contents`] restores all files contents as described by `file_infos`
/// using the [`DecryptReadBackend`] `be` and writing them into the [`LocalDestination`] `dest`.
///
/// # Type Parameters
///
/// * `P` - The progress bar type.
/// * `S` - The state the repository is in.
///
/// # Arguments
///
/// * `repo` - The repository to restore.
/// * `dest` - The destination to restore to.
/// * `file_infos` - The restore information.
///
/// # Errors
///
/// * If the thread pool could not be made.
///
/// # Returns
///
/// BackOtter: the files whose contents couldn't be written (one that can't
/// be opened for writing, say), by their paths in the snapshot, each
/// reported once, with an error, and left as they are; stock rustic stopped
/// at the first, or panicked.
#[allow(clippy::too_many_lines)]
fn restore_contents<S: Open>(
    repo: &Repository<S>,
    dest: &LocalDestination,
    filenames: &Filenames,
    file_lengths: Vec<u64>,
    sparse: &[bool],
    restore_info: RestoreInfo,
    restore_size: u64,
) -> RusticResult<BTreeSet<PathBuf>> {
    let be = repo.dbe();

    // BackOtter: fewer readers on a small machine (see the constants).
    let threads =
        std::thread::available_parallelism().map_or(constants::MAX_READER_THREADS_NUM, |cpus| {
            cpus.get()
                .saturating_mul(constants::READER_THREADS_PER_CPU)
                .min(constants::MAX_READER_THREADS_NUM)
        });

    // BackOtter: each file is written through one handle while it has
    // writes under way, kept open (a bounded number of them) while it has
    // writes to come, and closed after its last, as in BackOtter's restic:
    // opened and closed for each blob, a file on ext4 lost its block
    // preallocation at each close and came out in scattered extents
    // (files_writer). Its writes, one per blob it gets that isn't there
    // already, are counted first. The files that couldn't be written are
    // reported there, each once.
    let mut file_writes = vec![0; file_lengths.len()];
    for fl in restore_info.values().flatten().filter(|fl| !fl.matches) {
        file_writes[fl.file_idx] += 1;
    }
    let writer = files_writer::FilesWriter::new(
        dest,
        filenames,
        sparse,
        &file_lengths,
        file_writes,
        files_writer::max_idle(threads),
    );

    // first create needed empty files, as they are not created later.
    for (i, size) in file_lengths.iter().enumerate() {
        if *size == 0 {
            let path = &filenames[i];
            if let Err(err) = dest.set_length(path, *size, sparse[i]) {
                writer.fail(i, &err);
            }
        }
    }
    drop(file_lengths);

    let p = repo.progress_bytes("restoring file contents...");
    p.set_length(restore_size);

    let packs: Vec<_> = restore_info
        .into_iter()
        .map(|((pack_id, bl), fls)| {
            let from_file = fls
                .iter()
                .find(|fl| fl.matches)
                .map(|fl| (fl.file_idx, fl.file_start, bl.data_length()));

            let name_dests = fls
                .iter()
                .filter(|fl| !fl.matches)
                .map(|fl| (fl.file_idx, fl.file_start))
                .collect();

            PackInfo {
                pack_id,
                from_file,
                locations: BlobLocations::from_blob_location(bl, name_dests),
            }
        })
        // optimize reading from backend by reading many blobs in a row
        .coalesce(PackInfo::coalesce)
        .collect();

    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|err| {
            RusticError::with_source(
                ErrorKind::Internal,
                "Failed to create the thread pool with `{num_threads}` threads. Please try again.",
                err,
            )
            .attach_context("num_threads", threads.to_string())
        })?;

    let budget = &budget::ByteBudget::new(constants::MAX_RESTORE_BYTES_IN_FLIGHT);

    pool.in_place_scope(|s| {
        for PackInfo {
            pack_id,
            from_file,
            locations:
                BlobLocations {
                    offset,
                    length,
                    blobs,
                },
        } in packs
        {
            let p = &p;
            let writer = &writer;

            if !blobs.is_empty() {
                // BackOtter: a pack's bytes are taken from the budget here,
                // on the thread that runs this closure (not the pool's,
                // whose tasks give them back), and held by the reader task
                // and each write task it spawns, until the last is done: the
                // read (or the existing file's part) and its decrypted blobs.
                let cost = match &from_file {
                    Some((_, _, length_file)) => u64::from(*length_file),
                    None => blobs.iter().fold(u64::from(length), |cost, (bl, _)| {
                        cost + u64::from(bl.data_length())
                    }),
                };
                let held = Arc::new(budget.acquire(cost));
                // TODO: error handling!
                s.spawn(move |s1| {
                    let read_data = match &from_file {
                        Some((file_idx, offset_file, length_file)) => {
                            // read from existing file. BackOtter: one that
                            // can't be read (gone since the plan) leaves the
                            // files that were to get its part without their
                            // contents, each reported, not a panic.
                            let name = &filenames[*file_idx];
                            match dest.read_at(name, *offset_file, (*length_file).into()) {
                                Ok(data) => data,
                                Err(err) => {
                                    let err = format!("{} not read: {err}", name.display());
                                    for (bl, name_dests) in blobs {
                                        for (file_idx, _) in name_dests {
                                            writer.skip(file_idx, &err);
                                            p.inc(bl.data_length().into());
                                        }
                                    }
                                    return;
                                }
                            }
                        }
                        None => {
                            // read needed part of the pack
                            be.read_partial(FileType::Pack, &pack_id, false, offset, length)
                                .unwrap()
                        }
                    };

                    // save into needed files in parallel
                    for (bl, name_dests) in blobs {
                        let size = bl.data_length().into();
                        let data = if from_file.is_some() {
                            read_data.clone()
                        } else {
                            let start = usize::try_from(bl.offset - offset)
                                .expect("convert from u32 to usize should not fail!");
                            let end = usize::try_from(bl.offset + bl.length - offset)
                                .expect("convert from u32 to usize should not fail!");
                            be.read_encrypted_from_partial(
                                &read_data[start..end],
                                bl.uncompressed_length,
                            )
                            .unwrap()
                        };
                        // BackOtter: an all-zero blob (holes give many,
                        // each written at many offsets) is looked at once:
                        // a file restored sparse gets nothing of it.
                        let zeros = name_dests.iter().any(|&(file_idx, _)| sparse[file_idx])
                            && local_destination::is_zero(&data);
                        for (file_idx, start) in name_dests {
                            let data = data.clone();
                            let held = Arc::clone(&held);
                            s1.spawn(move |_| {
                                let _held = held;
                                // BackOtter: through the file's handle,
                                // which its first write sizes; a file that
                                // can't be sized or written is reported
                                // and left, not a panic.
                                writer.write(file_idx, start, &data, zeros);
                                p.inc(size);
                            });
                        }
                    }
                });
            }
        }
    });

    p.finish();

    // BackOtter: closes what is left open (nothing, once every write ran).
    let failed = writer.finish();
    Ok(failed.into_iter().map(|i| filenames[i].clone()).collect())
}

/// Information about what will be restored.
///
/// Struct that contains information of file contents grouped by
/// 1) pack ID,
/// 2) blob within this pack
/// 3) the actual files and position of this blob within those
/// 4) Statistical information
///
/// BackOtter: it also says which files are restored sparse: those the
/// restore options and the files' `unix.sparse` marks make sparse, and only
/// where nothing was at their path when the plan was made.
#[derive(Debug, Default)]
pub struct RestorePlan {
    /// The names of the files to restore
    names: Filenames,
    /// The length of the files to restore
    file_lengths: Vec<u64>,
    /// BackOtter: whether to restore each file sparse (`write_sparse`)
    sparse: Vec<bool>,
    /// The restore information
    r: RestoreInfo,
    /// candidates for hardlinks
    hardlink_candidates: BTreeMap<HardlinkKey, PathBuf>,
    /// BackOtter: the existing directories the restore hasn't changed, and
    /// those whose XFS options came off before the restore put entries in
    /// them, with those they had, for the late pass to put back where their
    /// nodes have none; a plan dropped before (an error, or one not
    /// restored) puts them all back.
    dirs: DirChanges,
    /// BackOtter: the files, by their paths in the snapshot, whose hard
    /// link `--exact` couldn't break, left exactly as they are: no
    /// contents, no metadata, and the snapshot's other names for them not
    /// linked to them.
    unbroken: BTreeSet<PathBuf>,
    /// The total restore size
    pub restore_size: u64,
    /// The total size of matched content, i.e. content with needs no restore.
    pub matched_size: u64,
    /// BackOtter: the total size of the files cloned (`--clone-from`)
    pub cloned_size: u64,
    /// Statistics about the restore.
    pub stats: RestoreStats,
}

/// [`FileLocation`] contains information about a file within a blob
#[derive(Debug)]
struct FileLocation {
    // TODO: The index of the file within ... ?
    file_idx: usize,
    /// The start of the file within the blob
    file_start: u64,
    /// Whether the file matches the blob
    ///
    /// This indicates that the file exists and these contents are already correct.
    matches: bool,
}

/// BackOtter: what [`RestorePlan::match_file`] found for a file.
#[derive(Debug)]
enum FileMatch {
    /// It is there, of the right size (and mtime): left as it is.
    Existing,
    /// Its blobs, to restore those that don't match.
    Blobs(MatchedFile),
}

/// BackOtter: a file matched blob by blob ([`RestorePlan::match_file`]), for
/// [`RestorePlan::push_file`].
#[derive(Debug)]
struct MatchedFile {
    /// Its name.
    name: PathBuf,
    /// Its blobs: pack, location, offset in the file, length, whether it
    /// matches what is there.
    blobs: Vec<(PackId, BlobLocation, u64, u64, bool)>,
    /// Its length.
    length: u64,
    /// Whether some blob doesn't match.
    has_unmatched: bool,
    /// Whether it was there, of its size, to match.
    open: bool,
}

impl MatchedFile {
    /// Whether the restore writes to it: some blob doesn't match, or it
    /// wasn't there to match.
    const fn changes(&self) -> bool {
        self.has_unmatched || !self.open
    }
}

/// [`AddFileResult`] indicates the result of adding a file to [`FileLocation`]
// TODO: Add documentation!
enum AddFileResult {
    Verified,
    Modify,
}

impl RestorePlan {
    /// Matches the file `file`, at `name`, against what is there, using
    /// `index` to get blob information: [`FileMatch::Existing`] when it is
    /// there with the right size (and mtime, unless `ignore_mtime`), else its
    /// blobs, each matched or not, for [`Self::push_file`]. BackOtter: stock
    /// rustic's `add_file`, split so that the restore can clone the file or
    /// ready it (its restricting flags) between the two, once it knows the
    /// file changes.
    ///
    /// # Errors
    ///
    /// * If the file could not be matched.
    fn match_file<S: IndexedFull>(
        &mut self,
        dest: &LocalDestination,
        file: &Node,
        name: PathBuf,
        repo: &Repository<S>,
        ignore_mtime: bool,
    ) -> RusticResult<FileMatch> {
        let mut open_file = dest.get_matching_file(&name, file.meta.size);

        // Empty files which exists with correct size should always return Ok(Existing)!
        if file.meta.size == 0
            && let Some(meta) = open_file
                .as_ref()
                .map(std::fs::File::metadata)
                .transpose()
                .map_err(|err|
                    RusticError::with_source(
                        ErrorKind::InputOutput,
                        "Failed to get the metadata of the file `{path}`. Please check the path and try again.",
                        err
                    )
                    .attach_context("path", name.display().to_string())
                )?
                && meta.len() == 0 {
                    // Empty file exists
                    return Ok(FileMatch::Existing);
                }

        if !ignore_mtime
            && let Some(meta) = open_file
                .as_ref()
                .map(std::fs::File::metadata)
                .transpose()
                .map_err(|err|
                    RusticError::with_source(
                        ErrorKind::InputOutput,
                        "Failed to get the metadata of the file `{path}`. Please check the path and try again.",
                        err
                    )
                    .attach_context("path", name.display().to_string())
                )?
            {
                // TODO: This is the same logic as in backend/ignore.rs => consolidate!
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| Timestamp::try_from(t).ok());
                if meta.len() == file.meta.size && mtime == file.meta.mtime {
                    // File exists with fitting mtime => we suspect this file is ok!
                    debug!("file {} exists with suitable size and mtime, accepting it!",name.display());
                    self.matched_size += file.meta.size;
                    return Ok(FileMatch::Existing);
                }
            }

        let mut file_pos = 0;
        let mut has_unmatched = false;
        let mut blobs = Vec::new();
        for id in file.content.iter().flatten() {
            let ie = repo.get_index_entry(id)?;
            let bl = ie.location;
            let length: u64 = bl.data_length().into();

            let matches = open_file
                .as_mut()
                .is_some_and(|file| id.blob_matches_reader(length, file));
            has_unmatched |= !matches;
            blobs.push((ie.pack, bl, file_pos, length, matches));
            file_pos += length;
        }

        Ok(FileMatch::Blobs(MatchedFile {
            name,
            blobs,
            length: file_pos,
            has_unmatched,
            open: open_file.is_some(),
        }))
    }

    /// Adds the file `file`, matched by [`Self::match_file`], to
    /// [`FileLocation`], restored sparse if `sparse`.
    fn push_file(&mut self, file: MatchedFile, sparse: bool) -> AddFileResult {
        let file_idx = self.names.len();
        self.names.push(file.name);
        for (pack, bl, file_start, length, matches) in file.blobs {
            self.r.entry((pack, bl)).or_default().push(FileLocation {
                file_idx,
                file_start,
                matches,
            });
            if matches {
                self.matched_size += length;
            } else {
                self.restore_size += length;
            }
        }

        self.file_lengths.push(file.length);
        self.sparse.push(sparse);

        if !file.has_unmatched && file.open {
            AddFileResult::Verified
        } else {
            AddFileResult::Modify
        }
    }

    /// Get a list of all pack files needed to perform the restore
    ///
    /// This can be used e.g. to warm-up those pack files before doing the actual restore.
    #[must_use]
    pub fn to_packs(&self) -> Vec<PackId> {
        self.r
            .iter()
            // filter out packs which we need
            .filter(|(_, fls)| fls.iter().all(|fl| !fl.matches))
            .map(|((pack, _), _)| *pack)
            .dedup()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::node::generic_attributes::UNIX_SPARSE;

    #[test]
    fn write_sparse_when_marked_or_asked() {
        let plain = Node::default();
        let mut marked = Node::default();
        marked.meta.generic_attributes.set_true(UNIX_SPARSE);
        let by_content = Some(SparseRestore::ByContent);

        // Without --sparse, as before: files without the mark in full, ...
        assert!(!write_sparse(None, &plain, true));
        assert!(!write_sparse(Some(SparseRestore::No), &plain, true));
        // ... those with it sparse; --sparse no doesn't unmark them.
        assert!(write_sparse(None, &marked, true));
        assert!(write_sparse(Some(SparseRestore::No), &marked, true));
        // --sparse makes every file sparse.
        assert!(write_sparse(by_content, &plain, true));
        assert!(write_sparse(by_content, &marked, true));
        // A file that exists is written in full, whatever it was.
        assert!(!write_sparse(None, &marked, false));
        assert!(!write_sparse(by_content, &plain, false));
    }

    #[test]
    fn sockets_not_restored() {
        let node = |name: &str, node_type| {
            Node::new_node(
                name.as_ref(),
                node_type,
                crate::backend::node::Metadata::default(),
            )
        };
        let nodes = vec![
            Ok((PathBuf::from("dir"), node("dir", NodeType::Dir))),
            Ok((PathBuf::from("dir/file"), node("file", NodeType::File))),
            Ok((
                PathBuf::from("dir/socket"),
                node("socket", NodeType::Socket),
            )),
            Ok((PathBuf::from("dir/fifo"), node("fifo", NodeType::Fifo))),
        ];
        let paths: Vec<_> = without_sockets(nodes.into_iter())
            .map(|item| item.unwrap().0)
            .collect();
        assert_eq!(paths, ["dir", "dir/file", "dir/fifo"].map(PathBuf::from));
    }

    #[test]
    fn names_by_default() {
        // As in stock rustic: by name, unless --numeric-id.
        let opts = RestoreOptions::default();
        assert_eq!(ownership(opts), Ownership::ByName);
        assert_eq!(ownership(opts.numeric_id(true)), Ownership::Numeric);
        assert_eq!(ownership(opts.by_name(true)), Ownership::ByName);
        assert_eq!(ownership(opts.no_ownership(true)), Ownership::None);
    }

    #[test]
    fn snapshot_origins() {
        let of = SnapshotOrigin::from_program_version;
        assert_eq!(of("rustic 0.11.4+backotter.3"), SnapshotOrigin::BackOtter);
        assert_eq!(of("restic 0.19.1+backotter.3"), SnapshotOrigin::BackOtter);
        assert_eq!(of("restic 0.18.1"), SnapshotOrigin::Restic);
        assert_eq!(of("rustic v0.11.4"), SnapshotOrigin::Other);
        assert_eq!(of("rustic 0.11.4"), SnapshotOrigin::Other);
        // restic before 0.16 wrote no program version.
        assert_eq!(of(""), SnapshotOrigin::Restic);
        assert_eq!(RestoreOptions::default().origin, SnapshotOrigin::Other);
        assert!(SnapshotOrigin::BackOtter.known_bko());
        assert!(!SnapshotOrigin::Restic.known_bko());
        assert!(!SnapshotOrigin::Other.known_bko());
        assert!(SnapshotOrigin::Restic.omits_zero_mode());
        assert!(SnapshotOrigin::BackOtter.omits_zero_mode());
        assert!(!SnapshotOrigin::Other.omits_zero_mode());
        let snap = SnapshotFile {
            program_version: "restic 0.17.3".to_string(),
            ..SnapshotFile::default()
        };
        assert_eq!(SnapshotOrigin::of(&snap), SnapshotOrigin::Restic);
    }

    /// A regular file without a mode is restored with mode 0 only where
    /// that is what it had: from a Unix file system (an inode number), in a
    /// snapshot that leaves a mode of 0 out (restic's, BackOtter's). A file
    /// read from stdin or made on Windows (no inode number), or any in a
    /// stock rustic snapshot, keeps the mode it was created with.
    #[test]
    fn mode_zero_only_where_known() {
        let meta = crate::backend::node::Metadata::default;
        let mut unix = Node::new_node("shadow".as_ref(), NodeType::File, meta());
        unix.meta.inode = 1234;
        let stdin = Node::new_node("stdin".as_ref(), NodeType::File, meta());
        let restic = RestoreOptions::default().origin(SnapshotOrigin::Restic);
        let bko = RestoreOptions::default().origin(SnapshotOrigin::BackOtter);
        let stock = RestoreOptions::default();
        assert!(mode_zero_if_missing(restic, &unix));
        assert!(mode_zero_if_missing(bko, &unix));
        assert!(!mode_zero_if_missing(stock, &unix));
        assert!(!mode_zero_if_missing(restic, &stdin));
        assert!(!mode_zero_if_missing(bko, &stdin));
        let mut with_mode = unix.clone();
        with_mode.meta.mode = Some(0o644);
        assert!(!mode_zero_if_missing(bko, &with_mode));
        let mut dir = unix.clone();
        dir.node_type = NodeType::Dir;
        assert!(!mode_zero_if_missing(bko, &dir));
        // restic before 0.16 wrote no program version, and left mode 0 out
        // as every restic does; stock rustic always names itself.
        let old_restic = SnapshotFile {
            program_version: String::new(),
            ..SnapshotFile::default()
        };
        let opts = |snap: &SnapshotFile| RestoreOptions::default().origin(SnapshotOrigin::of(snap));
        assert!(mode_zero_if_missing(opts(&old_restic), &unix));
        assert!(!mode_zero_if_missing(opts(&old_restic), &stdin));
        let stock_rustic = SnapshotFile {
            program_version: "rustic 0.13.0".to_string(),
            ..SnapshotFile::default()
        };
        assert!(!mode_zero_if_missing(opts(&stock_rustic), &unix));
        assert!(!SnapshotOrigin::of(&old_restic).known_bko());
    }

    /// Holes of a file left as it is are filled only in BackOtter's
    /// snapshots, for a file without `unix.sparse`, and not with
    /// `--sparse by-content`.
    #[test]
    fn holes_filled_only_where_known() {
        let plain = Node::default();
        let mut marked = Node::default();
        marked.meta.generic_attributes.set_true(UNIX_SPARSE);
        let bko = RestoreOptions::default().origin(SnapshotOrigin::BackOtter);
        assert!(fills_holes(bko, &plain));
        assert!(!fills_holes(bko, &marked));
        assert!(!fills_holes(bko.sparse(SparseRestore::ByContent), &plain));
        assert!(fills_holes(bko.sparse(SparseRestore::No), &plain));
        assert!(!fills_holes(RestoreOptions::default(), &plain));
        assert!(!fills_holes(
            RestoreOptions::default().origin(SnapshotOrigin::Restic),
            &plain
        ));
    }

    /// ForkAudit1 G6-01: a file whose contents couldn't be restored gets
    /// its metadata but for its times, so that the next restore, which
    /// trusts a size and an mtime that match, writes it; any other file
    /// gets the node's times.
    #[cfg(unix)]
    #[test]
    fn contents_failed_sets_no_times() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let dest = LocalDestination::new(dir.path().to_str().unwrap(), true, false).unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, "old").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut node = Node::new_node(
            "f".as_ref(),
            NodeType::File,
            crate::backend::node::Metadata::default(),
        );
        node.meta.mode = Some(0o640);
        node.meta.mtime = Some(Timestamp::from_second(1_600_000_000).unwrap());
        let opts = RestoreOptions::default().no_ownership(true);
        let path = PathBuf::from("f");
        let mut tally = RestoreTally::new();
        let stat = || std::fs::metadata(&file).unwrap();

        assert!(set_metadata(
            &dest, opts, &path, &node, false, true, &mut tally
        ));
        assert_eq!(
            stat().mode() & 0o7777,
            0o640,
            "the rest of its metadata is set"
        );
        assert_ne!(stat().mtime(), 1_600_000_000);

        assert!(set_metadata(
            &dest, opts, &path, &node, false, false, &mut tally
        ));
        assert_eq!(stat().mtime(), 1_600_000_000);
        assert_eq!(tally.errors, 0);
    }

    /// ForkAudit1 G6-02: a step of the metadata that fails (here each of
    /// them: nothing is at the path) is warned of on a line that is stock
    /// rustic's to the letter, which bko-holt matches whole, and the next
    /// line gives its cause.
    #[cfg(unix)]
    #[test]
    fn metadata_warnings_give_the_cause() {
        test_log::capture();
        let dir = tempfile::tempdir().unwrap();
        let dest = LocalDestination::new(dir.path().to_str().unwrap(), true, false).unwrap();
        let name = "g602-nothing-here";
        let mut node = Node::new_node(
            name.as_ref(),
            NodeType::File,
            crate::backend::node::Metadata::default(),
        );
        node.meta.mode = Some(0o644);
        node.meta.mtime = Some(Timestamp::from_second(1_600_000_000).unwrap());
        let path = PathBuf::from(name);
        for (opts, owner) in [
            (
                RestoreOptions::default().numeric_id(true),
                "setting UID/GID",
            ),
            (RestoreOptions::default(), "setting User/Group"),
        ] {
            let before = test_log::lines(name).len();
            let mut tally = RestoreTally::new();
            assert!(set_metadata(
                &dest, opts, &path, &node, false, false, &mut tally
            ));
            assert!(tally.errors >= 3, "owner, mode and times: {}", tally.errors);
            let lines = test_log::lines(name).split_off(before);
            for what in [owner, "chmod", "setting file times"] {
                let failed = format!("restore {name}: {what} failed.");
                let at = lines
                    .iter()
                    .position(|(level, line)| *level == log::Level::Warn && *line == failed)
                    .unwrap_or_else(|| panic!("no line {failed:?} in {lines:?}"));
                let (level, cause) = &lines[at + 1];
                assert_eq!(*level, log::Level::Warn);
                assert!(
                    cause.starts_with(&format!("restore {name}: {what}: "))
                        && cause.contains("No such file or directory"),
                    "{cause}"
                );
            }
        }
    }

    #[cfg(feature = "clap")]
    #[test]
    fn ownership_options() {
        use clap::Parser;

        let parse = |args: &[&str]| {
            RestoreOptions::try_parse_from(std::iter::once("restore").chain(args.iter().copied()))
        };
        assert_eq!(ownership(parse(&[]).unwrap()), Ownership::ByName);
        assert_eq!(
            ownership(parse(&["--numeric-id"]).unwrap()),
            Ownership::Numeric
        );
        assert_eq!(ownership(parse(&["--by-name"]).unwrap()), Ownership::ByName);
        // restic's name for it.
        assert_eq!(
            ownership(parse(&["--ownership-by-name"]).unwrap()),
            Ownership::ByName
        );
        assert_eq!(
            ownership(parse(&["--no-ownership"]).unwrap()),
            Ownership::None
        );
        assert!(parse(&["--by-name", "--numeric-id"]).is_err());
        assert!(parse(&["--by-name", "--no-ownership"]).is_err());
        assert!(parse(&["--ownership-by-name", "--numeric-id"]).is_err());
    }
}
