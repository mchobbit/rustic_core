//! `restore` subcommand

use derive_setters::Setters;
use jiff::Timestamp;
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Mutex,
};

use itertools::Itertools;
use rayon::ThreadPoolBuilder;
use walkdir::{DirEntry, WalkDir};

use crate::{
    backend::{
        FileType, ReadBackend,
        decrypt::DecryptReadBackend,
        local_destination::{self, LocalDestination},
        node::{Node, NodeType, generic_attributes::XfsOptions},
        osattrs,
    },
    blob::{BlobLocation, BlobLocations},
    error::{ErrorKind, RusticError, RusticResult},
    repofile::{SnapshotFile, packfile::PackId},
    repository::{IndexedFull, IndexedTree, Open, Repository},
};

pub(crate) mod constants {
    /// The maximum number of reader threads to use for restoring.
    pub(crate) const MAX_READER_THREADS_NUM: usize = 20;
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
        clap(long, visible_alias = "ownership-by-name", conflicts_with = "numeric_id")
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

/// BackOtter: whether a restore into `dest` gives `dest` the metadata of
/// the node it restores there (`restore SNAP:subfolder DEST`).
///
/// Only when `dest` is fresh: it doesn't exist (the restore creates it), or
/// every entry found walking it (no symlink followed) is one of
///
/// - (a) an entry a file system makes itself ([`made_by_file_system`]:
///   `lost+found`, a directory; FreeBSD UFS's `.snap`, a directory, and
///   `.sujournal`, a regular file; nilfs2's `.nilfs`, an empty regular
///   file), whatever it holds; on Haiku also the empty `trash` directory
///   its Tracker makes on every volume mounted ([`made_by_tracker`]);
/// - (b) a directory that is a mount point: its device (`st_dev`) differs
///   from its parent's. That is also a ZFS dataset's and a btrfs
///   subvolume's root, which have devices of their own. What it holds
///   must again be (a), (b) or (c), relative to it;
/// - (c) a directory on the path to one: it holds only (a), (b) and (c),
///   and at least one (b) at some depth;
///
/// in at most 4096 directories ([`FRESH_TARGET_MAX_DIRS`]). That is a new
/// file system's root with the new file systems of the system restored
/// mounted below it (`/boot`, `/boot/efi`, `/home`, ZFS datasets, btrfs
/// subvolumes): BackOtter's bare-metal restore. Anything else (a file, a
/// symlink, a device, a plain directory, even empty, on `dest`'s own file
/// system, a directory that can't be read) means `dest` stays as it is
/// (owner, mode, times, extended attributes, ACLs and flags), as in stock
/// rustic: a freshly booted server's `/tmp`, with nothing in it but empty
/// `.X11-unix`, `.ICE-unix` and `systemd-private-*/tmp`, keeps its sticky
/// bit. A symlink at `dest` is not fresh. Nor is an existing `dest` that
/// is sticky or that others may write in (mode bits 01000 or 0002,
/// [`shared_dir`]), even empty: a shared directory such as an empty
/// `/tmp` or `/dev/shm` keeps its mode, owner, extended attributes and
/// ACLs. mkfs, newfs, `zfs create` and `btrfs subvolume create` never
/// make such a root. Where there are no device numbers (Windows), no
/// directory is a mount point, and there are no such mode bits. As in
/// BackOtter's restic. Call it before the restore starts.
#[must_use]
pub fn restore_target_is_fresh(dest: impl AsRef<std::path::Path>) -> bool {
    fresh_target_with(dest.as_ref(), &|_, meta| device_of(meta))
}

/// The device of the file of `meta`, where there is one.
#[cfg(unix)]
#[allow(clippy::unnecessary_wraps)] // None on other systems
fn device_of(meta: &std::fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(meta.dev())
}

/// The device of the file of `meta`, where there is one.
#[cfg(not(unix))]
const fn device_of(_meta: &std::fs::Metadata) -> Option<u64> {
    None
}

/// Whether the directory of `meta` is sticky or others may write in it
/// (mode bits 01000 or 0002): a directory shared by its users, like
/// `/tmp`, never a new file system's root.
#[cfg(unix)]
fn shared_dir(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o1002 != 0
}

/// Whether the directory of `meta` is sticky or others may write in it:
/// never, where there are no such mode bits.
#[cfg(not(unix))]
const fn shared_dir(_meta: &std::fs::Metadata) -> bool {
    false
}

/// The device of a path, given its (`lstat`) metadata.
type DeviceOf<'a> = dyn Fn(&std::path::Path, &std::fs::Metadata) -> Option<u64> + 'a;

/// [`restore_target_is_fresh`], with the devices from `device`.
fn fresh_target_with(dest: &std::path::Path, device: &DeviceOf<'_>) -> bool {
    match std::fs::symlink_metadata(dest) {
        Err(err) => err.kind() == std::io::ErrorKind::NotFound,
        Ok(meta) if meta.is_dir() && !shared_dir(&meta) => {
            let mut budget = FRESH_TARGET_MAX_DIRS;
            fresh_dir(dest, device(dest, &meta), device, &mut budget).is_some()
        }
        Ok(_) => false,
    }
}

/// The most directories [`restore_target_is_fresh`] looks at, `dest`
/// included: a destination with more isn't fresh. As BackOtter's restic.
const FRESH_TARGET_MAX_DIRS: usize = 4096;

/// Whether the directory `dir`, on the device `dev`, holds only entries of
/// a fresh target (see [`restore_target_is_fresh`]): None if not, else
/// whether it holds a mount point at some depth. Looks at no more than
/// `budget` directories, `dir` included, and takes those off it.
fn fresh_dir(
    dir: &std::path::Path,
    dev: Option<u64>,
    device: &DeviceOf<'_>,
    budget: &mut usize,
) -> Option<bool> {
    *budget = budget.checked_sub(1)?;
    let mut holds_mount = false;
    for entry in std::fs::read_dir(dir).ok()? {
        let path = entry.ok()?.path();
        // Doesn't follow a symlink; does see what is mounted on `path`.
        let meta = std::fs::symlink_metadata(&path).ok()?;
        if made_by_file_system(path.file_name()?, &meta) || made_by_tracker(&path, &meta) {
            continue;
        }
        if !meta.is_dir() {
            return None;
        }
        let sub_dev = device(&path, &meta);
        let mount_point = sub_dev.is_some() && dev.is_some() && sub_dev != dev;
        let holds = fresh_dir(&path, sub_dev, device, budget)?;
        if !(mount_point || holds) {
            // A plain directory on `dir`'s file system.
            return None;
        }
        holds_mount = true;
    }
    Some(holds_mount)
}

/// Whether the entry `name`, with the (`lstat`) metadata `meta`, is one a
/// new file system has: `lost+found`, a directory (ext2/3/4, bcachefs,
/// illumos UFS); FreeBSD UFS's `.snap`, a directory (newfs without `-n`),
/// and `.sujournal`, a regular file (newfs `-j`); nilfs2's `.nilfs`, an
/// empty regular file (mkfs.nilfs2 2.0.0 to 2.2.9, as in Ubuntu 24.04).
/// As BackOtter's restic.
fn made_by_file_system(name: &std::ffi::OsStr, meta: &std::fs::Metadata) -> bool {
    let file_type = meta.file_type();
    (file_type.is_dir() && (name == "lost+found" || name == ".snap"))
        || (file_type.is_file() && name == ".sujournal")
        || (file_type.is_file() && name == ".nilfs" && meta.len() == 0)
}

/// BackOtter: whether the entry `path`, with the (`lstat`) metadata
/// `meta`, is the `trash` directory that Haiku's Tracker makes, empty, on
/// every BFS volume as soon as it is mounted, a new one too (a Haiku
/// rescuer runs the desktop): on Haiku only, where a new file system's
/// root would otherwise never be fresh, and the restore would leave it
/// mkfs's metadata and the time of its last entry's creation. One that
/// holds anything, or isn't a directory, isn't Tracker's alone.
fn made_by_tracker(path: &std::path::Path, meta: &std::fs::Metadata) -> bool {
    cfg!(target_os = "haiku") && empty_trash(path, meta)
}

/// Whether `path`, with the (`lstat`) metadata `meta`, is an empty
/// directory named `trash` ([`made_by_tracker`], on any system).
fn empty_trash(path: &std::path::Path, meta: &std::fs::Metadata) -> bool {
    meta.is_dir()
        && path.file_name() == Some(std::ffi::OsStr::new("trash"))
        && std::fs::read_dir(path).is_ok_and(|mut dir| dir.next().is_none())
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
pub(crate) fn restore_repository<S: IndexedTree>(
    file_infos: RestorePlan,
    repo: &Repository<S>,
    opts: RestoreOptions,
    node_streamer: impl Iterator<Item = RusticResult<(PathBuf, Node)>>,
    dest: &LocalDestination,
) -> RusticResult<()> {
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
    restore_metadata(
        without_sockets(node_streamer),
        &file_infos.hardlink_candidates,
        opts,
        dest,
    )?;
    p.finish();

    // BackOtter: files whose contents couldn't be written fail the restore,
    // as in BackOtter's restic (exit 1), once everything else is restored.
    if failed > 0 {
        return Err(RusticError::new(
            ErrorKind::InputOutput,
            "The contents of `{count}` files could not be restored; see the errors above.",
        )
        .attach_context("count", failed.to_string()));
    }

    Ok(())
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
    let known_bko = opts.origin.known_bko();
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

    let next_entry = |walker: &mut walkdir::IntoIter| -> Option<DirEntry> {
        walker
            .inspect(|r| {
                if let Err(err) = r {
                    error!("Error during collection of files: {err:?}");
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
                // BackOtter: flags that refuse removal (immutable, ...) stay
                // as they are, as in stock rustic: such a file isn't
                // removed, and the error says why.
                (true, false, true) => {
                    if let Err(err) = dest.remove_dir(entry.path()) {
                        error!("error removing {}: {err}", entry.path().display());
                    }
                }
                (true, false, false) => {
                    if let Err(err) = dest.remove_file(entry.path()) {
                        error!("error removing {}: {err}", entry.path().display());
                    }
                }
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

    // BackOtter: what has a node's name but another type, and any special
    // file, is removed first, with or without --delete, as BackOtter's restic
    // does: a directory is restored as a directory, not through a symlink to
    // wherever that points, and a file or special file is made anew. Without
    // --delete a directory only goes if it is empty. Returns the next entry
    // and whether the old one is gone.
    let replace_existing =
        |walker: &mut walkdir::IntoIter, entry: &DirEntry| -> (Option<DirEntry>, bool) {
            if entry.depth() == 0 {
                return (next_entry(walker), false);
            }
            let is_dir = entry.file_type().is_dir();
            let removed = if dry_run {
                info!("would have replaced {}", entry.path().display());
                true
            } else {
                // BackOtter: nothing below a directory loses its flags:
                // what refuses removal stays, as with --delete.
                match (is_dir, opts.delete) {
                    (false, _) => dest.remove_file(entry.path()).map_err(|err| err.to_string()),
                    (true, true) => dest.remove_dir(entry.path()).map_err(|err| err.to_string()),
                    (true, false) => {
                        std::fs::remove_dir(entry.path()).map_err(|err| err.to_string())
                    }
                }
                .map_err(|err| error!("error removing {}: {err}", entry.path().display()))
                .is_ok()
            };
            if is_dir {
                walker.skip_current_dir();
            }
            (next_entry(walker), removed)
        };

    // A node's path in the destination; one that would leave it ("..", an
    // absolute path) is an error. BackOtter: every path this restore
    // touches outside LocalDestination's own calls is taken from here, so
    // that it is checked too.
    let target_of = |path: &PathBuf| -> RusticResult<PathBuf> {
        dest.path(path).map_err(|err| {
            RusticError::with_source(
                ErrorKind::InputOutput,
                "Invalid path in snapshot for restore destination: `{path}`.",
                err,
            )
            .attach_context("path", path.display().to_string())
        })
    };

    let mut process_node = |path: &PathBuf, node: &Node, exists: bool| -> RusticResult<_> {
        let target = target_of(path)?;
        match node.node_type {
            NodeType::Dir => {
                if exists {
                    stats.dirs.modify += 1;
                    trace!("existing dir {}", path.display());
                    // BackOtter: an empty directory (a mount point, the
                    // destination of SNAP:subfolder) gets the flags that go
                    // on before entries as one the restore creates.
                    if !dry_run
                        && std::fs::symlink_metadata(&target).is_ok_and(|m| m.is_dir())
                        && std::fs::read_dir(&target).is_ok_and(|mut dir| dir.next().is_none())
                        && let Err(err) = osattrs::prepare_dir(&target, node, known_bko)
                    {
                        warn!("restore {}: {err}", path.display());
                    }
                } else {
                    stats.dirs.restore += 1;
                    debug!("to restore: {}", path.display());
                    if !dry_run {
                        dest.create_dir(path)
                            .map_err(|err| {
                                RusticError::with_source(
                                    ErrorKind::InputOutput,
                                    "Failed to create the directory `{path}`. Please check the path and try again.",
                                    err
                                )
                                .attach_context("path", path.display().to_string())
                            })?;
                        // BackOtter: flags a file system only takes on an
                        // empty directory (casefolding) go on before its
                        // entries, or come off if it inherited them where
                        // the node says it had none (a snapshot of
                        // BackOtter's); without a word on them, it keeps
                        // what it inherited.
                        if let Err(err) = osattrs::prepare_dir(&target, node, known_bko)
                        {
                            warn!("restore {}: {err}", path.display());
                        }
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
                        std::collections::btree_map::Entry::Occupied(_) => return Ok(()), // this is a hardlink to an existing candidate, will be processed later while setting metadata
                    }
                }
                // BackOtter: a file whose contents weren't backed up (one
                // illumos quarantined) is restored empty, with the rest of its
                // metadata, its system attributes last as for any file; one
                // warning for it, not for each of its hard links.
                if let Some(size) = osattrs::unread_size(node) {
                    warn!(
                        "{}: contents were not backed up (av_quarantined at backup, {size} bytes)",
                        target.display()
                    );
                    // It goes into a new, empty file, as in BackOtter's
                    // restic: a file there may be quarantined, which keeps
                    // its contents and extended attributes closed to the
                    // restore too.
                    if !dry_run
                        && std::fs::symlink_metadata(&target).is_ok_and(|m| m.is_file())
                        && let Err(err) = std::fs::remove_file(&target)
                    {
                        warn!("restore {}: {err}", path.display());
                    }
                }
                // BackOtter: whether the file goes into a new, empty file,
                // which can be restored sparse (write_sparse): nothing is
                // there now, seen by the walk of the destination or not (a
                // file below a symlinked directory), or left there by
                // --delete.
                let fresh = if dry_run {
                    !exists
                } else {
                    matches!(std::fs::symlink_metadata(&target),
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound)
                };
                let sparse = write_sparse(opts.sparse, node, fresh);
                // BackOtter: a file left as it is, which had no holes at
                // backup, gets its holes allocated (a swap file left with
                // holes by an interrupted restore): only where the snapshot
                // says so (fills_holes). Whether it did (with --dry-run:
                // would), which makes it a file modified, as in BackOtter's
                // restic.
                let fill_holes = || {
                    if !fills_holes(opts, node) {
                        return false;
                    }
                    if dry_run {
                        return osattrs::holes_to_fill(&target, node.meta.size);
                    }
                    let filled = osattrs::fill_holes(&target, node.meta.size);
                    if let Some(err) = &filled.error {
                        warn!("restore {}: holes not filled: {err}", path.display());
                    }
                    filled.changed
                };
                // collect blobs needed for restoring
                match (
                    exists,
                    restore_infos.add_file(
                        dest,
                        node,
                        path.clone(),
                        repo,
                        opts.verify_existing,
                        sparse,
                    )?,
                ) {
                    // Note that exists = false and Existing or Verified can happen if the file is changed between scanning the dir
                    // and calling add_file. So we don't care about exists but trust add_file here.
                    (_, AddFileResult::Existing) => {
                        trace!("identical file: {}", path.display());
                        if fill_holes() {
                            stats.files.modify += 1;
                        } else {
                            stats.files.unchanged += 1;
                        }
                    }
                    (_, AddFileResult::Verified) => {
                        trace!("verified identical file: {}", path.display());
                        if fill_holes() {
                            stats.files.modify += 1;
                        } else {
                            stats.files.verified += 1;
                        }
                    }
                    // TODO: The differentiation between files to modify and files to create could be done only by add_file
                    // Currently, add_file never returns Modify, but always New, so we differentiate based on exists
                    (true, AddFileResult::Modify) => {
                        stats.files.modify += 1;
                        debug!("to modify: {}", path.display());
                    }
                    (false, AddFileResult::Modify) => {
                        stats.files.restore += 1;
                        debug!("to restore: {}", path.display());
                        // BackOtter: flags a file system only takes on an
                        // empty file (btrfs's no-copy-on-write) go on before
                        // the contents.
                        if !dry_run
                            && let Err(err) = osattrs::prepare_file(&target, node)
                        {
                            warn!("restore {}: {err}", path.display());
                        }
                    }
                }
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
                let target_path = target_of(path)?;
                match destination.path().cmp(&target_path) {
                    Ordering::Less => {
                        next_dst = process_existing(&mut walker, destination)?;
                    }
                    Ordering::Equal => {
                        // BackOtter: what the restore finds in its way loses
                        // the flags that would refuse its being rewritten,
                        // replaced or given its metadata (immutable,
                        // append-only, undeletable), as in BackOtter's
                        // restic, where its node says which flags it had:
                        // the late flags pass sets those. Elsewhere they
                        // stay, as in stock rustic, and what they refuse
                        // fails with its error.
                        if !dry_run && osattrs::node_sets_flags(node, known_bko) {
                            osattrs::clear_restricting_flags(destination.path());
                        }
                        // process existing node
                        if (node.is_dir() && !destination.file_type().is_dir())
                            || (node.is_file() && !destination.file_type().is_file())
                            || node.is_special()
                        {
                            // if types do not match, first remove the existing file
                            let removed;
                            (next_dst, removed) = replace_existing(&mut walker, destination);
                            process_node(path, node, !removed)?;
                        } else {
                            next_dst = next_entry(&mut walker);
                            process_node(path, node, true)?;
                        }
                        next_node = node_streamer.next().transpose()?;
                    }
                    Ordering::Greater => {
                        process_node(path, node, false)?;
                        next_node = node_streamer.next().transpose()?;
                    }
                }
            }
            (None, Some((path, node))) => {
                process_node(path, node, false)?;
                next_node = node_streamer.next().transpose()?;
            }
        }
    }

    if additional_existing {
        warn!("Note: additional entries exist in destination");
    }

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
fn restore_metadata(
    mut node_streamer: impl Iterator<Item = RusticResult<(PathBuf, Node)>>,
    hardlink_candidates: &BTreeMap<HardlinkKey, PathBuf>,
    opts: RestoreOptions,
    dest: &LocalDestination,
) -> RusticResult<()> {
    // BackOtter: file flags go on last of all (osattrs), once per file:
    // they belong to the file, not each of its names, and an immutable file
    // (on illumos) refuses having them set again. ZFS's DOS flags (Linux)
    // just before them.
    let mut file_flags = Vec::new();
    let mut flags_linked = BTreeSet::new();
    let mut finish = |path: &PathBuf, node: &Node| {
        let made = set_metadata(dest, opts, path, node);
        let late = LateAttrs {
            flags: osattrs::file_flags(node),
            dos_flags: osattrs::zfs_dos_flags(node),
            fat_attrs: osattrs::fat_attrs(node),
            xfs_options: osattrs::xfs_options(node),
        };
        if made
            && late.any()
            && hardlink_key(node).is_none_or(|key| flags_linked.insert(key))
        {
            file_flags.push((
                path.clone(),
                node.node_type.clone(),
                late,
                osattrs::flags_xattrs(node),
            ));
        }
    };

    let mut dir_stack = Vec::new();
    while let Some((path, node)) = node_streamer.next().transpose()? {
        // Create hardlink directly, if this is one.
        if let Some(key) = hardlink_key(&node)
            && let Some(canonical) = hardlink_candidates.get(&key)
            && canonical != &path
        {
            debug!(
                "restoring hardlink {} -> {}",
                path.display(),
                canonical.display()
            );
            dest.hard_link(canonical, &path).map_err(|err| {
                RusticError::with_source(
                    ErrorKind::InputOutput,
                    "Failed to recreate the hardlink `{path}` from `{canonical}`.",
                    err,
                )
                .attach_context("path", path.display().to_string())
                .attach_context("canonical", canonical.display().to_string())
            })?;
        }

        match node.node_type {
            NodeType::Dir => {
                // set metadata for all non-parent paths in stack
                while let Some((stackpath, _)) = dir_stack.last() {
                    if path.starts_with(stackpath) {
                        break;
                    }
                    let (path, node) = dir_stack.pop().unwrap();
                    finish(&path, &node);
                }
                // push current path to the stack
                dir_stack.push((path, node));
            }
            _ => finish(&path, &node),
        }
    }

    // empty dir stack and set metadata
    for (path, node) in dir_stack.into_iter().rev() {
        finish(&path, &node);
    }

    for (path, node_type, late, xattrs) in file_flags {
        // set_metadata made it, so its path is in the destination.
        let Ok(target) = dest.path(&path) else {
            continue;
        };
        if let Some(attrs) = late.fat_attrs {
            osattrs::restore_fat_attrs(&target, &node_type, attrs)
                .unwrap_or_else(|err| osattrs::warn_restore(&path, &err));
        }
        if let Some(opts) = &late.xfs_options {
            osattrs::restore_xfs_options(&target, &node_type, opts)
                .unwrap_or_else(|err| osattrs::warn_restore(&path, &err));
        }
        let (flags, dos_flags) = (late.flags, late.dos_flags);
        if let Some(dos_flags) = dos_flags {
            osattrs::restore_zfs_dos_flags(&target, &node_type, dos_flags)
                .unwrap_or_else(|err| osattrs::warn_restore(&path, &err));
        }
        if let Some(flags) = flags {
            osattrs::restore_file_flags(&target, &node_type, flags, &xattrs)
                .unwrap_or_else(|err| osattrs::warn_restore(&path, &err));
        }
    }
    // BackOtter: how many files had metadata the file system doesn't
    // support, warned about once.
    osattrs::report_unsupported();

    Ok(())
}

/// BackOtter: the metadata the restore sets last, once every file has
/// everything else: file flags, and before them ZFS's DOS flags, FAT's
/// attributes and XFS's options (Linux).
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

/// BackOtter: whether the regular file `node`, which has no mode, had mode
/// 0 (permissions `0000`, as /etc/shadow has): when it was read from a Unix
/// file system (it has an inode number; a file read from stdin or made on
/// Windows has none) and the snapshot leaves a mode of 0 out (restic's, or
/// BackOtter's rustic's before it wrote `"mode":0`). Otherwise its mode is
/// unknown, and the file keeps the one it was created with, as in stock
/// rustic.
const fn mode_zero_if_missing(opts: RestoreOptions, node: &Node) -> bool {
    matches!(node.node_type, NodeType::File)
        && node.meta.mode.is_none()
        && node.meta.inode != 0
        && opts.origin.omits_zero_mode()
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
/// it (restic reports an error), not one more for each step after.
// TODO: Return a result here, introduce errors and get rid of logging.
pub(crate) fn set_metadata(
    dest: &LocalDestination,
    opts: RestoreOptions,
    path: &PathBuf,
    node: &Node,
) -> bool {
    debug!("setting metadata for {}", path.display());
    if let Err(err) = dest.create_special(path, node) {
        warn!(
            "restore {}: creating special file failed: {err}",
            path.display()
        );
        return false;
    }
    // BackOtter: by name, unless numeric ids are asked for (--numeric-id);
    // then on illumos the ids an owner and group that are SIDs have here,
    // before the mode, which a change of owner can clear the setuid bit of.
    // A change of owner refused to a restore not running as root is no
    // warning, as in restic.
    // create_special refused (and warned of) a path that leaves the
    // destination, so this is one in it.
    let Ok(target) = dest.path(path) else {
        return false;
    };
    let chown_failed = |what: &str, err: &local_destination::LocalDestinationErrorKind| {
        if LocalDestination::chown_refused_not_root(err) {
            debug!(
                "not running as root, {} of {} not set: {err}",
                what,
                path.display()
            );
        } else {
            warn!("restore {}: setting {what} failed.", path.display());
        }
    };
    match ownership(opts) {
        Ownership::None => {}
        Ownership::Numeric => dest
            .set_uid_gid(path, &node.meta)
            .unwrap_or_else(|err| chown_failed("UID/GID", &err)),
        Ownership::ByName => dest
            .set_user_group(path, &node.meta)
            .unwrap_or_else(|err| chown_failed("User/Group", &err)),
    }
    if ownership(opts) != Ownership::None {
        osattrs::restore_owner(&target, node)
            .unwrap_or_else(|err| osattrs::warn_restore(path, &err));
    }
    // BackOtter: the attributes osattrs keeps; ACLs after the mode. One
    // warning naming each attribute not set, and its error.
    let known_bko = opts.origin.known_bko();
    let set_attributes = || {
        // BackOtter: stock rustic's names on FreeBSD and NetBSD
        // (`user.NAME`) in any snapshot not BackOtter's.
        dest.set_extended_attributes(path, &node.meta.extended_attributes, !known_bko)
            .unwrap_or_else(|err| {
                warn!(
                    "restore {}: setting extended attributes failed: {err}",
                    path.display()
                );
            });
        osattrs::restore_attributes(&target, node, known_bko)
            .unwrap_or_else(|err| osattrs::warn_restore(path, &err));
    };
    // On Haiku before the mode: BFS wants write access to the file for
    // each attribute it writes, which a restore by a user other than root
    // wouldn't have on a read-only file.
    if cfg!(target_os = "haiku") {
        set_attributes();
    }
    dest.set_permission(path, node, mode_zero_if_missing(opts, node))
        .unwrap_or_else(|_| warn!("restore {}: chmod failed.", path.display()));
    if node.is_symlink() {
        osattrs::restore_symlink_mode(&target, node)
            .unwrap_or_else(|err| warn!("restore {}: {err}", path.display()));
    }
    if !cfg!(target_os = "haiku") {
        set_attributes();
    }
    osattrs::restore_acls(&target, node)
        .unwrap_or_else(|err| osattrs::warn_restore(path, &err));
    // BackOtter: the birth time just before the times, which on FreeBSD and
    // NetBSD replace the earlier mtime it is set as.
    osattrs::restore_birthtime(&target, node)
        .unwrap_or_else(|err| warn!("restore {}: {err}", path.display()));
    dest.set_times(path, &node.meta)
        .unwrap_or_else(|_| warn!("restore {}: setting file times failed.", path.display()));
    true
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
/// BackOtter: the number of files whose contents couldn't be written (one
/// that can't be opened for writing, say), each reported once, with an
/// error, and left as they are; stock rustic stopped at the first, or
/// panicked.
#[allow(clippy::too_many_lines)]
fn restore_contents<S: Open>(
    repo: &Repository<S>,
    dest: &LocalDestination,
    filenames: &Filenames,
    file_lengths: Vec<u64>,
    sparse: &[bool],
    restore_info: RestoreInfo,
    restore_size: u64,
) -> RusticResult<usize> {
    let be = repo.dbe();

    // BackOtter: the files that couldn't be written, each reported once.
    let failed = &Mutex::new(BTreeSet::new());
    let fail = &|file_idx: usize, err: &dyn std::fmt::Display| {
        if failed.lock().unwrap().insert(file_idx) {
            error!(
                "restore {}: contents not restored: {err}",
                filenames[file_idx].display()
            );
        }
    };

    // first create needed empty files, as they are not created later.
    for (i, size) in file_lengths.iter().enumerate() {
        if *size == 0 {
            let path = &filenames[i];
            if let Err(err) = dest.set_length(path, *size, sparse[i]) {
                fail(i, &err);
            }
        }
    }

    let sizes = &Mutex::new(file_lengths);

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

    let threads = constants::MAX_READER_THREADS_NUM;

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

            if !blobs.is_empty() {
                // TODO: error handling!
                s.spawn(move |s1| {
                    let read_data = match &from_file {
                        Some((file_idx, offset_file, length_file)) => {
                            // read from existing file
                            dest.read_at(&filenames[*file_idx], *offset_file, (*length_file).into())
                                .unwrap()
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
                            let is_sparse = sparse[file_idx];
                            s1.spawn(move |_| {
                                let path = &filenames[file_idx];
                                // Allocate file if it is not yet allocated
                                let mut sizes_guard = sizes.lock().unwrap();
                                let filesize = sizes_guard[file_idx];
                                if filesize > 0 {
                                    // BackOtter: a file that can't be
                                    // sized (opened for writing) is
                                    // reported and left, not a panic.
                                    if let Err(err) = dest.set_length(path, filesize, is_sparse) {
                                        fail(file_idx, &err);
                                    }
                                    sizes_guard[file_idx] = 0;
                                }
                                drop(sizes_guard);
                                if failed.lock().unwrap().contains(&file_idx) {
                                    p.inc(size);
                                    return;
                                }
                                // BackOtter: in a file restored sparse
                                // (write_sparse), the blob's all-zero parts
                                // of the file system's blocks stay holes, as
                                // BackOtter's restic leaves them; any other
                                // file gets every byte, so that it is
                                // allocated.
                                let written = if is_sparse {
                                    if zeros {
                                        Ok(())
                                    } else {
                                        dest.write_sparse_at(path, start, &data)
                                    }
                                } else {
                                    dest.write_at(path, start, &data)
                                };
                                if let Err(err) = written {
                                    fail(file_idx, &err);
                                }
                                p.inc(size);
                            });
                        }
                    }
                });
            }
        }
    });

    p.finish();

    Ok(failed.lock().unwrap().len())
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
    /// The total restore size
    pub restore_size: u64,
    /// The total size of matched content, i.e. content with needs no restore.
    pub matched_size: u64,
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

/// [`AddFileResult`] indicates the result of adding a file to [`FileLocation`]
// TODO: Add documentation!
enum AddFileResult {
    Existing,
    Verified,
    Modify,
}

impl RestorePlan {
    /// Add the file to [`FileLocation`] using `index` to get blob information.
    ///
    /// # Type Parameters
    ///
    /// * `P` - The progress bar type.
    /// * `S` - The type of the indexed tree.
    ///
    /// # Arguments
    ///
    /// * `dest` - The destination to restore to.
    /// * `file` - The file to add.
    /// * `name` - The name of the file.
    /// * `repo` - The repository to restore.
    /// * `ignore_mtime` - If true, ignore the modification time of the file.
    /// * `sparse` - If true, restore zero chunks as holes.
    ///
    /// # Errors
    ///
    /// * If the file could not be added.
    fn add_file<S: IndexedFull>(
        &mut self,
        dest: &LocalDestination,
        file: &Node,
        name: PathBuf,
        repo: &Repository<S>,
        ignore_mtime: bool,
        sparse: bool,
    ) -> RusticResult<AddFileResult> {
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
                    return Ok(AddFileResult::Existing);
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
                    return Ok(AddFileResult::Existing);
                }
            }

        let file_idx = self.names.len();
        self.names.push(name);
        let mut file_pos = 0;
        let mut has_unmatched = false;
        for id in file.content.iter().flatten() {
            let ie = repo.get_index_entry(id)?;
            let bl = ie.location;
            let length: u64 = bl.data_length().into();

            let matches = open_file
                .as_mut()
                .is_some_and(|file| id.blob_matches_reader(length, file));

            let blob_location = self.r.entry((ie.pack, bl)).or_default();
            blob_location.push(FileLocation {
                file_idx,
                file_start: file_pos,
                matches,
            });

            if matches {
                self.matched_size += length;
            } else {
                self.restore_size += length;
                has_unmatched = true;
            }

            file_pos += length;
        }

        self.file_lengths.push(file_pos);
        self.sparse.push(sparse);

        if !has_unmatched && open_file.is_some() {
            Ok(AddFileResult::Verified)
        } else {
            Ok(AddFileResult::Modify)
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
            Node::new_node(name.as_ref(), node_type, crate::backend::node::Metadata::default())
        };
        let nodes = vec![
            Ok((PathBuf::from("dir"), node("dir", NodeType::Dir))),
            Ok((PathBuf::from("dir/file"), node("file", NodeType::File))),
            Ok((PathBuf::from("dir/socket"), node("socket", NodeType::Socket))),
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
        assert!(!fills_holes(RestoreOptions::default().origin(SnapshotOrigin::Restic), &plain));
    }

    /// A destination is fresh when it doesn't exist, or holds only what a
    /// file system makes itself (`lost+found`, `.snap`, `.sujournal`,
    /// an empty `.nilfs`),
    /// mount points, and directories on the path to them, at any depth. The
    /// mount points are made up here: a directory in `mounts` and what is
    /// below it are on a device of their own.
    #[cfg(unix)]
    #[test]
    fn target_fresh_only_when_new_or_empty() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("d");
        let mounts = std::cell::RefCell::new(Vec::<PathBuf>::new());
        let device = |path: &std::path::Path, _: &std::fs::Metadata| {
            let mounts = mounts.borrow();
            let i = mounts.iter().position(|m| path.starts_with(m));
            Some(i.map_or(0, |i| i as u64 + 1))
        };
        let fresh = |d: &std::path::Path| fresh_target_with(d, &device);
        let mount = |sub: &str| {
            std::fs::create_dir_all(d.join(sub)).unwrap();
            // The deepest first, so that it is found first.
            mounts.borrow_mut().insert(0, d.join(sub));
        };
        assert!(fresh(&d));
        std::fs::create_dir(&d).unwrap();
        // As mkfs makes it, whatever the umask.
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(fresh(&d));
        std::fs::create_dir(d.join("lost+found")).unwrap();
        std::fs::write(d.join("lost+found/#123"), b"x").unwrap();
        assert!(fresh(&d), "lost+found only");
        std::fs::write(d.join(".sujournal"), b"").unwrap();
        std::fs::create_dir(d.join(".snap")).unwrap();
        assert!(fresh(&d), "UFS's own entries");

        // A freshly booted server's /tmp: empty directories on its own
        // file system.
        let tmp = dir.path().join("tmp");
        for sub in [".X11-unix", ".ICE-unix", ".font-unix", "systemd-private-1-x/tmp"] {
            std::fs::create_dir_all(tmp.join(sub)).unwrap();
        }
        assert!(!fresh(&tmp), "/tmp");
        std::fs::create_dir(d.join("srv")).unwrap();
        assert!(!fresh(&d), "an empty directory");
        std::fs::remove_dir(d.join("srv")).unwrap();

        // Mount points: /boot and /boot/efi, /home with its lost+found,
        // /var with UFS's own, /usr/local below a plain /usr (a ZFS
        // dataset's parent).
        for sub in ["boot", "boot/efi", "home", "var", "usr/local"] {
            mount(sub);
        }
        std::fs::create_dir(d.join("home/lost+found")).unwrap();
        std::fs::create_dir(d.join("var/.snap")).unwrap();
        std::fs::write(d.join("var/.sujournal"), b"").unwrap();
        assert!(fresh(&d), "bare-metal root");

        // Anything else, at any depth, is not.
        for (what, make) in [
            ("file", "f"),
            ("file in a mount point", "boot/efi/f"),
            ("file on the path to a mount point", "usr/f"),
            ("empty directory in a mount point", "boot/grub/"),
            ("empty directory beside a mount point", "usr/share/"),
            ("lost+found file", "usr/lost+found"),
            (".sujournal directory", "home/.sujournal/"),
            (".snap file", "home/.snap"),
        ] {
            let path = d.join(make.trim_end_matches('/'));
            if make.ends_with('/') {
                std::fs::create_dir(&path).unwrap();
            } else {
                std::fs::write(&path, b"x").unwrap();
            }
            assert!(!fresh(&d), "{what}");
            if path.is_dir() {
                std::fs::remove_dir(&path).unwrap();
            } else {
                std::fs::remove_file(&path).unwrap();
            }
            assert!(fresh(&d), "{what} removed");
        }
        // A directory on the path to a mount point holding only
        // lost+found is a plain directory.
        std::fs::create_dir_all(d.join("opt/lost+found")).unwrap();
        assert!(!fresh(&d), "a plain directory with lost+found");
        std::fs::remove_dir_all(d.join("opt")).unwrap();

        // At most 4096 directories: d, boot, efi, home, var, usr, local,
        // many and those in it (not lost+found or .snap).
        let have = 8;
        mount("many");
        for i in 0..FRESH_TARGET_MAX_DIRS - have {
            mount(&format!("many/{i}"));
        }
        assert!(fresh(&d), "4096 directories");
        mount("many/one more");
        assert!(!fresh(&d), "4097 directories");
        std::fs::remove_dir_all(d.join("many")).unwrap();
        assert!(fresh(&d));

        // A symlink, even to a directory, is not followed.
        std::os::unix::fs::symlink("/", d.join("boot/link")).unwrap();
        assert!(!fresh(&d), "symlink");
        std::fs::remove_file(d.join("boot/link")).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&d, &link).unwrap();
        assert!(!fresh(&link), "symlink as the destination");
        let f = dir.path().join("f");
        std::fs::write(&f, b"x").unwrap();
        assert!(!fresh(&f), "file as the destination");

        // A shared directory, sticky or writable by others, is not fresh,
        // even empty: an empty /tmp or /dev/shm.
        let shm = dir.path().join("shm");
        std::fs::create_dir(&shm).unwrap();
        for (mode, want) in [
            (0o1777, false),
            (0o1755, false),
            (0o777, false),
            (0o757, false),
            (0o775, true),
            (0o755, true),
            (0o700, true),
        ] {
            std::fs::set_permissions(&shm, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(fresh(&shm), want, "empty, mode {mode:o}");
            assert_eq!(restore_target_is_fresh(&shm), want, "empty, mode {mode:o}");
        }
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(!fresh(&d), "bare-metal root, mode 1777");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(fresh(&d));

        // The devices restore_target_is_fresh itself sees: none of these
        // directories is a mount point.
        assert!(restore_target_is_fresh(dir.path().join("new")));
        let lf = dir.path().join("lf");
        std::fs::create_dir_all(lf.join("lost+found/x")).unwrap();
        assert!(restore_target_is_fresh(&lf));
        assert!(!restore_target_is_fresh(&d));
        assert!(!restore_target_is_fresh(&tmp));
    }

    /// A new nilfs2 file system's root may hold `.nilfs`, an empty regular
    /// file (mkfs.nilfs2 2.0.0 to 2.2.9): it is fresh, as are its mount
    /// points' roots with one. A `.nilfs` with something in it, or of
    /// another type, is not what mkfs made. The mount points are made up
    /// here, as above.
    #[cfg(unix)]
    #[test]
    fn target_fresh_with_nilfs_entry() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("d");
        let mounts = std::cell::RefCell::new(Vec::<PathBuf>::new());
        let device = |path: &std::path::Path, _: &std::fs::Metadata| {
            let mounts = mounts.borrow();
            let i = mounts.iter().position(|m| path.starts_with(m));
            Some(i.map_or(0, |i| i as u64 + 1))
        };
        let fresh = |d: &std::path::Path| fresh_target_with(d, &device);
        let nilfs = d.join(".nilfs");
        std::fs::create_dir(&d).unwrap();
        std::fs::write(&nilfs, b"").unwrap();
        assert!(fresh(&d), "an empty .nilfs only");
        assert!(restore_target_is_fresh(&d), "an empty .nilfs only");

        std::fs::write(&nilfs, b"x").unwrap();
        assert!(!fresh(&d), ".nilfs with data");
        assert!(!restore_target_is_fresh(&d), ".nilfs with data");
        std::fs::remove_file(&nilfs).unwrap();
        std::fs::create_dir(&nilfs).unwrap();
        assert!(!fresh(&d), ".nilfs directory");
        std::fs::remove_dir(&nilfs).unwrap();
        // To an empty regular file, so following it would accept it.
        let empty = dir.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        std::os::unix::fs::symlink(&empty, &nilfs).unwrap();
        assert!(!fresh(&d), ".nilfs symlink to an empty file");
        assert!(!restore_target_is_fresh(&d), ".nilfs symlink to an empty file");
        std::fs::remove_file(&nilfs).unwrap();
        std::fs::write(d.join(".nilfs2"), b"").unwrap();
        assert!(!fresh(&d), "another name");
        std::fs::remove_file(d.join(".nilfs2")).unwrap();

        std::fs::write(&nilfs, b"").unwrap();
        std::fs::create_dir(d.join("lost+found")).unwrap();
        assert!(fresh(&d), ".nilfs and lost+found");
        std::fs::remove_dir(d.join("lost+found")).unwrap();

        // A mount point below, itself a new nilfs2 root.
        let boot = d.join("boot");
        std::fs::create_dir(&boot).unwrap();
        mounts.borrow_mut().push(boot.clone());
        assert!(fresh(&d), ".nilfs and a mount point");
        std::fs::write(boot.join(".nilfs"), b"").unwrap();
        assert!(fresh(&d), ".nilfs in the root and in a mount point");
        std::fs::write(boot.join(".nilfs"), b"x").unwrap();
        assert!(!fresh(&d), ".nilfs with data in a mount point");
        std::fs::write(boot.join(".nilfs"), b"").unwrap();
        std::fs::write(boot.join("f"), b"").unwrap();
        assert!(!fresh(&d), "an empty file beside .nilfs");
    }

    /// Haiku's Tracker puts an empty `trash` directory on every volume it
    /// sees mounted, a new one too: on Haiku that root is fresh, as with
    /// lost+found, elsewhere not; a `trash` with something in it, or of
    /// another type, or another name, is not Tracker's alone anywhere.
    #[cfg(unix)]
    #[test]
    fn target_fresh_with_tracker_trash() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("d");
        let trash = d.join("trash");
        let lstat = |p: &std::path::Path| std::fs::symlink_metadata(p).unwrap();
        std::fs::create_dir_all(&trash).unwrap();
        assert!(empty_trash(&trash, &lstat(&trash)));
        assert_eq!(
            restore_target_is_fresh(&d),
            cfg!(target_os = "haiku"),
            "an empty trash only"
        );
        std::fs::create_dir(d.join("lost+found")).unwrap();
        assert_eq!(
            restore_target_is_fresh(&d),
            cfg!(target_os = "haiku"),
            "with lost+found"
        );
        std::fs::remove_dir(d.join("lost+found")).unwrap();

        std::fs::write(trash.join("f"), b"").unwrap();
        assert!(!empty_trash(&trash, &lstat(&trash)), "trash with a file");
        assert!(!restore_target_is_fresh(&d), "trash with a file");
        std::fs::remove_file(trash.join("f")).unwrap();
        std::fs::remove_dir(&trash).unwrap();

        std::fs::write(&trash, b"").unwrap();
        assert!(!empty_trash(&trash, &lstat(&trash)), "trash a file");
        assert!(!restore_target_is_fresh(&d), "trash a file");
        std::fs::remove_file(&trash).unwrap();
        // To an empty directory, so following it would accept it.
        let empty = dir.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        std::os::unix::fs::symlink(&empty, &trash).unwrap();
        assert!(!empty_trash(&trash, &lstat(&trash)), "trash symlink");
        assert!(!restore_target_is_fresh(&d), "trash symlink");
        std::fs::remove_file(&trash).unwrap();
        let other = d.join("Trash");
        std::fs::create_dir(&other).unwrap();
        assert!(!empty_trash(&other, &lstat(&other)), "another name");
        assert!(!restore_target_is_fresh(&d), "another name");
    }

    /// As root on Linux, with tmpfs mounts: a new root with /boot and
    /// /boot/efi mounted below it is fresh; an empty directory or a file
    /// on any of them is not.
    #[cfg(target_os = "linux")]
    #[test]
    fn target_fresh_with_a_mount_in_it() {
        if !nix::unistd::geteuid().is_root() {
            eprintln!("not root: no mount");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let boot = d.join("boot");
        let efi = boot.join("efi");
        let mount = |at: &std::path::Path| {
            std::fs::create_dir_all(at).unwrap();
            std::process::Command::new("mount")
                .args(["-t", "tmpfs", "bkotest"])
                .arg(at)
                .status()
                .is_ok_and(|s| s.success())
        };
        if !mount(&boot) {
            eprintln!("tmpfs not mounted");
            return;
        }
        let results = (|| {
            if !mount(&efi) {
                return None;
            }
            // An empty tmpfs (mode 1777) as the destination, as /dev/shm,
            // is not fresh; mounted below a fresh one, it may be.
            let mut results = vec![("empty tmpfs", false, restore_target_is_fresh(&efi))];
            std::fs::create_dir(efi.join("lost+found")).unwrap();
            results.push(("boot and boot/efi mounted", true, restore_target_is_fresh(d)));
            for (what, sub) in [
                ("empty directory in efi", "efi/EFI"),
                ("empty directory in boot", "grub"),
            ] {
                std::fs::create_dir(boot.join(sub)).unwrap();
                results.push((what, false, restore_target_is_fresh(d)));
                std::fs::remove_dir(boot.join(sub)).unwrap();
            }
            std::fs::write(efi.join("vmlinuz"), b"x").unwrap();
            results.push(("file in efi", false, restore_target_is_fresh(d)));
            std::fs::remove_file(efi.join("vmlinuz")).unwrap();
            std::fs::create_dir(d.join("tmp")).unwrap();
            results.push(("empty directory beside boot", false, restore_target_is_fresh(d)));
            std::fs::remove_dir(d.join("tmp")).unwrap();
            std::fs::write(d.join(".nilfs"), b"").unwrap();
            std::fs::write(boot.join(".nilfs"), b"").unwrap();
            results.push((
                "empty .nilfs in the root and in boot",
                true,
                restore_target_is_fresh(d),
            ));
            std::fs::write(boot.join(".nilfs"), b"x").unwrap();
            results.push((
                "a .nilfs with data in boot",
                false,
                restore_target_is_fresh(d),
            ));
            std::fs::remove_file(boot.join(".nilfs")).unwrap();
            std::fs::remove_file(d.join(".nilfs")).unwrap();
            results.push(("all removed", true, restore_target_is_fresh(d)));
            Some(results)
        })();
        let _ = std::process::Command::new("umount").arg(&efi).status();
        let _ = std::process::Command::new("umount").arg(&boot).status();
        let results = results.expect("tmpfs mounted on boot/efi");
        for (what, want, got) in results {
            assert_eq!(got, want, "{what}");
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
        assert_eq!(ownership(parse(&["--numeric-id"]).unwrap()), Ownership::Numeric);
        assert_eq!(ownership(parse(&["--by-name"]).unwrap()), Ownership::ByName);
        // restic's name for it.
        assert_eq!(ownership(parse(&["--ownership-by-name"]).unwrap()), Ownership::ByName);
        assert_eq!(ownership(parse(&["--no-ownership"]).unwrap()), Ownership::None);
        assert!(parse(&["--by-name", "--numeric-id"]).is_err());
        assert!(parse(&["--by-name", "--no-ownership"]).is_err());
        assert!(parse(&["--ownership-by-name", "--numeric-id"]).is_err());
    }
}
