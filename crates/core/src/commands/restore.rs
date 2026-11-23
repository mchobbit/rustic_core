//! `restore` subcommand

use derive_setters::Setters;
use jiff::Timestamp;
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use std::{
    cell::{Cell, RefCell},
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex, PoisonError, RwLock, RwLockReadGuard},
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
        osattrs,
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
pub fn restore_target_is_fresh(dest: impl AsRef<Path>) -> bool {
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
type DeviceOf<'a> = dyn Fn(&Path, &std::fs::Metadata) -> Option<u64> + 'a;

/// [`restore_target_is_fresh`], with the devices from `device`.
fn fresh_target_with(dest: &Path, device: &DeviceOf<'_>) -> bool {
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
    dir: &Path,
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
fn made_by_tracker(path: &Path, meta: &std::fs::Metadata) -> bool {
    cfg!(target_os = "haiku") && empty_trash(path, meta)
}

/// Whether `path`, with the (`lstat`) metadata `meta`, is an empty
/// directory named `trash` ([`made_by_tracker`], on any system).
fn empty_trash(path: &Path, meta: &std::fs::Metadata) -> bool {
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
    /// BackOtter: failures while collecting and preparing (walking the
    /// destination for `--delete`, removing what `--delete` or a node of
    /// another type wants gone, flags that go on before entries or
    /// contents), warned about each, which BackOtter's restic counts as
    /// errors (exit 1)
    pub errors: u64,
}

#[derive(Default, Debug, Clone, Copy)]
#[non_exhaustive]
/// BackOtter: what restoring a plan couldn't do and only warned about:
/// metadata not set for a reason other than the target not supporting it,
/// special files not made. BackOtter's restic counts each as an error (exit
/// 1).
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
    /// `not_root_ok` for the steps restic's restore not running as root
    /// doesn't count a permission refused for.
    fn io(&mut self, path: &Path, err: &std::io::Error, not_root_ok: bool) {
        osattrs::warn_restore(path, err);
        self.count(err, not_root_ok);
    }

    /// Counts `err`, warned about already, if restic would.
    fn count(&mut self, err: &std::io::Error, not_root_ok: bool) {
        if osattrs::restore_error_counts(err, not_root_ok, self.root) {
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
    // BackOtter: the existing directories the restore hasn't changed yet,
    // which keep their restricting flags and XFS options until it does
    // (DirChanges); the destination itself too, also where it keeps its own
    // metadata (no node of its own, "" in the snapshot). The files with
    // other names a name of which the restore removed (Replaced), the files
    // left shared whose hard link --exact couldn't break (unbroken), and the
    // first name of each hard-linked file. RefCells, as the closures below
    // share them.
    let dirs = RefCell::new(DirChanges::default());
    let replaced = RefCell::new(Replaced::default());
    let unbroken = RefCell::new(BTreeSet::new());
    let mut hardlink_candidates = BTreeMap::new();
    if !dry_run && std::fs::symlink_metadata(&dest_path).is_ok_and(|m| m.is_dir()) {
        dirs.borrow_mut().note(&dest_path, Path::new(""), false);
    }
    let numeric = ownership(opts) == Ownership::Numeric;
    // BackOtter: --exact compares owners only as root, who sets them (as
    // BackOtter's restic): not root, the restore leaves them as they are.
    let owned = ownership(opts) != Ownership::None && osattrs::is_root();

    let mut additional_existing = false;
    // BackOtter: failures restic counts as errors (RestoreStats::errors); a
    // Cell, as the closures below borrow parts of `stats` already.
    let errors = Cell::new(0_u64);
    let count = || errors.set(errors.get() + 1);
    let root = osattrs::is_root();
    // BackOtter: flags that go on before entries or contents, which count
    // unless the file system doesn't support them.
    let prepare_failed = |path: &PathBuf, err: &std::io::Error| {
        warn!("restore {}: {err}", path.display());
        if osattrs::restore_error_counts(err, false, root) {
            count();
        }
    };
    // BackOtter: restricting flags that couldn't be put back on the other
    // names of a file whose name the restore removed (remove_held).
    let put_back_failed = |path: &Path, err: &std::io::Error| {
        error!(
            "restore {}: restricting flags not put back on its other names: {err}",
            path.display()
        );
        count();
    };

    let next_entry = |walker: &mut walkdir::IntoIter| -> Option<DirEntry> {
        walker
            .inspect(|r| {
                if let Err(err) = r {
                    error!("Error during collection of files: {err:?}");
                    // BackOtter: restic walks the destination only for
                    // --delete, and fails then; a destination that isn't
                    // there yet holds nothing to delete.
                    let missing_root = err.depth() == 0
                        && err
                            .io_error()
                            .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound);
                    if opts.delete && !missing_root {
                        count();
                    }
                }
            })
            .find_map(Result::ok)
    };

    // BackOtter: what --delete removes, removed once the walk is done
    // (remove_extra), so that every file the restore replaces a name of is
    // known by then (Replaced), whatever order the names come in.
    let mut extra = Vec::new();
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

    // BackOtter: what has a node's name but another type, and any special
    // file, is removed first, with or without --delete, as BackOtter's restic
    // does: a directory is restored as a directory, not through a symlink to
    // wherever that points, and a file or special file is made anew. Without
    // --delete a directory only goes if it is empty. It loses the
    // restricting flags that would refuse that first, where its node says
    // what they are (`sets`), and a file with other names gets them back
    // once this name is gone (remove_held). Whether the old one is gone.
    let remove_in_the_way = |path: &Path, is_dir: bool, sets: bool| -> bool {
        dirs.borrow_mut().change_parent(path);
        // BackOtter: nothing below a directory loses its flags: what
        // refuses removal stays, as with --delete.
        let (removed, put_back) =
            remove_held(path, sets, &replaced, |path| match (is_dir, opts.delete) {
                (false, _) => std::fs::remove_file(walkdir::short_path(path)),
                (true, true) => remove_tree(path, &replaced),
                (true, false) => std::fs::remove_dir(walkdir::short_path(path)),
            });
        if let Err(err) = put_back {
            put_back_failed(path, &err);
        }
        removed
            .map_err(|err| {
                error!("error removing {}: {err}", path.display());
                count();
            })
            .is_ok()
    };
    // The same for an entry of the walk: returns the next entry and whether
    // the old one is gone.
    let replace_existing = |walker: &mut walkdir::IntoIter,
                            entry: &DirEntry,
                            sets: bool|
     -> (Option<DirEntry>, bool) {
        if entry.depth() == 0 {
            return (next_entry(walker), false);
        }
        let is_dir = entry.file_type().is_dir();
        let removed = if dry_run {
            info!("would have replaced {}", entry.path().display());
            true
        } else {
            remove_in_the_way(entry.path(), is_dir, sets)
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

    // BackOtter: under --exact, the existing file `target`, which has other
    // names, gets a name of its own before the restore writes to it or sets
    // its metadata, so that nothing reaches them (exact::break_link). Its
    // restricting flags come off first, where its node says what they are,
    // for the rename or removal, and go back on the file it was, which its
    // other names still are, through a descriptor held open (remove_held).
    // One whose link can't be broken is an error, and is left exactly as it
    // is (unbroken): no contents, no holes filled, no metadata, nor any of
    // the snapshot's other names for it linked to it. True if it was
    // broken.
    let break_shared = |path: &PathBuf, node: &Node, target: &Path| -> bool {
        dirs.borrow_mut().change_parent(target);
        let sets = osattrs::node_sets_flags(node, known_bko);
        let (broken, put_back) = remove_held(target, sets, &replaced, |target| {
            exact::break_link(target).map(|cloned| {
                debug!("hard link of {} broken, cloned: {cloned}", target.display());
            })
        });
        match broken {
            Ok(()) => {
                if let Err(err) = put_back {
                    put_back_failed(target, &err);
                }
                true
            }
            Err(err) => {
                let err = match put_back {
                    Ok(()) => err.to_string(),
                    Err(perr) => format!("{err}; its restricting flags not set back: {perr}"),
                };
                error!("restore {}: left as it is, its hard link not broken: {err}", path.display());
                count();
                _ = unbroken.borrow_mut().insert(path.clone());
                false
            }
        }
    };

    // BackOtter: plans the contents of the file `node` at `target`, which
    // was there (`exists`) or not: what is there, of its size, is matched
    // blob by blob, and what differs is written, or cloned whole from a
    // file restored elsewhere (--clone-from). A file there loses the
    // restricting flags that would refuse its being rewritten (immutable,
    // append-only), where its node says what they are, only as the restore
    // changes it: before it is written, cloned over, or its holes filled;
    // one whose contents are right keeps them, and its inode its change
    // time. The late flags pass sets the node's.
    let mut plan_file = |path: &PathBuf, node: &Node, target: &Path, exists: bool| -> RusticResult<()> {
        let sets = osattrs::node_sets_flags(node, known_bko);
        // BackOtter: whether the file goes into a new, empty file,
        // which can be restored sparse (write_sparse): nothing is
        // there now, seen by the walk of the destination or not (a
        // file below a symlinked directory), or left there by
        // a hard link broken, or a file in the way removed.
        let fresh = if dry_run {
            !exists
        } else {
            matches!(std::fs::symlink_metadata(walkdir::short_path(target)),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound)
        };
        if fresh && !dry_run {
            dirs.borrow_mut().change_parent(target);
        }
        let sparse = write_sparse(opts.sparse, node, fresh);
        // BackOtter: a file left as it is, which had no holes at
        // backup, gets its holes allocated (a swap file left with
        // holes by an interrupted restore): only where the snapshot
        // says so (fills_holes). Whether it did (with --dry-run:
        // would), which makes it a file modified, as in BackOtter's
        // restic. One to fill loses the flags that would refuse that
        // first.
        let fill_holes = || {
            if !fills_holes(opts, node) {
                return false;
            }
            if dry_run {
                return osattrs::holes_to_fill(target, node.meta.size);
            }
            if sets && osattrs::holes_to_fill(target, node.meta.size) {
                osattrs::clear_restricting_flags(target);
            }
            let filled = osattrs::fill_holes(target, node.meta.size);
            if let Some(err) = &filled.error {
                warn!("restore {}: holes not filled: {err}", path.display());
            }
            filled.changed
        };
        // collect blobs needed for restoring
        let matched =
            match restore_infos.match_file(dest, node, path.clone(), repo, opts.verify_existing)? {
                FileMatch::Existing => {
                    // Note that exists = false and Existing can happen if the file is changed between scanning the dir
                    // and calling match_file. So we don't care about exists but trust match_file here.
                    trace!("identical file: {}", path.display());
                    if fill_holes() {
                        stats.files.modify += 1;
                    } else {
                        stats.files.unchanged += 1;
                    }
                    return Ok(());
                }
                FileMatch::Blobs(matched) => matched,
            };
        if matched.changes() && !dry_run {
            if !fresh && sets {
                osattrs::clear_restricting_flags(target);
            }
            // BackOtter: under --exact, a file restored elsewhere with
            // the same contents (--clone-from) is cloned, not written; a
            // clone that fails leaves the file as it was, for the restore
            // to write only what differs.
            let clone = (opts.exact && exact::clone_ok(node))
                .then(|| node.content.as_deref().and_then(|c| dest.clone_source(c)))
                .flatten();
            if let Some(src) = clone {
                dirs.borrow_mut().change_parent(target);
                match exact::clone_file(&src, target, node.meta.size) {
                    Ok(()) => {
                        restore_infos.cloned_size += node.meta.size;
                        if exists {
                            stats.files.modify += 1;
                        } else {
                            stats.files.restore += 1;
                        }
                        debug!("cloned: {}", path.display());
                        return Ok(());
                    }
                    Err(err @ exact::CloneFailed::TempLeft { .. }) => {
                        warn!("restore {}: not cloned from {}: {err}", path.display(), src.display());
                    }
                    Err(err) => debug!("not cloned from {}: {err}", src.display()),
                }
            }
        }
        match restore_infos.push_file(matched, sparse) {
            AddFileResult::Verified => {
                trace!("verified identical file: {}", path.display());
                if fill_holes() {
                    stats.files.modify += 1;
                } else {
                    stats.files.verified += 1;
                }
            }
            // TODO: The differentiation between files to modify and files to create could be done only by add_file
            // Currently, add_file never returns Modify, but always New, so we differentiate based on exists
            AddFileResult::Modify if exists && !fresh => {
                stats.files.modify += 1;
                debug!("to modify: {}", path.display());
            }
            AddFileResult::Modify => {
                if exists {
                    stats.files.modify += 1;
                } else {
                    stats.files.restore += 1;
                }
                debug!("to restore: {}", path.display());
                // BackOtter: flags a file system only takes on an
                // empty file (btrfs's no-copy-on-write) go on before
                // the contents.
                if !dry_run
                    && let Err(err) = osattrs::prepare_file(target, node)
                {
                    prepare_failed(path, &err);
                }
            }
        }
        Ok(())
    };

    // BackOtter: under --exact, the hard-linked files whose first name is a
    // file with other names, decided once the walk has seen all their names
    // (LinkGroup), by the device and inode in the snapshot; and under
    // --delete, the later names of hard-linked files in the way of the link
    // the metadata pass makes, with other names themselves (removed early).
    let mut groups: Vec<LinkGroup> = Vec::new();
    let mut group_of: BTreeMap<HardlinkKey, usize> = BTreeMap::new();
    let mut in_the_way = Vec::new();

    // BackOtter: a destination that held something may have a node's
    // entry under another name the walk saw: in a case-insensitive
    // directory (ext4 or tmpfs casefolding, APFS, ZFS casesensitivity=
    // insensitive) `SAME` is the snapshot's `same`. It is the snapshot's
    // file or directory (restored as one there, or replaced by one, as for
    // any type that differs), so --delete, which sees the name `SAME` as
    // unexpected, leaves it: the snapshot targets found under another name,
    // and those below a directory so found, by their names folded
    // (Aliases). Only where nothing between the destination and the entry
    // is a symlink: what is reached through one isn't the destination's.
    let may_alias = !dry_run && std::fs::read_dir(&dest_path).is_ok_and(|mut d| d.next().is_some());
    let canonical_dest = may_alias.then(|| dest_path.canonicalize().ok()).flatten();
    let no_symlink_to = |target: &Path| -> bool {
        let (Some(canonical), Some(parent)) = (&canonical_dest, target.parent()) else {
            return false;
        };
        parent.strip_prefix(&dest_path).is_ok_and(|rel| match parent.canonicalize() {
            Ok(c) => c == canonical.join(rel),
            // BackOtter: past PATH_MAX, which no canonical path is given
            // for (ENAMETOOLONG): each directory below the destination looked
            // at, through a short path to it.
            Err(err) if err.kind() == std::io::ErrorKind::InvalidFilename => {
                no_symlink_below(&dest_path, rel)
            }
            Err(_) => false,
        })
    };
    let mut aliases = Aliases::default();

    let mut process_node = |path: &PathBuf, node: &Node, exists: bool| -> RusticResult<_> {
        let target = target_of(path)?;
        let mut exists = exists;
        if may_alias && !exists && matches!(node.node_type, NodeType::Dir | NodeType::File) {
            let below = aliases.below_alias(&target);
            if let Ok(meta) = std::fs::symlink_metadata(walkdir::short_path(&target))
                && (below || no_symlink_to(&target))
            {
                debug!("{} is there under another name", target.display());
                let right_type = if node.is_dir() { meta.is_dir() } else { meta.is_file() };
                exists = right_type
                    || !remove_in_the_way(
                        &target,
                        meta.is_dir(),
                        osattrs::node_sets_flags(node, known_bko),
                    );
                aliases.add(&target);
            } else if below {
                aliases.add(&target);
            }
        }
        match node.node_type {
            NodeType::Dir => {
                if exists {
                    stats.dirs.modify += 1;
                    trace!("existing dir {}", path.display());
                    // BackOtter: a directory there keeps its restricting
                    // flags and XFS options until the restore makes,
                    // removes or renames an entry in it (DirChanges), so
                    // that one it leaves as it is keeps its inode's change
                    // time. Then the XFS options come off until the late
                    // pass, so that the entries the restore makes in it
                    // inherit none of them (as in one it creates, which
                    // gets them last): realtime inheritance would make its
                    // new regular files realtime, on an XFS with a realtime
                    // device, for good once they have data.
                    let is_dir = std::fs::symlink_metadata(walkdir::short_path(&target))
                        .is_ok_and(|m| m.is_dir());
                    if !dry_run && is_dir {
                        dirs.borrow_mut().note(&target, path, osattrs::node_sets_flags(node, known_bko));
                    }
                    // BackOtter: an empty directory (a mount point, the
                    // destination of SNAP:subfolder) gets the flags that go
                    // on before entries as one the restore creates, unless
                    // its metadata already match (--exact).
                    if !dry_run
                        && is_dir
                        && std::fs::read_dir(walkdir::short_path(&target))
                            .is_ok_and(|mut dir| dir.next().is_none())
                        && !(opts.exact
                            && exact::already_matches(&target, node, numeric, owned, known_bko))
                    {
                        dirs.borrow_mut().change(&target);
                        if let Err(err) = osattrs::prepare_dir(&target, node, known_bko) {
                            prepare_failed(path, &err);
                        }
                    }
                } else {
                    stats.dirs.restore += 1;
                    debug!("to restore: {}", path.display());
                    if !dry_run {
                        dirs.borrow_mut().change_parent(&target);
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
                            prepare_failed(path, &err);
                        }
                    }
                }
            }
            NodeType::File => {
                let key = hardlink_key(node);
                if let Some(key) = key {
                    match hardlink_candidates.entry(key) {
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            trace!("Adding hardlink candidate {}", path.display());
                            _ = entry.insert(path.clone());
                        }
                        // this is a hardlink to an existing candidate, will be processed later while setting metadata
                        // BackOtter: a name of a LinkGroup's is in the way
                        // too, when the group gets a file of its own, as in
                        // BackOtter's restic (linkedInTheWay).
                        std::collections::btree_map::Entry::Occupied(_) => {
                            if let Some(&g) = group_of.get(&key) {
                                groups[g].others.push(target.clone());
                            }
                            if opts.delete
                                && !dry_run
                                && exists
                                && osattrs::node_sets_flags(node, known_bko)
                                && file_id(&target).is_some_and(|(_, linked)| linked)
                            {
                                in_the_way.push((target, key));
                            }
                            return Ok(());
                        }
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
                        && std::fs::symlink_metadata(walkdir::short_path(&target))
                            .is_ok_and(|m| m.is_file())
                    {
                        dirs.borrow_mut().change_parent(&target);
                        let sets = osattrs::node_sets_flags(node, known_bko);
                        let (removed, put_back) =
                            remove_held(&target, sets, &replaced, |t| {
                                std::fs::remove_file(walkdir::short_path(t))
                            });
                        if let Err(err) = removed {
                            warn!("restore {}: {err}", path.display());
                            count();
                        }
                        if let Err(err) = put_back {
                            put_back_failed(&target, &err);
                        }
                    }
                }
                // BackOtter: under --exact, a file there with other names
                // gets one of its own before the restore writes to it, so
                // that nothing reaches them, unless its names are already
                // exactly the snapshot's (LinkGroup): that is known once
                // the walk has seen them all.
                if opts.exact && exists && !dry_run && exact::has_other_names(&target) {
                    if let Some(key) = key {
                        _ = group_of.insert(key, groups.len());
                        groups.push(LinkGroup {
                            path: path.clone(),
                            node: node.clone(),
                            target,
                            others: Vec::new(),
                        });
                        return Ok(());
                    }
                    if !break_shared(path, node, &target) {
                        return Ok(());
                    }
                }
                plan_file(path, node, &target, exists)?;
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
                        // restic, where its node says which flags it had,
                        // and only as the restore changes it (DirChanges,
                        // remove_held, plan_file, the metadata pass): the
                        // late flags pass sets those. Elsewhere they stay,
                        // as in stock rustic, and what they refuse fails
                        // with its error.
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
                            let removed;
                            (next_dst, removed) = replace_existing(
                                &mut walker,
                                destination,
                                osattrs::node_sets_flags(node, known_bko),
                            );
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

    // BackOtter: under --exact, each hard-linked file whose names in the
    // destination, all seen now, are exactly the snapshot's keeps its
    // inode; any other gets a name of its own, to be linked to in the
    // metadata pass.
    for group in &groups {
        if !group.kept() && !break_shared(&group.path, &group.node, &group.target) {
            continue;
        }
        plan_file(&group.path, &group.node, &group.target, true)?;
    }

    // BackOtter: what the metadata pass links over that has other names
    // goes now, so that --delete knows them (Replaced). What can't be
    // removed is left for the metadata pass, which tries again and reports
    // it.
    for (target, key) in in_the_way {
        let Some(canonical) = hardlink_candidates.get(&key) else {
            continue;
        };
        if unbroken.borrow().contains(canonical)
            || dest.path(canonical).is_ok_and(|c| exact::same_file(&c, &target))
        {
            continue;
        }
        dirs.borrow_mut().change_parent(&target);
        match remove_held(&target, true, &replaced, |t| std::fs::remove_file(walkdir::short_path(t))) {
            (Ok(()), Err(err)) => put_back_failed(&target, &err),
            (Ok(()), Ok(())) => {}
            (Err(err), _) => debug!("{} not removed early: {err}", target.display()),
        }
    }

    // BackOtter: --delete, past what it can't remove, each an error: a
    // name of a file the restore replaced another name of loses its
    // restricting flags first, held, which the file's other names get back
    // (remove_extra). What is a snapshot target under another name stays,
    // and only what is unexpected below it goes (Aliases); what is gone
    // already (replaced as such a target) is no error.
    for (path, is_dir) in extra {
        if let Err(err) = remove_unexpected(&path, is_dir, &aliases, &dirs, &replaced) {
            error!("error removing {}: {err}", path.display());
            count();
        }
    }

    if additional_existing {
        warn!("Note: additional entries exist in destination");
    }

    restore_infos.hardlink_candidates = hardlink_candidates;
    restore_infos.unbroken = unbroken.into_inner();
    restore_infos.dirs = dirs.into_inner();
    stats.errors = errors.get();
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
    mut dirs: DirChanges,
    opts: RestoreOptions,
    dest: &LocalDestination,
) -> RusticResult<u64> {
    let mut tally = RestoreTally::new();
    // BackOtter: file flags go on last of all (osattrs), once per file:
    // they belong to the file, not each of its names, and an immutable file
    // (on illumos) refuses having them set again. ZFS's DOS flags (Linux)
    // just before them.
    let mut late = LatePass::default();
    let numeric = ownership(opts) == Ownership::Numeric;
    // BackOtter: --exact compares owners only as root, who sets them (as
    // BackOtter's restic): not root, the restore leaves them as they are.
    let owned = ownership(opts) != Ownership::None && osattrs::is_root();
    let known_bko = opts.origin.known_bko();
    let finish = |late: &mut LatePass,
                  dirs: &mut DirChanges,
                  tally: &mut RestoreTally,
                  path: &PathBuf,
                  node: &Node| {
        // BackOtter: a directory whose XFS options came off before its
        // entries went in gets those it had back, last, where its node has
        // none, and wherever nothing else is set on it here. It stays in
        // xfs_cleared until the late pass sets them: a restore that stops
        // before puts them back.
        let had_xfs = if node.is_dir() { dirs.xfs.had(path) } else { None };
        let only_had_xfs = LateAttrs { flags: None, dos_flags: None, fat_attrs: None, xfs_options: had_xfs };
        // BackOtter: under --exact, an entry whose metadata already matches
        // is left untouched, its restricting flags too: setting it again
        // would change its inode (the change time), which a btrfs snapshot
        // then no longer shares. On NetBSD one whose atime alone differs
        // (the restore's own reads moved it) gets it back alone, which
        // leaves its change time.
        let attrs = if opts.exact
            && dest.path(path).is_ok_and(|t| {
                exact::already_matches(&t, node, numeric, owned, known_bko)
                    || exact::atime_put_back(&t, node, numeric, owned, known_bko)
            })
        {
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
                tally.always();
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
                let linked = link_name(dest, canonical, &path, &node, key, sets, &mut dirs, &mut late, &mut tally);
                if let Err(err) = linked {
                    error!(
                        "restore {}: hard link to {} not made: {err}",
                        path.display(),
                        canonical.display()
                    );
                    tally.always();
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
                    finish(&mut late, &mut dirs, &mut tally, &path, &node);
                }
                // push current path to the stack
                dir_stack.push((path, node));
            }
            _ => finish(&mut late, &mut dirs, &mut tally, &path, &node),
        }
    }

    // empty dir stack and set metadata
    for (path, node) in dir_stack.into_iter().rev() {
        finish(&mut late, &mut dirs, &mut tally, &path, &node);
    }

    for (path, node_type, late, xattrs) in late.file_flags {
        // set_metadata made it, so its path is in the destination.
        let Ok(target) = dest.path(&path) else {
            continue;
        };
        // BackOtter: these count as errors as root and not (restic's late
        // flags pass), unless the file system doesn't support them.
        if let Some(attrs) = late.fat_attrs {
            osattrs::restore_fat_attrs(&target, &node_type, attrs)
                .unwrap_or_else(|err| tally.io(&path, &err, false));
        }
        if let Some(opts) = &late.xfs_options {
            osattrs::restore_xfs_options(&target, &node_type, opts)
                .unwrap_or_else(|err| tally.io(&path, &err, false));
            // BackOtter: a directory's options, cleared before its entries
            // went in or not, are its node's or those it had now.
            if node_type == NodeType::Dir {
                dirs.xfs.take(&path);
            }
        }
        let (flags, dos_flags) = (late.flags, late.dos_flags);
        if let Some(dos_flags) = dos_flags {
            osattrs::restore_zfs_dos_flags(&target, &node_type, dos_flags)
                .unwrap_or_else(|err| tally.io(&path, &err, false));
        }
        if let Some(flags) = flags {
            osattrs::restore_file_flags(&target, &node_type, flags, &xattrs)
                .unwrap_or_else(|err| tally.io(&path, &err, false));
        }
    }
    // BackOtter: the directories cleared whose options the late pass didn't
    // set (the destination, which keeps its own metadata) get back those
    // they had.
    dirs.xfs.put_back(|path, err| tally.io(path, err, false));
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
#[derive(Default)]
struct LatePass {
    file_flags: Vec<(PathBuf, NodeType, LateAttrs, Vec<ExtendedAttribute>)>,
    flags_linked: BTreeSet<HardlinkKey>,
}

/// BackOtter: links the name `path` of the hard-linked file `node` (`key`)
/// to its first name, `canonical`, as the metadata pass does
/// (`LocalDestination::hard_link`): an entry made in its directory
/// (DirChanges). Where its node says which flags it had, the file loses
/// those that would refuse a link to it (immutable, append-only), which the
/// late flags pass puts back on it, and what is in the way loses those that
/// would refuse its removal, held: its other names get them back once this
/// name is gone (remove_held).
///
/// # Errors
///
/// * If the link couldn't be made.
#[allow(clippy::too_many_arguments)]
fn link_name(
    dest: &LocalDestination,
    canonical: &Path,
    path: &Path,
    node: &Node,
    key: HardlinkKey,
    sets: bool,
    dirs: &mut DirChanges,
    late: &mut LatePass,
    tally: &mut RestoreTally,
) -> Result<(), String> {
    let (Ok(first), Ok(target)) = (dest.path(canonical), dest.path(path)) else {
        return dest.hard_link(canonical, path).map_err(|err| err.to_string());
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
    let replaced = RefCell::new(Replaced::default());
    let (linked, put_back) = remove_held(&target, sets && in_the_way, &replaced, |_| {
        dest.hard_link(canonical, path)
            .map_err(|err| std::io::Error::other(err.to_string()))
    });
    if let Err(err) = put_back {
        error!(
            "restore {}: restricting flags not put back on its other names: {err}",
            target.display()
        );
        tally.always();
    }
    linked.map_err(|err| err.to_string())
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
            warn!("restore {}: setting {what} failed.", path.display());
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
        osattrs::restore_owner(&target, node).unwrap_or_else(|err| tally.io(path, &err, true));
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
        osattrs::restore_attributes(&target, node, known_bko)
            .unwrap_or_else(|err| tally.io(path, &err, true));
    };
    // On Haiku before the mode: BFS wants write access to the file for
    // each attribute it writes, which a restore by a user other than root
    // wouldn't have on a read-only file.
    if cfg!(target_os = "haiku") {
        set_attributes(tally);
    }
    dest.set_permission(path, node, mode_zero_if_missing(opts, node))
        .unwrap_or_else(|err| {
            warn!("restore {}: chmod failed.", path.display());
            tally.dest(&err);
        });
    if node.is_symlink() {
        osattrs::restore_symlink_mode(&target, node).unwrap_or_else(|err| {
            warn!("restore {}: {err}", path.display());
            tally.count(&err, true);
        });
    }
    if !cfg!(target_os = "haiku") {
        set_attributes(tally);
    }
    osattrs::restore_acls(&target, node).unwrap_or_else(|err| tally.io(path, &err, true));
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
        tally.count(&err, true);
    });
    dest.set_times(path, &node.meta).unwrap_or_else(|err| {
        warn!("restore {}: setting file times failed.", path.display());
        tally.dest(&err);
    });
    true
}

/// BackOtter: the bytes of pack data [`restore_contents`] may hold at once
/// ([`constants::MAX_RESTORE_BYTES_IN_FLIGHT`]).
struct ByteBudget {
    total: u64,
    free: Mutex<u64>,
    freed: Condvar,
}

impl ByteBudget {
    const fn new(total: u64) -> Self {
        Self {
            total,
            free: Mutex::new(total),
            freed: Condvar::new(),
        }
    }

    /// Waits until `bytes` are free and takes them, until the guard is
    /// dropped. More than the whole budget takes the whole budget: such a
    /// pack goes alone rather than never.
    ///
    /// Only the thread that spawns the restore's tasks may wait here, never
    /// one of the pool's: the bytes are given back by the pool's tasks, which
    /// must be free to run.
    fn acquire(&self, bytes: u64) -> BudgetGuard<'_> {
        let bytes = bytes.min(self.total);
        let mut free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
        while *free < bytes {
            free = self
                .freed
                .wait(free)
                .unwrap_or_else(PoisonError::into_inner);
        }
        *free -= bytes;
        drop(free);
        BudgetGuard {
            budget: self,
            bytes,
        }
    }
}

/// Bytes taken from a [`ByteBudget`], given back on drop (a panic or an early
/// return too).
struct BudgetGuard<'a> {
    budget: &'a ByteBudget,
    bytes: u64,
}

impl Drop for BudgetGuard<'_> {
    fn drop(&mut self) {
        *self
            .budget
            .free
            .lock()
            .unwrap_or_else(PoisonError::into_inner) += self.bytes;
        self.budget.freed.notify_all();
    }
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

    let budget = &ByteBudget::new(constants::MAX_RESTORE_BYTES_IN_FLIGHT);

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

/// BackOtter: the existing directories whose XFS options came off before the
/// restore put entries in them ([`XfsCleared::clear`]), by path in the
/// snapshot ("" for the destination itself), with their target and the
/// options they had. The late pass takes each it sets the options of
/// ([`XfsCleared::take`]); the rest get theirs back as they were: the
/// destination, which keeps its own metadata, at the end of the late pass,
/// and every one when the restore stops early (an error, a plan that isn't
/// restored, as with `--dry-run-warmup`), as the snapshot may say nothing
/// about them (a node without options), when this is dropped, or on an
/// interrupt, which exits without dropping it ([`put_back_xfs_options`]).
/// Best effort: what fails is a warning.
#[derive(Debug, Default)]
struct XfsCleared(BTreeMap<PathBuf, (PathBuf, XfsOptions)>);

/// BackOtter: the targets of every [`XfsCleared`] in this process, with the
/// options they had, for [`put_back_xfs_options`]; `None` once that ran, and
/// no directory loses its options after.
static XFS_PENDING: Mutex<Option<BTreeMap<PathBuf, XfsOptions>>> = Mutex::new(Some(BTreeMap::new()));

impl XfsCleared {
    /// Takes the XFS options off the directory `target`, at `path` in the
    /// snapshot, and keeps those it had, unless it was cleared already.
    // The lock is held throughout, so that an interrupt's put-back
    // (put_back_xfs_options) sees each directory cleared or not, and comes
    // before or after this.
    #[allow(clippy::significant_drop_tightening)]
    fn clear(&mut self, path: &Path, target: &Path) {
        let mut pending = XFS_PENDING.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(pending) = pending.as_mut() else { return };
        if self.0.contains_key(path) {
            return;
        }
        if let Some(had) = osattrs::clear_dir_xfs_options(target) {
            _ = pending.insert(target.to_path_buf(), had);
            _ = self.0.insert(path.to_path_buf(), (target.to_path_buf(), had));
        }
    }

    /// The options the directory at `path` had, if they came off.
    fn had(&self, path: &Path) -> Option<XfsOptions> {
        self.0.get(path).map(|(_, had)| *had)
    }

    /// The late pass sets the options of the directory at `path`.
    fn take(&mut self, path: &Path) {
        if let Some((target, _)) = self.0.remove(path)
            && let Some(pending) = XFS_PENDING.lock().unwrap_or_else(PoisonError::into_inner).as_mut()
        {
            _ = pending.remove(&target);
        }
    }

    /// Puts back the options of every directory left, calling `failed`
    /// with its path in the snapshot and the error where that fails.
    // The lock is held throughout, so that an interrupt's put-back
    // (put_back_xfs_options) sees each directory cleared or not, and comes
    // before or after this.
    #[allow(clippy::significant_drop_tightening)]
    fn put_back(&mut self, mut failed: impl FnMut(&Path, &std::io::Error)) {
        let left = std::mem::take(&mut self.0);
        let mut pending = XFS_PENDING.lock().unwrap_or_else(PoisonError::into_inner);
        // An interrupt put them back already.
        let Some(pending) = pending.as_mut() else { return };
        for (path, (target, had)) in left {
            _ = pending.remove(&target);
            debug!("putting back XFS options {}: {had:?}", target.display());
            if let Err(err) = osattrs::restore_xfs_options(&target, &NodeType::Dir, &had) {
                failed(&path, &err);
            }
        }
    }
}

impl Drop for XfsCleared {
    fn drop(&mut self) {
        self.put_back(|path, err| {
            warn!("restore {}: XFS options not put back: {err}", path.display());
        });
    }
}

/// BackOtter: the existing directories, by target, that the restore hasn't
/// changed yet: each keeps its restricting flags and XFS options until the
/// restore is about to make, remove or rename an entry in it
/// ([`Self::change`]), so that one it leaves as it is, and whose metadata
/// already match under `--exact`, keeps its inode's change time, which a
/// btrfs snapshot then still shares. As in BackOtter's restic
/// (`changeDir`). Then the XFS options come off until the late pass
/// ([`XfsCleared`]).
#[derive(Debug, Default)]
struct DirChanges {
    /// The directories not changed yet, by target: their path in the
    /// snapshot, and whether their nodes say which flags they had
    /// (`osattrs::node_sets_flags`).
    untouched: BTreeMap<PathBuf, (PathBuf, bool)>,
    /// The XFS options taken off the directories changed.
    xfs: XfsCleared,
}

impl DirChanges {
    /// The directory `target`, at `path` in the snapshot, was there
    /// already; `sets_flags` as [`osattrs::node_sets_flags`] says for its
    /// node.
    fn note(&mut self, target: &Path, path: &Path, sets_flags: bool) {
        _ = self
            .untouched
            .insert(target.to_path_buf(), (path.to_path_buf(), sets_flags));
    }

    /// Readies the directory `dir` (a target), which the restore is about to
    /// make, remove or rename an entry in, if it was there and hasn't been
    /// changed yet: it loses the restricting flags that would refuse that,
    /// where its node says what they are, and its XFS options, so that the
    /// entries the restore makes in it inherit none of them; the late pass
    /// gives it its node's.
    fn change(&mut self, dir: &Path) {
        if let Some((path, sets_flags)) = self.untouched.remove(dir) {
            if sets_flags {
                osattrs::clear_restricting_flags(dir);
            }
            self.xfs.clear(&path, dir);
        }
    }

    /// [`Self::change`] for the directory of `target`.
    fn change_parent(&mut self, target: &Path) {
        if let Some(dir) = target.parent() {
            self.change(dir);
        }
    }
}

/// BackOtter: under `--exact`, a hard-linked file of the snapshot whose
/// first name in the destination is a file with other names: it is left
/// alone, inode and all, when its names there are already exactly the
/// snapshot's ([`Self::kept`]), and otherwise gets a name of its own, once
/// the walk has seen them all. As in BackOtter's restic (`linkGroup`).
#[derive(Debug)]
struct LinkGroup {
    /// The first name, in the snapshot.
    path: PathBuf,
    /// Its node.
    node: Node,
    /// The first name, in the destination.
    target: PathBuf,
    /// The targets of the snapshot's other names for it.
    others: Vec<PathBuf>,
}

impl LinkGroup {
    /// Whether the names the destination has for the file are exactly the
    /// snapshot's, as one file: the file at the first name has a link for
    /// each of them and no more (none outside the destination), and every
    /// other name is that file. Then nothing of the restore can reach a
    /// name the snapshot hasn't got: its contents, if they differ, are
    /// written into it, as into one file of its own.
    fn kept(&self) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            std::fs::symlink_metadata(walkdir::short_path(&self.target)).is_ok_and(|m| {
                m.is_file() && m.nlink() == 1 + self.others.len() as u64
            }) && self
                .others
                .iter()
                .all(|other| exact::same_file(&self.target, other))
        }
        #[cfg(not(unix))]
        false
    }
}

/// BackOtter: the files with other names, by device and inode, a name of
/// which the restore removed or renamed another file over, clearing their
/// restricting flags for that ([`remove_held`]): they were the restore's to
/// manage, and `--delete` clears them again for an unexpected name of such
/// a file ([`remove_extra`]). A bcachefs snapshot can share the device and
/// inode numbers of its origin's files, so a name there of another file
/// may count too: `--delete` removes it all the same, only past its
/// restricting flags. As in BackOtter's restic (`replacedLinks`).
#[derive(Debug, Default)]
struct Replaced(BTreeSet<(u64, u64)>);

/// BackOtter: the device and inode of what is at `path`, and whether it has
/// other names; `None` for a directory, or nothing there.
fn file_id(path: &Path) -> Option<((u64, u64), bool)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(walkdir::short_path(path))
            .ok()
            .filter(|m| !m.is_dir())
            .map(|m| ((m.dev(), m.ino()), m.nlink() > 1))
    }
    #[cfg(not(unix))]
    {
        _ = path;
        None
    }
}

/// BackOtter: removes the name `target` with `remove` (or renames another
/// file over it: a hard link broken), past the restricting flags that would
/// refuse that, where its node says what they are (`sets_flags`): they come
/// off held ([`osattrs::clear_restricting_flags_held`]) and go back on the
/// file it was, through the descriptor held since, whether the name is
/// gone or not, so that its other names, outside the destination too, keep
/// them. A file with other names whose name is gone is noted in
/// `replaced`, for `--delete`. Returns what `remove` returned, and whether
/// the flags went back.
fn remove_held(
    target: &Path,
    sets_flags: bool,
    replaced: &RefCell<Replaced>,
    remove: impl FnOnce(&Path) -> std::io::Result<()>,
) -> (std::io::Result<()>, std::io::Result<()>) {
    // BackOtter: past PATH_MAX, `remove` and the calls here take a short
    // path to it each (walkdir::short_path), and their messages name
    // `target`.
    if !sets_flags {
        return (remove(target), Ok(()));
    }
    let id = file_id(target);
    let held = osattrs::clear_restricting_flags_held(target);
    let removed = remove(target);
    let gone = removed
        .as_ref()
        .map_or_else(|err| err.kind() == std::io::ErrorKind::NotFound, |()| true);
    if gone && let Some((id, true)) = id {
        _ = replaced.borrow_mut().0.insert(id);
    }
    (removed, held.put_back())
}

/// BackOtter: removes the file `path`, which `--delete` removes: a name of a
/// file the restore replaced another name of ([`Replaced`]) loses its
/// restricting flags first, held, and the file's other names get them back
/// once it is gone; any other keeps its flags, as in stock rustic, and
/// what they refuse fails with its error.
///
/// # Errors
///
/// * If it couldn't be removed, or the flags couldn't be put back.
fn remove_extra(path: &Path, replaced: &RefCell<Replaced>) -> std::io::Result<()> {
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    if !file_id(path).is_some_and(|(id, _)| replaced.borrow().0.contains(&id)) {
        return std::fs::remove_file(path);
    }
    let held = osattrs::clear_restricting_flags_held(path);
    let removed = std::fs::remove_file(path);
    let put_back = held.put_back();
    removed?;
    put_back.map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!("removed, but restricting flags not put back on its other names: {err}"),
        )
    })
}

/// BackOtter: the snapshot targets (files and directories) a restore found
/// under another name than the walk of the destination saw, as in a
/// case-insensitive directory, where `SAME` is the snapshot's `same`, and
/// every target below a directory so found, by their paths with letters
/// folded to lower case ([`Self::key`]): `--delete` leaves such an entry,
/// which is the snapshot's ([`remove_unexpected`]). Removing it once the
/// walk was done removed a file the restore had planned, which it then
/// failed to read: a panic, the rest of the restore not done
/// (rustic-bko 0.11.4+backotter.14). Folding letters, not Unicode
/// normalization: a name the file system takes as another only by its
/// normal form is still removed.
#[derive(Debug, Default)]
struct Aliases(BTreeMap<String, PathBuf>);

impl Aliases {
    fn key(path: &Path) -> String {
        path.to_string_lossy().to_lowercase()
    }

    fn add(&mut self, target: &Path) {
        _ = self.0.insert(Self::key(target), target.to_path_buf());
    }

    /// Whether the directory of `target` is one of them.
    fn below_alias(&self, target: &Path) -> bool {
        !self.0.is_empty()
            && target
                .parent()
                .is_some_and(|dir| self.0.contains_key(&Self::key(dir)))
    }

    /// The target that the entry at `path` is, if it is one of them: the
    /// same entry (device and inode).
    fn target_of(&self, path: &Path) -> Option<&Path> {
        self.0
            .get(&Self::key(path))
            .map(PathBuf::as_path)
            .filter(|target| same_entry(path, target))
    }
}

/// BackOtter: whether each component of `rel`, below `dest`, is a
/// directory, not a symlink to one: what a canonical path shows, for a path
/// past `PATH_MAX`, which has none (`process_node`'s `no_symlink_to`).
fn no_symlink_below(dest: &Path, rel: &Path) -> bool {
    let mut path = dest.to_path_buf();
    rel.components().all(|c| {
        path.push(c);
        matches!(c, std::path::Component::Normal(_))
            && std::fs::symlink_metadata(walkdir::short_path(&path)).is_ok_and(|m| m.is_dir())
    })
}

/// BackOtter: whether `a` and `b` are the same entry, the same device and
/// inode, not following a symlink; a directory too.
fn same_entry(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (
            std::fs::symlink_metadata(walkdir::short_path(a)),
            std::fs::symlink_metadata(walkdir::short_path(b)),
        ) {
            (Ok(a), Ok(b)) => (a.dev(), a.ino()) == (b.dev(), b.ino()),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        a == b
    }
}

/// BackOtter: removes what `--delete` removes at `path` (a directory if
/// `is_dir`), unless it is a snapshot target under another name
/// ([`Aliases`]): a file then stays, and a directory loses only what is
/// unexpected below it, each entry in it as `path` is, its name taken as
/// the target's. Nothing there is no error: it went as such a target of
/// another type. Past what fails: the error is the first.
///
/// # Errors
///
/// * If some of it couldn't be removed.
fn remove_unexpected(
    path: &Path,
    is_dir: bool,
    aliases: &Aliases,
    dirs: &RefCell<DirChanges>,
    replaced: &RefCell<Replaced>,
) -> std::io::Result<()> {
    if std::fs::symlink_metadata(walkdir::short_path(path))
        .is_err_and(|err| err.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(());
    }
    let Some(target) = aliases.target_of(path) else {
        // Only a directory an entry goes from changes: one left as it is
        // keeps its flags and change time (DirChanges).
        dirs.borrow_mut().change_parent(path);
        return if is_dir {
            remove_tree(path, replaced)
        } else {
            remove_extra(path, replaced)
        };
    };
    debug!("{} left: it is {}", path.display(), target.display());
    // A directory the walk saw there may since have been replaced by the
    // snapshot's file of that name: that stays, as a whole.
    if !is_dir || !std::fs::symlink_metadata(walkdir::short_path(target)).is_ok_and(|m| m.is_dir()) {
        return Ok(());
    }
    let mut first = None;
    for entry in std::fs::read_dir(walkdir::short_path(target))? {
        let removed = entry.and_then(|entry| {
            let child = target.join(entry.file_name());
            let child_dir = entry.file_type()?.is_dir();
            remove_unexpected(&child, child_dir, aliases, dirs, replaced).map_err(|err| {
                std::io::Error::new(err.kind(), format!("{}: {err}", child.display()))
            })
        });
        if let Err(err) = removed {
            _ = first.get_or_insert(err);
        }
    }
    first.map_or(Ok(()), Err)
}

/// BackOtter: removes the directory `dir` and all below it, which `--delete`
/// removes, each file as [`remove_extra`] does, one at a time, and past
/// what it can't remove: the error then says what failed first, and how
/// much was and wasn't removed. As in BackOtter's restic, which reports what
/// a partial removal deleted.
///
/// # Errors
///
/// * If some of it couldn't be removed.
fn remove_tree(dir: &Path, replaced: &RefCell<Replaced>) -> std::io::Result<()> {
    let (mut removed, mut failed) = (0_u64, 0_u64);
    let mut first = None;
    for entry in WalkDir::new(dir).follow_links(false).contents_first(true) {
        let result = match &entry {
            Err(err) => Err(std::io::Error::other(err.to_string())),
            Ok(entry) if entry.file_type().is_dir() => {
                std::fs::remove_dir(walkdir::short_path(entry.path()))
            }
            Ok(entry) => remove_extra(entry.path(), replaced),
        };
        match result {
            Ok(()) => removed += 1,
            Err(err) => {
                failed += 1;
                if first.is_none() {
                    let path = entry.as_ref().map_or_else(
                        |err| err.path().unwrap_or(dir).to_path_buf(),
                        |entry| entry.path().to_path_buf(),
                    );
                    first = Some((path, err));
                }
            }
        }
    }
    match first {
        None => Ok(()),
        Some((path, err)) => Err(std::io::Error::new(
            err.kind(),
            format!(
                "{failed} entries not removed, the first {}: {err}; {removed} removed",
                path.display()
            ),
        )),
    }
}

/// BackOtter: held (shared) by a restore while it makes an entry in the
/// destination, or writes to one ([`making_entries`]); [`put_back_xfs_options`]
/// takes it for good, so that nothing is made after it in a directory whose
/// options are back, to inherit them (realtime, an extent size hint, which
/// XFS changes on no file with data).
static MAKING_ENTRIES: RwLock<()> = RwLock::new(());

/// BackOtter: for a restore about to make an entry in the destination, or
/// write to one: it waits for the exit once [`put_back_xfs_options`] ran.
pub(crate) fn making_entries() -> RwLockReadGuard<'static, ()> {
    MAKING_ENTRIES.read().unwrap_or_else(PoisonError::into_inner)
}

/// BackOtter: puts back, as they were, the XFS options a restore in this
/// process took off existing directories and hasn't put back yet.
///
/// For a program about to exit on an interrupt, which leaves a restore
/// stopped where it is, without its late pass: call it once, before exiting.
/// Once the entries being made are, no restore in this process makes or
/// writes one ([`making_entries`]: its threads wait for the exit) or takes a
/// directory's options off. Best effort: what fails is a warning.
pub fn put_back_xfs_options() {
    if XFS_PENDING.lock().unwrap_or_else(PoisonError::into_inner).is_none() {
        return;
    }
    std::mem::forget(MAKING_ENTRIES.write().unwrap_or_else(PoisonError::into_inner));
    let Some(pending) = XFS_PENDING.lock().unwrap_or_else(PoisonError::into_inner).take() else {
        return;
    };
    for (target, had) in pending {
        debug!("putting back XFS options {}: {had:?}", target.display());
        if let Err(err) = osattrs::restore_xfs_options(&target, &NodeType::Dir, &had) {
            warn!("restore {}: XFS options not put back: {err}", target.display());
        }
    }
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
enum FileMatch {
    /// It is there, of the right size (and mtime): left as it is.
    Existing,
    /// Its blobs, to restore those that don't match.
    Blobs(MatchedFile),
}

/// BackOtter: a file matched blob by blob ([`RestorePlan::match_file`]), for
/// [`RestorePlan::push_file`].
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

        assert!(set_metadata(&dest, opts, &path, &node, false, true, &mut tally));
        assert_eq!(stat().mode() & 0o7777, 0o640, "the rest of its metadata is set");
        assert_ne!(stat().mtime(), 1_600_000_000);

        assert!(set_metadata(&dest, opts, &path, &node, false, false, &mut tally));
        assert_eq!(stat().mtime(), 1_600_000_000);
        assert_eq!(tally.errors, 0);
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
        let mounts = RefCell::new(Vec::<PathBuf>::new());
        let device = |path: &Path, _: &std::fs::Metadata| {
            let mounts = mounts.borrow();
            let i = mounts.iter().position(|m| path.starts_with(m));
            Some(i.map_or(0, |i| i as u64 + 1))
        };
        let fresh = |d: &Path| fresh_target_with(d, &device);
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
        let mounts = RefCell::new(Vec::<PathBuf>::new());
        let device = |path: &Path, _: &std::fs::Metadata| {
            let mounts = mounts.borrow();
            let i = mounts.iter().position(|m| path.starts_with(m));
            Some(i.map_or(0, |i| i as u64 + 1))
        };
        let fresh = |d: &Path| fresh_target_with(d, &device);
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
        let lstat = |p: &Path| std::fs::symlink_metadata(p).unwrap();
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
        let mount = |at: &Path| {
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

    /// BackOtter: once `put_back_xfs_options` ran (an interrupt, about to
    /// exit), a restore makes no entry: it waits for the exit, so that
    /// nothing inherits the options put back. In a child of this test
    /// binary, as it holds every restore in the process for good.
    #[test]
    fn no_entry_after_put_back() {
        const CHILD: &str = "BKO_TEST_PUT_BACK_CHILD";
        let name = format!(
            "{}::no_entry_after_put_back",
            module_path!().split_once("::").unwrap().1
        );
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--test-threads=1"])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success(), "{name} in a child: {status}");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let dest =
            LocalDestination::new(dir.path().to_str().unwrap(), false, false).unwrap();
        dest.create_dir("before").unwrap();
        assert!(dir.path().join("before").is_dir());
        put_back_xfs_options();
        // A second call (none should come) returns.
        put_back_xfs_options();
        let (tx, rx) = std::sync::mpsc::channel();
        let tx2 = tx.clone();
        _ = std::thread::spawn(move || {
            _ = dest.set_length("after", 1, false);
            _ = tx.send(());
        });
        // The plan's own creation of a file that takes a flag before its
        // data (btrfs's no-copy-on-write), on the main thread.
        let early = dir.path().join("early");
        let mut nocow = Node::default();
        nocow.meta.generic_attributes.set_u64(
            crate::backend::node::generic_attributes::LINUX_INODE_FLAGS,
            0x0080_0000,
        );
        let path = early.clone();
        _ = std::thread::spawn(move || {
            _ = osattrs::prepare_file(&path, &nocow);
            _ = tx2.send(());
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(500)).is_err(),
            "a file was made after the put-back"
        );
        assert!(!dir.path().join("after").exists());
        assert!(!early.exists());
    }

    /// BackOtter (RustAudit1 XR1-02): what a removal past `PATH_MAX` can't
    /// remove is named by its own path, not by the short one it was reached
    /// through (in `$TMPDIR/.bko-longpath-PID-N`, gone at exit), which
    /// rustic-bko 0.11.4+backotter.20's `remove_held` named.
    #[cfg(target_os = "linux")]
    #[test]
    fn removal_past_path_max_names_the_long_path() {
        use std::fs::{self, Permissions};
        use std::os::unix::fs::PermissionsExt;

        if nix::unistd::geteuid().is_root() {
            eprintln!("root removes it anyway");
            return;
        }
        let top = tempfile::tempdir().unwrap();
        let mut deep = top.path().to_path_buf();
        for i in 0..110 {
            deep.push(format!("d{i:03}{}", "x".repeat(36)));
            fs::create_dir(walkdir::short_path(&deep)).unwrap();
        }
        let held = deep.join("held");
        fs::create_dir(walkdir::short_path(&held)).unwrap();
        fs::write(walkdir::short_path(&held.join("f")), b"x").unwrap();
        fs::set_permissions(walkdir::short_path(&held), Permissions::from_mode(0o555)).unwrap();
        assert!(held.as_os_str().len() > 4096);
        let replaced = RefCell::new(Replaced::default());
        let (removed, put_back) =
            remove_held(&deep, false, &replaced, |path| remove_tree(path, &replaced));
        fs::set_permissions(walkdir::short_path(&held), Permissions::from_mode(0o755)).unwrap();
        assert!(put_back.is_ok());
        let msg = removed.unwrap_err().to_string();
        assert!(msg.contains(&*held.join("f").to_string_lossy()), "{msg}");
        assert!(!msg.contains(".bko-longpath"), "{msg}");
    }
}
