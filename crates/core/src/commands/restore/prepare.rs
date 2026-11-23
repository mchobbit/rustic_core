//! BackOtter: what a restore keeps of the destination while it plans and
//! prepares it (`collect_and_prepare`), and how it removes what is in its
//! way: the directories it hasn't changed yet and the XFS options it took
//! off them, the hard-linked files it replaced a name of, the snapshot's
//! entries found under another name, and the removals past restricting
//! flags.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError, RwLock, RwLockReadGuard},
};

use log::{debug, error, info, trace, warn};
use walkdir::{DirEntry, WalkDir};

use super::{
    AddFileResult, FileDirStats, FileMatch, HardlinkKey, RestoreOptions, RestorePlan,
    RestoreStats, exact,
};
use crate::{
    backend::{
        local_destination::LocalDestination,
        node::{Node, NodeType, generic_attributes::XfsOptions},
        osattrs,
    },
    error::{ErrorKind, RusticError, RusticResult},
    repository::{IndexedFull, Repository},
};

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
pub(super) struct XfsCleared(BTreeMap<PathBuf, (PathBuf, XfsOptions)>);

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
    pub(super) fn had(&self, path: &Path) -> Option<XfsOptions> {
        self.0.get(path).map(|(_, had)| *had)
    }

    /// The late pass sets the options of the directory at `path`.
    pub(super) fn take(&mut self, path: &Path) {
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
    pub(super) fn put_back(&mut self, mut failed: impl FnMut(&Path, &std::io::Error)) {
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
pub(super) struct DirChanges {
    /// The directories not changed yet, by target: their path in the
    /// snapshot, and whether their nodes say which flags they had
    /// (`osattrs::node_sets_flags`).
    untouched: BTreeMap<PathBuf, (PathBuf, bool)>,
    /// The XFS options taken off the directories changed.
    pub(super) xfs: XfsCleared,
}

impl DirChanges {
    /// The directory `target`, at `path` in the snapshot, was there
    /// already; `sets_flags` as [`osattrs::node_sets_flags`] says for its
    /// node.
    pub(super) fn note(&mut self, target: &Path, path: &Path, sets_flags: bool) {
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
    pub(super) fn change(&mut self, dir: &Path) {
        if let Some((path, sets_flags)) = self.untouched.remove(dir) {
            if sets_flags {
                osattrs::clear_restricting_flags(dir);
            }
            self.xfs.clear(&path, dir);
        }
    }

    /// [`Self::change`] for the directory of `target`.
    pub(super) fn change_parent(&mut self, target: &Path) {
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
pub(super) struct Replaced(BTreeSet<(u64, u64)>);

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
pub(super) fn remove_held(
    target: &Path,
    sets_flags: bool,
    replaced: &mut Replaced,
    remove: impl FnOnce(&Path, &mut Replaced) -> std::io::Result<()>,
) -> (std::io::Result<()>, std::io::Result<()>) {
    // BackOtter: past PATH_MAX, `remove` and the calls here take a short
    // path to it each (walkdir::short_path), and their messages name
    // `target`.
    if !sets_flags {
        return (remove(target, replaced), Ok(()));
    }
    let id = file_id(target);
    let held = osattrs::clear_restricting_flags_held(target);
    let removed = remove(target, replaced);
    let gone = removed
        .as_ref()
        .map_or_else(|err| err.kind() == std::io::ErrorKind::NotFound, |()| true);
    if gone && let Some((id, true)) = id {
        _ = replaced.0.insert(id);
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
fn remove_extra(path: &Path, replaced: &Replaced) -> std::io::Result<()> {
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    if !file_id(path).is_some_and(|(id, _)| replaced.0.contains(&id)) {
        return std::fs::remove_file(path);
    }
    let held = osattrs::clear_restricting_flags_held(path);
    let removed = std::fs::remove_file(path);
    removed_and_put_back(removed, held.put_back())
}

/// BackOtter: what [`remove_extra`] says of a removal past restricting
/// flags, held, and of their put-back: the removal's error, and the
/// put-back's too when that failed as well, since the file then stays
/// under all its names, outside the destination too, without the flags it
/// had (as `break_shared` reports it); a put-back that failed after the
/// name went is an error of its own.
fn removed_and_put_back(
    removed: std::io::Result<()>,
    put_back: std::io::Result<()>,
) -> std::io::Result<()> {
    match (removed, put_back) {
        (removed, Ok(())) => removed,
        (Ok(()), Err(err)) => Err(std::io::Error::new(
            err.kind(),
            format!("removed, but restricting flags not put back on its other names: {err}"),
        )),
        (Err(err), Err(perr)) => Err(std::io::Error::new(
            err.kind(),
            format!("{err}; its restricting flags not set back: {perr}"),
        )),
    }
}

/// BackOtter: reports how the early removal of `target` went, a later name
/// of a hard-linked file in the way of the link the metadata pass makes
/// (`removal`: what [`remove_held`] returned). A name that stays is no
/// error yet: the metadata pass tries again and reports it. Flags that
/// didn't go back on the file's other names are reported here
/// (`put_back_failed`), whether the name went or not: the metadata pass
/// finds them off already, so its own put-back has nothing to fail on.
fn report_early_removal(
    target: &Path,
    removal: (std::io::Result<()>, std::io::Result<()>),
    put_back_failed: impl FnOnce(&Path, &std::io::Error),
) {
    let (removed, put_back) = removal;
    if let Err(err) = removed {
        debug!("{} not removed early: {err}", target.display());
    }
    if let Err(err) = put_back {
        put_back_failed(target, &err);
    }
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
            .filter(|target| exact::same_entry(path, target))
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
    dirs: &mut DirChanges,
    replaced: &Replaced,
) -> std::io::Result<()> {
    if std::fs::symlink_metadata(walkdir::short_path(path))
        .is_err_and(|err| err.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(());
    }
    let Some(target) = aliases.target_of(path) else {
        // Only a directory an entry goes from changes: one left as it is
        // keeps its flags and change time (DirChanges).
        dirs.change_parent(path);
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
fn remove_tree(dir: &Path, replaced: &Replaced) -> std::io::Result<()> {
    let (mut removed, mut failed) = (0_u64, 0_u64);
    let mut first = None;
    // BackOtter: all but this process's own links' directory (paths past
    // PATH_MAX), there when $TMPDIR is in `dir`: it stays, and so do the
    // directories above it, each an error (ForkAudit1 G7-01).
    let entries = WalkDir::new(dir).follow_links(false).contents_first(true).into_iter();
    for entry in entries.filter_entry(|e| !walkdir::is_short_path_dir(e.path())) {
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

/// BackOtter: whether `err`, from the walk of the destination, counts as an
/// error of the restore: restic walks the destination only for `--delete`
/// (`delete`), and fails then; a destination that isn't there yet holds
/// nothing to delete.
pub(super) fn walk_error_counts(err: &walkdir::Error, delete: bool) -> bool {
    let missing_root = err.depth() == 0
        && err
            .io_error()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound);
    delete && !missing_root
}

/// BackOtter: what `collect_and_prepare` keeps of our own while it plans a
/// restore, and what it does to the destination that stock rustic doesn't,
/// as its walk of the snapshot's nodes and the destination's entries comes
/// to each (the methods, in the order the walk calls them) and once it is
/// done ([`Self::finish`]). Upstream's loop and closures stay in
/// `collect_and_prepare`, and call these.
#[derive(Debug)]
pub(super) struct Prepare<'a> {
    opts: RestoreOptions,
    dest: &'a LocalDestination,
    /// The destination's own path.
    dest_path: &'a Path,
    dry_run: bool,
    /// How `--exact` compares an entry with its node.
    how: exact::Compared,
    /// Whether the restore runs as root.
    root: bool,
    /// The existing directories the restore hasn't changed yet, which keep
    /// their restricting flags and XFS options until it does; the
    /// destination itself too, also where it keeps its own metadata (no
    /// node of its own, "" in the snapshot).
    pub(super) dirs: DirChanges,
    /// The files with other names a name of which the restore removed.
    replaced: Replaced,
    /// The files left shared whose hard link `--exact` couldn't break, by
    /// their paths in the snapshot.
    unbroken: BTreeSet<PathBuf>,
    /// The failures restic counts as errors (`RestoreStats::errors`).
    errors: u64,
    /// The files planned: to restore, unchanged, verified, to modify.
    files: FileDirStats,
    /// Whether the destination held something, so that a node's entry may
    /// be there under another name the walk saw: in a case-insensitive
    /// directory (ext4 or tmpfs casefolding, APFS, ZFS
    /// casesensitivity=insensitive) `SAME` is the snapshot's `same`. It is
    /// the snapshot's file or directory (restored as one there, or replaced
    /// by one, as for any type that differs), so `--delete`, which sees the
    /// name `SAME` as unexpected, leaves it: the snapshot targets found
    /// under another name, and those below a directory so found, by their
    /// names folded (`aliases`). Only where nothing between the destination
    /// and the entry is a symlink: what is reached through one isn't the
    /// destination's.
    may_alias: bool,
    /// The destination's canonical path, where an entry may be an alias.
    canonical_dest: Option<PathBuf>,
    aliases: Aliases,
    /// Under `--exact`, the hard-linked files whose first name is a file
    /// with other names, decided once the walk has seen all their names
    /// ([`LinkGroup`]), by the device and inode in the snapshot.
    groups: Vec<LinkGroup>,
    group_of: BTreeMap<HardlinkKey, usize>,
    /// Under `--delete`, the later names of hard-linked files in the way of
    /// the link the metadata pass makes, with other names themselves
    /// (removed early).
    in_the_way: Vec<(PathBuf, HardlinkKey)>,
}

impl<'a> Prepare<'a> {
    /// For a restore with `opts` into `dest`, whose own path is
    /// `dest_path`; with `dry_run`, nothing there is made, removed or
    /// changed.
    pub(super) fn new(
        opts: RestoreOptions,
        dest: &'a LocalDestination,
        dest_path: &'a Path,
        dry_run: bool,
    ) -> Self {
        let mut dirs = DirChanges::default();
        if !dry_run && std::fs::symlink_metadata(dest_path).is_ok_and(|m| m.is_dir()) {
            dirs.note(dest_path, Path::new(""), false);
        }
        let how = super::compared(opts);
        let root = osattrs::is_root();
        let may_alias =
            !dry_run && std::fs::read_dir(dest_path).is_ok_and(|mut d| d.next().is_some());
        let canonical_dest = may_alias.then(|| dest_path.canonicalize().ok()).flatten();
        Self {
            opts,
            dest,
            dest_path,
            dry_run,
            how,
            root,
            dirs,
            replaced: Replaced::default(),
            unbroken: BTreeSet::new(),
            errors: 0,
            files: FileDirStats::default(),
            may_alias,
            canonical_dest,
            aliases: Aliases::default(),
            groups: Vec::new(),
            group_of: BTreeMap::new(),
            in_the_way: Vec::new(),
        }
    }

    /// Whether the snapshot is BackOtter's: a node's missing attributes
    /// mean none.
    const fn known_bko(&self) -> bool {
        self.opts.origin.known_bko()
    }

    /// One more failure restic counts as an error.
    const fn count(&mut self) {
        self.errors += 1;
    }

    /// Flags that go on before entries or contents couldn't be set, which
    /// counts unless the file system doesn't support them.
    fn prepare_failed(&mut self, path: &Path, err: &std::io::Error) {
        warn!("restore {}: {err}", path.display());
        if osattrs::restore_error_counts(err, false, self.root) {
            self.count();
        }
    }

    /// Restricting flags couldn't be put back on the other names of a file
    /// whose name the restore removed ([`remove_held`]).
    fn put_back_failed(&mut self, path: &Path, err: &std::io::Error) {
        error!(
            "restore {}: restricting flags not put back on its other names: {err}",
            path.display()
        );
        self.count();
    }

    /// A node's path in the destination; one that would leave it (`..`, an
    /// absolute path) is an error. Every path this restore touches outside
    /// `LocalDestination`'s own calls is taken from here, so that it is
    /// checked too.
    pub(super) fn target_of(&self, path: &Path) -> RusticResult<PathBuf> {
        self.dest.path(path).map_err(|err| {
            RusticError::with_source(
                ErrorKind::InputOutput,
                "Invalid path in snapshot for restore destination: `{path}`.",
                err,
            )
            .attach_context("path", path.display().to_string())
        })
    }

    /// What has a node's name but another type, and any special file, is
    /// removed first, with or without `--delete`, as BackOtter's restic
    /// does: a directory is restored as a directory, not through a symlink
    /// to wherever that points, and a file or special file is made anew.
    /// Without `--delete` a directory only goes if it is empty. It loses
    /// the restricting flags that would refuse that first, where its node
    /// says what they are (`sets`), and a file with other names gets them
    /// back once this name is gone ([`remove_held`]). Whether the old one
    /// is gone.
    fn remove_in_the_way(&mut self, path: &Path, is_dir: bool, sets: bool) -> bool {
        self.dirs.change_parent(path);
        let delete = self.opts.delete;
        // BackOtter: nothing below a directory loses its flags: what
        // refuses removal stays, as with --delete.
        let (removed, put_back) =
            remove_held(path, sets, &mut self.replaced, |path, replaced| {
                match (is_dir, delete) {
                    (false, _) => std::fs::remove_file(walkdir::short_path(path)),
                    (true, true) => remove_tree(path, replaced),
                    (true, false) => std::fs::remove_dir(walkdir::short_path(path)),
                }
            });
        if let Err(err) = put_back {
            self.put_back_failed(path, &err);
        }
        removed
            .map_err(|err| {
                error!("error removing {}: {err}", path.display());
                self.count();
            })
            .is_ok()
    }

    /// [`Self::remove_in_the_way`] for `entry` of the walk `walker`, which
    /// is in the way of `node`: returns the next entry (`next_entry`'s) and
    /// whether the old one is gone.
    ///
    /// What the restore finds in its way loses the flags that would refuse
    /// its being rewritten, replaced or given its metadata (immutable,
    /// append-only, undeletable), as in BackOtter's restic, where its node
    /// says which flags it had, and only as the restore changes it
    /// ([`DirChanges`], [`remove_held`], [`Self::plan_file`], the metadata
    /// pass): the late flags pass sets those. Elsewhere they stay, as in
    /// stock rustic, and what they refuse fails with its error.
    pub(super) fn replace_existing(
        &mut self,
        walker: &mut walkdir::IntoIter,
        entry: &DirEntry,
        node: &Node,
        next_entry: impl Fn(&mut walkdir::IntoIter) -> Option<DirEntry>,
    ) -> (Option<DirEntry>, bool) {
        let sets = osattrs::node_sets_flags(node, self.known_bko());
        if entry.depth() == 0 {
            return (next_entry(walker), false);
        }
        let is_dir = entry.file_type().is_dir();
        let removed = if self.dry_run {
            info!("would have replaced {}", entry.path().display());
            true
        } else {
            self.remove_in_the_way(entry.path(), is_dir, sets)
        };
        if is_dir {
            walker.skip_current_dir();
        }
        (next_entry(walker), removed)
    }

    /// Whether `target`, the path of `node`, is there (`exists`: as the
    /// walk saw it), under another name too (`may_alias`): an entry found
    /// under another name is the snapshot's if its type is the node's, and
    /// is removed as in the way otherwise ([`Self::remove_in_the_way`]).
    pub(super) fn found_under_another_name(
        &mut self,
        target: &Path,
        node: &Node,
        exists: bool,
    ) -> bool {
        let mut exists = exists;
        if self.may_alias && !exists && matches!(node.node_type, NodeType::Dir | NodeType::File) {
            let below = self.aliases.below_alias(target);
            if let Ok(meta) = std::fs::symlink_metadata(walkdir::short_path(target))
                && (below || self.no_symlink_to(target))
            {
                debug!("{} is there under another name", target.display());
                let right_type = if node.is_dir() { meta.is_dir() } else { meta.is_file() };
                exists = right_type
                    || !self.remove_in_the_way(
                        target,
                        meta.is_dir(),
                        osattrs::node_sets_flags(node, self.known_bko()),
                    );
                self.aliases.add(target);
            } else if below {
                self.aliases.add(target);
            }
        }
        exists
    }

    /// Whether nothing between the destination and `target` is a symlink.
    fn no_symlink_to(&self, target: &Path) -> bool {
        let (Some(canonical), Some(parent)) = (&self.canonical_dest, target.parent()) else {
            return false;
        };
        parent
            .strip_prefix(self.dest_path)
            .is_ok_and(|rel| match parent.canonicalize() {
                Ok(c) => c == canonical.join(rel),
                // BackOtter: past PATH_MAX, which no canonical path is given
                // for (ENAMETOOLONG): each directory below the destination
                // looked at, through a short path to it.
                Err(err) if err.kind() == std::io::ErrorKind::InvalidFilename => {
                    no_symlink_below(self.dest_path, rel)
                }
                Err(_) => false,
            })
    }

    /// The directory `node`, at `path` in the snapshot, is there, at
    /// `target`.
    ///
    /// A directory there keeps its restricting flags and XFS options until
    /// the restore makes, removes or renames an entry in it
    /// ([`DirChanges`]), so that one it leaves as it is keeps its inode's
    /// change time. Then the XFS options come off until the late pass, so
    /// that the entries the restore makes in it inherit none of them (as in
    /// one it creates, which gets them last): realtime inheritance would
    /// make its new regular files realtime, on an XFS with a realtime
    /// device, for good once they have data.
    ///
    /// An empty directory (a mount point, the destination of
    /// `SNAP:subfolder`) gets the flags that go on before entries as one
    /// the restore creates, unless its metadata already match (`--exact`).
    pub(super) fn existing_dir(&mut self, path: &Path, node: &Node, target: &Path) {
        let is_dir =
            std::fs::symlink_metadata(walkdir::short_path(target)).is_ok_and(|m| m.is_dir());
        if !self.dry_run && is_dir {
            self.dirs
                .note(target, path, osattrs::node_sets_flags(node, self.known_bko()));
        }
        if !self.dry_run
            && is_dir
            && std::fs::read_dir(walkdir::short_path(target))
                .is_ok_and(|mut dir| dir.next().is_none())
            && !(self.opts.exact && exact::already_matches(target, node, self.how))
        {
            self.dirs.change(target);
            if let Err(err) = osattrs::prepare_dir(target, node, self.known_bko()) {
                self.prepare_failed(path, &err);
            }
        }
    }

    /// The restore made the directory `node`, at `path` in the snapshot, at
    /// `target`: flags a file system only takes on an empty directory
    /// (casefolding) go on before its entries, or come off if it inherited
    /// them where the node says it had none (a snapshot of BackOtter's);
    /// without a word on them, it keeps what it inherited.
    pub(super) fn created_dir(&mut self, path: &Path, node: &Node, target: &Path) {
        if let Err(err) = osattrs::prepare_dir(target, node, self.known_bko()) {
            self.prepare_failed(path, &err);
        }
    }

    /// `target` is a later name of the hard-linked file `node` (`key`),
    /// which the metadata pass links to its first name; it is there or not
    /// (`exists`). A name of a [`LinkGroup`]'s is in the way too, when the
    /// group gets a file of its own, as in BackOtter's restic
    /// (`linkedInTheWay`).
    pub(super) fn later_link_name(
        &mut self,
        key: HardlinkKey,
        node: &Node,
        target: PathBuf,
        exists: bool,
    ) {
        if let Some(&g) = self.group_of.get(&key) {
            self.groups[g].others.push(target.clone());
        }
        if self.opts.delete
            && !self.dry_run
            && exists
            && osattrs::node_sets_flags(node, self.known_bko())
            && file_id(&target).is_some_and(|(_, linked)| linked)
        {
            self.in_the_way.push((target, key));
        }
    }

    /// Plans the regular file `node`, at `path` in the snapshot and
    /// `target` in the destination, there or not (`exists`): a first name,
    /// or a file without other names in the snapshot.
    ///
    /// A file whose contents weren't backed up (one illumos quarantined) is
    /// restored empty, with the rest of its metadata, its system attributes
    /// last as for any file; one warning for it, not for each of its hard
    /// links. It goes into a new, empty file, as in BackOtter's restic: a
    /// file there may be quarantined, which keeps its contents and extended
    /// attributes closed to the restore too.
    ///
    /// Under `--exact`, a file there with other names gets one of its own
    /// before the restore writes to it, so that nothing reaches them,
    /// unless its names are already exactly the snapshot's ([`LinkGroup`]):
    /// that is known once the walk has seen them all ([`Self::finish`]).
    ///
    /// # Errors
    ///
    /// * If the file could not be matched against what is there.
    pub(super) fn plan_node_file<S: IndexedFull>(
        &mut self,
        plan: &mut RestorePlan,
        repo: &Repository<S>,
        path: &Path,
        node: &Node,
        target: &Path,
        exists: bool,
    ) -> RusticResult<()> {
        if let Some(size) = osattrs::unread_size(node) {
            warn!(
                "{}: contents were not backed up (av_quarantined at backup, {size} bytes)",
                target.display()
            );
            if !self.dry_run
                && std::fs::symlink_metadata(walkdir::short_path(target))
                    .is_ok_and(|m| m.is_file())
            {
                self.dirs.change_parent(target);
                let sets = osattrs::node_sets_flags(node, self.known_bko());
                let (removed, put_back) =
                    remove_held(target, sets, &mut self.replaced, |t, _| {
                        std::fs::remove_file(walkdir::short_path(t))
                    });
                if let Err(err) = removed {
                    warn!("restore {}: {err}", path.display());
                    self.count();
                }
                if let Err(err) = put_back {
                    self.put_back_failed(target, &err);
                }
            }
        }
        if self.opts.exact && exists && !self.dry_run && exact::has_other_names(target) {
            if let Some(key) = super::hardlink_key(node) {
                _ = self.group_of.insert(key, self.groups.len());
                self.groups.push(LinkGroup {
                    path: path.to_path_buf(),
                    node: node.clone(),
                    target: target.to_path_buf(),
                    others: Vec::new(),
                });
                return Ok(());
            }
            if !self.break_shared(path, node, target) {
                return Ok(());
            }
        }
        self.plan_file(plan, repo, path, node, target, exists)
    }

    /// Under `--exact`, the existing file `target`, which has other names,
    /// gets a name of its own before the restore writes to it or sets its
    /// metadata, so that nothing reaches them (`exact::break_link`). Its
    /// restricting flags come off first, where its node says what they
    /// are, for the rename or removal, and go back on the file it was,
    /// which its other names still are, through a descriptor held open
    /// ([`remove_held`]). One whose link can't be broken is an error, and
    /// is left exactly as it is (`unbroken`): no contents, no holes filled,
    /// no metadata, nor any of the snapshot's other names for it linked to
    /// it. True if it was broken.
    fn break_shared(&mut self, path: &Path, node: &Node, target: &Path) -> bool {
        self.dirs.change_parent(target);
        let sets = osattrs::node_sets_flags(node, self.known_bko());
        let (broken, put_back) = remove_held(target, sets, &mut self.replaced, |target, _| {
            exact::break_link(target).map(|cloned| {
                debug!("hard link of {} broken, cloned: {cloned}", target.display());
            })
        });
        match broken {
            Ok(()) => {
                if let Err(err) = put_back {
                    self.put_back_failed(target, &err);
                }
                true
            }
            Err(err) => {
                let err = match put_back {
                    Ok(()) => err.to_string(),
                    Err(perr) => format!("{err}; its restricting flags not set back: {perr}"),
                };
                error!(
                    "restore {}: left as it is, its hard link not broken: {err}",
                    path.display()
                );
                self.count();
                _ = self.unbroken.insert(path.to_path_buf());
                false
            }
        }
    }

    /// Plans the contents of the file `node` at `target`, which was there
    /// (`exists`) or not: what is there, of its size, is matched blob by
    /// blob, and what differs is written, or cloned whole from a file
    /// restored elsewhere (`--clone-from`). A file there loses the
    /// restricting flags that would refuse its being rewritten (immutable,
    /// append-only), where its node says what they are, only as the restore
    /// changes it: before it is written, cloned over, or its holes filled;
    /// one whose contents are right keeps them, and its inode its change
    /// time. The late flags pass sets the node's.
    ///
    /// Upstream's match on what `add_file` found (here
    /// [`RestorePlan::match_file`] and [`RestorePlan::push_file`]), with
    /// its counts of files unchanged, verified, to modify and to restore.
    fn plan_file<S: IndexedFull>(
        &mut self,
        plan: &mut RestorePlan,
        repo: &Repository<S>,
        path: &Path,
        node: &Node,
        target: &Path,
        exists: bool,
    ) -> RusticResult<()> {
        let (opts, dry_run) = (self.opts, self.dry_run);
        let sets = osattrs::node_sets_flags(node, self.known_bko());
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
            self.dirs.change_parent(target);
        }
        let sparse = super::write_sparse(opts.sparse, node, fresh);
        // BackOtter: a file left as it is, which had no holes at
        // backup, gets its holes allocated (a swap file left with
        // holes by an interrupted restore): only where the snapshot
        // says so (fills_holes). Whether it did (with --dry-run:
        // would), which makes it a file modified, as in BackOtter's
        // restic. One to fill loses the flags that would refuse that
        // first.
        let fill_holes = || {
            if !super::fills_holes(opts, node) {
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
            match plan.match_file(self.dest, node, path.to_path_buf(), repo, opts.verify_existing)? {
                FileMatch::Existing => {
                    // Note that exists = false and Existing can happen if the file is changed between scanning the dir
                    // and calling match_file. So we don't care about exists but trust match_file here.
                    trace!("identical file: {}", path.display());
                    if fill_holes() {
                        self.files.modify += 1;
                    } else {
                        self.files.unchanged += 1;
                    }
                    return Ok(());
                }
                FileMatch::Blobs(matched) => matched,
            };
        if matched.changes() && !dry_run {
            if !fresh && sets {
                osattrs::clear_restricting_flags(target);
            }
            if self.cloned(plan, path, node, target, exists) {
                return Ok(());
            }
        }
        match plan.push_file(matched, sparse) {
            AddFileResult::Verified => {
                trace!("verified identical file: {}", path.display());
                if fill_holes() {
                    self.files.modify += 1;
                } else {
                    self.files.verified += 1;
                }
            }
            // TODO: The differentiation between files to modify and files to create could be done only by add_file
            // Currently, add_file never returns Modify, but always New, so we differentiate based on exists
            AddFileResult::Modify if exists && !fresh => {
                self.files.modify += 1;
                debug!("to modify: {}", path.display());
            }
            AddFileResult::Modify => {
                if exists {
                    self.files.modify += 1;
                } else {
                    self.files.restore += 1;
                }
                debug!("to restore: {}", path.display());
                // BackOtter: flags a file system only takes on an
                // empty file (btrfs's no-copy-on-write) go on before
                // the contents.
                if !dry_run && let Err(err) = osattrs::prepare_file(target, node) {
                    self.prepare_failed(path, &err);
                }
            }
        }
        Ok(())
    }

    /// Under `--exact`, a file restored elsewhere with the same contents
    /// (`--clone-from`) is cloned, not written; a clone that fails leaves
    /// the file as it was, for the restore to write only what differs.
    /// Whether the file `node` at `target` was cloned, and so counted (to
    /// modify if it was there, `exists`, else to restore).
    fn cloned(
        &mut self,
        plan: &mut RestorePlan,
        path: &Path,
        node: &Node,
        target: &Path,
        exists: bool,
    ) -> bool {
        let clone = (self.opts.exact && exact::clone_ok(node))
            .then(|| node.content.as_deref().and_then(|c| self.dest.clone_source(c)))
            .flatten();
        let Some(src) = clone else {
            return false;
        };
        self.dirs.change_parent(target);
        match exact::clone_file(&src, target, node.meta.size) {
            Ok(()) => {
                plan.cloned_size += node.meta.size;
                if exists {
                    self.files.modify += 1;
                } else {
                    self.files.restore += 1;
                }
                debug!("cloned: {}", path.display());
                true
            }
            Err(err @ exact::CloneFailed::TempLeft { .. }) => {
                warn!("restore {}: not cloned from {}: {err}", path.display(), src.display());
                false
            }
            Err(err) => {
                debug!("not cloned from {}: {err}", src.display());
                false
            }
        }
    }

    /// What waits until the walk has seen every name, in this order.
    ///
    /// Under `--exact`, each hard-linked file whose names in the
    /// destination, all seen now, are exactly the snapshot's keeps its
    /// inode; any other gets a name of its own, to be linked to in the
    /// metadata pass.
    ///
    /// What the metadata pass links over that has other names goes now, so
    /// that `--delete` knows them ([`Replaced`]). What can't be removed is
    /// left for the metadata pass, which tries again and reports it.
    ///
    /// `--delete` (`extra`: what it removes, as the walk found it), past
    /// what it can't remove, each an error: a name of a file the restore
    /// replaced another name of loses its restricting flags first, held,
    /// which the file's other names get back (`remove_extra`). What is a
    /// snapshot target under another name stays, and only what is
    /// unexpected below it goes ([`Aliases`]); what is gone already
    /// (replaced as such a target) is no error.
    ///
    /// # Errors
    ///
    /// * If a file could not be matched against what is there.
    pub(super) fn finish<S: IndexedFull>(
        &mut self,
        plan: &mut RestorePlan,
        repo: &Repository<S>,
        extra: Vec<(PathBuf, bool)>,
    ) -> RusticResult<()> {
        for group in std::mem::take(&mut self.groups) {
            if !group.kept() && !self.break_shared(&group.path, &group.node, &group.target) {
                continue;
            }
            self.plan_file(plan, repo, &group.path, &group.node, &group.target, true)?;
        }

        for (target, key) in std::mem::take(&mut self.in_the_way) {
            let Some(canonical) = plan.hardlink_candidates.get(&key) else {
                continue;
            };
            if self.unbroken.contains(canonical)
                || self
                    .dest
                    .path(canonical)
                    .is_ok_and(|c| exact::same_file(&c, &target))
            {
                continue;
            }
            self.dirs.change_parent(&target);
            let removal = remove_held(&target, true, &mut self.replaced, |t, _| {
                std::fs::remove_file(walkdir::short_path(t))
            });
            report_early_removal(&target, removal, |path, err| self.put_back_failed(path, err));
        }

        for (path, is_dir) in extra {
            if let Err(err) =
                remove_unexpected(&path, is_dir, &self.aliases, &mut self.dirs, &self.replaced)
            {
                error!("error removing {}: {err}", path.display());
                self.count();
            }
        }
        Ok(())
    }

    /// Hands `plan` what the rest of the restore goes on with (the
    /// directories not changed yet and the XFS options taken off, the files
    /// whose hard link wasn't broken), and `stats` the errors counted and
    /// the files planned.
    pub(super) fn into_plan(self, plan: &mut RestorePlan, stats: &mut RestoreStats) {
        plan.unbroken = self.unbroken;
        plan.dirs = self.dirs;
        stats.errors += self.errors;
        stats.files.restore += self.files.restore;
        stats.files.unchanged += self.files.unchanged;
        stats.files.verified += self.files.verified;
        stats.files.modify += self.files.modify;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ForkAudit1 G6-03: restricting flags that didn't go back on the
    /// other names of a file removed early are reported whether its name
    /// went or not; a name that stays, its flags back, is left to the
    /// metadata pass.
    #[test]
    fn early_removal_reports_a_failed_put_back() {
        let failed = |msg: &str| Err(std::io::Error::other(msg.to_string()));
        let reported = |removed, put_back| {
            let mut said = None;
            report_early_removal(Path::new("d/b"), (removed, put_back), |path, err| {
                said = Some(format!("{}: {err}", path.display()));
            });
            said
        };
        assert_eq!(reported(Ok(()), Ok(())), None);
        assert_eq!(reported(failed("busy"), Ok(())), None);
        assert_eq!(reported(Ok(()), failed("EIO")), Some("d/b: EIO".to_string()));
        // Both failed: this one was dropped.
        assert_eq!(reported(failed("busy"), failed("EIO")), Some("d/b: EIO".to_string()));
    }

    /// ForkAudit1 G6-04: `--delete` removing a name past restricting flags
    /// says so when the flags didn't go back, with the removal's error too
    /// when the name stayed.
    #[test]
    fn removal_and_put_back_errors_both_reported() {
        use std::io::{Error, ErrorKind};

        let busy = || Err(Error::new(ErrorKind::ResourceBusy, "busy"));
        let eio = || Err(Error::other("EIO"));
        assert!(removed_and_put_back(Ok(()), Ok(())).is_ok());
        let err = removed_and_put_back(busy(), Ok(())).unwrap_err();
        assert_eq!((err.kind(), err.to_string()), (ErrorKind::ResourceBusy, "busy".to_string()));
        let err = removed_and_put_back(Ok(()), eio()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "removed, but restricting flags not put back on its other names: EIO"
        );
        // Both failed: the put-back's error was dropped.
        let err = removed_and_put_back(busy(), eio()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ResourceBusy);
        assert_eq!(err.to_string(), "busy; its restricting flags not set back: EIO");
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
        let mut replaced = Replaced::default();
        let (removed, put_back) =
            remove_held(&deep, false, &mut replaced, |path, replaced| remove_tree(path, replaced));
        fs::set_permissions(walkdir::short_path(&held), Permissions::from_mode(0o755)).unwrap();
        assert!(put_back.is_ok());
        let msg = removed.unwrap_err().to_string();
        assert!(msg.contains(&*held.join("f").to_string_lossy()), "{msg}");
        assert!(!msg.contains(".bko-longpath"), "{msg}");
    }
}
