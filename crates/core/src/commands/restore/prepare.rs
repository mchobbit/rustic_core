//! BackOtter: what a restore keeps of the destination while it plans and
//! prepares it (`collect_and_prepare`), and how it removes what is in its
//! way: the directories it hasn't changed yet and the XFS options it took
//! off them, the hard-linked files it replaced a name of, the snapshot's
//! entries found under another name, and the removals past restricting
//! flags.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError, RwLock, RwLockReadGuard},
};

use log::{debug, warn};
use walkdir::WalkDir;

use super::exact;
use crate::backend::{
    node::{Node, NodeType, generic_attributes::XfsOptions},
    osattrs,
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
pub(super) struct LinkGroup {
    /// The first name, in the snapshot.
    pub(super) path: PathBuf,
    /// Its node.
    pub(super) node: Node,
    /// The first name, in the destination.
    pub(super) target: PathBuf,
    /// The targets of the snapshot's other names for it.
    pub(super) others: Vec<PathBuf>,
}

impl LinkGroup {
    /// Whether the names the destination has for the file are exactly the
    /// snapshot's, as one file: the file at the first name has a link for
    /// each of them and no more (none outside the destination), and every
    /// other name is that file. Then nothing of the restore can reach a
    /// name the snapshot hasn't got: its contents, if they differ, are
    /// written into it, as into one file of its own.
    pub(super) fn kept(&self) -> bool {
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
pub(super) fn file_id(path: &Path) -> Option<((u64, u64), bool)> {
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
pub(super) fn report_early_removal(
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
pub(super) struct Aliases(BTreeMap<String, PathBuf>);

impl Aliases {
    fn key(path: &Path) -> String {
        path.to_string_lossy().to_lowercase()
    }

    pub(super) fn add(&mut self, target: &Path) {
        _ = self.0.insert(Self::key(target), target.to_path_buf());
    }

    /// Whether the directory of `target` is one of them.
    pub(super) fn below_alias(&self, target: &Path) -> bool {
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
pub(super) fn no_symlink_below(dest: &Path, rel: &Path) -> bool {
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
pub(super) fn remove_unexpected(
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
pub(super) fn remove_tree(dir: &Path, replaced: &RefCell<Replaced>) -> std::io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::local_destination::LocalDestination;

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
