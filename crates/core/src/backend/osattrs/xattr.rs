//! BackOtter: extended attributes, around the xattr crate: where it doesn't
//! support them (illumos, Haiku), where it misnames or misreads them
//! (FreeBSD's and NetBSD's namespaces, large values on Linux), the names a
//! node keeps them under, and the ones a restore leaves alone (the SELinux
//! label, bcachefs's views of a file's options).

use std::{
    io,
    path::{Path, PathBuf},
    sync::Mutex,
};

use log::warn;

use super::{XattrErrors, os, same_error};
use crate::backend::node::ExtendedAttribute;

/// BackOtter: the extended attributes of a file a backup read
/// (`attrs`), and those it couldn't read (`unreadable`, each name with its
/// error), which it leaves out with a warning each, keeping the others.
#[derive(Debug, Default)]
pub(crate) struct XattrsRead {
    /// The attributes read.
    pub(crate) attrs: Vec<ExtendedAttribute>,
    /// The names of those that couldn't be read, with the errors.
    pub(crate) unreadable: Vec<(String, io::Error)>,
}

/// BackOtter: the largest extended attribute a repository can hold, where
/// one is a file of any size: an illumos named attribute (`runat(1)`, an
/// SMB alternate data stream) and a BFS attribute in an inode of its own.
/// A node holds its attributes' values inline, base64-encoded in its
/// tree's JSON, and a tree is one blob, whose length a pack's header and
/// the index keep in 32 bits: this is the most bytes whose base64 text is
/// no longer than that, 3 GiB less 3. A tree with a larger value can't be
/// saved by either tool (`encrypt_data`'s "Failed to convert data length",
/// restic's "blob is larger than 4GB"), and the backup failed on it.
///
/// It is no limit for memory's sake: every attribute a repository can hold
/// is kept, as it was before 0.14.0+backotter.2, whose first limit of 16
/// MiB left out attributes that had restored until then (the review of
/// ForkAudit1 G5-07's fix). One over it is left out with a warning,
/// counted as any attribute that couldn't be read, and the file's others
/// are kept; so is one no memory can be had for ([`xattr_buffer`]). Linux's
/// are 64 KiB at most, and the BSDs' are read whole.
pub(crate) const NATIVE_XATTR_MAX: u64 = (u32::MAX as u64 / 4) * 3;

/// BackOtter: the error for an extended attribute of `size` bytes, over
/// `max` ([`NATIVE_XATTR_MAX`]).
#[cfg_attr(
    not(any(test, target_os = "illumos", target_os = "haiku")),
    allow(dead_code)
)]
pub(crate) fn xattr_too_large(size: u64, max: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::FileTooLarge,
        format!("too large to keep ({size} bytes, over {max})"),
    )
}

/// BackOtter: an empty buffer with room for `size` bytes of an extended
/// attribute's value, taken at once and for its size alone, so that a
/// value read into it is in memory once.
///
/// # Errors
///
/// * If the memory can't be had (`ErrorKind::OutOfMemory`): an attribute
///   of up to [`NATIVE_XATTR_MAX`] bytes on a small machine, or a size a
///   damaged file system made up. The backup leaves that attribute out as
///   one it couldn't read, where an allocation that fails ends the process.
#[cfg_attr(
    not(any(test, target_os = "illumos", target_os = "haiku")),
    allow(dead_code)
)]
pub(crate) fn xattr_buffer(size: u64) -> io::Result<Vec<u8>> {
    let mut value = Vec::new();
    usize::try_from(size)
        .ok()
        .and_then(|size| value.try_reserve_exact(size).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!("no memory for its {size} bytes"),
            )
        })?;
    Ok(value)
}

impl From<Vec<ExtendedAttribute>> for XattrsRead {
    fn from(attrs: Vec<ExtendedAttribute>) -> Self {
        Self {
            attrs,
            unreadable: Vec::new(),
        }
    }
}

/// The extended attributes of the file at `path`, where the xattr crate
/// doesn't support them: on illumos, named attribute files (`runat(1)`); on
/// Haiku, the file's attributes of type `B_XATTR_TYPE`. Elsewhere they go
/// through the xattr crate.
///
/// # Errors
///
/// * If they can't be listed, or this is neither illumos nor Haiku.
#[cfg_attr(not(any(target_os = "illumos", target_os = "haiku")), allow(dead_code))]
pub(crate) fn native_xattrs(path: &Path) -> io::Result<XattrsRead> {
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    // BackOtter: on illumos and Haiku, one whose value can't be read is
    // left out alone (in `unreadable`), as BackOtter's restic does.
    #[cfg(any(target_os = "illumos", target_os = "haiku"))]
    return os::xattrs_read(path);
    #[cfg(not(any(target_os = "illumos", target_os = "haiku")))]
    os::xattrs(path).map(XattrsRead::from)
}

/// Gives the file at `path` exactly the extended attributes `attrs`, on
/// illumos and Haiku. One that can't be set or removed doesn't keep the
/// others from being set or removed.
///
/// # Errors
///
/// * Each attribute that couldn't be set or removed; or that the file system
///   has none, or this is neither illumos nor Haiku.
#[cfg_attr(not(any(target_os = "illumos", target_os = "haiku")), allow(dead_code))]
pub(crate) fn set_native_xattrs(
    path: &Path,
    attrs: &[ExtendedAttribute],
) -> Result<(), XattrErrors> {
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    os::set_xattrs(path, attrs)
}

/// The names of the extended attributes of the file at `path`, as the xattr
/// crate names them. On FreeBSD and NetBSD, those of the user namespace
/// only, listed here: the xattr crate (1.6, and 1.7 the same) names the
/// last attribute of the system namespace as one of the user namespace
/// (which is kept as a generic attribute anyway).
///
/// # Errors
///
/// * If they can't be listed.
#[cfg(not(any(
    windows,
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "haiku"
)))]
pub(crate) fn xattr_list(path: &Path) -> io::Result<Vec<std::ffi::OsString>> {
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    let names = super::freebsd_netbsd::user_extattr_names(path)?;
    #[cfg(target_os = "linux")]
    let names = os::xattr_list(path)?;
    #[cfg(not(any(target_os = "freebsd", target_os = "netbsd", target_os = "linux")))]
    let names = xattr::list(path)?.collect();
    Ok(names)
}

/// The value of the extended attribute `name` (as the xattr crate names it)
/// of the file at `path`, not following a symlink; `None` where it has
/// none. On Linux, read whole here: the xattr crate before 1.7 read a
/// value over 4 KiB as empty (`os::xattr_get`).
///
/// # Errors
///
/// * If it can't be read.
#[cfg(not(any(
    windows,
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "haiku"
)))]
pub(crate) fn xattr_get(path: &Path, name: &std::ffi::OsStr) -> io::Result<Option<Vec<u8>>> {
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    #[cfg(target_os = "linux")]
    return os::xattr_get(path, name);
    #[cfg(not(target_os = "linux"))]
    xattr::get(path, name)
}

/// The name an extended attribute has in a node, from the name the xattr
/// crate lists it by, or `None` for one that isn't kept as an extended
/// attribute. On FreeBSD and NetBSD restic keeps the user namespace only,
/// under bare names, where the xattr crate says `user.NAME` and
/// `system.NAME`; their system namespace is kept as a generic attribute. On
/// Linux, bcachefs' `bcachefs_effective.*` aren't kept: they show the
/// options a file has, its own (`bcachefs.*`, kept) or inherited, and its
/// project ID, and setting one does nothing; nor is `bcachefs.project`, a
/// project ID the file was given (bcachefs 1.39 lists it, Linux 6.12's
/// doesn't), which `linux.project_id` carries and bcachefs won't have set to
/// anything but 0 (`EINVAL`). A restore neither sets nor removes them,
/// whatever a snapshot holds, as in BackOtter's restic.
#[cfg(not(any(
    windows,
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "haiku"
)))]
pub(crate) fn xattr_node_name(name: &std::ffi::OsStr) -> Option<String> {
    let name = name.to_string_lossy();
    if cfg!(any(target_os = "freebsd", target_os = "netbsd")) {
        return name.strip_prefix("user.").map(str::to_string);
    }
    if cfg!(target_os = "linux")
        && (name.starts_with(BCACHEFS_EFFECTIVE) || name == BCACHEFS_OWN_PROJECT)
    {
        return None;
    }
    Some(name.into_owned())
}

/// The extended attribute that holds a file's SELinux label.
pub(crate) const SELINUX_LABEL: &str = "security.selinux";

/// Whether a restore leaves the extended attribute `name` (a node's name for
/// it) alone on a file whose node hasn't got it, rather than removing it:
/// the SELinux label, which the system gives every new file and SELinux
/// never lets anyone remove (`EACCES`, even as root). A node without one
/// (from a system without SELinux, a btrfs subvolume's root, a directory
/// above the backed-up path in an older rustic-bko snapshot) keeps the label
/// the restored file got, as in BackOtter's restic. A node with one sets it.
#[cfg_attr(
    any(
        windows,
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "haiku"
    ),
    allow(dead_code)
)]
pub(crate) fn xattr_never_removed(name: &str) -> bool {
    name == SELINUX_LABEL
}

/// BackOtter: the SELinux labels `restore --exact` was refused to remove
/// with `EACCES` ([`label_refused`]): the first file, its error, and how
/// many in all.
static LABELS_KEPT: Mutex<Option<(PathBuf, io::Error, u64)>> = Mutex::new(None);

/// BackOtter: whether `err`, removing the SELinux label `name` of `path`
/// (`restore --exact`, where the node has none), is the refusal of a host
/// where SELinux is active, enforcing or permissive (`EACCES`, root too),
/// which would come for every file of such a snapshot: then it is noted
/// for [`report_labels_kept`], one error for the whole restore, and not the
/// file's. Any other failure (`EPERM` too) is the file's. As in BackOtter's
/// restic (`removeLabel`).
#[cfg_attr(
    any(
        windows,
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "haiku"
    ),
    allow(dead_code)
)]
pub(crate) fn label_refused(name: &str, path: &Path, err: &io::Error) -> bool {
    #[cfg(unix)]
    let refused = name == SELINUX_LABEL && err.raw_os_error() == Some(libc::EACCES);
    #[cfg(not(unix))]
    let refused = false;
    if refused {
        let mut kept = LABELS_KEPT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match kept.as_mut() {
            Some((_, _, n)) => *n += 1,
            None => *kept = Some((path.to_path_buf(), same_error(err), 1)),
        }
    }
    refused
}

/// BackOtter: reports the SELinux labels [`label_refused`] noted, if any, as
/// one warning naming the first file and how many there were, and whether
/// there were: one error for the whole restore, as root or not.
pub(crate) fn report_labels_kept() -> bool {
    let kept = LABELS_KEPT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let Some((first, err, n)) = kept else {
        return false;
    };
    warn!(
        "SELinux labels the snapshot hasn't got not removed: {n} files in all, the first {}: {err}",
        first.display()
    );
    true
}

/// The prefix of bcachefs' extended attributes that show a file's options as
/// they apply to it, whether its own or inherited ([`xattr_node_name`]).
#[cfg(not(any(
    windows,
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "haiku"
)))]
pub(crate) const BCACHEFS_EFFECTIVE: &str = "bcachefs_effective.";

/// The extended attribute in which bcachefs shows a project ID a file was
/// given, not inherited ([`xattr_node_name`]).
#[cfg(not(any(
    windows,
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "haiku"
)))]
pub(crate) const BCACHEFS_OWN_PROJECT: &str = "bcachefs.project";

/// bcachefs' casefolding option of a directory, which bcachefs sets, clears
/// and even sets again to the value it has only while the directory is
/// empty (`ENOTEMPTY`). A restore gives it to each directory it creates, or
/// finds empty, before anything goes in, and later leaves it alone where it
/// is right, as every extended attribute.
#[cfg(not(any(
    windows,
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "haiku"
)))]
pub(crate) const BCACHEFS_CASEFOLD: &str = "bcachefs.casefold";

/// Whether `err`, from setting or removing the extended attribute `name` (a
/// node's name for it), is bcachefs refusing to change the casefolding of a
/// directory with entries: a warning, "casefolding (bcachefs.casefold) not
/// restored on PATH: directory not empty", as for chattr's F, and not one
/// of the file's errors, as in BackOtter's restic.
#[cfg(not(any(
    windows,
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "haiku"
)))]
pub(crate) fn casefold_not_empty(name: &str, err: &io::Error) -> bool {
    name == BCACHEFS_CASEFOLD && err.kind() == io::ErrorKind::DirectoryNotEmpty
}

/// The name the xattr crate takes for a node's extended attribute; see
/// [`xattr_node_name`].
#[cfg(not(any(
    windows,
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "haiku"
)))]
pub(crate) fn xattr_os_name(name: &str) -> String {
    if cfg!(any(target_os = "freebsd", target_os = "netbsd")) {
        format!("user.{name}")
    } else {
        name.to_string()
    }
}
