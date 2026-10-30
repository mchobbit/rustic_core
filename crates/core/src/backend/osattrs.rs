//! BackOtter: metadata some systems keep that rustic otherwise doesn't save:
//! file flags (Linux's `chattr(1)` flags, the BSDs' `chflags(1)` flags,
//! illumos' system attributes), ACLs (FreeBSD's and illumos') and FreeBSD's
//! system extended attributes. They are kept as restic generic attributes
//! ([`generic_attributes`](super::node::generic_attributes)), in the same
//! form as BackOtter's restic.
//!
//! On restore, ACLs go on after the mode, which rewrites an NFSv4 ACL, and
//! file flags last of all, once every file has its contents, hard links and
//! other metadata: an immutable file refuses new hard links, times and
//! permissions, and an immutable directory new entries.
//!
//! Every Unix also marks regular files with holes (`unix.sparse`), for the
//! restore to make them sparse again.

// System calls and ioctls rustic's dependencies don't wrap.
#![allow(unsafe_code)]

use std::{collections::BTreeSet, io, path::Path, sync::Mutex};

use log::warn;

use crate::backend::node::{
    Node, NodeType,
    generic_attributes::{KNOWN, UNIX_SPARSE},
};

mod freebsd_acl;
mod illumos_acl;
mod illumos_sysattr;
#[cfg(unix)]
mod sparse;

#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "freebsd")]
use freebsd as os;
#[cfg(target_os = "illumos")]
mod illumos;
#[cfg(target_os = "illumos")]
use illumos as os;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as os;
#[cfg(target_os = "openbsd")]
mod openbsd;
#[cfg(target_os = "openbsd")]
use openbsd as os;
#[cfg(not(any(
    target_os = "freebsd",
    target_os = "illumos",
    target_os = "linux",
    target_os = "openbsd"
)))]
mod other;
#[cfg(not(any(
    target_os = "freebsd",
    target_os = "illumos",
    target_os = "linux",
    target_os = "openbsd"
)))]
use other as os;

/// Records the file flags and other attributes of the file at `path` in the
/// generic attributes of its `node`. Errors are warned about: the rest of
/// the node is still worth saving.
pub(crate) fn fill(path: &Path, node: &mut Node, m: &std::fs::Metadata) {
    if let Some(name) = os::FILE_FLAGS {
        match os::file_flags(path, &node.node_type, m) {
            Ok(flags) => node.meta.generic_attributes.set_number(name, flags),
            Err(err) => warn!("ignoring file flags of {}: {err}", path.display()),
        }
    }
    if let Err(err) = os::fill_attributes(path, node) {
        warn!("ignoring attributes of {}: {err}", path.display());
    }
    // A regular file, not a block device saved as one.
    #[cfg(unix)]
    if node.is_file() && m.is_file() && sparse::has_holes(path, m) {
        node.meta.generic_attributes.set_true(UNIX_SPARSE);
    }
}

/// Whether the file `node` had holes when it was backed up.
pub(crate) fn is_sparse(node: &Node) -> bool {
    node.meta.generic_attributes.is_true(UNIX_SPARSE)
}

/// The file flags `node` holds for this system, if any.
pub(crate) fn file_flags(node: &Node) -> Option<u32> {
    os::FILE_FLAGS.and_then(|name| node.meta.generic_attributes.number(name))
}

/// Creates an empty file at `path` with those of `node`'s flags that a file
/// system only takes while a file is empty (btrfs's no-copy-on-write), for
/// the restore to write the contents into. Does nothing when there are none,
/// or when `path` exists already.
///
/// # Errors
///
/// * If the file can't be created, or the flags set.
pub(crate) fn prepare_file(path: &Path, node: &Node) -> io::Result<()> {
    match file_flags(node) {
        Some(flags) if flags & os::FLAGS_BEFORE_DATA != 0 => {
            os::prepare_file_for_flags(path, flags & os::FLAGS_BEFORE_DATA)
        }
        _ => Ok(()),
    }
}

/// Gives the new, empty directory at `path` those of `node`'s flags that a
/// file system only takes while a directory is empty (casefolding, on ext4
/// and f2fs), before the restore puts anything in it. Flags the file system
/// doesn't support are left for [`restore_file_flags`] to report.
///
/// # Errors
///
/// * If the flags couldn't be set.
pub(crate) fn prepare_dir(path: &Path, node: &Node) -> io::Result<()> {
    match file_flags(node) {
        Some(flags) if flags & os::FLAGS_BEFORE_ENTRIES != 0 => {
            os::prepare_dir_for_flags(path, flags & os::FLAGS_BEFORE_ENTRIES)
        }
        _ => Ok(()),
    }
}

/// Sets the file flags of the file at `path`, of type `node_type`. Flags the
/// file system doesn't support are left out, and named in the error.
///
/// # Errors
///
/// * If some or all of the flags couldn't be set.
pub(crate) fn restore_file_flags(path: &Path, node_type: &NodeType, flags: u32) -> io::Result<()> {
    os::restore_file_flags(path, node_type, flags)
}

/// Restores the attributes that go along with the extended attributes
/// (FreeBSD's system extended attributes), and warns once about each generic
/// attribute that isn't known at all.
///
/// # Errors
///
/// * If an attribute couldn't be set.
pub(crate) fn restore_attributes(path: &Path, node: &Node) -> io::Result<()> {
    warn_unknown(node);
    os::restore_attributes(path, node)
}

/// Restores the ACLs. This goes after the mode: `chmod(2)` rewrites an
/// NFSv4 ACL, and setting an ACL sets the mode's permission bits.
///
/// # Errors
///
/// * If an ACL couldn't be set.
pub(crate) fn restore_acls(path: &Path, node: &Node) -> io::Result<()> {
    os::restore_acls(path, node)
}

/// Gives a symlink its own permissions back, where the system keeps them
/// (FreeBSD).
///
/// # Errors
///
/// * If the permissions couldn't be set.
pub(crate) fn restore_symlink_mode(path: &Path, node: &Node) -> io::Result<()> {
    os::restore_symlink_mode(path, node)
}

/// The extended attributes of the file at `path`, on illumos: named
/// attribute files (`runat(1)`), which the xattr crate doesn't support.
///
/// # Errors
///
/// * If they can't be read.
#[cfg(target_os = "illumos")]
pub(crate) fn illumos_xattrs(path: &Path) -> io::Result<Vec<crate::backend::node::ExtendedAttribute>> {
    os::xattrs(path)
}

/// Gives the file at `path` exactly the extended attributes `attrs`, on
/// illumos.
///
/// # Errors
///
/// * If they can't be set, or the file system has none.
#[cfg(target_os = "illumos")]
pub(crate) fn set_illumos_xattrs(
    path: &Path,
    attrs: &[crate::backend::node::ExtendedAttribute],
) -> io::Result<()> {
    os::set_xattrs(path, attrs)
}

/// The names of the extended attributes of the file at `path`, as the xattr
/// crate names them. On FreeBSD, those of the user namespace only, listed
/// here: xattr 1.6 names the last attribute of the system namespace as one
/// of the user namespace (which is kept as a generic attribute anyway).
///
/// # Errors
///
/// * If they can't be listed.
#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos")))]
pub(crate) fn xattr_list(path: &Path) -> io::Result<Vec<std::ffi::OsString>> {
    #[cfg(target_os = "freebsd")]
    let names = os::user_extattr_names(path)?
        .into_iter()
        .map(|name| format!("user.{name}").into())
        .collect();
    #[cfg(not(target_os = "freebsd"))]
    let names = xattr::list(path)?.collect();
    Ok(names)
}

/// The name an extended attribute has in a node, from the name the xattr
/// crate lists it by, or `None` for one that isn't kept as an extended
/// attribute. On FreeBSD and NetBSD restic keeps the user namespace only,
/// under bare names, where the xattr crate says `user.NAME` and
/// `system.NAME`; FreeBSD's system namespace is kept as a generic attribute.
#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos")))]
pub(crate) fn xattr_node_name(name: &std::ffi::OsStr) -> Option<String> {
    let name = name.to_string_lossy();
    if cfg!(any(target_os = "freebsd", target_os = "netbsd")) {
        return name.strip_prefix("user.").map(str::to_string);
    }
    Some(name.into_owned())
}

/// The name the xattr crate takes for a node's extended attribute; see
/// [`xattr_node_name`].
#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos")))]
pub(crate) fn xattr_os_name(name: &str) -> String {
    if cfg!(any(target_os = "freebsd", target_os = "netbsd")) {
        format!("user.{name}")
    } else {
        name.to_string()
    }
}

/// Warns once about each generic attribute that neither restic nor BackOtter
/// knows, which a newer version may have written. One of another system is
/// skipped quietly, as restic does.
fn warn_unknown(node: &Node) {
    static WARNED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
    for name in node.meta.generic_attributes.names() {
        if KNOWN.contains(&name) {
            continue;
        }
        let mut warned = WARNED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if warned.insert(name.to_string()) {
            warn!("ignoring unknown generic attribute {name}, maybe from a newer version");
        }
    }
}

/// `path` as a C string.
#[cfg(any(target_os = "freebsd", target_os = "illumos", target_os = "openbsd"))]
fn c_path(path: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(io::Error::from)
}

/// The result of a C call that returns -1 (or less than 0) and sets errno
/// when it fails.
#[cfg(any(target_os = "freebsd", target_os = "illumos", target_os = "openbsd"))]
fn check<T: Copy + Default + PartialOrd>(r: T) -> io::Result<T> {
    if r < T::default() {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

/// An error that names the operation and the file.
#[cfg_attr(
    not(any(
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "linux",
        target_os = "openbsd"
    )),
    allow(dead_code)
)]
fn path_error(op: &str, path: &Path, err: &io::Error) -> io::Error {
    io::Error::new(err.kind(), format!("{op} {}: {err}", path.display()))
}

/// Calls `set` with `want`. If that fails, sets as many of `want`'s bits as
/// `set` accepts, one at a time, and returns an error naming the bits it
/// refused, with `set`'s first error.
#[cfg_attr(
    not(any(
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "linux",
        target_os = "openbsd"
    )),
    allow(dead_code)
)]
fn set_flags_best_effort(
    want: u32,
    mut set: impl FnMut(u32) -> io::Result<()>,
) -> io::Result<()> {
    let Err(first) = set(want) else {
        return Ok(());
    };
    let (mut got, mut refused) = (0, 0);
    for bit in (0..32).map(|i| 1_u32 << i).filter(|bit| want & bit != 0) {
        if set(got | bit).is_ok() {
            got |= bit;
        } else {
            refused |= bit;
        }
    }
    if refused == 0 {
        return Ok(());
    }
    Err(io::Error::new(
        first.kind(),
        format!("file flags {refused:#x} of {want:#x} not set: {first}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_flags_best_effort_sets_what_it_can() {
        // A file system that refuses bit 0x4, as ZFS refuses some FreeBSD flags.
        let mut current = 0;
        let mut set = |f: u32| {
            if f & 0x4 != 0 {
                return Err(io::Error::from(io::ErrorKind::Unsupported));
            }
            current = f;
            Ok(())
        };
        set_flags_best_effort(0x3, &mut set).unwrap();
        let err = set_flags_best_effort(0x15, &mut set).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("0x4 of 0x15"), "{err}");
        assert_eq!(current, 0x11);
    }
}
