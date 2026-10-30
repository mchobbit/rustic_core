//! BackOtter: metadata some systems keep that rustic otherwise doesn't save:
//! file flags (Linux's `chattr(1)` flags, the BSDs' `chflags(1)` flags,
//! illumos' system attributes), ACLs (FreeBSD's and illumos'), FreeBSD's
//! system extended attributes and Haiku's typed file attributes. They are
//! kept as restic generic attributes
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

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::File,
    io,
    path::{Path, PathBuf},
    sync::Mutex,
};

use log::{debug, warn};

use crate::backend::node::{
    ExtendedAttribute, Node, NodeType,
    generic_attributes::{KNOWN, UNIX_SPARSE},
};

mod freebsd_acl;
mod haiku_attrs;
mod illumos_acl;
mod illumos_sysattr;
#[cfg(unix)]
mod sparse;

#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "freebsd")]
use freebsd as os;
#[cfg(target_os = "haiku")]
mod haiku;
#[cfg(target_os = "haiku")]
use haiku as os;
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
    target_os = "haiku",
    target_os = "illumos",
    target_os = "linux",
    target_os = "openbsd"
)))]
mod other;
#[cfg(not(any(
    target_os = "freebsd",
    target_os = "haiku",
    target_os = "illumos",
    target_os = "linux",
    target_os = "openbsd"
)))]
use other as os;

/// Records the file flags and other attributes of the file at `path`, with
/// metadata `m` (its lstat), in the generic attributes of its `node`. Errors
/// are warned about: the rest of the node is still worth saving.
pub(crate) fn fill(path: &Path, node: &mut Node, m: &std::fs::Metadata) {
    // On Linux, the one open of the file for its flags, project ID and holes.
    let f = os::open_for_attrs(path, &node.node_type, m);
    if let Some(name) = os::FILE_FLAGS {
        match os::file_flags(path, &node.node_type, m, f.as_ref()) {
            Ok(flags) => node.meta.generic_attributes.set_number(name, flags),
            Err(err) => warn!("ignoring file flags of {}: {err}", path.display()),
        }
    }
    if let Err(err) = os::fill_attributes(path, node, f.as_ref()) {
        warn!("ignoring attributes of {}: {err}", path.display());
    }
    // A regular file, not a block device saved as one.
    #[cfg(unix)]
    if node.is_file() && m.is_file() && sparse::has_holes(path, m, f.as_ref()) {
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

/// Gives the empty directory at `path` (one the restore created, or found
/// empty) exactly those of `node`'s flags that a file system only takes
/// while a directory is empty (casefolding, on ext4 and f2fs), before the
/// restore puts anything in it: it sets them where `node` has them, and
/// clears them where it hasn't, so that a directory doesn't inherit
/// casefolding from its parent when it had none. Flags the file system
/// doesn't support are left for [`restore_file_flags`] to report.
///
/// # Errors
///
/// * If the flags couldn't be set.
pub(crate) fn prepare_dir(path: &Path, node: &Node) -> io::Result<()> {
    if os::FLAGS_BEFORE_ENTRIES == 0 {
        return Ok(());
    }
    os::prepare_dir_for_flags(path, file_flags(node).unwrap_or(0) & os::FLAGS_BEFORE_ENTRIES)
}

/// The extended attributes of `node` that [`restore_file_flags`] needs:
/// btrfs's `btrfs.compression` on Linux, which setting the flags rewrites.
pub(crate) fn flags_xattrs(node: &Node) -> Vec<ExtendedAttribute> {
    node.meta
        .extended_attributes
        .iter()
        .filter(|attr| os::FLAGS_XATTRS.contains(&attr.name.as_str()))
        .cloned()
        .collect()
}

/// Sets the file flags of the file at `path`, of type `node_type`, which has
/// the extended attributes `xattrs` ([`flags_xattrs`]). Flags the file
/// system doesn't support are left out, and named in the error.
///
/// # Errors
///
/// * If some or all of the flags couldn't be set: an [`Unsupported`] error
///   if the file system has none of those it refused.
pub(crate) fn restore_file_flags(
    path: &Path,
    node_type: &NodeType,
    flags: u32,
    xattrs: &[ExtendedAttribute],
) -> io::Result<()> {
    os::restore_file_flags(path, node_type, flags, xattrs)
}

/// Allocates the first `len` bytes of the file `f`, holes included, where the
/// system can (Linux, macOS), for a file the restore doesn't restore sparse.
/// Errors only go to the debug log: the restore writes every byte anyway.
pub(crate) fn preallocate(f: &File, len: u64) {
    if len == 0 {
        return;
    }
    if let Err(err) = os_preallocate(f, len) {
        debug!("not preallocated: {err}");
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn os_preallocate(f: &File, len: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let len = libc::off_t::try_from(len).map_err(io::Error::other)?;
    loop {
        // SAFETY: f is an open file. Mode 0 allocates holes and unwritten
        // space, and leaves data as it is.
        if unsafe { libc::fallocate(f.as_raw_fd(), 0, 0, len) } == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(target_vendor = "apple")]
fn os_preallocate(f: &File, len: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    // As restic does: contiguous first, then in any form, but all of it.
    let mut store = libc::fstore_t {
        fst_flags: libc::F_ALLOCATECONTIG | libc::F_ALLOCATEALL,
        fst_posmode: libc::F_PEOFPOSMODE,
        fst_offset: 0,
        fst_length: libc::off_t::try_from(len).map_err(io::Error::other)?,
        fst_bytesalloc: 0,
    };
    // SAFETY: F_PREALLOCATE reads and writes a fstore_t.
    if unsafe { libc::fcntl(f.as_raw_fd(), libc::F_PREALLOCATE, &raw mut store) } == 0 {
        return Ok(());
    }
    store.fst_flags = libc::F_ALLOCATEALL;
    // SAFETY: as above.
    if unsafe { libc::fcntl(f.as_raw_fd(), libc::F_PREALLOCATE, &raw mut store) } == 0 {
        return Ok(());
    }
    Err(io::Error::last_os_error())
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn os_preallocate(_f: &File, _len: u64) -> io::Result<()> {
    Ok(())
}

/// Allocates the holes of the regular file at `path`, of `len` bytes, which
/// the restore leaves as it is and doesn't restore sparse: a swap file left
/// with holes by an interrupted restore. Only where the system can fill
/// them (Linux, macOS); errors only go to the debug log.
pub(crate) fn fill_holes(path: &Path, len: u64) {
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    {
        use std::{
            fs::OpenOptions,
            os::unix::fs::{MetadataExt, OpenOptionsExt},
        };

        let f = match OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(path)
        {
            Ok(f) => f,
            Err(err) => {
                debug!("holes of {} not filled: {err}", path.display());
                return;
            }
        };
        match f.metadata() {
            Ok(m) if m.is_file() && m.blocks().saturating_mul(512) < len => {
                debug!("filling the holes of {}", path.display());
                preallocate(&f, len);
            }
            Ok(_) => {}
            Err(err) => debug!("holes of {} not filled: {err}", path.display()),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    {
        _ = (path, len);
    }
}

/// BackOtter: an error saying that the file system doesn't support a kind
/// of metadata (`attr`, and of file flags `bits`), rather than that setting
/// it failed. The restore warns about each kind once
/// ([`warn_restore`]).
#[derive(Debug)]
pub(crate) struct Unsupported {
    /// The generic attribute.
    pub(crate) attr: &'static str,
    /// The file flags refused, or 0.
    pub(crate) bits: u32,
    /// The system's error.
    pub(crate) source: io::Error,
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} not supported by the file system: {}", self.kind(), self.source)
    }
}

impl std::error::Error for Unsupported {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl Unsupported {
    /// An [`io::Error`] for this.
    #[cfg_attr(
        not(any(
            target_os = "freebsd",
            target_os = "illumos",
            target_os = "linux",
            target_os = "openbsd"
        )),
        allow(dead_code)
    )]
    fn error(attr: &'static str, bits: u32, source: io::Error) -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, Self { attr, bits, source })
    }

    /// What isn't supported: `linux.inode_flags 0x10`, `linux.project_id`.
    fn kind(&self) -> String {
        if self.bits == 0 {
            self.attr.to_string()
        } else {
            format!("{} {:#x}", self.attr, self.bits)
        }
    }
}

/// The kinds of unsupported metadata the restore has warned about, with the
/// first file of each and the number of files.
static UNSUPPORTED: Mutex<BTreeMap<String, (PathBuf, u64)>> = Mutex::new(BTreeMap::new());

/// Warns about an error restoring the metadata of `path`: an [`Unsupported`]
/// one once per kind, with the first file, and [`report_unsupported`] counts
/// the files; any other each time.
pub(crate) fn warn_restore(path: &Path, err: &io::Error) {
    let Some(unsupported) = err.get_ref().and_then(|e| e.downcast_ref::<Unsupported>()) else {
        warn!("restore {}: {err}", path.display());
        return;
    };
    let mut seen = UNSUPPORTED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_, n) = seen
        .entry(unsupported.kind())
        .or_insert_with(|| (path.to_path_buf(), 0));
    *n += 1;
    let first = *n == 1;
    drop(seen);
    if first {
        warn!("restore {}: {unsupported}", path.display());
    }
}

/// Warns, once a restore is done, about the number of files with each kind
/// of unsupported metadata [`warn_restore`] saw more than once, and starts
/// counting again.
pub(crate) fn report_unsupported() {
    let seen = std::mem::take(
        &mut *UNSUPPORTED.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    for (kind, (first, n)) in seen {
        if n > 1 {
            warn!(
                "{kind} not supported by the file system: {n} files, the first {}",
                first.display()
            );
        }
    }
}

/// Restores the attributes that go along with the extended attributes
/// (FreeBSD's system extended attributes, Haiku's typed attributes), and
/// warns once about each generic attribute that isn't known at all.
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

/// The extended attributes of the file at `path`, where the xattr crate
/// doesn't support them: on illumos, named attribute files (`runat(1)`); on
/// Haiku, the file's attributes of type `B_XATTR_TYPE`.
///
/// # Errors
///
/// * If they can't be read.
#[cfg(any(target_os = "illumos", target_os = "haiku"))]
pub(crate) fn native_xattrs(path: &Path) -> io::Result<Vec<ExtendedAttribute>> {
    os::xattrs(path)
}

/// Gives the file at `path` exactly the extended attributes `attrs`, on
/// illumos and Haiku.
///
/// # Errors
///
/// * If they can't be set, or the file system has none.
#[cfg(any(target_os = "illumos", target_os = "haiku"))]
pub(crate) fn set_native_xattrs(
    path: &Path,
    attrs: &[ExtendedAttribute],
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
#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos", target_os = "haiku")))]
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
#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos", target_os = "haiku")))]
pub(crate) fn xattr_node_name(name: &std::ffi::OsStr) -> Option<String> {
    let name = name.to_string_lossy();
    if cfg!(any(target_os = "freebsd", target_os = "netbsd")) {
        return name.strip_prefix("user.").map(str::to_string);
    }
    Some(name.into_owned())
}

/// The name the xattr crate takes for a node's extended attribute; see
/// [`xattr_node_name`].
#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos", target_os = "haiku")))]
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
#[cfg(any(
    target_os = "freebsd",
    target_os = "haiku",
    target_os = "illumos",
    target_os = "openbsd"
))]
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
        target_os = "haiku",
        target_os = "illumos",
        target_os = "linux",
        target_os = "openbsd"
    )),
    allow(dead_code)
)]
fn path_error(op: &str, path: &Path, err: &io::Error) -> io::Error {
    io::Error::new(err.kind(), format!("{op} {}: {err}", path.display()))
}

/// Calls `set` with `want`, the flags `attr` of the file at `path`, which
/// `op` sets. If that fails, sets as many of `want`'s bits as `set` accepts,
/// one at a time, and returns an error naming the bits it refused, with
/// `set`'s first error: an [`Unsupported`] one if every refusal said the
/// file system doesn't have those flags (`EINVAL`, `ENOTSUP`, `EOPNOTSUPP`,
/// `ENOTTY`), or else with the first error that didn't.
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
    attr: &'static str,
    path: &Path,
    op: &str,
    want: u32,
    mut set: impl FnMut(u32) -> io::Result<()>,
) -> io::Result<()> {
    let Err(first) = set(want) else {
        return Ok(());
    };
    let (mut got, mut refused) = (0, 0);
    let mut failed = (!unsupported(&first)).then_some(first);
    let mut unsupported_err = None;
    for bit in (0..32).map(|i| 1_u32 << i).filter(|bit| want & bit != 0) {
        match set(got | bit) {
            Ok(()) => got |= bit,
            Err(err) => {
                refused |= bit;
                if !unsupported(&err) {
                    _ = failed.get_or_insert(err);
                } else if unsupported_err.is_none() {
                    unsupported_err = Some(err);
                }
            }
        }
    }
    if refused == 0 {
        return Ok(());
    }
    match (failed, unsupported_err) {
        (Some(err), _) => Err(path_error(
            op,
            path,
            &io::Error::new(
                err.kind(),
                format!("file flags {refused:#x} of {want:#x} not set: {err}"),
            ),
        )),
        (None, Some(err)) => Err(Unsupported::error(attr, refused, err)),
        (None, None) => Err(path_error(
            op,
            path,
            &io::Error::other(format!("file flags {refused:#x} of {want:#x} not set")),
        )),
    }
}

/// Errors that mean the file system doesn't have a kind of metadata (file
/// flags, a project ID), rather than that setting it failed.
#[cfg_attr(
    not(any(
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "linux",
        target_os = "openbsd"
    )),
    allow(dead_code)
)]
fn unsupported(err: &io::Error) -> bool {
    #[cfg(unix)]
    {
        err.raw_os_error().is_some_and(|code| {
            [libc::EINVAL, libc::ENOTSUP, libc::EOPNOTSUPP, libc::ENOTTY].contains(&code)
        })
    }
    #[cfg(not(unix))]
    {
        err.kind() == io::ErrorKind::Unsupported
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn set_flags_best_effort_sets_what_it_can() {
        let path = Path::new("f");
        // A file system that refuses bit 0x4, as ZFS refuses some FreeBSD
        // flags, and bit 0x8 to all but root.
        let current = std::cell::Cell::new(0);
        let mut set = |f: u32| {
            if f & 0x4 != 0 {
                return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
            }
            if f & 0x8 != 0 {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            current.set(f);
            Ok(())
        };
        set_flags_best_effort("x.flags", path, "set", 0x3, &mut set).unwrap();

        // Unsupported: a warning once.
        let err = set_flags_best_effort("x.flags", path, "set", 0x15, &mut set).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        let unsupported = err.get_ref().unwrap().downcast_ref::<Unsupported>().unwrap();
        assert_eq!((unsupported.attr, unsupported.bits), ("x.flags", 0x4));
        assert_eq!(current.get(), 0x11);

        // Unsupported and not permitted: an error.
        let err = set_flags_best_effort("x.flags", path, "set", 0x1d, &mut set).unwrap_err();
        assert!(err.get_ref().unwrap().downcast_ref::<Unsupported>().is_none());
        assert!(err.to_string().contains("0xc of 0x1d"), "{err}");
        assert_eq!(current.get(), 0x11);
    }
}
