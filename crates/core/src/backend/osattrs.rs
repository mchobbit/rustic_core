//! BackOtter: metadata some systems keep that rustic otherwise doesn't save:
//! file flags (Linux's `chattr(1)` flags, the BSDs' `chflags(1)` flags,
//! illumos' system attributes), ACLs (FreeBSD's, NetBSD's and illumos') and
//! FreeBSD's and NetBSD's system extended attributes. They are kept as
//! restic generic attributes
//! ([`generic_attributes`](super::node::generic_attributes)), in the same
//! form as BackOtter's restic.
//!
//! On restore, ACLs go on after the mode, which rewrites an NFSv4 ACL, and
//! file flags last of all, once every file has its contents, hard links and
//! other metadata: an immutable file refuses new hard links, times and
//! permissions, and an immutable directory new entries. On Linux, ZFS's DOS
//! flags go on just before the file flags: a read-only file refuses writes,
//! and every write sets the archive flag again.
//!
//! Every Unix also marks regular files with holes (`unix.sparse`), for the
//! backup to read them by their data extents and the restore to make them
//! sparse again, and FreeBSD, NetBSD and illumos keep birth times
//! (`unix.birthtime`), which the restore sets just before the atime and
//! mtime.
//!
//! illumos also keeps the SIDs of owners and ACL entries that are SIDs, the
//! owner, mode, times and ACL of each extended attribute, and ZFS project
//! IDs.

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

use jiff::Timestamp;
use log::{debug, warn};

use crate::backend::node::{
    ExtendedAttribute, Node, NodeType,
    generic_attributes::{
        ILLUMOS_SYSTEM_ATTRIBUTES, ILLUMOS_UNREAD_SIZE, KNOWN, UNIX_BIRTHTIME, UNIX_SPARSE,
    },
};

mod bsd_flags;
mod freebsd_acl;
#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
mod freebsd_netbsd;
mod illumos_acl;
#[cfg(target_os = "illumos")]
mod illumos_idmap;
mod illumos_project;
mod illumos_sysattr;
mod illumos_xattrmeta;
#[cfg(unix)]
mod sparse;

#[cfg(target_os = "dragonfly")]
mod dragonfly;
#[cfg(target_os = "dragonfly")]
use dragonfly as os;
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
#[cfg(target_os = "netbsd")]
mod netbsd;
#[cfg(target_os = "netbsd")]
use netbsd as os;
#[cfg(target_os = "openbsd")]
mod openbsd;
#[cfg(target_os = "openbsd")]
use openbsd as os;
#[cfg(not(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "illumos",
    target_os = "linux",
    target_os = "netbsd",
    target_os = "openbsd"
)))]
mod other;
#[cfg(not(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "illumos",
    target_os = "linux",
    target_os = "netbsd",
    target_os = "openbsd"
)))]
use other as os;

/// Records the file flags and other attributes of the file at `path`, with
/// metadata `m` (its lstat), in the generic attributes of its `node`. Errors
/// are warned about: the rest of the node is still worth saving.
///
/// `xattrs` says whether the backup keeps extended attributes; on illumos
/// this records their metadata then, which must come before their values
/// are read (illumos has no `O_NOATIME`, and a read moves an attribute's
/// atime).
pub(crate) fn fill(path: &Path, node: &mut Node, m: &std::fs::Metadata, xattrs: bool) {
    // On Linux, the one open of the file for its flags, project ID and holes;
    // on illumos, of its system attribute view.
    let f = os::open_for_attrs(path, &node.node_type, m);
    if let Some(name) = os::FILE_FLAGS {
        // The system's module says when there are none worth an attribute:
        // a 0 can say something (a cleared archive flag on ZFS).
        match os::file_flags(path, &node.node_type, m, f.as_ref()) {
            Ok(Some(flags)) => node.meta.generic_attributes.set_u64(name, flags.into()),
            Ok(None) => {}
            Err(err) => warn!("ignoring file flags of {}: {err}", path.display()),
        }
    }
    if let Err(err) = os::fill_attributes(path, node, f.as_ref()) {
        warn!("ignoring attributes of {}: {err}", path.display());
    }
    if xattrs {
        os::fill_xattr_meta(path, node);
    }
    // The birth time of every type of file, where the lstat has one (on
    // illumos it is in the system attribute view, which `fill_attributes`
    // reads). Not on Linux, which can't set one back, nor OpenBSD or
    // DragonFly, which keep none.
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    if let Some(birth) = m.created().ok().and_then(|t| Timestamp::try_from(t).ok()) {
        node.meta.generic_attributes.set_timestamp(UNIX_BIRTHTIME, birth);
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

/// The reader the backup gives the chunker for the regular file `f`, whose
/// node is `sparse` (marked `unix.sparse`): where the backup probes for holes
/// with `SEEK_HOLE` (Linux and Android, FreeBSD, macOS, illumos), a file
/// with holes is read by its data extents, and its holes given as zeros
/// without being read. The bytes are those plain reading gives, so the
/// chunks, blobs and trees are the same.
#[cfg(unix)]
pub(crate) fn backup_reader(f: File, sparse: bool) -> Box<dyn io::Read + Send> {
    sparse::backup_reader(f, sparse)
}

/// The reader the backup gives the chunker for the file `f`: `f` itself.
#[cfg(not(unix))]
pub(crate) fn backup_reader(f: File, _sparse: bool) -> Box<dyn io::Read + Send> {
    Box::new(f)
}

/// The size of the blocks a file restored sparse, `f`, has its holes in:
/// its file system's block size (else its `st_blksize`), at least 4096
/// bytes, as BackOtter's restic.
#[cfg(unix)]
pub(crate) fn hole_block_size(f: &File) -> u64 {
    sparse::hole_block_size(f)
}

/// The size of the blocks a file restored sparse, `f`, has its holes in:
/// 4096 bytes.
#[cfg(not(unix))]
pub(crate) const fn hole_block_size(_f: &File) -> u64 {
    4096
}

/// The file flags `node` holds for this system, if any.
pub(crate) fn file_flags(node: &Node) -> Option<u32> {
    os::FILE_FLAGS.and_then(|name| node.meta.generic_attributes.number(name))
}

/// The ZFS DOS flags `node` holds, on Linux, if any.
pub(crate) fn zfs_dos_flags(node: &Node) -> Option<u64> {
    os::ZFS_DOS_FLAGS.and_then(|name| node.meta.generic_attributes.number_u64(name))
}

/// Whether `node`, a regular file, has illumos' `av_quarantined` among the
/// system attributes [`fill`] recorded: no one may open such a file for
/// reading, root included (`EACCES`), nor its extended attributes; its
/// metadata can be read all the same (the system attributes through its
/// attribute directory, as `getattrat(3C)` reads them).
pub(crate) fn is_quarantined(node: &Node) -> bool {
    node.is_file()
        && node
            .meta
            .generic_attributes
            .number(ILLUMOS_SYSTEM_ATTRIBUTES)
            .is_some_and(|mask| mask & illumos_sysattr::AV_QUARANTINED != 0)
}

/// Whether opening the regular file at `path` for reading is refused with
/// `EACCES`, as for a file illumos quarantined ([`is_quarantined`]). It is
/// opened and closed, nothing more.
pub(crate) fn open_refused(path: &Path) -> bool {
    match File::open(path) {
        Ok(_) => false,
        #[cfg(unix)]
        Err(err) => err.raw_os_error() == Some(libc::EACCES),
        #[cfg(not(unix))]
        Err(_) => false,
    }
}

/// Makes `node`, a regular file whose contents couldn't be read (one
/// illumos quarantined: [`is_quarantined`], [`open_refused`]), a node
/// without contents: no content, size 0, and the size it has in
/// `illumos.unread_size`, which says its contents weren't backed up. Its
/// extended attributes, which couldn't be read either, are left out; the
/// rest of its metadata is kept. A warning names it.
pub(crate) fn keep_unread(path: &Path, node: &mut Node) {
    let size = node.meta.size;
    node.content = Some(Vec::new());
    node.meta.size = 0;
    node.meta.extended_attributes.clear();
    node.meta.generic_attributes.set_u64(ILLUMOS_UNREAD_SIZE, size);
    warn!(
        "{}: av_quarantined: contents not backed up ({size} bytes)",
        path.display()
    );
}

/// The size of the file `node` when its contents weren't backed up
/// ([`keep_unread`]): the restore makes it an empty file, and warns.
pub(crate) fn unread_size(node: &Node) -> Option<u64> {
    node.meta.generic_attributes.number_u64(ILLUMOS_UNREAD_SIZE)
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

/// Sets the ZFS DOS flags (Linux) of the file at `path`, of type
/// `node_type`, to `flags`, leaving those `linux.inode_flags` carries as they
/// are. This goes before [`restore_file_flags`]: changing them needs no
/// `CAP_LINUX_IMMUTABLE` as long as immutable and append-only stay as they
/// are.
///
/// # Errors
///
/// * If some or all of the flags couldn't be set: an [`Unsupported`] error
///   if the file system has none (one that isn't ZFS).
pub(crate) fn restore_zfs_dos_flags(
    path: &Path,
    node_type: &NodeType,
    flags: u64,
) -> io::Result<()> {
    os::restore_zfs_dos_flags(path, node_type, flags)
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
    pub(crate) bits: u64,
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
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "illumos",
            target_os = "linux",
            target_os = "netbsd",
            target_os = "openbsd"
        )),
        allow(dead_code)
    )]
    fn error(attr: &'static str, bits: u64, source: io::Error) -> io::Error {
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

/// BackOtter: a SID on illumos that idmap couldn't map to an id here
/// (idmapd isn't running, say): the owner or group of a file
/// (`illumos.owner_sid`, `illumos.group_sid`), or the user or group of an
/// ACL entry (`illumos.acl`, `illumos.xattr_meta`), which got nobody (60001)
/// instead, not the number the backup saw: that may be another SID's by now.
/// The restore warns about each attribute once ([`warn_restore`]).
#[derive(Debug)]
pub(crate) struct SidUnmapped {
    /// The generic attribute.
    pub(crate) attr: &'static str,
    /// The SID.
    pub(crate) sid: String,
    /// idmap's error.
    pub(crate) source: io::Error,
}

impl fmt::Display for SidUnmapped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} not mapped by idmap, nobody (60001) used: {}",
            self.attr, self.sid, self.source
        )
    }
}

impl std::error::Error for SidUnmapped {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl SidUnmapped {
    /// An [`io::Error`] for this.
    #[cfg_attr(not(target_os = "illumos"), allow(dead_code))]
    fn error(attr: &'static str, sid: &str, source: io::Error) -> io::Error {
        io::Error::other(Self {
            attr,
            sid: sid.to_string(),
            source,
        })
    }
}

/// BackOtter: more than one error from one step of restoring a file's
/// metadata, which [`warn_restore`] warns about each as if alone: the owner
/// and the group both SIDs that idmap couldn't map, a warning for each
/// attribute.
#[derive(Debug)]
pub(crate) struct RestoreErrors(Vec<io::Error>);

impl RestoreErrors {
    /// `Ok` for no errors, the error itself for one, and one that holds them
    /// all for more.
    #[cfg_attr(not(target_os = "illumos"), allow(dead_code))]
    fn result(mut errors: Vec<io::Error>) -> io::Result<()> {
        match errors.len() {
            0 => Ok(()),
            1 => Err(errors.remove(0)),
            _ => Err(io::Error::other(Self(errors))),
        }
    }
}

impl fmt::Display for RestoreErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, err) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{err}")?;
        }
        Ok(())
    }
}

impl std::error::Error for RestoreErrors {}

/// BackOtter: what a restore couldn't do to the extended attributes of a
/// file, each with its error: setting one (named), removing one, listing
/// them. One that can't be set doesn't keep the others from being set or
/// removed, as in BackOtter's restic, and one warning per file names them
/// all, as in `trusted.a: Operation not permitted (os error 1); removing
/// user.b: ...`.
#[derive(Debug, Default)]
pub(crate) struct XattrErrors(Vec<(String, io::Error)>);

impl XattrErrors {
    /// Adds the failure of `what`: an attribute's name, for setting it, or
    /// what else was done (`removing NAME`, `listing`).
    #[cfg_attr(any(windows, target_os = "openbsd"), allow(dead_code))]
    pub(crate) fn push(&mut self, what: impl Into<String>, err: io::Error) {
        self.0.push((what.into(), err));
    }

    /// `Ok` if nothing failed.
    ///
    /// # Errors
    ///
    /// * These failures, if there are any.
    #[cfg_attr(any(windows, target_os = "openbsd"), allow(dead_code))]
    pub(crate) fn into_result(self) -> Result<(), Self> {
        if self.0.is_empty() { Ok(()) } else { Err(self) }
    }
}

/// BackOtter: a copy of `err`, for each of several things it kept from being
/// done, such as each extended attribute of a file on a file system without
/// them.
#[cfg_attr(any(windows, target_os = "openbsd", target_os = "illumos"), allow(dead_code))]
pub(crate) fn same_error(err: &io::Error) -> io::Error {
    err.raw_os_error().map_or_else(
        || io::Error::new(err.kind(), err.to_string()),
        io::Error::from_raw_os_error,
    )
}

/// An error that isn't about one attribute: the file's extended attributes
/// can't be read or written at all.
impl From<io::Error> for XattrErrors {
    fn from(err: io::Error) -> Self {
        Self(vec![(String::new(), err)])
    }
}

impl fmt::Display for XattrErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (what, err)) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            if what.is_empty() {
                write!(f, "{err}")?;
            } else {
                write!(f, "{what}: {err}")?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for XattrErrors {}

/// The kinds of metadata the restore has warned about once (unsupported
/// metadata, unmapped SIDs), each with the first file and the number of
/// files.
static UNSUPPORTED: Mutex<BTreeMap<String, (PathBuf, u64)>> = Mutex::new(BTreeMap::new());

/// Warns about an error restoring the metadata of `path`: an [`Unsupported`]
/// or [`SidUnmapped`] one once per kind, with the first file, and
/// [`report_unsupported`] counts the files; any other each time; each of
/// [`RestoreErrors`] as if alone.
pub(crate) fn warn_restore(path: &Path, err: &io::Error) {
    let inner = err.get_ref();
    if let Some(errors) = inner.and_then(|e| e.downcast_ref::<RestoreErrors>()) {
        for err in &errors.0 {
            warn_restore(path, err);
        }
        return;
    }
    let (kind, msg) = if let Some(e) = inner.and_then(|e| e.downcast_ref::<Unsupported>()) {
        (format!("{} not supported by the file system", e.kind()), e.to_string())
    } else if let Some(e) = inner.and_then(|e| e.downcast_ref::<SidUnmapped>()) {
        (format!("{}: SIDs not mapped by idmap, nobody (60001) used", e.attr), e.to_string())
    } else {
        warn!("restore {}: {err}", path.display());
        return;
    };
    let mut seen = UNSUPPORTED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_, n) = seen.entry(kind).or_insert_with(|| (path.to_path_buf(), 0));
    *n += 1;
    let first = *n == 1;
    drop(seen);
    if first {
        warn!("restore {}: {msg}", path.display());
    }
}

/// Warns, once a restore is done, about the number of files with each kind
/// of metadata [`warn_restore`] saw more than once, and starts counting
/// again.
pub(crate) fn report_unsupported() {
    let seen = std::mem::take(
        &mut *UNSUPPORTED.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    for (kind, (first, n)) in seen {
        if n > 1 {
            warn!("{kind}: {n} files, the first {}", first.display());
        }
    }
}

/// Gives the file at `path` the owner and group that `node` keeps as SIDs
/// (illumos), as the ids they have here, after the restore gave it its
/// numbers. Elsewhere, nothing.
///
/// # Errors
///
/// * If the owner couldn't be set, or a SID couldn't be mapped (a
///   [`SidUnmapped`] error: the file got nobody instead).
pub(crate) fn restore_owner(path: &Path, node: &Node) -> io::Result<()> {
    os::restore_owner(path, node)
}

/// Restores the attributes that go along with the extended attributes
/// (FreeBSD's and NetBSD's system extended attributes, illumos' extended
/// attributes' own metadata and ZFS project IDs), and warns once about each
/// generic attribute that isn't known at all.
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

/// Sets the birth time of the file at `path`, where the system keeps one
/// (FreeBSD, NetBSD, illumos), just before the restore sets its atime and
/// mtime: on FreeBSD and NetBSD it is set as an earlier mtime, which they
/// replace. Elsewhere, and where the file system has none, it is skipped,
/// with a note in the debug log.
///
/// # Errors
///
/// * If the birth time couldn't be set.
pub(crate) fn restore_birthtime(path: &Path, node: &Node) -> io::Result<()> {
    let Some(birth) = node.meta.generic_attributes.timestamp(UNIX_BIRTHTIME) else {
        return Ok(());
    };
    match os::restore_birthtime(path, node, birth) {
        Err(err) if err.kind() == io::ErrorKind::Unsupported => {
            debug!("birth time of {} not restored: {err}", path.display());
            Ok(())
        }
        result => result,
    }
}

/// The mtime to set before `node`'s final atime and mtime on FreeBSD and
/// NetBSD, for its birth time `birth` to come back, if there is one to set:
/// the birth time, when it is earlier than the mtime.
///
/// The kernels of FreeBSD and NetBSD have no call that sets a birth time,
/// but they lower it to any mtime set earlier than it (UFS2, NetBSD's FFS
/// and ZFS alike; files, directories and symlinks; owners too). The final
/// atime and mtime then leave it. A birth time that isn't earlier needs
/// nothing: the final times lower the new file's, the time of the restore,
/// to the mtime, the closest they can get.
#[cfg_attr(
    not(any(target_os = "freebsd", target_os = "netbsd")),
    allow(dead_code)
)]
fn birthtime_first(node: &Node, birth: Timestamp) -> Option<Timestamp> {
    node.meta.mtime.filter(|&mtime| birth < mtime).map(|_| birth)
}

/// Sets `node`'s birth time `birth`, when it is earlier than its mtime, as
/// the mtime of the file at `path` (see [`birthtime_first`]), with
/// `utimensat(2)`, leaving the atime: filetime goes through `utimes(2)` on
/// some systems, which drops the nanoseconds. A symlink is not followed;
/// where that can't be done, its times are left as they are, as the
/// restore leaves them.
#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
fn lower_birthtime(path: &Path, node: &Node, birth: Timestamp) -> io::Result<()> {
    let Some(birth) = birthtime_first(node, birth) else {
        return Ok(());
    };
    match utimensat_nofollow(path, None, birth) {
        Ok(()) => Ok(()),
        Err(err)
            if node.is_symlink()
                && matches!(
                    err.raw_os_error(),
                    Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL)
                ) =>
        {
            Err(io::Error::new(io::ErrorKind::Unsupported, err))
        }
        Err(err) => Err(path_error("utimensat (birth time)", path, &err)),
    }
}

/// Sets the atime and mtime of the file at `path`, not following a symlink,
/// to the nanosecond, with `utimensat(2)`: on DragonFly, where the filetime
/// crate goes through `utimes(2)` and `lutimes(2)`, which take microseconds
/// (on the other systems it goes through `utimensat(2)` too).
///
/// # Errors
///
/// * If the times can't be set.
#[cfg(target_os = "dragonfly")]
pub(crate) fn set_times(path: &Path, atime: Timestamp, mtime: Timestamp) -> io::Result<()> {
    utimensat_nofollow(path, Some(atime), mtime)
}

/// Sets the mtime of the file at `path` and its atime, unless that is
/// `None` (`UTIME_OMIT`), with `utimensat(2)` and `AT_SYMLINK_NOFOLLOW`, to
/// the nanosecond.
#[cfg(any(target_os = "dragonfly", target_os = "freebsd", target_os = "netbsd"))]
fn utimensat_nofollow(path: &Path, atime: Option<Timestamp>, mtime: Timestamp) -> io::Result<()> {
    let spec = |t: Option<Timestamp>| {
        t.map_or(
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            |t| {
                let (sec, nsec) = unix_time(t);
                libc::timespec {
                    tv_sec: sec,
                    tv_nsec: nsec.into(),
                }
            },
        )
    };
    let p = c_path(path)?;
    let times = [spec(atime), spec(Some(mtime))];
    // SAFETY: p is a C string, times two timespecs.
    let r = unsafe {
        libc::utimensat(libc::AT_FDCWD, p.as_ptr(), times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW)
    };
    check(r).map(drop)
}

/// `t` as C's `time_t` and nanoseconds, which are never negative: the
/// seconds rounded down.
#[cfg_attr(
    not(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "netbsd"
    )),
    allow(dead_code)
)]
fn unix_time(t: Timestamp) -> (i64, u32) {
    let nsec = t.subsec_nanosecond();
    if nsec < 0 {
        (t.as_second() - 1, (nsec + 1_000_000_000).unsigned_abs())
    } else {
        (t.as_second(), nsec.unsigned_abs())
    }
}

/// Gives a symlink its own permissions back, where the system keeps them
/// (FreeBSD, NetBSD, OpenBSD, DragonFly).
///
/// # Errors
///
/// * If the permissions couldn't be set.
pub(crate) fn restore_symlink_mode(path: &Path, node: &Node) -> io::Result<()> {
    os::restore_symlink_mode(path, node)
}

/// The extended attributes of the file at `path`, on illumos: named
/// attribute files (`runat(1)`), which the xattr crate doesn't support.
/// Elsewhere they go through the xattr crate.
///
/// # Errors
///
/// * If they can't be read, or this isn't illumos.
#[cfg_attr(not(target_os = "illumos"), allow(dead_code))]
pub(crate) fn illumos_xattrs(path: &Path) -> io::Result<Vec<ExtendedAttribute>> {
    os::xattrs(path)
}

/// Gives the file at `path` exactly the extended attributes `attrs`, on
/// illumos. One that can't be set or removed doesn't keep the others from
/// being set or removed.
///
/// # Errors
///
/// * Each attribute that couldn't be set or removed; or that the file system
///   has none, or this isn't illumos.
#[cfg_attr(not(target_os = "illumos"), allow(dead_code))]
pub(crate) fn set_illumos_xattrs(
    path: &Path,
    attrs: &[ExtendedAttribute],
) -> Result<(), XattrErrors> {
    os::set_xattrs(path, attrs)
}

/// The names of the extended attributes of the file at `path`, as the xattr
/// crate names them. On FreeBSD and NetBSD, those of the user namespace
/// only, listed here: xattr 1.6 names the last attribute of the system
/// namespace as one of the user namespace (which is kept as a generic
/// attribute anyway).
///
/// # Errors
///
/// * If they can't be listed.
#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos")))]
pub(crate) fn xattr_list(path: &Path) -> io::Result<Vec<std::ffi::OsString>> {
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    let names = freebsd_netbsd::user_extattr_names(path)?
        .into_iter()
        .map(|name| format!("user.{name}").into())
        .collect();
    #[cfg(not(any(target_os = "freebsd", target_os = "netbsd")))]
    let names = xattr::list(path)?.collect();
    Ok(names)
}

/// The name an extended attribute has in a node, from the name the xattr
/// crate lists it by, or `None` for one that isn't kept as an extended
/// attribute. On FreeBSD and NetBSD restic keeps the user namespace only,
/// under bare names, where the xattr crate says `user.NAME` and
/// `system.NAME`; their system namespace is kept as a generic attribute. On
/// Linux, bcachefs' `bcachefs_effective.*` aren't kept: they show the
/// options a file has, its own (`bcachefs.*`, kept) or inherited, and its
/// project ID, and setting one does nothing.
#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos")))]
pub(crate) fn xattr_node_name(name: &std::ffi::OsStr) -> Option<String> {
    let name = name.to_string_lossy();
    if cfg!(any(target_os = "freebsd", target_os = "netbsd")) {
        return name.strip_prefix("user.").map(str::to_string);
    }
    if cfg!(target_os = "linux") && name.starts_with(BCACHEFS_EFFECTIVE) {
        return None;
    }
    Some(name.into_owned())
}

/// The prefix of bcachefs' extended attributes that show a file's options as
/// they apply to it, whether its own or inherited ([`xattr_node_name`]).
#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos")))]
pub(crate) const BCACHEFS_EFFECTIVE: &str = "bcachefs_effective.";

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
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "illumos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
fn c_path(path: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(io::Error::from)
}

/// The result of a C call that returns -1 (or less than 0) and sets errno
/// when it fails.
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "illumos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
fn check<T: Copy + Default + PartialOrd>(r: T) -> io::Result<T> {
    if r < T::default() {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

/// Gives the symlink at `path` the permissions of `node`'s mode, which
/// OpenBSD, NetBSD and DragonFly keep (`fchmodat(2)` with
/// `AT_SYMLINK_NOFOLLOW`; OpenBSD has no `lchmod(2)`), and `ls(1)` and
/// `mtree(8)` show, though access doesn't depend on them. Without this a
/// restored symlink gets 0755. A file system that keeps none only goes to
/// the debug log.
#[cfg(any(target_os = "dragonfly", target_os = "netbsd", target_os = "openbsd"))]
fn chmod_symlink(path: &Path, node: &Node) -> io::Result<()> {
    use crate::backend::ignore::mapper::nix_mapper::map_mode_from_go;

    let Some(mode) = node.meta.mode else {
        return Ok(());
    };
    let p = c_path(path)?;
    let mode = libc::mode_t::try_from(map_mode_from_go(mode) & 0o7777).unwrap_or(0o755);
    // SAFETY: p is a C string.
    let r = unsafe { libc::fchmodat(libc::AT_FDCWD, p.as_ptr(), mode, libc::AT_SYMLINK_NOFOLLOW) };
    match check(r) {
        Ok(_) => Ok(()),
        Err(err) if matches!(err.raw_os_error(), Some(libc::EOPNOTSUPP | libc::EINVAL)) => {
            debug!("symlink mode of {} not set: {err}", path.display());
            Ok(())
        }
        Err(err) => Err(path_error("fchmodat", path, &err)),
    }
}

/// An error that names the operation and the file.
#[cfg_attr(
    not(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd"
    )),
    allow(dead_code)
)]
fn path_error(op: &str, path: &Path, err: &io::Error) -> io::Error {
    io::Error::new(err.kind(), format!("{op} {}: {err}", path.display()))
}

/// Calls `set` with `want`, the flags `attr` of the file at `path`, which
/// `op` sets: 32 bits (`u32`), or 64 (`u64`, ZFS's DOS flags). If that
/// fails, changes the flags from `current`, what the file has (0 if not
/// known), towards `want` one bit at a time, keeping each change `set`
/// accepts: so a flag only root may set, or one the owner may set but not
/// clear (illumos' `av_modified`), doesn't keep the others from being set or
/// cleared, though `set` sets all the flags at once. It returns an error
/// naming the bits it couldn't set or clear, with `set`'s first error: an
/// [`Unsupported`] one if every refusal said the file system doesn't have
/// those flags (`EINVAL`, `ENOTSUP`, `EOPNOTSUPP`, `ENOTTY`), or else with
/// the first error that didn't. If nothing differs from `current`, there is
/// nothing to try one at a time: that is `Ok` if `current` is known, and
/// `set`'s error if not.
#[cfg_attr(
    not(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd"
    )),
    allow(dead_code)
)]
fn set_flags_best_effort<F: Copy + Into<u64> + TryFrom<u64>>(
    attr: &'static str,
    path: &Path,
    op: &str,
    current: Option<F>,
    want: F,
    mut set: impl FnMut(F) -> io::Result<()>,
) -> io::Result<()> {
    let Err(first) = set(want) else {
        return Ok(());
    };
    let want: u64 = want.into();
    let known = current.is_some();
    let current: u64 = current.map_or(0, Into::into);
    let change = want ^ current;
    if change == 0 {
        return if known {
            Ok(())
        } else if unsupported(&first) {
            Err(Unsupported::error(attr, 0, first))
        } else {
            Err(path_error(op, path, &first))
        };
    }
    let (mut got, mut refused) = (current, 0);
    let mut failed = (!unsupported(&first)).then_some(first);
    let mut unsupported_err = None;
    for bit in (0..64).map(|i| 1_u64 << i).filter(|bit| change & bit != 0) {
        // current and want fit, so this does.
        let Ok(bits) = F::try_from(got ^ bit) else {
            continue;
        };
        match set(bits) {
            Ok(()) => got ^= bit,
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
    let what = match (refused & want, refused & !want) {
        (set, 0) => format!("file flags {set:#x} of {want:#x} not set"),
        (0, cleared) => format!("file flags {cleared:#x} not cleared"),
        (set, cleared) => {
            format!("file flags {set:#x} of {want:#x} not set, {cleared:#x} not cleared")
        }
    };
    match (failed, unsupported_err) {
        (Some(err), _) => Err(path_error(
            op,
            path,
            &io::Error::new(err.kind(), format!("{what}: {err}")),
        )),
        (None, Some(err)) => Err(Unsupported::error(attr, refused, err)),
        (None, None) => Err(path_error(op, path, &io::Error::other(what))),
    }
}

/// Errors that mean the file system doesn't have a kind of metadata (file
/// flags, a project ID), rather than that setting it failed.
#[cfg_attr(
    not(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "linux",
        target_os = "netbsd",
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

    // A file illumos quarantined, as the backup builds its node from the
    // lstat and the system attributes: no contents, size 0, its size in
    // illumos.unread_size, its other metadata kept.
    #[test]
    fn quarantined_node_without_contents() {
        use crate::backend::node::Metadata;

        let mut meta = Metadata {
            mode: Some(0o644),
            uid: Some(0),
            inode: 7,
            links: 1,
            size: 12,
            extended_attributes: vec![ExtendedAttribute {
                name: "note".to_string(),
                value: Some(b"x".to_vec()),
            }],
            ..Metadata::default()
        };
        let quarantined = illumos_sysattr::AV_QUARANTINED | illumos_sysattr::AUTOMATIC;
        meta.generic_attributes
            .set_u64(ILLUMOS_SYSTEM_ATTRIBUTES, quarantined.into());
        let mut node = Node::new_node(std::ffi::OsStr::new("q"), NodeType::File, meta);
        assert!(is_quarantined(&node));
        assert_eq!(unread_size(&node), None);

        keep_unread(Path::new("/q"), &mut node);
        assert_eq!(node.content, Some(Vec::new()));
        assert_eq!(node.meta.size, 0);
        assert!(node.meta.extended_attributes.is_empty());
        assert_eq!(unread_size(&node), Some(12));
        assert_eq!(node.meta.mode, Some(0o644));
        assert_eq!(node.meta.inode, 7);
        assert_eq!(file_flags_mask(&node), Some(u64::from(quarantined)));
        let json = serde_json::to_string(&node).unwrap();
        assert!(json.contains(r#""content":[]"#), "{json}");
        assert!(json.contains(r#""illumos.unread_size":12"#), "{json}");
        assert!(!json.contains(r#""size""#), "{json}");

        // Other files, and a directory with the attribute, aren't.
        let mut other = Node::default();
        other.meta.generic_attributes.set_u64(ILLUMOS_SYSTEM_ATTRIBUTES, 1 << 5);
        assert!(!is_quarantined(&other));
        let mut dir = Node::new_node(std::ffi::OsStr::new("d"), NodeType::Dir, Metadata::default());
        dir.meta.generic_attributes.set_u64(ILLUMOS_SYSTEM_ATTRIBUTES, quarantined.into());
        assert!(!is_quarantined(&dir));
        assert!(!open_refused(Path::new("/nonexistent/bko")));
    }

    fn file_flags_mask(node: &Node) -> Option<u64> {
        node.meta.generic_attributes.number_u64(ILLUMOS_SYSTEM_ATTRIBUTES)
    }

    #[test]
    fn xattr_errors_name_each() {
        let mut errors = XattrErrors::default();
        assert!(XattrErrors::default().into_result().is_ok());
        errors.push("trusted.a", io::Error::from(io::ErrorKind::PermissionDenied));
        errors.push("removing user.b", io::Error::other("busy"));
        let msg = errors.into_result().unwrap_err().to_string();
        assert_eq!(msg, "trusted.a: permission denied; removing user.b: busy");
        let all = XattrErrors::from(io::Error::other("no extended attributes"));
        assert_eq!(all.to_string(), "no extended attributes");
    }

    #[test]
    fn birthtime_first_only_when_earlier() {
        let t = |sec, nsec| Timestamp::new(sec, nsec).unwrap();
        let mut node = Node::default();
        node.meta.mtime = Some(t(1_200_000_000, 222_222_222));
        // Earlier: set first (two utimensat calls), else not (one).
        for (birth, first) in [
            (t(1_000_000_000, 111_111_111), true),
            (t(1_200_000_000, 222_222_221), true),
            (t(1_200_000_000, 222_222_222), false),
            (t(1_300_000_000, 0), false),
        ] {
            assert_eq!(birthtime_first(&node, birth), first.then_some(birth), "{birth}");
        }
        // Without an mtime, which the restore then doesn't set.
        node.meta.mtime = None;
        assert_eq!(birthtime_first(&node, t(1_000_000_000, 0)), None);
    }

    #[test]
    fn restore_birthtime_without_attribute() {
        // No attribute: nothing to do, and no system call either.
        restore_birthtime(Path::new("/nonexistent"), &Node::default()).unwrap();
    }

    #[test]
    fn unix_time_rounds_down() {
        let t = |sec, nsec| Timestamp::new(sec, nsec).unwrap();
        assert_eq!(unix_time(t(1_000_000_000, 123_456_789)), (1_000_000_000, 123_456_789));
        assert_eq!(unix_time(t(0, 0)), (0, 0));
        assert_eq!(unix_time(t(0, -1)), (-1, 999_999_999));
        assert_eq!(unix_time(t(-2, 500_000_000)), (-2, 500_000_000));
    }

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
        set_flags_best_effort("x.flags", path, "set", None, 0x3, &mut set).unwrap();

        // Unsupported: a warning once.
        let err = set_flags_best_effort("x.flags", path, "set", None, 0x15, &mut set).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        let unsupported = err.get_ref().unwrap().downcast_ref::<Unsupported>().unwrap();
        assert_eq!((unsupported.attr, unsupported.bits), ("x.flags", 0x4));
        assert_eq!(current.get(), 0x11);

        // Unsupported and not permitted: an error.
        let err = set_flags_best_effort("x.flags", path, "set", None, 0x1d, &mut set).unwrap_err();
        assert!(err.get_ref().unwrap().downcast_ref::<Unsupported>().is_none());
        assert!(err.to_string().contains("0xc of 0x1d"), "{err}");
        assert_eq!(current.get(), 0x11);
    }

    #[cfg(unix)]
    #[test]
    fn set_flags_best_effort_64_bits() {
        let path = Path::new("f");
        // ZFS's DOS flags: sparse not supported, read-only not permitted.
        let (readonly, hidden, sparse) = (0x1_0000_0000_u64, 0x2_0000_0000, 0x2000_0000_0000);
        let current = std::cell::Cell::new(0);
        let mut set = |f: u64| {
            if f & sparse != 0 {
                return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
            }
            if f & readonly != 0 {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            current.set(f);
            Ok(())
        };
        let err = set_flags_best_effort("x.flags", path, "set", None, hidden | sparse, &mut set)
            .unwrap_err();
        let unsupported = err.get_ref().unwrap().downcast_ref::<Unsupported>().unwrap();
        assert_eq!(unsupported.bits, sparse);
        assert_eq!(unsupported.kind(), "x.flags 0x200000000000");
        assert_eq!(current.get(), hidden);

        let all = readonly | hidden | sparse;
        let err = set_flags_best_effort("x.flags", path, "set", None, all, &mut set).unwrap_err();
        assert!(err.get_ref().unwrap().downcast_ref::<Unsupported>().is_none());
        assert!(
            err.to_string().contains("0x200100000000 of 0x200300000000"),
            "{err}"
        );
        assert_eq!(current.get(), hidden);
    }

    #[cfg(unix)]
    #[test]
    fn set_flags_best_effort_from_current() {
        // illumos as the owner: every write names every flag; immutable
        // (0x20) only root may set, av_modified (0x200) the owner may set
        // but not clear. A new file has archive (0x8) and av_modified.
        let path = Path::new("f");
        let (archive, immutable, av_modified) = (0x8_u32, 0x20, 0x200);
        let current = std::cell::Cell::new(archive | av_modified);
        let mut set = |f: u32| {
            let was = current.get();
            if f & immutable != 0 && was & immutable == 0
                || f & av_modified == 0 && was & av_modified != 0
            {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            current.set(f);
            Ok(())
        };
        // hidden (0x1) and archive set beside immutable, which isn't.
        let want = 0x1 | archive | immutable | av_modified;
        let err = set_flags_best_effort("x.flags", path, "set", Some(current.get()), want, &mut set)
            .unwrap_err();
        assert!(err.to_string().contains("file flags 0x20 of 0x229 not set:"), "{err}");
        assert_eq!(current.get(), 0x1 | archive | av_modified);

        // archive cleared beside av_modified, which can't be.
        current.set(archive | av_modified);
        let err = set_flags_best_effort("x.flags", path, "set", Some(current.get()), 0, &mut set)
            .unwrap_err();
        assert!(err.to_string().contains("file flags 0x200 not cleared:"), "{err}");
        assert_eq!(current.get(), av_modified);

        // Both at once.
        current.set(archive | av_modified);
        let err =
            set_flags_best_effort("x.flags", path, "set", Some(current.get()), immutable, &mut set)
                .unwrap_err();
        assert!(
            err.to_string().contains("file flags 0x20 of 0x20 not set, 0x200 not cleared:"),
            "{err}"
        );
        assert_eq!(current.get(), av_modified);

        // Nothing to change: whatever set says, the file has the flags.
        set_flags_best_effort("x.flags", path, "set", Some(av_modified), av_modified, |_| {
            Err(io::Error::from_raw_os_error(libc::EPERM))
        })
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn set_flags_best_effort_0_fails_with_set() {
        // Nothing to try one at a time: the error is set's.
        let path = Path::new("f");
        let err = set_flags_best_effort("x.flags", path, "set", None, 0_u64, |_| {
            Err(io::Error::from_raw_os_error(libc::EACCES))
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.get_ref().unwrap().downcast_ref::<Unsupported>().is_none());
        let err = set_flags_best_effort("x.flags", path, "set", None, 0_u32, |_| {
            Err(io::Error::from_raw_os_error(libc::ENOTTY))
        })
        .unwrap_err();
        let unsupported = err.get_ref().unwrap().downcast_ref::<Unsupported>().unwrap();
        assert_eq!(unsupported.kind(), "x.flags");
    }
}
