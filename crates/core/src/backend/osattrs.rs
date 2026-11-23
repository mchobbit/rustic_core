//! BackOtter: metadata some systems keep that rustic otherwise doesn't save:
//! file flags (Linux's `chattr(1)` flags, the BSDs' `chflags(1)` flags,
//! illumos' system attributes), ACLs (FreeBSD's, NetBSD's and illumos'),
//! FreeBSD's and NetBSD's system extended attributes and Haiku's typed file
//! attributes. They are kept as restic generic attributes
//! ([`generic_attributes`](super::node::generic_attributes)), in the same
//! form as BackOtter's restic.
//!
//! On restore, ACLs go on after the mode, which rewrites an NFSv4 ACL, and
//! file flags last of all, once every file has its contents, hard links and
//! other metadata: an immutable file refuses new hard links, times and
//! permissions, and an immutable directory new entries. On Linux, ZFS's DOS
//! flags, FAT's attributes and XFS's options go on just before the file
//! flags: a read-only file refuses writes, and every write sets the archive
//! flag again.
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

// BackOtter: the workspace denies unsafe code; the modules and functions
// here that make system calls and ioctls rustic's dependencies don't wrap
// allow it, each for itself, and every unsafe block says why it is sound.
#![warn(clippy::undocumented_unsafe_blocks)]

use std::{
    borrow::Cow,
    collections::BTreeSet,
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
        ILLUMOS_SYSTEM_ATTRIBUTES, ILLUMOS_UNREAD_SIZE, ILLUMOS_XATTR_META, KNOWN, LINUX_FAT_ATTRS,
        LINUX_XFS_OPTIONS, UNIX_BIRTHTIME, UNIX_SPARSE, XfsOptions,
    },
};

#[cfg(unix)]
mod bsd_extattr;
mod bsd_flags;
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
#[allow(unsafe_code)]
mod bsd_held;
mod errors;
mod freebsd_acl;
#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
#[allow(unsafe_code)]
mod freebsd_netbsd;
mod haiku_attrs;
mod illumos_acl;
#[cfg(target_os = "illumos")]
#[allow(unsafe_code)]
mod illumos_idmap;
mod illumos_project;
mod illumos_sysattr;
mod illumos_xattrmeta;
#[cfg(test)]
pub(crate) mod malformed;
#[cfg(unix)]
mod sparse;
mod xattr;

// BackOtter: the errors and the extended attributes' helpers, under the
// names they had here.
pub(crate) use errors::*;
pub(crate) use xattr::*;

#[cfg(target_os = "dragonfly")]
#[allow(unsafe_code)]
mod dragonfly;
#[cfg(target_os = "dragonfly")]
use dragonfly as os;
#[cfg(target_os = "freebsd")]
#[allow(unsafe_code)]
mod freebsd;
#[cfg(target_os = "freebsd")]
use freebsd as os;
#[cfg(target_os = "haiku")]
#[allow(unsafe_code)]
mod haiku;
#[cfg(target_os = "haiku")]
use haiku as os;
#[cfg(target_os = "illumos")]
#[allow(unsafe_code)]
mod illumos;
#[cfg(target_os = "illumos")]
use illumos as os;
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux;
#[cfg(target_os = "linux")]
use linux as os;
#[cfg(target_os = "netbsd")]
#[allow(unsafe_code)]
mod netbsd;
#[cfg(target_os = "netbsd")]
use netbsd as os;
#[cfg(target_os = "openbsd")]
#[allow(unsafe_code)]
mod openbsd;
#[cfg(target_os = "openbsd")]
use openbsd as os;
#[cfg(not(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "haiku",
    target_os = "illumos",
    target_os = "linux",
    target_os = "netbsd",
    target_os = "openbsd"
)))]
mod other;
#[cfg(not(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "haiku",
    target_os = "illumos",
    target_os = "linux",
    target_os = "netbsd",
    target_os = "openbsd"
)))]
use other as os;

/// BackOtter: has the first error that keeps `walkdir::short_path` from
/// shortening a path of `PATH_MAX` bytes or more (no directory for its
/// links in `$TMPDIR`, a link refused) warned about, once in the process:
/// such a path then fails as "File name too long", which doesn't say why.
/// For a backup's source and a restore's destination.
pub(crate) fn warn_on_short_path_errors() {
    walkdir::report_short_path_errors(|err| {
        warn!(
            "paths of PATH_MAX bytes or more can't be reached, and fail as \"File name too long\": {err}"
        );
    });
}

/// Records the file flags and other attributes of the file at `path`, with
/// metadata `m` (its lstat), in the generic attributes of its `node`. Errors
/// are warned about: the rest of the node is still worth saving.
///
/// `xattrs` says whether the backup keeps extended attributes; on illumos
/// this records their metadata then, which must come before their values
/// are read (illumos has no `O_NOATIME`, and a read moves an attribute's
/// atime).
///
/// Returns whether it warned that file flags or attributes couldn't be read
/// (left out of the node), which BackOtter's restic counts toward its exit
/// status 3.
pub(crate) fn fill(path: &Path, node: &mut Node, m: &std::fs::Metadata, xattrs: bool) -> bool {
    // BackOtter: past PATH_MAX, through a short path to it (`sys`); the
    // warnings name `path`.
    let sys = &*walkdir::short_path(path);
    let mut incomplete = false;
    // On Linux, the one open of the file for its flags, project ID and holes;
    // on illumos, of its system attribute view.
    let f = os::open_for_attrs(sys, &node.node_type, m);
    if let Some(name) = os::FILE_FLAGS {
        // The system's module says when there are none worth an attribute:
        // a 0 can say something (a cleared archive flag on ZFS).
        match os::file_flags(sys, &node.node_type, m, f.as_ref()) {
            Ok(Some(flags)) => node.meta.generic_attributes.set_u64(name, flags.into()),
            Ok(None) => {}
            Err(err) => {
                warn!("ignoring file flags of {}: {err}", path.display());
                incomplete = true;
            }
        }
    }
    if let Err(err) = os::fill_attributes(sys, node, f.as_ref()) {
        warn!("ignoring attributes of {}: {err}", path.display());
        incomplete = true;
    }
    if xattrs {
        os::fill_xattr_meta(sys, node);
    }
    // The birth time of every type of file, where the lstat has one (on
    // illumos it is in the system attribute view, which `fill_attributes`
    // reads). Not on Linux, which can't set one back, nor OpenBSD or
    // DragonFly, which keep none.
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    if let Some(birth) = m.created().ok().and_then(|t| Timestamp::try_from(t).ok()) {
        node.meta
            .generic_attributes
            .set_timestamp(UNIX_BIRTHTIME, birth);
    }
    // A regular file, not a block device saved as one.
    #[cfg(unix)]
    if node.is_file() && m.is_file() && sparse::has_holes(sys, m, f.as_ref()) {
        node.meta.generic_attributes.set_true(UNIX_SPARSE);
    }
    incomplete
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
/// its file system's block size (else its `st_blksize`), at least 512
/// bytes, 4096 where neither is known, as BackOtter's restic.
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

/// The FAT attributes `node` holds, on Linux (`linux.fat_attrs`), if any.
pub(crate) fn fat_attrs(node: &Node) -> Option<u32> {
    if cfg!(target_os = "linux") {
        node.meta.generic_attributes.number(LINUX_FAT_ATTRS)
    } else {
        None
    }
}

/// The XFS options `node` holds, on Linux (`linux.xfs_options`), if any.
pub(crate) fn xfs_options(node: &Node) -> Option<XfsOptions> {
    if cfg!(target_os = "linux") {
        node.meta.generic_attributes.decoded(LINUX_XFS_OPTIONS)
    } else {
        None
    }
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
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
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
    node.meta
        .generic_attributes
        .set_u64(ILLUMOS_UNREAD_SIZE, size);
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

/// BackOtter: gives `dst` the whole contents of `src`, sharing its extents
/// (Linux's `FICLONE`), where the file system can; for
/// `restore --clone-from`.
///
/// # Errors
///
/// * `FICLONE`'s: the file system can't clone (`EOPNOTSUPP`, `ENOTTY`), the
///   two files are on different file systems (`EXDEV`), `dst` isn't open for
///   writing or is no regular file (`EBADF`, `EINVAL`), and the like.
/// * `ErrorKind::Unsupported` on every system but Linux.
#[cfg_attr(target_os = "linux", allow(unsafe_code))]
pub(crate) fn clone_contents(src: &File, dst: &File) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: FICLONE takes the source's descriptor as its argument;
        // both are open for the call's duration.
        if unsafe { libc::ioctl(dst.as_raw_fd(), FICLONE, src.as_raw_fd()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        _ = (src, dst);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// `FICLONE` from `<linux/fs.h>`, `_IOW(0x94, 9, int)`: built as the
/// architecture encodes an ioctl's direction and size (powerpc, mips and
/// sparc not as the others).
#[cfg(target_os = "linux")]
const FICLONE: libc::Ioctl = libc::_IOW::<libc::c_int>(0x94, 9);

/// BackOtter: whether [`prepare_file`] has nothing to do for `node`: no flag
/// or option that goes on before the data, so that its contents may come
/// whole from a clone (`restore --clone-from`).
// `os::FLAGS_BEFORE_DATA` is 0 but on Linux.
#[cfg_attr(not(target_os = "linux"), allow(clippy::bad_bit_mask))]
pub(crate) fn takes_nothing_before_data(node: &Node) -> bool {
    let flags = file_flags(node).is_none_or(|f| f & os::FLAGS_BEFORE_DATA == 0);
    #[cfg(target_os = "linux")]
    let options = xfs_options(node).is_none();
    #[cfg(not(target_os = "linux"))]
    let options = true;
    flags && options
}

/// Creates an empty file at `path` with those of `node`'s flags that a file
/// system only takes while a file is empty (btrfs's no-copy-on-write), for
/// the restore to write the contents into. Does nothing when there are none,
/// or when `path` exists already.
///
/// # Errors
///
/// * If the file can't be created, or the flags set.
// `os::FLAGS_BEFORE_DATA` is 0 but on Linux.
#[cfg_attr(not(target_os = "linux"), allow(clippy::bad_bit_mask))]
pub(crate) fn prepare_file(path: &Path, node: &Node) -> io::Result<()> {
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    // BackOtter: it creates the file when there is none, so it waits for the
    // exit once XFS options are put back.
    let _making = crate::commands::restore::making_entries();
    let flags = match file_flags(node) {
        Some(flags) if flags & os::FLAGS_BEFORE_DATA != 0 => {
            os::prepare_file_for_flags(path, flags & os::FLAGS_BEFORE_DATA)
        }
        _ => Ok(()),
    };
    // BackOtter: XFS's extent size hint too (Linux), which XFS takes on no
    // file with data. Errors are left for the late pass to report.
    #[cfg(target_os = "linux")]
    if let Some(opts) = xfs_options(node) {
        os::prepare_file_for_xfs(path, &opts);
    }
    flags
}

/// Gives the empty directory at `path` (one the restore created, or found
/// empty) exactly those of `node`'s flags that a file system only takes
/// while a directory is empty (casefolding, on ext4 and f2fs), before the
/// restore puts anything in it: it sets them where `node` has them, and
/// clears them where it hasn't, so that a directory doesn't inherit
/// casefolding from its parent when it had none. Flags the file system
/// doesn't support are left for [`restore_file_flags`] to report.
///
/// A node without flags had none only in a snapshot of BackOtter's
/// (`known_bko`), which records every directory's; in any other the
/// directory keeps what it has or inherited (casefolding from its parent),
/// as in stock rustic.
///
/// BackOtter: on bcachefs (Linux) it then gives the directory its options
/// and project ID too, which bcachefs passes only to entries created after
/// them, as BackOtter's restic does (`linux::prepare_dir_for_options`).
///
/// # Errors
///
/// * If the flags couldn't be set.
pub(crate) fn prepare_dir(path: &Path, node: &Node, known_bko: bool) -> io::Result<()> {
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    if os::FLAGS_BEFORE_ENTRIES == 0 {
        return Ok(());
    }
    let flags = node_flags(node, known_bko).map_or(Ok(()), |flags| {
        os::prepare_dir_for_flags(path, flags & os::FLAGS_BEFORE_ENTRIES)
    });
    #[cfg(target_os = "linux")]
    os::prepare_dir_for_options(path, node, known_bko);
    flags
}

/// The file flags `node` says its file had: those it holds, or none (0)
/// where it holds none in a snapshot of BackOtter's (`known_bko`), which
/// records them wherever there are any. `None`: not known (a snapshot of
/// stock restic or rustic, which record none).
pub(crate) fn node_flags(node: &Node, known_bko: bool) -> Option<u32> {
    file_flags(node).or_else(|| known_bko.then_some(0))
}

/// Whether the restore clears the restricting flags of what it finds at the
/// path of `node` ([`clear_restricting_flags`]): only where the node says
/// which flags its file had ([`node_flags`]), so that the late flags pass
/// puts those back. Otherwise what the restore finds keeps its flags, as in
/// stock rustic, and where they refuse the restore its error says so.
pub(crate) fn node_sets_flags(node: &Node, known_bko: bool) -> bool {
    node_flags(node, known_bko).is_some()
}

/// Whether listing a directory can leave its access time as it was: on Linux
/// and Android, with `O_NOATIME` (where the user may ask for it). Elsewhere
/// on Unix every listing moves it, unless the file system doesn't keep
/// access times (read-only, `noatime`, ZFS's `atime=off`). Not a Unix
/// (Windows): as stock rustic.
pub(crate) const LISTING_KEEPS_ATIMES: bool =
    cfg!(any(target_os = "linux", target_os = "android")) || !cfg!(unix);

/// Whether a backup skips scanning the source for its size first (as
/// `--no-scan`), as BackOtter's restic does, when it stores real access
/// times (`--set-atime yes`, `real_atimes`) where listing a directory moves
/// its access time (`listing_keeps_atimes` false: Unix but Linux): the scan
/// would list each directory before the backup takes its metadata, and the
/// snapshot would have the scan's time as its access time. With atimes
/// stored as the mtime (the default) or not at all, the scan runs, as in
/// stock rustic, on every system.
pub(crate) const fn scan_moves_saved_atimes(real_atimes: bool, listing_keeps_atimes: bool) -> bool {
    real_atimes && !listing_keeps_atimes
}

/// Clears the flags of the file at `path` (not following a symlink) that
/// would keep the restore from rewriting, replacing or changing it, before
/// the restore touches a file it finds in its way, as BackOtter's restic
/// does: immutable, append-only and undeletable on the BSDs (`schg`,
/// `uchg`, `sappnd`, `uappnd`, `sunlnk`, `uunlnk`) and ZFS's DOS read-only
/// on FreeBSD (`urdonly`), immutable and append-only on Linux (`i`, `a`). The
/// others stay as they are; the late flags pass gives the file its node's.
/// Nothing there, or no such flags, is nothing to do. A failure (a
/// securelevel above 0, not root) is only logged: what the restore does
/// next to the file fails and says why.
pub(crate) fn clear_restricting_flags(path: &Path) {
    // BackOtter: past PATH_MAX, through a short path to it; the message
    // names `path`.
    match os::clear_restricting_flags(&walkdir::short_path(path)) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => {
            debug!("restricting flags of {} not cleared: {err}", path.display());
        }
        _ => {}
    }
}

/// BackOtter: the restricting flags [`clear_restricting_flags_held`] took off
/// a file, held for [`HeldFlags::put_back`].
#[derive(Debug)]
pub(crate) enum HeldFlags {
    /// None came off: nothing there, none set, or not cleared.
    Nothing,
    /// The flags `cleared` came off the file open as `file`, at `path`.
    #[cfg_attr(
        not(any(
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "linux",
            target_os = "netbsd",
            target_os = "openbsd"
        )),
        allow(dead_code)
    )]
    Held {
        file: File,
        cleared: u32,
        path: PathBuf,
    },
    /// They came off by path, from the file `dev` and `ino` (a symlink on
    /// the BSDs, which can't be opened), which had other names (`linked`).
    #[cfg_attr(
        not(any(
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd"
        )),
        allow(dead_code)
    )]
    ByPath {
        path: PathBuf,
        dev: u64,
        ino: u64,
        linked: bool,
        cleared: u32,
    },
}

impl HeldFlags {
    /// Sets the flags that came off again on the file they came off, through
    /// the descriptor held open since, wherever its names are by then, so
    /// that its other names, outside the destination too, keep them; a file
    /// left without a name needs none. One cleared by path gets them back
    /// where it still is; once that name is gone, one that had other names
    /// may have lost them, and the error says so.
    ///
    /// # Errors
    ///
    /// * If they couldn't be set again.
    pub(crate) fn put_back(self) -> io::Result<()> {
        match self {
            Self::Nothing => Ok(()),
            #[cfg(unix)]
            Self::Held {
                file,
                cleared,
                path,
            } => {
                use std::os::unix::fs::MetadataExt;
                if file.metadata()?.nlink() == 0 {
                    return Ok(());
                }
                #[cfg(target_os = "linux")]
                return os::put_back_restricting_flags(&file, &path, cleared);
                #[cfg(any(
                    target_os = "dragonfly",
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd"
                ))]
                return bsd_held::put_back_restricting_flags(&file, &path, cleared);
                #[allow(unreachable_code)]
                {
                    _ = (cleared, path);
                    Ok(())
                }
            }
            #[cfg(unix)]
            Self::ByPath {
                path,
                dev,
                ino,
                linked,
                cleared,
            } => {
                use std::os::unix::fs::MetadataExt;
                match std::fs::symlink_metadata(&path) {
                    Ok(m) if (m.dev(), m.ino()) == (dev, ino) => {
                        #[cfg(any(
                            target_os = "dragonfly",
                            target_os = "freebsd",
                            target_os = "netbsd",
                            target_os = "openbsd"
                        ))]
                        return bsd_held::put_back_restricting_flags_path(&path, cleared);
                        #[allow(unreachable_code)]
                        {
                            _ = cleared;
                            Ok(())
                        }
                    }
                    _ if linked => Err(io::Error::other(format!(
                        "{} cleared by path and gone: its other names keep none of them",
                        path.display()
                    ))),
                    _ => Ok(()),
                }
            }
            #[cfg(not(unix))]
            _ => Ok(()),
        }
    }
}

/// BackOtter: [`clear_restricting_flags`] for a file whose name the restore
/// is about to remove, or rename another file over (a hard link broken, a
/// file replaced, linked over, or removed by `--delete`): the file is held
/// open (`O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY`) from before its flags
/// come off, and [`HeldFlags::put_back`], which must follow, once the name
/// is gone or wasn't, sets them again through that descriptor (`fchflags`,
/// Linux's ioctls). As in BackOtter's restic (`ClearRestrictingFlagsHeld`).
pub(crate) fn clear_restricting_flags_held(path: &Path) -> HeldFlags {
    // BackOtter: past PATH_MAX, through a short path to it (`sys`); the
    // messages name `path`, as does `put_back`'s, which on Linux takes no
    // path but for them.
    let sys = &*walkdir::short_path(path);
    #[cfg(target_os = "linux")]
    let held = os::clear_restricting_flags_held(sys).map(|held| match held {
        HeldFlags::Held { file, cleared, .. } => HeldFlags::Held {
            file,
            cleared,
            path: path.to_path_buf(),
        },
        held => held,
    });
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    let held = bsd_held::clear_restricting_flags_held(sys);
    #[cfg(not(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd"
    )))]
    let held = os::clear_restricting_flags(sys).map(|()| HeldFlags::Nothing);
    match held {
        Ok(held) => held,
        Err(err) => {
            if err.kind() != io::ErrorKind::NotFound {
                debug!("restricting flags of {} not cleared: {err}", path.display());
            }
            HeldFlags::Nothing
        }
    }
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
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
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
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    os::restore_zfs_dos_flags(path, node_type, flags)
}

/// Sets the FAT attributes (Linux) of the file at `path`, of type
/// `node_type`, to `attrs`, before [`restore_file_flags`]: any write sets
/// archive again. Elsewhere nothing.
///
/// # Errors
///
/// * If they couldn't be set: an [`Unsupported`] error if the file system
///   isn't FAT, or refuses them as unsupported.
// Nothing to fail but on Linux.
#[cfg_attr(not(target_os = "linux"), allow(clippy::unnecessary_wraps))]
pub(crate) fn restore_fat_attrs(path: &Path, node_type: &NodeType, attrs: u32) -> io::Result<()> {
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    #[cfg(target_os = "linux")]
    return os::restore_fat_attrs(path, node_type, attrs);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, node_type, attrs);
        Ok(())
    }
}

/// Takes the XFS options (Linux) off the existing directory at `path`, which
/// the restore is about to put entries in, so that they inherit none of them
/// (XFS passes each to the entries a directory gets after it), and returns
/// those it had, if it took any off, for [`restore_xfs_options`] to put back
/// in the late pass where the directory's node has none. Only on XFS; an
/// error leaves the directory as it is. Elsewhere nothing.
pub(crate) fn clear_dir_xfs_options(path: &Path) -> Option<XfsOptions> {
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    #[cfg(target_os = "linux")]
    return os::clear_dir_xfs_options(path);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        None
    }
}

/// Sets the XFS options (Linux) of the file at `path`, of type `node_type`,
/// to `opts`, before [`restore_file_flags`]. Elsewhere nothing.
///
/// # Errors
///
/// * If they couldn't be set: an [`Unsupported`] error if the file system
///   isn't XFS, or refuses them (`EINVAL`: a new extent size hint on a file
///   that has data); a directory refused realtime inheritance alone
///   (`EINVAL`: with an extent size hint's inheritance whose size isn't a
///   multiple of the realtime extent size) gets the rest, with an
///   [`Unsupported`] error for bit `0x100`.
// Nothing to fail but on Linux.
#[cfg_attr(not(target_os = "linux"), allow(clippy::unnecessary_wraps))]
pub(crate) fn restore_xfs_options(
    path: &Path,
    node_type: &NodeType,
    opts: &XfsOptions,
) -> io::Result<()> {
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    #[cfg(target_os = "linux")]
    return os::restore_xfs_options(path, node_type, opts);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, node_type, opts);
        Ok(())
    }
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
#[allow(unsafe_code)]
fn os_preallocate(f: &File, len: u64) -> io::Result<()> {
    use sparse::seek::lfs::{fallocate, off_t};
    use std::os::fd::AsRawFd;

    // Not on btrfs but for a NOCOW file, nor on bcachefs: they never
    // compress what fallocate(2) allocated (sparse::allocates_type).
    if !sparse::allocates_on(f) {
        return Ok(());
    }
    let len = off_t::try_from(len).map_err(io::Error::other)?;
    loop {
        // SAFETY: f is an open file. Mode 0 allocates holes and unwritten
        // space, and leaves data as it is.
        if unsafe { fallocate(f.as_raw_fd(), 0, 0, len) } == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(target_vendor = "apple")]
#[allow(unsafe_code)]
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

// The signature of the systems that can.
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
#[allow(clippy::unnecessary_wraps)]
fn os_preallocate(_f: &File, _len: u64) -> io::Result<()> {
    Ok(())
}

/// What [`fill_holes`] did: whether the file changed (it has more blocks
/// than before, which a failed `fallocate(2)` can leave too), and the error
/// that kept it from filling them all.
#[derive(Debug, Default)]
pub(crate) struct FilledHoles {
    /// Whether the file has more blocks allocated than before.
    pub(crate) changed: bool,
    /// Why its holes weren't all filled, where they weren't.
    pub(crate) error: Option<io::Error>,
}

/// Allocates the holes of the regular file at `path`, of `len` bytes, which
/// the restore leaves as it is and doesn't restore sparse: a swap file left
/// with holes by an interrupted restore. It looks first, without opening the
/// file for writing: only a file with fewer blocks than its size, where
/// `SEEK_HOLE` (where there is one) finds a hole, is opened for writing, so
/// that a file without holes (most, and those a file system compresses)
/// gets no close-write event, and a running program no `ETXTBSY`. On Linux
/// `fallocate(2)` fills them, except on ZFS, on btrfs but for a NOCOW file,
/// and on bcachefs (`sparse::allocates_type`). Elsewhere nothing is done, as
/// in BackOtter's restic: macOS's `F_PREALLOCATE` only adds space past the
/// end of a file, and nothing is written into a file whose contents are
/// right already.
pub(crate) fn fill_holes(path: &Path, len: u64) -> FilledHoles {
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    return sparse::fill_holes(path, len);
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        _ = (path, len);
        FilledHoles::default()
    }
}

/// Whether [`fill_holes`] would fill holes of the regular file at `path`, of
/// `len` bytes, looked at as it looks (never opened for writing): for
/// `restore --dry-run`, which counts such a file as one to modify, as
/// BackOtter's restic does.
pub(crate) fn holes_to_fill(path: &Path, len: u64) -> bool {
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    return sparse::holes_to_fill(path, len);
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        _ = (path, len);
        false
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
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    os::restore_owner(path, node)
}

/// Restores the attributes that go along with the extended attributes
/// (FreeBSD's and NetBSD's system extended attributes, illumos' extended
/// attributes' own metadata and ZFS project IDs, Haiku's typed attributes),
/// and warns once about each generic attribute that isn't known at all.
///
/// On Linux a node without a project ID had 0 in a snapshot of BackOtter's
/// (`known_bko`), which bcachefs then gets where the file inherited another;
/// in any other snapshot the file keeps the one it has or inherited. On
/// illumos such a node's file loses its ZFS project, and one without system
/// attributes gets a new file's, where it has others. On the BSDs a node
/// without file flags had none then (a new file's), and its file loses the
/// kept flags it has now, but for the restricting ones, which came off
/// before. On Linux likewise, for a regular file or directory: the inode
/// flags, and on ZFS and FAT the DOS flags and attributes, that a node
/// without `linux.inode_flags`, `linux.zfs_dos_flags` or `linux.fat_attrs`
/// didn't have.
///
/// `owners` says whether the restore sets owners (not `--no-ownership`): on
/// illumos each extended attribute has an owner and group of its own, set
/// only then.
///
/// # Errors
///
/// * If an attribute couldn't be set.
pub(crate) fn restore_attributes(
    path: &Path,
    node: &Node,
    known_bko: bool,
    owners: bool,
) -> io::Result<()> {
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    warn_unknown(node);
    #[cfg(any(
        target_os = "linux",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    {
        let _ = owners;
        os::restore_attributes(path, node, known_bko)
    }
    #[cfg(target_os = "illumos")]
    {
        os::restore_attributes(path, node, known_bko, owners)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "illumos",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    )))]
    {
        let _ = (known_bko, owners);
        os::restore_attributes(path, node)
    }
}

/// BackOtter: whether `now`, the value of the generic attribute `name` a
/// backup would record for a file, is `want`, a node's, as a restore leaves
/// it: the same, or, where the restore sets no owners (`ownership` false:
/// `--no-ownership`, or not running as root), illumos' extended attributes'
/// metadata the same but for their owners and groups, which it leaves.
pub(crate) fn same_generic_attribute(
    name: &str,
    now: &serde_json::Value,
    want: &serde_json::Value,
    ownership: bool,
) -> bool {
    now == want
        || (!ownership
            && name == ILLUMOS_XATTR_META
            && illumos_xattrmeta::same_but_owners(now, want))
}

/// BackOtter: `value`, the generic attribute `name` of a node whose
/// extended attributes are `xattrs`, as a restore of that node sets it, or
/// none where it sets nothing for it. That is `value` itself, but for
/// illumos' extended attributes' metadata, which a restore sets only for
/// the attributes the node has values for
/// ([`illumos_xattrmeta::held_only`]): a node has that of one a backup left
/// out as well, and a file the restore took that attribute off (or a new
/// one, which never had it) then never matched its node, so that every
/// `--exact` run set its metadata again (the review of ForkAudit1 G5-07's
/// fix).
pub(crate) fn generic_attribute_as_restored<'a>(
    name: &str,
    value: &'a serde_json::Value,
    xattrs: &[ExtendedAttribute],
) -> Option<Cow<'a, serde_json::Value>> {
    if name != ILLUMOS_XATTR_META {
        return Some(Cow::Borrowed(value));
    }
    illumos_xattrmeta::held_only(value, |name| xattrs.iter().any(|a| a.name == name))
}

/// Restores the ACLs. This goes after the mode: `chmod(2)` rewrites an
/// NFSv4 ACL, and setting an ACL sets the mode's permission bits.
///
/// On illumos a node without an ACL had a trivial one in a snapshot of
/// BackOtter's (`known_bko`): the file gets its mode's then, in place of any
/// other it has, which `chmod(2)` doesn't always take off. In any other
/// snapshot the file keeps the ACL it has.
///
/// On FreeBSD and NetBSD a node without an ACL had none that says more than
/// its mode in such a snapshot: an ACL the file has then goes (an NFSv4 one
/// becomes the mode's trivial one, a POSIX.1e access ACL its three entries,
/// a default ACL nothing), which `chmod(2)` doesn't see to either.
///
/// # Errors
///
/// * If an ACL couldn't be set.
pub(crate) fn restore_acls(path: &Path, node: &Node, known_bko: bool) -> io::Result<()> {
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    #[cfg(any(target_os = "illumos", target_os = "freebsd", target_os = "netbsd"))]
    {
        os::restore_acls(path, node, known_bko)
    }
    #[cfg(not(any(target_os = "illumos", target_os = "freebsd", target_os = "netbsd")))]
    {
        let _ = known_bko;
        os::restore_acls(path, node)
    }
}

/// BackOtter: whether a node without the generic attribute `name` leaves
/// what the file has as it is in a snapshot of BackOtter's too, where a
/// missing attribute otherwise says the file had none ([`node_flags`]):
/// FreeBSD's and NetBSD's system extended attributes, which only root can
/// list, so that a backup by another user records none for a file that has
/// some. `restore --exact` then doesn't count them as a difference.
pub(crate) fn absent_is_unknown(name: &str) -> bool {
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    {
        freebsd_netbsd::absent_is_unknown(name)
    }
    #[cfg(not(any(target_os = "freebsd", target_os = "netbsd")))]
    {
        let _ = name;
        false
    }
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
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
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
    node.meta
        .mtime
        .filter(|&mtime| birth < mtime)
        .map(|_| birth)
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
    match utimensat_nofollow(path, None, Some(birth)) {
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
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    utimensat_nofollow(path, Some(atime), Some(mtime))
}

/// Sets the atime of the file at `path` alone, not following a symlink, to
/// the nanosecond, with `utimensat(2)` and the mtime omitted: on NetBSD's
/// FFS that leaves the change time as it is, which setting the mtime with
/// it doesn't. `--exact` puts back the atimes the restore's own reads moved
/// with it (`commands::restore::exact`).
///
/// # Errors
///
/// * If the atime can't be set.
#[cfg(target_os = "netbsd")]
pub(crate) fn set_atime(path: &Path, atime: Timestamp) -> io::Result<()> {
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    utimensat_nofollow(path, Some(atime), None)
        .map_err(|err| path_error("utimensat (atime)", path, &err))
}

/// Sets the atime and mtime of the file at `path`, each unless it is
/// `None` (`UTIME_OMIT`), with `utimensat(2)` and `AT_SYMLINK_NOFOLLOW`, to
/// the nanosecond.
#[cfg(any(target_os = "dragonfly", target_os = "freebsd", target_os = "netbsd"))]
#[allow(unsafe_code)]
fn utimensat_nofollow(
    path: &Path,
    atime: Option<Timestamp>,
    mtime: Option<Timestamp>,
) -> io::Result<()> {
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
    let times = [spec(atime), spec(mtime)];
    // SAFETY: p is a C string, times two timespecs.
    let r = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            p.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
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
    // BackOtter: past PATH_MAX, through a short path to it.
    let path = &*walkdir::short_path(path);
    os::restore_symlink_mode(path, node)
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
        let mut warned = WARNED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
    target_os = "linux",
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
    target_os = "haiku",
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
/// FreeBSD, OpenBSD, NetBSD and DragonFly keep (`fchmodat(2)` with
/// `AT_SYMLINK_NOFOLLOW`; OpenBSD has no `lchmod(2)`), and `ls(1)` and
/// `mtree(8)` show, though access doesn't depend on them. Without this a
/// restored symlink gets 0755. A file system that keeps none only goes to
/// the debug log.
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
#[allow(unsafe_code)]
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

#[cfg(test)]
mod tests;
