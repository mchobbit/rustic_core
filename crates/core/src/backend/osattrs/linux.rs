//! Linux: the inode flags `chattr(1)` sets (`FS_IOC_GETFLAGS`), the project
//! ID (`FS_IOC_FSGETXATTR`) that project quotas count by, and the DOS flags
//! ZFS keeps for SMB (`ZFS_IOC_GETDOSFLAGS`).

use std::{
    fs::{File, Metadata, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

use jiff::Timestamp;
use log::{debug, warn};

use super::{Unsupported, XattrErrors, path_error, set_flags_best_effort, unsupported};
use crate::backend::node::{
    ExtendedAttribute, Node, NodeType,
    generic_attributes::{LINUX_INODE_FLAGS, LINUX_PROJECT_ID, LINUX_ZFS_DOS_FLAGS},
};

pub(super) const FILE_FLAGS: Option<&str> = Some(LINUX_INODE_FLAGS);
pub(super) const ZFS_DOS_FLAGS: Option<&str> = Some(LINUX_ZFS_DOS_FLAGS);

/// From `<linux/fs.h>`: the inode flags `chattr(1)` sets, s u c S i a d A m
/// j t D T C P, and casefolding (F). The rest belong to the file system
/// (extents, inline data, ...) or need more than setting (DAX, verity,
/// encryption).
const INODE_FLAGS: u32 = 0x0000_0001 // FS_SECRM_FL        s
    | 0x0000_0002 // FS_UNRM_FL         u
    | 0x0000_0004 // FS_COMPR_FL        c
    | 0x0000_0008 // FS_SYNC_FL         S
    | FS_IMMUTABLE_FL //                i
    | FS_APPEND_FL //                   a
    | 0x0000_0040 // FS_NODUMP_FL       d
    | 0x0000_0080 // FS_NOATIME_FL      A
    | 0x0000_0400 // FS_NOCOMP_FL       m
    | 0x0000_4000 // FS_JOURNAL_DATA_FL j
    | 0x0000_8000 // FS_NOTAIL_FL       t
    | 0x0001_0000 // FS_DIRSYNC_FL      D
    | 0x0002_0000 // FS_TOPDIR_FL       T
    | 0x0080_0000 // FS_NOCOW_FL        C
    | 0x2000_0000 // FS_PROJINHERIT_FL  P
    | FS_CASEFOLD_FL; //                F

const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
const FS_APPEND_FL: u32 = 0x0000_0020;

/// Case-insensitive names in a directory (ext4, f2fs).
const FS_CASEFOLD_FL: u32 = 0x4000_0000;

/// The flags a file system only takes while a file is empty: btrfs ignores
/// `FS_NOCOW_FL` on a file with data, without an error.
pub(super) const FLAGS_BEFORE_DATA: u32 = 0x0080_0000; // FS_NOCOW_FL

/// The flags a file system only takes while a directory is empty: ext4 and
/// f2fs refuse to change `FS_CASEFOLD_FL` on one with entries.
pub(super) const FLAGS_BEFORE_ENTRIES: u32 = FS_CASEFOLD_FL;

/// The flags set once a file has everything else: all but those
/// [`prepare_dir_for_flags`] sets, which stay as they are by then.
const KEPT_LATE: u32 = INODE_FLAGS & !FLAGS_BEFORE_ENTRIES;

/// btrfs's compression property, which every `FS_IOC_SETFLAGS` rewrites.
const BTRFS_COMPRESSION: &str = "btrfs.compression";

/// The extended attributes [`restore_file_flags`] needs.
pub(super) const FLAGS_XATTRS: &[&str] = &[BTRFS_COMPRESSION];

/// `struct fsxattr` from `<linux/fs.h>`, which `FS_IOC_FSGETXATTR` and
/// `FS_IOC_FSSETXATTR` take.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct FsXattr {
    xflags: u32,
    extsize: u32,
    nextents: u32,
    projid: u32,
    cowextsize: u32,
    pad: [u8; 8],
}

const FS_IOC_FSGETXATTR: libc::Ioctl = libc::_IOR::<FsXattr>(0x58, 31); // 'X'
const FS_IOC_FSSETXATTR: libc::Ioctl = libc::_IOW::<FsXattr>(0x58, 32); // 'X'

// fsxattr's xflags for FS_IMMUTABLE_FL and FS_APPEND_FL.
const FS_XFLAG_IMMUTABLE: u32 = 0x0000_0008;
const FS_XFLAG_APPEND: u32 = 0x0000_0010;

/// statfs's `f_type` for ZFS.
const ZFS_SUPER_MAGIC: u32 = 0x2fc1_2fc1;

/// statfs's `f_type` for bcachefs.
const BCACHEFS_SUPER_MAGIC: u32 = 0xca45_1a4e;

/// The extended attribute that shows a bcachefs file's project ID.
const BCACHEFS_PROJECT: &str = "bcachefs_effective.project";

// OpenZFS's DOS flags, from its <sys/fs/zfs.h> (Linux only): a uint64_t,
// on a descriptor of the file itself. ZFS_IOC_SETDOSFLAGS replaces all the
// flags ZFS_IOC_GETDOSFLAGS shows.
const ZFS_IOC_GETDOSFLAGS: libc::Ioctl = libc::_IOR::<u64>(0x83, 1);
const ZFS_IOC_SETDOSFLAGS: libc::Ioctl = libc::_IOW::<u64>(0x83, 2);

/// The DOS flags kept: those `ZFS_IOC_SETDOSFLAGS` sets, but immutable,
/// append-only and nodump, which are inode flags too (`i`, `a`, `d`), and
/// reparse, which it refuses to change (`EPERM`).
const ZFS_DOS_KEPT: u64 = 0x0000_0001_0000_0000 // ZFS_READONLY
    | 0x0000_0002_0000_0000 // ZFS_HIDDEN
    | 0x0000_0004_0000_0000 // ZFS_SYSTEM
    | ZFS_ARCHIVE
    | 0x0000_0020_0000_0000 // ZFS_NOUNLINK
    | 0x0000_1000_0000_0000 // ZFS_OFFLINE
    | 0x0000_2000_0000_0000; // ZFS_SPARSE

/// The DOS flag every new file gets, and every write of its contents sets
/// again.
const ZFS_ARCHIVE: u64 = 0x0000_0008_0000_0000;

/// Opens a regular file or directory for `FS_IOC_GETFLAGS` and
/// `FS_IOC_SETFLAGS`, as `lsattr(1)` and `chattr(1)` do, so as not to follow
/// a symlink, wait on a lock or take a terminal. Other types of file have no
/// flags, and opening a device or FIFO could have side effects. An error if
/// what it opens isn't of type `typ`, or, given `listed` (the backup's
/// lstat), isn't that file.
fn open_for_flags(path: &Path, typ: &NodeType, listed: Option<&Metadata>) -> io::Result<File> {
    let mut how = libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY;
    let dir = match typ {
        NodeType::File => false,
        NodeType::Dir => {
            how |= libc::O_DIRECTORY;
            true
        }
        _ => return Err(io::Error::from(io::ErrorKind::Unsupported)),
    };
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(how)
        .open(path)
        .map_err(|err| path_error("open", path, &err))?;
    let m = f.metadata().map_err(|err| path_error("fstat", path, &err))?;
    let replaced = listed.is_some_and(|l| (l.dev(), l.ino()) != (m.dev(), m.ino()));
    if (if dir { !m.is_dir() } else { !m.is_file() }) || replaced {
        return Err(io::Error::other(format!(
            "{} was replaced while it was read",
            path.display()
        )));
    }
    Ok(f)
}

/// Opens the regular file or directory at `path`, with metadata `m` (its
/// lstat), once for its flags, project ID and holes. `None` for other types
/// of file, and where it can't be opened (not readable, gone, replaced):
/// then it has none of those.
pub(super) fn open_for_attrs(path: &Path, typ: &NodeType, m: &Metadata) -> Option<File> {
    if !matches!(typ, NodeType::File | NodeType::Dir) {
        return None;
    }
    // Not readable (not root) or gone: the backup reports that for the
    // contents, if it matters.
    open_for_flags(path, typ, Some(m))
        .inspect_err(|err| debug!("no file flags, project ID or holes: {err}"))
        .ok()
}

fn get_flags(f: &File) -> io::Result<u32> {
    let mut flags: libc::c_int = 0;
    // SAFETY: FS_IOC_GETFLAGS writes an int to the pointer.
    if unsafe { libc::ioctl(f.as_raw_fd(), libc::FS_IOC_GETFLAGS, &raw mut flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(u32::from_ne_bytes(flags.to_ne_bytes()))
}

fn set_flags(f: &File, flags: u32) -> io::Result<()> {
    let flags = libc::c_int::from_ne_bytes(flags.to_ne_bytes());
    // SAFETY: FS_IOC_SETFLAGS reads an int from the pointer.
    if unsafe { libc::ioctl(f.as_raw_fd(), libc::FS_IOC_SETFLAGS, &raw const flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn get_fsxattr(f: &File) -> io::Result<FsXattr> {
    let mut attr = FsXattr::default();
    // SAFETY: FS_IOC_FSGETXATTR writes a struct fsxattr to the pointer.
    if unsafe { libc::ioctl(f.as_raw_fd(), FS_IOC_FSGETXATTR, &raw mut attr) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(attr)
}

fn set_fsxattr(f: &File, attr: &FsXattr) -> io::Result<()> {
    // SAFETY: FS_IOC_FSSETXATTR reads a struct fsxattr from the pointer.
    if unsafe { libc::ioctl(f.as_raw_fd(), FS_IOC_FSSETXATTR, &raw const *attr) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether the file `f` is on the file system whose statfs `f_type` is
/// `magic`.
fn is_on(f: &File, magic: u32) -> io::Result<bool> {
    let mut st = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fstatfs writes a struct statfs to the pointer.
    if unsafe { libc::fstatfs(f.as_raw_fd(), st.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatfs succeeded, so it wrote the struct.
    let st = unsafe { st.assume_init() };
    Ok(u32::try_from(st.f_type).is_ok_and(|t| t == magic))
}

/// Whether the file `f` is on ZFS: the DOS flag ioctls go to no other file
/// system, whose driver could take their numbers for something else.
fn is_zfs(f: &File) -> io::Result<bool> {
    is_on(f, ZFS_SUPER_MAGIC)
}

/// The project ID of the file `f`, whose `FS_IOC_FSGETXATTR` gave `attr`.
/// bcachefs (Linux 6.12) gives there the ID the file had when its inode
/// was read in, 0 for one set since (`chattr -p`, a restore), until it is
/// read in again; the ID it has is in the extended attribute
/// `bcachefs_effective.project`, which is taken where there is one.
fn file_projid(f: &File, attr: &FsXattr) -> u32 {
    if !is_on(f, BCACHEFS_SUPER_MAGIC).unwrap_or(false) {
        return attr.projid;
    }
    get_xattr(f, BCACHEFS_PROJECT)
        .ok()
        .and_then(|value| String::from_utf8(value).ok())
        .and_then(|value| value.trim_end_matches('\0').trim().parse().ok())
        .unwrap_or(attr.projid)
}

/// The value of the extended attribute `name` of the file `f`.
fn get_xattr(f: &File, name: &str) -> io::Result<Vec<u8>> {
    let name = std::ffi::CString::new(name.as_bytes()).map_err(io::Error::from)?;
    let mut value = vec![0_u8; 64];
    loop {
        // SAFETY: name is a C string, value a buffer of its length.
        let n = unsafe {
            libc::fgetxattr(f.as_raw_fd(), name.as_ptr(), value.as_mut_ptr().cast(), value.len())
        };
        if let Ok(n) = usize::try_from(n) {
            value.truncate(n);
            return Ok(value);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ERANGE) || value.len() >= 1 << 16 {
            return Err(err);
        }
        value.resize(value.len() * 4, 0);
    }
}

fn get_dos_flags(f: &File) -> io::Result<u64> {
    let mut flags: u64 = 0;
    // SAFETY: ZFS_IOC_GETDOSFLAGS writes a uint64_t to the pointer.
    if unsafe { libc::ioctl(f.as_raw_fd(), ZFS_IOC_GETDOSFLAGS, &raw mut flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags)
}

fn set_dos_flags(f: &File, flags: u64) -> io::Result<()> {
    // SAFETY: ZFS_IOC_SETDOSFLAGS reads a uint64_t from the pointer.
    if unsafe { libc::ioctl(f.as_raw_fd(), ZFS_IOC_SETDOSFLAGS, &raw const flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Sets the extended attribute `name` of the file `f` to `value`.
fn set_xattr(f: &File, name: &str, value: &[u8]) -> io::Result<()> {
    let name = std::ffi::CString::new(name.as_bytes()).map_err(io::Error::from)?;
    // SAFETY: name is a C string, value a buffer of its length.
    if unsafe { libc::fsetxattr(f.as_raw_fd(), name.as_ptr(), value.as_ptr().cast(), value.len(), 0) }
        < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The flags a file that has `current` gets for `flags`: the [`KEPT_LATE`]
/// flags of `flags`, and the file system's own and casefolding as they are.
const fn wanted_flags(current: u32, flags: u32) -> u32 {
    (current & !KEPT_LATE) | (flags & KEPT_LATE)
}

pub(super) fn file_flags(
    path: &Path,
    _typ: &NodeType,
    _m: &Metadata,
    f: Option<&File>,
) -> io::Result<Option<u32>> {
    let Some(f) = f else {
        return Ok(None);
    };
    // A file system without inode flags (ENOTTY, EOPNOTSUPP, ...).
    let flags = get_flags(f);
    Ok(Some(
        flags
            .inspect_err(|err| debug!("no file flags for {}: {err}", path.display()))
            .unwrap_or_default()
            & INODE_FLAGS,
    )
    .filter(|&flags| flags != 0))
}

/// Records the project ID of a regular file or directory, unless it is 0,
/// and on ZFS its DOS flags ([`dos_flags_attribute`]).
pub(super) fn fill_attributes(path: &Path, node: &mut Node, f: Option<&File>) -> io::Result<()> {
    let Some(f) = f else {
        return Ok(());
    };
    let dos_flags = fill_dos_flags(path, node, f);
    match get_fsxattr(f) {
        Ok(attr) => node.meta.generic_attributes.set_number(LINUX_PROJECT_ID, file_projid(f, &attr)),
        Err(err) if unsupported(&err) => {}
        Err(err) => return Err(path_error("FS_IOC_FSGETXATTR", path, &err)),
    }
    dos_flags
}

/// Records the DOS flags of the file `f` at `path`, if it is on ZFS and they
/// are worth an attribute. A ZFS without them (`ENOTTY`, ...) only goes to
/// the debug log.
fn fill_dos_flags(path: &Path, node: &mut Node, f: &File) -> io::Result<()> {
    if !is_zfs(f).map_err(|err| path_error("fstatfs", path, &err))? {
        return Ok(());
    }
    match get_dos_flags(f) {
        Ok(flags) => {
            if let Some(flags) = dos_flags_attribute(flags) {
                node.meta.generic_attributes.set_u64(LINUX_ZFS_DOS_FLAGS, flags);
            }
        }
        Err(err) if unsupported(&err) => {
            debug!("no ZFS DOS flags for {}: {err}", path.display());
        }
        Err(err) => return Err(path_error("ZFS_IOC_GETDOSFLAGS", path, &err)),
    }
    Ok(())
}

/// What `linux.zfs_dos_flags` records for a file with the DOS flags
/// `flags`: the [`ZFS_DOS_KEPT`] ones, 0 included (archive cleared), unless
/// they are archive alone, which a file restored without the attribute gets
/// anyway when it is written.
const fn dos_flags_attribute(flags: u64) -> Option<u64> {
    let kept = flags & ZFS_DOS_KEPT;
    if kept == ZFS_ARCHIVE { None } else { Some(kept) }
}

pub(super) fn restore_file_flags(
    path: &Path,
    typ: &NodeType,
    flags: u32,
    xattrs: &[ExtendedAttribute],
) -> io::Result<()> {
    let f = open_for_flags(path, typ, None)?;
    let current = get_flags(&f).map_err(|err| {
        if unsupported(&err) {
            Unsupported::error(LINUX_INODE_FLAGS, (flags & INODE_FLAGS).into(), err)
        } else {
            path_error("FS_IOC_GETFLAGS", path, &err)
        }
    })?;
    if casefold_differs(typ, current, flags) {
        warn!(
            "casefolding (F) not restored on {}: directory not empty or not supported",
            path.display()
        );
    }
    let compression = xattrs
        .iter()
        .find(|attr| attr.name == BTRFS_COMPRESSION)
        .and_then(|attr| attr.value.as_deref());
    restore_flags_with(
        path,
        current,
        flags,
        compression,
        |flags| set_flags(&f, flags),
        |value| set_xattr(&f, BTRFS_COMPRESSION, value),
        |xflags| {
            let mut attr = get_fsxattr(&f)?;
            attr.xflags |= xflags;
            set_fsxattr(&f, &attr)
        },
    )
}

/// Gives the regular file or directory at `path` the DOS flags `flags`
/// (`linux.zfs_dos_flags`), on ZFS, before its inode flags, which leave them
/// as they are.
pub(super) fn restore_zfs_dos_flags(path: &Path, typ: &NodeType, flags: u64) -> io::Result<()> {
    let f = open_for_flags(path, typ, None)?;
    let unsupported_err = |err: io::Error| Unsupported::error(LINUX_ZFS_DOS_FLAGS, 0, err);
    if !is_zfs(&f).map_err(|err| path_error("fstatfs", path, &err))? {
        return Err(unsupported_err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("ZFS DOS flags {flags:#x} not restored: not ZFS"),
        )));
    }
    let current = get_dos_flags(&f).map_err(|err| {
        if unsupported(&err) {
            unsupported_err(err)
        } else {
            path_error("ZFS_IOC_GETDOSFLAGS", path, &err)
        }
    })?;
    restore_dos_flags_with(path, current, flags, |flags| set_dos_flags(&f, flags))
}

/// The DOS flags a file that has `current` gets for `flags`: the
/// [`ZFS_DOS_KEPT`] flags of `flags`, and immutable, append-only, nodump and
/// reparse as they are, since `ZFS_IOC_SETDOSFLAGS` sets them all.
const fn wanted_dos_flags(current: u64, flags: u64) -> u64 {
    (current & !ZFS_DOS_KEPT) | (flags & ZFS_DOS_KEPT)
}

/// Gives a file that has the DOS flags `current` the [`ZFS_DOS_KEPT`] flags
/// of `flags`, with `set`, unless it has them already.
fn restore_dos_flags_with(
    path: &Path,
    current: u64,
    flags: u64,
    mut set: impl FnMut(u64) -> io::Result<()>,
) -> io::Result<()> {
    if wanted_dos_flags(current, flags) == current {
        return Ok(());
    }
    let own = current & !ZFS_DOS_KEPT;
    set_flags_best_effort(
        LINUX_ZFS_DOS_FLAGS,
        path,
        "ZFS_IOC_SETDOSFLAGS",
        Some(current & ZFS_DOS_KEPT),
        flags & ZFS_DOS_KEPT,
        |f| set(own | f),
    )
}

/// Whether the directory [`restore_file_flags`] gives `flags` has other
/// casefolding than `flags` say, which the restore only sets on an empty
/// directory ([`prepare_dir_for_flags`]): one that had entries already, or a
/// file system without casefolding.
const fn casefold_differs(typ: &NodeType, current: u32, flags: u32) -> bool {
    matches!(typ, NodeType::Dir) && (current ^ flags) & FS_CASEFOLD_FL != 0
}

/// Gives a file that has the flags `current` the [`KEPT_LATE`] flags of
/// `flags`, with `set`, unless it has them already. On btrfs every
/// `FS_IOC_SETFLAGS` rewrites the `btrfs.compression` property, restored
/// before as an extended attribute (or deletes it, without `FS_COMPR_FL`).
/// So for a file with the property (`compression`), `set` gets the flags
/// but immutable and append-only, `set_compression` puts the property back,
/// and `add_xflags` adds those two through `FS_IOC_FSSETXATTR`, which leaves
/// it alone.
fn restore_flags_with(
    path: &Path,
    current: u32,
    flags: u32,
    compression: Option<&[u8]>,
    mut set: impl FnMut(u32) -> io::Result<()>,
    mut set_compression: impl FnMut(&[u8]) -> io::Result<()>,
    mut add_xflags: impl FnMut(u32) -> io::Result<()>,
) -> io::Result<()> {
    if wanted_flags(current, flags) == current {
        return Ok(());
    }
    // Keep the file system's own flags and casefolding as they are.
    let own = current & !KEPT_LATE;
    let Some(compression) = compression else {
        return set_flags_best_effort(
            LINUX_INODE_FLAGS,
            path,
            "FS_IOC_SETFLAGS",
            Some(current & KEPT_LATE),
            flags & KEPT_LATE,
            |f| set(own | f),
        );
    };
    let late = flags & (FS_IMMUTABLE_FL | FS_APPEND_FL);
    let first = flags & KEPT_LATE & !late;
    let set_first = if own | first == current {
        Ok(())
    } else {
        set_flags_best_effort(
            LINUX_INODE_FLAGS,
            path,
            "FS_IOC_SETFLAGS",
            Some(current & KEPT_LATE),
            first,
            |f| set(own | f),
        )
    };
    let set_property = set_compression(compression)
        .map_err(|err| path_error(&format!("set {BTRFS_COMPRESSION} of"), path, &err));
    let mut xflags = 0;
    if late & FS_IMMUTABLE_FL != 0 {
        xflags |= FS_XFLAG_IMMUTABLE;
    }
    if late & FS_APPEND_FL != 0 {
        xflags |= FS_XFLAG_APPEND;
    }
    let set_late = match xflags {
        0 => Ok(()),
        _ => add_xflags(xflags).map_err(|err| {
            if unsupported(&err) {
                Unsupported::error(LINUX_INODE_FLAGS, late.into(), err)
            } else {
                path_error("FS_IOC_FSSETXATTR", path, &err)
            }
        }),
    };
    set_first.and(set_property).and(set_late)
}

pub(super) fn prepare_file_for_flags(path: &Path, flags: u32) -> io::Result<()> {
    let f = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        // The restore decides what to do with an existing file.
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
        Err(err) => return Err(path_error("create", path, &err)),
    };
    let current = match get_flags(&f) {
        Ok(current) => current,
        Err(err) if unsupported(&err) => return Ok(()),
        Err(err) => return Err(path_error("FS_IOC_GETFLAGS", path, &err)),
    };
    // A file system without them (ext4 and XFS have no no-copy-on-write) is
    // no error here: restore_file_flags reports that later.
    match set_flags(&f, current | flags) {
        Err(err) if !unsupported(&err) => Err(path_error("FS_IOC_SETFLAGS", path, &err)),
        _ => Ok(()),
    }
}

pub(super) fn prepare_dir_for_flags(path: &Path, flags: u32) -> io::Result<()> {
    let f = open_for_flags(path, &NodeType::Dir, None)?;
    prepare_dir_with(flags, || get_flags(&f), |flags| set_flags(&f, flags))
        .map_err(|err| path_error("FS_IOC_SETFLAGS", path, &err))
}

/// Gives a directory exactly the [`FLAGS_BEFORE_ENTRIES`] of `flags`, with
/// `get` and `set`, setting them only if they differ. A file system without
/// them (btrfs and XFS have no casefolding) is no error here:
/// [`restore_file_flags`] reports that later.
fn prepare_dir_with(
    flags: u32,
    get: impl FnOnce() -> io::Result<u32>,
    set: impl FnOnce(u32) -> io::Result<()>,
) -> io::Result<()> {
    let current = match get() {
        Ok(current) => current,
        Err(err) if unsupported(&err) => return Ok(()),
        Err(err) => return Err(err),
    };
    let wanted = (current & !FLAGS_BEFORE_ENTRIES) | (flags & FLAGS_BEFORE_ENTRIES);
    if wanted == current {
        return Ok(());
    }
    match set(wanted) {
        Err(err) if !unsupported(&err) => Err(err),
        _ => Ok(()),
    }
}

/// The numeric owner the restore gives is all there is.
pub(super) fn restore_owner(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

/// Restores the project ID, along with the extended attributes. A project
/// ID of 0 is the default, and left as it is.
pub(super) fn restore_attributes(path: &Path, node: &Node) -> io::Result<()> {
    let projid = match node.meta.generic_attributes.number(LINUX_PROJECT_ID) {
        None | Some(0) => return Ok(()),
        Some(projid) => projid,
    };
    let classify = |op: &str, err: io::Error| {
        if unsupported(&err) {
            Unsupported::error(LINUX_PROJECT_ID, 0, err)
        } else {
            path_error(op, path, &err)
        }
    };
    let f = open_for_flags(path, &node.node_type, None)?;
    let mut attr = get_fsxattr(&f).map_err(|err| classify("FS_IOC_FSGETXATTR", err))?;
    if file_projid(&f, &attr) != projid {
        attr.projid = projid;
        set_fsxattr(&f, &attr).map_err(|err| classify("FS_IOC_FSSETXATTR", err))?;
    }
    Ok(())
}

pub(super) fn restore_acls(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

pub(super) fn restore_symlink_mode(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

/// Linux reads birth times (`statx(2)`), but has no call that sets one.
pub(super) fn restore_birthtime(_path: &Path, _node: &Node, _birth: Timestamp) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux can't set birth times"))
}

/// Extended attributes have no metadata of their own here.
pub(super) fn fill_xattr_meta(_path: &Path, _node: &mut Node) {}

/// Extended attributes go through the xattr crate here.
pub(super) fn xattrs(_path: &Path) -> io::Result<Vec<ExtendedAttribute>> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "extended attributes go through xattr"))
}

/// Extended attributes go through the xattr crate here.
pub(super) fn set_xattrs(_path: &Path, _attrs: &[ExtendedAttribute]) -> Result<(), XattrErrors> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "extended attributes go through xattr").into())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    const EXTENTS: u32 = 0x0008_0000; // FS_EXTENT_FL, ext4's own
    const COMPR: u32 = 0x0000_0004;
    const NODUMP: u32 = 0x0000_0040;
    const NOCOW: u32 = 0x0080_0000;

    #[test]
    fn fsxattr_ioctls() {
        assert_eq!(size_of::<FsXattr>(), 28);
        #[cfg(all(target_env = "gnu", any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            assert_eq!(FS_IOC_FSGETXATTR, 0x801c_581f);
            assert_eq!(FS_IOC_FSSETXATTR, 0x401c_5820);
        }
    }

    // OpenZFS's other DOS flags.
    const ZFS_READONLY: u64 = 0x0000_0001_0000_0000;
    const ZFS_HIDDEN: u64 = 0x0000_0002_0000_0000;
    const ZFS_SYSTEM: u64 = 0x0000_0004_0000_0000;
    const ZFS_IMMUTABLE: u64 = 0x0000_0010_0000_0000;
    const ZFS_APPENDONLY: u64 = 0x0000_0040_0000_0000;
    const ZFS_NODUMP: u64 = 0x0000_0080_0000_0000;
    const ZFS_REPARSE: u64 = 0x0000_0800_0000_0000;
    const ZFS_SPARSE: u64 = 0x0000_2000_0000_0000;

    #[test]
    fn zfs_dos_ioctls() {
        assert_eq!(ZFS_DOS_KEPT, 0x0000_302f_0000_0000);
        #[cfg(all(target_env = "gnu", any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            assert_eq!(ZFS_IOC_GETDOSFLAGS, 0x8008_8301);
            assert_eq!(ZFS_IOC_SETDOSFLAGS, 0x4008_8302);
        }
    }

    #[test]
    fn dos_flags_attribute_unless_archive_alone() {
        // A new or written file: no attribute.
        assert_eq!(dos_flags_attribute(ZFS_ARCHIVE), None);
        // Archive cleared: an attribute of 0.
        assert_eq!(dos_flags_attribute(0), Some(0));
        assert_eq!(dos_flags_attribute(ZFS_ARCHIVE | ZFS_HIDDEN), Some(ZFS_ARCHIVE | ZFS_HIDDEN));
        // Immutable, append-only and nodump are inode flags, reparse can't
        // be set: never stored.
        let others = ZFS_IMMUTABLE | ZFS_APPENDONLY | ZFS_NODUMP | ZFS_REPARSE;
        assert_eq!(dos_flags_attribute(ZFS_ARCHIVE | others), None);
        assert_eq!(dos_flags_attribute(others), Some(0));
        assert_eq!(dos_flags_attribute(ZFS_SYSTEM | others), Some(ZFS_SYSTEM));
    }

    #[test]
    fn wanted_dos_flags_keep_the_inode_flags() {
        let iad = ZFS_IMMUTABLE | ZFS_APPENDONLY | ZFS_NODUMP;
        assert_eq!(wanted_dos_flags(iad | ZFS_ARCHIVE, ZFS_HIDDEN), iad | ZFS_HIDDEN);
        assert_eq!(wanted_dos_flags(ZFS_REPARSE | ZFS_ARCHIVE, 0), ZFS_REPARSE);
        // Not even from a snapshot that has them.
        assert_eq!(wanted_dos_flags(ZFS_ARCHIVE, iad | ZFS_SYSTEM), ZFS_SYSTEM);
    }

    /// Runs [`restore_dos_flags_with`] on a file with the DOS flags
    /// `current`, where `set` refuses `refuse`, and returns its result and
    /// the flags it set.
    fn restore_dos_flags_calls(
        current: u64,
        flags: u64,
        refuse: u64,
    ) -> (io::Result<()>, Vec<u64>) {
        let mut calls = Vec::new();
        let result = restore_dos_flags_with(Path::new("f"), current, flags, |f| {
            calls.push(f);
            if f & refuse & ZFS_SPARSE != 0 {
                return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
            }
            if f & refuse != 0 {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(())
        });
        (result, calls)
    }

    #[test]
    fn restore_dos_flags_read_merge_write() {
        // As it should be: no ZFS_IOC_SETDOSFLAGS.
        let (result, calls) = restore_dos_flags_calls(ZFS_ARCHIVE | ZFS_NODUMP, ZFS_ARCHIVE, 0);
        assert!(result.is_ok());
        assert!(calls.is_empty());
        // Archive cleared, nodump kept.
        let (result, calls) = restore_dos_flags_calls(ZFS_ARCHIVE | ZFS_NODUMP, 0, 0);
        assert!(result.is_ok());
        assert_eq!(calls, [ZFS_NODUMP]);
        let (_, calls) = restore_dos_flags_calls(ZFS_ARCHIVE | ZFS_IMMUTABLE, ZFS_HIDDEN, 0);
        assert_eq!(calls, [ZFS_IMMUTABLE | ZFS_HIDDEN]);
    }

    #[test]
    fn restore_dos_flags_best_effort() {
        // Read-only refused (not permitted), hidden set: an error naming
        // read-only.
        let (result, calls) =
            restore_dos_flags_calls(ZFS_ARCHIVE, ZFS_READONLY | ZFS_HIDDEN, ZFS_READONLY);
        let err = result.unwrap_err();
        assert!(err.to_string().contains("0x100000000 of 0x300000000"), "{err}");
        assert_eq!(calls.last(), Some(&ZFS_HIDDEN));
        // Sparse not supported: a warning once.
        let (result, calls) =
            restore_dos_flags_calls(ZFS_NODUMP, ZFS_SPARSE | ZFS_SYSTEM, ZFS_SPARSE);
        let err = result.unwrap_err();
        let unsupported = err.get_ref().unwrap().downcast_ref::<Unsupported>().unwrap();
        assert_eq!((unsupported.attr, unsupported.bits), (LINUX_ZFS_DOS_FLAGS, ZFS_SPARSE));
        assert_eq!(
            calls,
            [
                ZFS_NODUMP | ZFS_SPARSE | ZFS_SYSTEM,
                ZFS_NODUMP | ZFS_SYSTEM,
                ZFS_NODUMP | ZFS_SYSTEM | ZFS_SPARSE
            ]
        );
    }

    #[test]
    fn zfs_dos_flags_round_trip() {
        // Only where the tests run on ZFS (TMPDIR on a ZFS data set).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        let m = std::fs::symlink_metadata(&path).unwrap();
        let f = open_for_attrs(&path, &NodeType::File, &m).unwrap();
        if !is_zfs(&f).unwrap() {
            // Not ZFS: no attribute, and a restore says so.
            let mut node = Node::default();
            fill_attributes(&path, &mut node, Some(&f)).unwrap();
            assert_eq!(node.meta.generic_attributes.number_u64(LINUX_ZFS_DOS_FLAGS), None);
            let err = restore_zfs_dos_flags(&path, &NodeType::File, ZFS_HIDDEN).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
            return;
        }
        let attribute = |path: &Path, typ: &NodeType| {
            let m = std::fs::symlink_metadata(path).unwrap();
            let mut node = Node::default();
            let f = open_for_attrs(path, typ, &m);
            fill_attributes(path, &mut node, f.as_ref()).unwrap();
            node.meta.generic_attributes.number_u64(LINUX_ZFS_DOS_FLAGS)
        };
        // A new file has archive: no attribute.
        assert_eq!(get_dos_flags(&f).unwrap(), ZFS_ARCHIVE);
        assert_eq!(attribute(&path, &NodeType::File), None);
        restore_zfs_dos_flags(&path, &NodeType::File, ZFS_HIDDEN | ZFS_SYSTEM).unwrap();
        assert_eq!(attribute(&path, &NodeType::File), Some(ZFS_HIDDEN | ZFS_SYSTEM));
        restore_zfs_dos_flags(&path, &NodeType::File, 0).unwrap();
        assert_eq!(attribute(&path, &NodeType::File), Some(0));
        // A write sets archive again.
        std::fs::write(&path, b"y").unwrap();
        assert_eq!(attribute(&path, &NodeType::File), None);
        restore_zfs_dos_flags(dir.path(), &NodeType::Dir, ZFS_HIDDEN).unwrap();
        assert_eq!(attribute(dir.path(), &NodeType::Dir), Some(ZFS_HIDDEN));
    }

    #[test]
    fn wanted_flags_keep_the_file_systems_own_and_casefolding() {
        assert_eq!(wanted_flags(EXTENTS | FS_IMMUTABLE_FL, FS_IMMUTABLE_FL), EXTENTS | FS_IMMUTABLE_FL);
        assert_eq!(wanted_flags(EXTENTS, FS_IMMUTABLE_FL | EXTENTS), EXTENTS | FS_IMMUTABLE_FL);
        assert_eq!(wanted_flags(EXTENTS | NOCOW, FS_IMMUTABLE_FL), EXTENTS | FS_IMMUTABLE_FL);
        // Casefolding stays as the directory has it, both ways.
        assert_eq!(
            wanted_flags(FS_CASEFOLD_FL, FS_IMMUTABLE_FL),
            FS_CASEFOLD_FL | FS_IMMUTABLE_FL
        );
        assert_eq!(wanted_flags(0, FS_CASEFOLD_FL | FS_IMMUTABLE_FL), FS_IMMUTABLE_FL);
    }

    #[test]
    fn casefold_differs_on_directories() {
        assert!(casefold_differs(&NodeType::Dir, 0, FS_CASEFOLD_FL));
        assert!(casefold_differs(&NodeType::Dir, FS_CASEFOLD_FL, NODUMP));
        assert!(!casefold_differs(&NodeType::Dir, FS_CASEFOLD_FL | EXTENTS, FS_CASEFOLD_FL));
        assert!(!casefold_differs(&NodeType::Dir, EXTENTS, NODUMP));
        assert!(!casefold_differs(&NodeType::File, 0, FS_CASEFOLD_FL));
    }

    /// Runs [`restore_flags_with`] on a file with the flags `current` and
    /// returns the calls it made.
    fn restore_flags_calls(current: u32, flags: u32, compression: Option<&[u8]>) -> Vec<String> {
        let calls = RefCell::new(Vec::new());
        restore_flags_with(
            Path::new("f"),
            current,
            flags,
            compression,
            |f| {
                calls.borrow_mut().push(format!("set {f:#x}"));
                Ok(())
            },
            |v| {
                calls
                    .borrow_mut()
                    .push(format!("compression {}", String::from_utf8_lossy(v)));
                Ok(())
            },
            |x| {
                calls.borrow_mut().push(format!("xflags {x:#x}"));
                Ok(())
            },
        )
        .unwrap();
        calls.into_inner()
    }

    #[test]
    fn restore_flags_only_what_differs() {
        // Nothing to change: no FS_IOC_SETFLAGS at all.
        assert!(restore_flags_calls(EXTENTS | NODUMP, NODUMP, None).is_empty());
        assert!(restore_flags_calls(FS_CASEFOLD_FL, FS_CASEFOLD_FL, None).is_empty());
        // Casefolding stays as it is, both ways.
        assert!(restore_flags_calls(FS_CASEFOLD_FL, 0, None).is_empty());
        assert!(restore_flags_calls(0, FS_CASEFOLD_FL, None).is_empty());
        assert_eq!(
            restore_flags_calls(FS_CASEFOLD_FL | EXTENTS, NODUMP, None),
            ["set 0x40080040"]
        );
        assert_eq!(restore_flags_calls(EXTENTS, FS_CASEFOLD_FL | NODUMP, None), ["set 0x80040"]);
    }

    #[test]
    fn restore_flags_keep_btrfs_compression() {
        let zstd = Some(&b"zstd"[..]);
        // Unchanged: the property stays as restored.
        assert!(restore_flags_calls(COMPR, COMPR, zstd).is_empty());
        assert_eq!(
            restore_flags_calls(COMPR, COMPR | NODUMP, zstd),
            ["set 0x44", "compression zstd"]
        );
        // Immutable last, through FS_IOC_FSSETXATTR.
        assert_eq!(
            restore_flags_calls(COMPR, COMPR | FS_IMMUTABLE_FL, zstd),
            ["compression zstd", "xflags 0x8"]
        );
        assert_eq!(
            restore_flags_calls(COMPR, COMPR | NODUMP | FS_APPEND_FL, zstd),
            ["set 0x44", "compression zstd", "xflags 0x10"]
        );
        // Without the property, as on any other file system.
        assert_eq!(restore_flags_calls(COMPR, COMPR | FS_IMMUTABLE_FL, None), ["set 0x14"]);
    }

    /// Runs [`prepare_dir_with`] on a directory with the flags `current` and
    /// returns what it set.
    fn prepare_dir_sets(current: io::Result<u32>, flags: u32) -> (io::Result<()>, Option<u32>) {
        let mut set = None;
        let result = prepare_dir_with(
            flags,
            || current,
            |f| {
                set = Some(f);
                Ok(())
            },
        );
        (result, set)
    }

    #[test]
    fn prepare_dir_sets_and_clears_casefolding() {
        // A directory that inherited casefolding, which its node lacks.
        let (result, set) = prepare_dir_sets(Ok(FS_CASEFOLD_FL | EXTENTS), 0);
        assert!(result.is_ok());
        assert_eq!(set, Some(EXTENTS));
        // One that should have it.
        let (_, set) = prepare_dir_sets(Ok(EXTENTS), FS_CASEFOLD_FL | NODUMP);
        assert_eq!(set, Some(FS_CASEFOLD_FL | EXTENTS));
        // As it should be: no FS_IOC_SETFLAGS.
        assert_eq!(prepare_dir_sets(Ok(FS_CASEFOLD_FL), FS_CASEFOLD_FL).1, None);
        assert_eq!(prepare_dir_sets(Ok(EXTENTS), NODUMP).1, None);
        // A file system without inode flags: nothing, and no error.
        let (result, set) =
            prepare_dir_sets(Err(io::Error::from_raw_os_error(libc::ENOTTY)), FS_CASEFOLD_FL);
        assert!(result.is_ok());
        assert_eq!(set, None);
    }

    #[test]
    fn no_project_id_no_attribute() {
        // A file a user creates has project ID 0, or the file system has no
        // project IDs: either way, no attribute; unless the directory the
        // tests run in has a project ID of its own, which files inherit.
        let dir = tempfile::tempdir().unwrap();
        let m = std::fs::symlink_metadata(dir.path()).unwrap();
        let f = open_for_attrs(dir.path(), &NodeType::Dir, &m);
        if f.as_ref().and_then(|f| get_fsxattr(f).ok()).is_some_and(|attr| attr.projid != 0) {
            return;
        }
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        let m = std::fs::symlink_metadata(&path).unwrap();
        let mut node = Node::default();
        let f = open_for_attrs(&path, &NodeType::File, &m);
        assert!(f.is_some());
        fill_attributes(&path, &mut node, f.as_ref()).unwrap();
        assert_eq!(node.meta.generic_attributes.number(LINUX_PROJECT_ID), None);
    }

    #[test]
    fn project_id_0_is_left_alone() {
        // Not even opened: a path that doesn't exist is no error.
        let mut node = Node::default();
        node.meta.generic_attributes.set(LINUX_PROJECT_ID, &0).unwrap();
        restore_attributes(Path::new("/nonexistent/bko"), &node).unwrap();
    }

    #[test]
    fn open_for_attrs_checks_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        let m = std::fs::symlink_metadata(&path).unwrap();
        assert!(open_for_attrs(&path, &NodeType::File, &m).is_some());
        // A directory where the backup listed a file.
        assert!(open_for_attrs(dir.path(), &NodeType::File, &m).is_none());
        // Replaced by another file.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(dir.path().join("g"), b"x").unwrap();
        std::fs::write(&path, b"x").unwrap();
        let again = std::fs::symlink_metadata(&path).unwrap();
        if again.ino() != m.ino() {
            assert!(open_for_attrs(&path, &NodeType::File, &m).is_none());
        }
        // A symlink isn't followed.
        std::os::unix::fs::symlink(&path, dir.path().join("l")).unwrap();
        let lm = std::fs::symlink_metadata(dir.path().join("l")).unwrap();
        assert!(open_for_attrs(&dir.path().join("l"), &NodeType::File, &lm).is_none());
    }
}
