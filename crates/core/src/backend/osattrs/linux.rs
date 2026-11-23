//! Linux: the inode flags `chattr(1)` sets (`FS_IOC_GETFLAGS`), the project
//! ID (`FS_IOC_FSGETXATTR`) that project quotas count by, the DOS flags
//! ZFS keeps for SMB (`ZFS_IOC_GETDOSFLAGS`), FAT's attributes
//! (`FAT_IOCTL_GET_ATTRIBUTES`) and XFS's options (`FS_IOC_FSGETXATTR`).

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

use super::{
    HeldFlags, RestoreErrors, Unsupported, XattrErrors, path_error, set_flags_best_effort,
    sparse::{
        BCACHEFS_SUPER_MAGIC, FS_NOCOW_FL, ZFS_SUPER_MAGIC, get_flags, statfs_type,
        statfs_type_path,
    },
    unsupported, xattr_unsupported,
};
use crate::backend::node::{
    ExtendedAttribute, Node, NodeType,
    generic_attributes::{
        LINUX_FAT_ATTRS, LINUX_INODE_FLAGS, LINUX_PROJECT_ID, LINUX_XFS_OPTIONS,
        LINUX_ZFS_DOS_FLAGS, XfsOptions,
    },
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
    | FS_NOCOW_FL //                    C
    | 0x2000_0000 // FS_PROJINHERIT_FL  P
    | FS_CASEFOLD_FL; //                F

const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
const FS_APPEND_FL: u32 = 0x0000_0020;

/// Case-insensitive names in a directory (ext4, f2fs).
const FS_CASEFOLD_FL: u32 = 0x4000_0000;

/// The flags a file system only takes while a file is empty: btrfs ignores
/// `FS_NOCOW_FL` on a file with data, without an error.
pub(super) const FLAGS_BEFORE_DATA: u32 = FS_NOCOW_FL;

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

// FAT's attributes, from <linux/msdos_fs.h>: a __u32 on a descriptor of the
// file. Only issued on FAT (MSDOS_SUPER_MAGIC): 'r' 0x10 may mean something
// else to another file system.
const FAT_IOCTL_GET_ATTRIBUTES: libc::Ioctl = libc::_IOR::<u32>(0x72, 0x10); // 'r'
const FAT_IOCTL_SET_ATTRIBUTES: libc::Ioctl = libc::_IOW::<u32>(0x72, 0x11); // 'r'

/// statfs's `f_type` for vfat and msdos.
const MSDOS_SUPER_MAGIC: u32 = 0x4d44;

/// FAT's read-only attribute (`ATTR_RO`).
const FAT_READONLY: u32 = 0x01;
/// FAT's archive attribute (`ATTR_ARCH`): Linux gives every new file it,
/// and sets it again on every write.
const FAT_ARCHIVE: u32 = 0x20;
/// The FAT attributes kept: those `FAT_IOCTL_SET_ATTRIBUTES` sets,
/// read-only, hidden (0x02), system (0x04) and archive. Volume label and
/// directory can't change.
const FAT_KEPT: u32 = FAT_READONLY | 0x02 | 0x04 | FAT_ARCHIVE;

/// statfs's `f_type` for XFS.
const XFS_SUPER_MAGIC: u32 = 0x5846_5342;

// fsx_xflags of XFS's options, from <linux/fs.h>.
const FS_XFLAG_RTINHERIT: u32 = 0x0000_0100; // t
const FS_XFLAG_EXTSIZE: u32 = 0x0000_0800; // e
const FS_XFLAG_EXTSZINHERIT: u32 = 0x0000_1000; // E
const FS_XFLAG_COWEXTSIZE: u32 = 0x0001_0000; // C

/// The `fsx_xflags` kept on XFS: those of a file's options that
/// `linux.inode_flags` doesn't carry (it has immutable, append-only, sync,
/// noatime, nodump and project inheritance) and that a file can be given:
/// nosymlinks (n), the extent size hint (e), its inheritance (E), nodefrag
/// (f), filestream (S) and the copy-on-write extent size hint (C); on a
/// directory also realtime inheritance (t, [`xfs_kept`]). Not realtime
/// (r), which a file has only on a realtime device, nor DAX; not
/// preallocated (p), which a restore that preallocates gives every file it
/// writes dense, and none it writes sparse.
const XFS_KEPT: u32 = 0x0000_0400 // FS_XFLAG_NOSYMLINKS n
    | FS_XFLAG_EXTSIZE
    | FS_XFLAG_EXTSZINHERIT
    | 0x0000_2000 // FS_XFLAG_NODEFRAG f
    | 0x0000_4000 // FS_XFLAG_FILESTREAM S
    | FS_XFLAG_COWEXTSIZE;

/// The `fsx_xflags` kept on XFS for a directory (`dir`) or a regular file:
/// [`XFS_KEPT`], and on a directory realtime inheritance (t), which XFS
/// takes on a directory with or without a realtime device and on no regular
/// file.
const fn xfs_kept(dir: bool) -> u32 {
    if dir {
        XFS_KEPT | FS_XFLAG_RTINHERIT
    } else {
        XFS_KEPT
    }
}

/// Opens a regular file or directory for `FS_IOC_GETFLAGS` and
/// `FS_IOC_SETFLAGS`, as `lsattr(1)` and `chattr(1)` do, so as not to follow
/// a symlink, wait on a lock or take a terminal. Other types of file have no
/// flags, and opening a device or FIFO could have side effects. An error if
/// what it opens isn't of type `typ` ("PATH is not a regular file", "... a
/// directory"), or, given `listed` (the backup's lstat), isn't that file
/// ("PATH was replaced since it was listed").
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
    let m = f
        .metadata()
        .map_err(|err| path_error("fstat", path, &err))?;
    // BackOtter (RustAudit1 R2-11): which of the two it is; a restore gives
    // no `listed`, and read nothing.
    if if dir { !m.is_dir() } else { !m.is_file() } {
        let what = if dir { "directory" } else { "regular file" };
        return Err(io::Error::other(format!(
            "{} is not a {what}",
            path.display()
        )));
    }
    if listed.is_some_and(|l| (l.dev(), l.ino()) != (m.dev(), m.ino())) {
        return Err(io::Error::other(format!(
            "{} was replaced since it was listed",
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
/// `magic` ([`statfs_type`]).
fn is_on(f: &File, magic: u32) -> io::Result<bool> {
    Ok(statfs_type(f)? == magic)
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

/// The value of the extended attribute `name` of the file `f`, whole
/// ([`read_whole`]).
fn get_xattr(f: &File, name: &str) -> io::Result<Vec<u8>> {
    let name = std::ffi::CString::new(name.as_bytes()).map_err(io::Error::from)?;
    // SAFETY: name is a C string, and value has room for size bytes, or is
    // null with size 0 (read_whole's contract).
    read_whole(|value, size| unsafe { libc::fgetxattr(f.as_raw_fd(), name.as_ptr(), value, size) })
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
    if unsafe {
        libc::fsetxattr(
            f.as_raw_fd(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    } < 0
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

#[allow(
    clippy::unnecessary_wraps,
    reason = "the signature every system's module has"
)]
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
/// on ZFS its DOS flags ([`dos_flags_attribute`]), on FAT its attributes
/// ([`fat_attrs_attribute`]) and on XFS its options ([`xfs_options`]).
pub(super) fn fill_attributes(path: &Path, node: &mut Node, f: Option<&File>) -> io::Result<()> {
    let Some(f) = f else {
        return Ok(());
    };
    let dos_flags = fill_dos_flags(path, node, f);
    fill_fat_attrs(path, node, f);
    match get_fsxattr(f) {
        Ok(attr) => {
            node.meta
                .generic_attributes
                .set_number(LINUX_PROJECT_ID, file_projid(f, &attr));
            if is_on(f, XFS_SUPER_MAGIC).unwrap_or(false)
                && let Some(opts) = xfs_options(&attr, node.is_dir())
            {
                node.meta
                    .generic_attributes
                    .set(LINUX_XFS_OPTIONS, &opts)
                    .map_err(io::Error::other)?;
            }
        }
        Err(err) if unsupported(&err) => {}
        Err(err) => return Err(path_error("FS_IOC_FSGETXATTR", path, &err)),
    }
    dos_flags
}

/// Records the FAT attributes of the file `f` at `path`, if it is on FAT and
/// they are worth an attribute. An error only goes to the debug log.
fn fill_fat_attrs(path: &Path, node: &mut Node, f: &File) {
    if !is_on(f, MSDOS_SUPER_MAGIC).unwrap_or(false) {
        return;
    }
    match get_u32(f, FAT_IOCTL_GET_ATTRIBUTES) {
        Ok(attrs) => {
            if let Some(kept) = fat_attrs_attribute(attrs, node.is_dir()) {
                node.meta
                    .generic_attributes
                    .set_u64(LINUX_FAT_ATTRS, kept.into());
            }
        }
        Err(err) => debug!("no FAT attributes for {}: {err}", path.display()),
    }
}

/// What `linux.fat_attrs` records for a regular file or (`dir`) directory
/// with the FAT attributes `attrs`: the [`FAT_KEPT`] ones, 0 included
/// (archive cleared), unless they are what it would have anyway if it were
/// restored without them: archive alone for a regular file (read-only or
/// not: its mode says which), none for a directory, so that a tree of
/// ordinary files on FAT gets no attribute. As in BackOtter's restic.
const fn fat_attrs_attribute(attrs: u32, dir: bool) -> Option<u32> {
    let kept = attrs & FAT_KEPT;
    let plain = if dir {
        kept == 0
    } else {
        kept & !FAT_READONLY == FAT_ARCHIVE
    };
    if plain { None } else { Some(kept) }
}

/// The FAT attributes a file that has `current` gets for `attrs`: the
/// [`FAT_KEPT`] ones of `attrs`, the others (directory) as they are.
const fn wanted_fat_attrs(current: u32, attrs: u32) -> u32 {
    (current & !FAT_KEPT) | (attrs & FAT_KEPT)
}

/// The FAT attributes a regular file or (`dir`) directory that has `current`
/// had when its node holds no `linux.fat_attrs` in a snapshot of
/// BackOtter's: those [`fat_attrs_attribute`] records nothing for. Archive
/// alone for a regular file, with read-only as the file has it (its mode
/// says which, and is set before); none for a directory.
const fn no_fat_attrs(current: u32, dir: bool) -> u32 {
    if dir {
        0
    } else {
        (current & FAT_READONLY) | FAT_ARCHIVE
    }
}

/// The XFS options of a directory (`dir`) or regular file whose
/// `FS_IOC_FSGETXATTR` gave `attr`, if it has any: the [`xfs_kept`] flags,
/// with the extent size hint where its flag or its inheritance is set, and
/// the copy-on-write one where its flag is. As in BackOtter's restic.
const fn xfs_options(attr: &FsXattr, dir: bool) -> Option<XfsOptions> {
    let xflags = attr.xflags & xfs_kept(dir);
    if xflags == 0 {
        return None;
    }
    Some(XfsOptions {
        xflags,
        extsize: if xflags & (FS_XFLAG_EXTSIZE | FS_XFLAG_EXTSZINHERIT) == 0 {
            0
        } else {
            attr.extsize
        },
        cowextsize: if xflags & FS_XFLAG_COWEXTSIZE == 0 {
            0
        } else {
            attr.cowextsize
        },
    })
}

/// `cur`, the `struct fsxattr` of a directory (`dir`) or regular file, with
/// the options `opts` in place of its own: the [`xfs_kept`] flags, and the
/// hints' sizes, 0 where their flags are off (XFS refuses a size without its
/// flag). The rest (other flags, the project ID) stays as it is.
const fn wanted_fsxattr(cur: &FsXattr, opts: &XfsOptions, dir: bool) -> FsXattr {
    let kept = xfs_kept(dir);
    let mut want = *cur;
    want.xflags = (cur.xflags & !kept) | (opts.xflags & kept);
    want.extsize = if want.xflags & (FS_XFLAG_EXTSIZE | FS_XFLAG_EXTSZINHERIT) == 0 {
        0
    } else {
        opts.extsize
    };
    want.cowextsize = if want.xflags & FS_XFLAG_COWEXTSIZE == 0 {
        0
    } else {
        opts.cowextsize
    };
    want
}

/// Whether `a` and `b` give a file the same XFS options.
const fn same_xfs_options(a: &FsXattr, b: &FsXattr) -> bool {
    a.xflags == b.xflags && a.extsize == b.extsize && a.cowextsize == b.cowextsize
}

fn get_u32(f: &File, req: libc::Ioctl) -> io::Result<u32> {
    let mut v: u32 = 0;
    // SAFETY: req (FAT_IOCTL_GET_ATTRIBUTES) writes a __u32 to the pointer.
    if unsafe { libc::ioctl(f.as_raw_fd(), req, &raw mut v) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(v)
}

fn set_u32(f: &File, req: libc::Ioctl, v: u32) -> io::Result<()> {
    // SAFETY: req (FAT_IOCTL_SET_ATTRIBUTES) reads a __u32 from the pointer.
    if unsafe { libc::ioctl(f.as_raw_fd(), req, &raw const v) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Gives the regular file or directory at `path` the FAT attributes `attrs`
/// (`linux.fat_attrs`), on FAT, before its inode flags: any write sets
/// archive again. `FAT_IOCTL_SET_ATTRIBUTES` also sets the mode's write
/// bits from read-only, as a `chmod(2)` would. Attributes that are right
/// already get no set at all. The file system's root directory takes none
/// (`EINVAL`), reported as unsupported.
pub(super) fn restore_fat_attrs(path: &Path, typ: &NodeType, attrs: u32) -> io::Result<()> {
    let f = open_for_flags(path, typ, None)?;
    let unsupported_err = |err: io::Error| Unsupported::error(LINUX_FAT_ATTRS, 0, err);
    if !is_on(&f, MSDOS_SUPER_MAGIC).map_err(|err| path_error("fstatfs", path, &err))? {
        return Err(unsupported_err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not FAT",
        )));
    }
    let current = get_u32(&f, FAT_IOCTL_GET_ATTRIBUTES).map_err(|err| {
        if unsupported(&err) {
            unsupported_err(err)
        } else {
            path_error("FAT_IOCTL_GET_ATTRIBUTES", path, &err)
        }
    })?;
    restore_fat_attrs_with(path, current, attrs, |a| {
        set_u32(&f, FAT_IOCTL_SET_ATTRIBUTES, a)
    })
}

/// [`restore_fat_attrs`] for a file that has the FAT attributes `current`,
/// with `set` (`FAT_IOCTL_SET_ATTRIBUTES`).
fn restore_fat_attrs_with(
    path: &Path,
    current: u32,
    attrs: u32,
    set: impl FnOnce(u32) -> io::Result<()>,
) -> io::Result<()> {
    let want = wanted_fat_attrs(current, attrs);
    if want == current {
        return Ok(());
    }
    set(want).map_err(|err| {
        if unsupported(&err) {
            Unsupported::error(
                LINUX_FAT_ATTRS,
                0,
                path_error("FAT_IOCTL_SET_ATTRIBUTES", path, &err),
            )
        } else {
            path_error("FAT_IOCTL_SET_ATTRIBUTES", path, &err)
        }
    })
}

/// Gives the directory (`dir`) or regular file `f` at `path` the XFS options
/// `opts`, unless it has them already.
fn set_xfs_options(f: &File, path: &Path, opts: &XfsOptions, dir: bool) -> io::Result<()> {
    let unsupported_or = |op: &str, err: io::Error| {
        if unsupported(&err) {
            Unsupported::error(LINUX_XFS_OPTIONS, 0, path_error(op, path, &err))
        } else {
            path_error(op, path, &err)
        }
    };
    let cur = get_fsxattr(f).map_err(|err| unsupported_or("FS_IOC_FSGETXATTR", err))?;
    let want = wanted_fsxattr(&cur, opts, dir);
    if same_xfs_options(&cur, &want) {
        return Ok(());
    }
    // XFS refuses (EINVAL) a new extent size hint on a regular file that has
    // data: one restored over an existing file. It refuses a directory
    // realtime inheritance along with the inheritance of an extent size hint
    // that isn't a multiple of its realtime extent size
    // (xfs_ioctl_setattr_check_extsize): the directory then gets the rest,
    // and only realtime inheritance is unsupported. As in BackOtter's restic.
    set_fsxattr(f, &want).map_err(|err| {
        if dir && err.raw_os_error() == Some(libc::EINVAL) && want.xflags & FS_XFLAG_RTINHERIT != 0
        {
            let mut rest = want;
            rest.xflags &= !FS_XFLAG_RTINHERIT;
            if set_fsxattr(f, &rest).is_ok() {
                return Unsupported::error(
                    LINUX_XFS_OPTIONS,
                    FS_XFLAG_RTINHERIT.into(),
                    path_error("FS_IOC_FSSETXATTR", path, &err),
                );
            }
        }
        unsupported_or("FS_IOC_FSSETXATTR", err)
    })
}

/// Takes the [`xfs_kept`] options off the existing directory at `path`,
/// which the restore is about to put entries in, so that none of them
/// inherits any (XFS passes each to the entries a directory gets after it),
/// and returns those it had, if it took any off, for the late pass to put
/// back where the directory's node has none. Only on XFS; an error leaves
/// the directory as it is. As in BackOtter's restic.
pub(super) fn clear_dir_xfs_options(path: &Path) -> Option<XfsOptions> {
    let cleared = (|| -> io::Result<Option<XfsOptions>> {
        let f = open_for_flags(path, &NodeType::Dir, None)?;
        if !is_on(&f, XFS_SUPER_MAGIC)? {
            return Ok(None);
        }
        let cur = get_fsxattr(&f)?;
        let Some(had) = xfs_options(&cur, true) else {
            return Ok(None);
        };
        set_fsxattr(&f, &wanted_fsxattr(&cur, &XfsOptions::default(), true))?;
        Ok(Some(had))
    })();
    cleared.unwrap_or_else(|err| {
        debug!("XFS options of {} not cleared: {err}", path.display());
        None
    })
}

/// Gives the regular file or directory at `path` the XFS options `opts`
/// (`linux.xfs_options`), on XFS, before its inode flags, leaving its other
/// flags and project ID as they are.
pub(super) fn restore_xfs_options(
    path: &Path,
    typ: &NodeType,
    opts: &XfsOptions,
) -> io::Result<()> {
    let f = open_for_flags(path, typ, None)?;
    if !is_on(&f, XFS_SUPER_MAGIC).map_err(|err| path_error("fstatfs", path, &err))? {
        return Err(Unsupported::error(
            LINUX_XFS_OPTIONS,
            0,
            io::Error::new(io::ErrorKind::Unsupported, "not XFS"),
        ));
    }
    set_xfs_options(&f, path, opts, matches!(typ, NodeType::Dir))
}

/// Gives the regular file at `path`, which the restore is about to write,
/// the XFS options `opts` while it is empty: XFS only takes an extent size
/// hint on a regular file without data. Creates the file (empty, mode 0600)
/// when there is none, as [`prepare_file_for_flags`] does, and leaves one
/// with data alone. Not XFS, or any error, is left for
/// [`restore_xfs_options`], in the late pass, to report.
pub(super) fn prepare_file_for_xfs(path: &Path, opts: &XfsOptions) {
    let f = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => Ok(f),
        // An empty file prepare_file_for_flags made.
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            open_for_flags(path, &NodeType::File, None)
        }
        Err(err) => Err(err),
    };
    let set = f.and_then(|f| {
        if f.metadata()?.len() != 0 || !is_on(&f, XFS_SUPER_MAGIC)? {
            return Ok(());
        }
        set_xfs_options(&f, path, opts, false)
    });
    if let Err(err) = set {
        debug!("XFS options of {} not set early: {err}", path.display());
    }
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
                node.meta
                    .generic_attributes
                    .set_u64(LINUX_ZFS_DOS_FLAGS, flags);
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
    if kept == ZFS_ARCHIVE {
        None
    } else {
        Some(kept)
    }
}

/// The DOS flags a file had when its node holds no `linux.zfs_dos_flags` in
/// a snapshot of BackOtter's: those [`dos_flags_attribute`] records nothing
/// for, archive alone.
const NO_DOS_FLAGS: u64 = ZFS_ARCHIVE;

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
    restore_flags_open(&f, path, current, flags, btrfs_compression(xattrs))
}

/// The value of btrfs's compression property among the extended attributes
/// `xattrs` of a node, if it has one.
fn btrfs_compression(xattrs: &[ExtendedAttribute]) -> Option<&[u8]> {
    xattrs
        .iter()
        .find(|attr| attr.name == BTRFS_COMPRESSION)
        .and_then(|attr| attr.value.as_deref())
}

/// [`restore_flags_with`] for the file open as `f`, at `path`, which has the
/// flags `current`.
fn restore_flags_open(
    f: &File,
    path: &Path,
    current: u32,
    flags: u32,
    compression: Option<&[u8]>,
) -> io::Result<()> {
    restore_flags_with(
        path,
        current,
        flags,
        compression,
        || get_flags(f),
        |flags| set_flags(f, flags),
        |value| set_xattr(f, BTRFS_COMPRESSION, value),
        |xflags| {
            let mut attr = get_fsxattr(f)?;
            attr.xflags |= xflags;
            set_fsxattr(f, &attr)
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

/// Clears immutable and append-only (`i`, `a`) on the regular file or
/// directory at `path`, which keep a restore from rewriting, replacing or
/// changing it, leaving its other flags as they are; the late flags pass
/// sets the node's. Through `FS_IOC_FSSETXATTR`, which leaves btrfs's
/// `btrfs.compression` property alone (`FS_IOC_SETFLAGS` rewrites it), or
/// `FS_IOC_SETFLAGS` where the file system has no `FS_IOC_FSSETXATTR` or
/// that left either set ([`clear_restricting_with`]). Symlinks and special
/// files have no flags.
pub(super) fn clear_restricting_flags(path: &Path) -> io::Result<()> {
    clear_restricting_open(path).map(drop)
}

/// [`clear_restricting_flags`], returning the file, open for its flags, and
/// the flags it cleared, if any.
fn clear_restricting_open(path: &Path) -> io::Result<Option<(File, u32)>> {
    let m = std::fs::symlink_metadata(path)?;
    let typ = if m.is_dir() {
        NodeType::Dir
    } else if m.is_file() {
        NodeType::File
    } else {
        return Ok(None);
    };
    let f = open_for_flags(path, &typ, Some(&m))?;
    let cleared = clear_restricting_with(
        path,
        || get_flags(&f),
        |flags| set_flags(&f, flags),
        |xflags| change_xflags(&f, |x| x & !xflags),
    )?;
    Ok((cleared != 0).then_some((f, cleared)))
}

/// BackOtter: [`clear_restricting_flags`] for a file whose name the restore
/// is about to remove, or rename another file over: the file stays open
/// (`O_RDONLY|O_NOFOLLOW|O_NONBLOCK`) in the [`HeldFlags`], for the flags to
/// go back on it, wherever its other names are ([`put_back_restricting_flags`]).
pub(super) fn clear_restricting_flags_held(path: &Path) -> io::Result<HeldFlags> {
    Ok(match clear_restricting_open(path)? {
        Some((file, cleared)) => HeldFlags::Held {
            file,
            cleared,
            path: path.to_path_buf(),
        },
        None => HeldFlags::Nothing,
    })
}

/// BackOtter: sets `cleared`, the restricting flags
/// [`clear_restricting_flags_held`] cleared, again on the file open as `f`
/// (at `path`, for errors).
pub(super) fn put_back_restricting_flags(f: &File, path: &Path, cleared: u32) -> io::Result<()> {
    put_back_restricting_with(
        path,
        || get_flags(f),
        |flags| set_flags(f, flags),
        |xflags| change_xflags(f, |x| x | xflags),
        cleared,
    )
}

/// Gives the file open as `f` the `fsx_xflags` `change` makes of those it
/// has (`FS_IOC_FSGETXATTR`, `FS_IOC_FSSETXATTR`).
fn change_xflags(f: &File, change: impl FnOnce(u32) -> u32) -> io::Result<()> {
    get_fsxattr(f).and_then(|mut attr| {
        attr.xflags = change(attr.xflags);
        set_fsxattr(f, &attr)
    })
}

/// Clears immutable and append-only of the file at `path` with `get`
/// (`FS_IOC_GETFLAGS`) and `set` (`FS_IOC_SETFLAGS`) and `clear_xflags`
/// (`FS_IOC_FSSETXATTR` without the `fsx_xflags` given): by its
/// `fsx_xflags`, then by its flags where the file system has no
/// `FS_IOC_FSSETXATTR`, or where that left either set. On Ubuntu 24.04's
/// OpenZFS (2.2) `FS_IOC_FSSETXATTR` cleared immutable alone and left
/// append-only, as if it took `fsx_xflags` for `FS_IOC_GETFLAGS`'s flags, in
/// which `FS_XFLAG_APPEND` is `FS_IMMUTABLE_FL`; a restore over an
/// append-only file couldn't change it there (ubuntu24, round 15). OpenZFS
/// 2.3.9 clears both. As in BackOtter's restic.
///
/// It returns those of the two the file had, which it cleared.
fn clear_restricting_with(
    path: &Path,
    mut get: impl FnMut() -> io::Result<u32>,
    set: impl FnOnce(u32) -> io::Result<()>,
    clear_xflags: impl FnOnce(u32) -> io::Result<()>,
) -> io::Result<u32> {
    let restricting = FS_IMMUTABLE_FL | FS_APPEND_FL;
    let mut current = get().map_err(|err| path_error("FS_IOC_GETFLAGS", path, &err))?;
    let had = current & restricting;
    if had == 0 {
        return Ok(0);
    }
    match clear_xflags(FS_XFLAG_IMMUTABLE | FS_XFLAG_APPEND) {
        Ok(()) => {
            current = get().map_err(|err| path_error("FS_IOC_GETFLAGS", path, &err))?;
            if current & restricting == 0 {
                return Ok(had);
            }
        }
        Err(err) if unsupported(&err) => {}
        Err(err) => return Err(path_error("FS_IOC_FSSETXATTR", path, &err)),
    }
    set(current & !restricting).map_err(|err| path_error("FS_IOC_SETFLAGS", path, &err))?;
    Ok(had)
}

/// BackOtter: sets `cleared`, the restricting flags
/// [`clear_restricting_with`] cleared, again on the file at `path`, with
/// `get`, `set` and `add_xflags` (`FS_IOC_FSSETXATTR` with the
/// `fsx_xflags` given): by its `fsx_xflags`, which leave btrfs's
/// compression property alone, then by its flags where the file system has
/// no `FS_IOC_FSSETXATTR`, or where that didn't give the file exactly its
/// flags and those (OpenZFS 2.2, which takes `fsx_xflags` for
/// `FS_IOC_GETFLAGS`'s flags). As in BackOtter's restic
/// (`putBackRestrictingWith`).
fn put_back_restricting_with(
    path: &Path,
    mut get: impl FnMut() -> io::Result<u32>,
    set: impl FnOnce(u32) -> io::Result<()>,
    add_xflags: impl FnOnce(u32) -> io::Result<()>,
    cleared: u32,
) -> io::Result<()> {
    let current = get().map_err(|err| path_error("FS_IOC_GETFLAGS", path, &err))?;
    let want = current | (cleared & (FS_IMMUTABLE_FL | FS_APPEND_FL));
    if want == current {
        return Ok(());
    }
    let mut xflags = 0;
    if cleared & FS_IMMUTABLE_FL != 0 {
        xflags |= FS_XFLAG_IMMUTABLE;
    }
    if cleared & FS_APPEND_FL != 0 {
        xflags |= FS_XFLAG_APPEND;
    }
    match add_xflags(xflags) {
        Ok(()) => {
            if get().is_ok_and(|now| now == want) {
                return Ok(());
            }
        }
        Err(err) if unsupported(&err) => {}
        Err(err) => return Err(path_error("FS_IOC_FSSETXATTR", path, &err)),
    }
    set(want).map_err(|err| path_error("FS_IOC_SETFLAGS", path, &err))
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
/// but immutable and append-only, `set_compression` puts the property back
/// after it (neither where those are right already; a file system without
/// the property is no error), and `add_xflags` adds those two through
/// `FS_IOC_FSSETXATTR`, which leaves it alone. Each step's error is kept,
/// in a [`RestoreErrors`] for more than one, as BackOtter's restic joins
/// them (`setLateFlags`). `get` (`FS_IOC_GETFLAGS`) then checks the two:
/// where the file system has no `FS_IOC_FSSETXATTR`, or that didn't give
/// the file exactly those two (ZFS 2.2, which takes `fsx_xflags` for
/// `FS_IOC_GETFLAGS`'s flags, so that `FS_XFLAG_APPEND` set immutable),
/// `set` gives it all its flags, as [`put_back_restricting_with`] does. Only
/// a file system without the property gets there: btrfs has
/// `FS_IOC_FSSETXATTR`, and maps the two.
#[allow(clippy::too_many_arguments)]
fn restore_flags_with(
    path: &Path,
    current: u32,
    flags: u32,
    compression: Option<&[u8]>,
    mut get: impl FnMut() -> io::Result<u32>,
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
    // BackOtter: each step's error is kept and warned about alone
    // (RestoreErrors), as BackOtter's restic joins them (setLateFlags).
    let mut errors = Vec::new();
    // Only an FS_IOC_SETFLAGS rewrites the property: without one it stays
    // as restored. Where the file system has no such property (ext4, XFS,
    // ZFS), that goes unsaid, as in BackOtter's restic (setCompression).
    if own | first != current {
        errors.extend(
            set_flags_best_effort(
                LINUX_INODE_FLAGS,
                path,
                "FS_IOC_SETFLAGS",
                Some(current & KEPT_LATE),
                first,
                |f| set(own | f),
            )
            .err(),
        );
        match set_compression(compression) {
            Err(err) if !xattr_unsupported(&err) => {
                errors.push(path_error(
                    &format!("set {BTRFS_COMPRESSION} of"),
                    path,
                    &err,
                ));
            }
            _ => {}
        }
    }
    let mut xflags = 0;
    if late & FS_IMMUTABLE_FL != 0 {
        xflags |= FS_XFLAG_IMMUTABLE;
    }
    if late & FS_APPEND_FL != 0 {
        xflags |= FS_XFLAG_APPEND;
    }
    let set_late = match xflags {
        0 => Ok(()),
        _ => match add_xflags(xflags) {
            Ok(()) if get().is_ok_and(|now| now & (FS_IMMUTABLE_FL | FS_APPEND_FL) == late) => {
                Ok(())
            }
            Ok(()) => set_all_late(path, own, first | late, get().ok(), &mut set),
            Err(err) if unsupported(&err) => {
                set_all_late(path, own, first | late, get().ok(), &mut set)
            }
            Err(err) => Err(path_error("FS_IOC_FSSETXATTR", path, &err)),
        },
    };
    errors.extend(set_late.err());
    RestoreErrors::result(errors)
}

/// Gives a file the [`KEPT_LATE`] flags `want` with `set`
/// (`FS_IOC_SETFLAGS`), keeping `own`, the file system's own flags and
/// casefolding, where [`restore_flags_with`]'s `FS_IOC_FSSETXATTR` didn't
/// give it immutable and append-only right. `now`, its flags as read back
/// (if they could be), are what a flag refused alone is reported against.
fn set_all_late(
    path: &Path,
    own: u32,
    want: u32,
    now: Option<u32>,
    set: &mut impl FnMut(u32) -> io::Result<()>,
) -> io::Result<()> {
    set_flags_best_effort(
        LINUX_INODE_FLAGS,
        path,
        "FS_IOC_SETFLAGS",
        now.map(|now| now & KEPT_LATE),
        want,
        |f| set(own | f),
    )
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
#[allow(
    clippy::unnecessary_wraps,
    reason = "the signature every system's module has"
)]
pub(super) fn restore_owner(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

/// Restores the project ID, along with the extended attributes
/// ([`restore_project_id`]), and in a snapshot of BackOtter's (`known_bko`)
/// gives a regular file or directory whose node has no inode flags, ZFS DOS
/// flags or FAT attributes a new file's, where it has others
/// ([`restore_absent`]).
pub(super) fn restore_attributes(path: &Path, node: &Node, known_bko: bool) -> io::Result<()> {
    let project = restore_project_id(path, node, known_bko);
    let absent = if known_bko {
        restore_absent(path, node)
    } else {
        Ok(())
    };
    RestoreErrors::result(
        [project, absent]
            .into_iter()
            .filter_map(Result::err)
            .collect(),
    )
}

/// Restores the project ID. A project
/// ID of 0 is the default, and left as it is; but on bcachefs a file without
/// one gets 0, where it inherited another from its directory (whose project
/// ID the restore gives it before its entries, [`prepare_dir_for_options`]),
/// as in BackOtter's restic: where its node has 0, or none in a snapshot of
/// BackOtter's (`known_bko`). A node without one in another snapshot says
/// nothing about it: the file keeps what it has or inherited.
fn restore_project_id(path: &Path, node: &Node, known_bko: bool) -> io::Result<()> {
    let projid = match node.meta.generic_attributes.number(LINUX_PROJECT_ID) {
        None if !known_bko => return Ok(()),
        None | Some(0) => {
            if matches!(node.node_type, NodeType::File | NodeType::Dir)
                && is_bcachefs_path(path)
                && let Err(err) = open_for_flags(path, &node.node_type, None)
                    .and_then(|f| set_projid(path, &f, 0))
            {
                debug!("project ID 0 not restored on {}: {err}", path.display());
            }
            return Ok(());
        }
        Some(projid) => projid,
    };
    let f = open_for_flags(path, &node.node_type, None)?;
    set_projid(path, &f, projid)
}

/// BackOtter (ForkAudit1 G4-03): gives the regular file or directory at
/// `path` what `node` says it had where `node` holds no `linux.inode_flags`,
/// no `linux.zfs_dos_flags` or no `linux.fat_attrs`, in a snapshot of
/// BackOtter's, which records each wherever a file has more than a new
/// file's: no inode flags of those the late flags pass sets ([`KEPT_LATE`]);
/// on ZFS the DOS flag archive alone ([`NO_DOS_FLAGS`]); on FAT archive
/// alone for a regular file and nothing for a directory ([`no_fat_attrs`]).
/// The late flags pass sets only what a node holds, so a flag set since the
/// backup (`chattr +d`, hidden), or one a file the restore made got from
/// its directory, stayed, and `restore --exact`, which counts it as a
/// difference, set such a file's metadata again on every run. The
/// restricting flags (`i`, `a`) came off before the restore changed the
/// file. A file that has just those is not written to; one whose flags
/// can't be read (it can't be opened, a file system without them) is left
/// as it is, as a backup records none for it. Symlinks and special files
/// have none.
///
/// Two flags can't change here, and stay with a warning each: casefolding
/// (`F`), which only an empty directory takes ([`prepare_dir_for_flags`]
/// cleared it on one), and btrfs's no-copy-on-write (`C`) on a file with
/// data, which btrfs keeps without an error.
///
/// # Errors
///
/// * If a flag or attribute couldn't be changed: as the late flags pass
///   reports it for a node that holds them, naming those refused.
fn restore_absent(path: &Path, node: &Node) -> io::Result<()> {
    let typ = &node.node_type;
    let dir = match typ {
        NodeType::File => false,
        NodeType::Dir => true,
        _ => return Ok(()),
    };
    let lacks = |name| node.meta.generic_attributes.value(name).is_none();
    let (flags, dos, fat) = (
        lacks(LINUX_INODE_FLAGS),
        lacks(LINUX_ZFS_DOS_FLAGS),
        lacks(LINUX_FAT_ATTRS),
    );
    if !(flags || dos || fat) {
        return Ok(());
    }
    let f = match open_for_flags(path, typ, None) {
        Ok(f) => f,
        Err(err) => {
            debug!("flags a node hasn't got not looked for: {err}");
            return Ok(());
        }
    };
    let on = statfs_type(&f).ok();
    let mut errors = Vec::new();
    if dos && on == Some(ZFS_SUPER_MAGIC) {
        match get_dos_flags(&f) {
            Ok(current) => errors.extend(
                restore_dos_flags_with(path, current, NO_DOS_FLAGS, |flags| {
                    set_dos_flags(&f, flags)
                })
                .err(),
            ),
            Err(err) => debug!("ZFS DOS flags of {} left: {err}", path.display()),
        }
    }
    if fat && on == Some(MSDOS_SUPER_MAGIC) {
        match get_u32(&f, FAT_IOCTL_GET_ATTRIBUTES) {
            Ok(current) => errors.extend(
                restore_fat_attrs_with(path, current, no_fat_attrs(current, dir), |attrs| {
                    set_u32(&f, FAT_IOCTL_SET_ATTRIBUTES, attrs)
                })
                .err(),
            ),
            Err(err) => debug!("FAT attributes of {} left: {err}", path.display()),
        }
    }
    if flags {
        let compression = btrfs_compression(&node.meta.extended_attributes);
        errors.extend(restore_no_flags(&f, path, typ, compression).err());
    }
    RestoreErrors::result(errors)
}

/// [`restore_absent`]'s inode flags: takes the [`KEPT_LATE`] flags off the
/// regular file or directory open as `f`, at `path`, where it has any, as
/// [`restore_file_flags`] would for a node that holds no flag
/// (`compression`: the node's `btrfs.compression`, which then stays).
fn restore_no_flags(
    f: &File,
    path: &Path,
    typ: &NodeType,
    compression: Option<&[u8]>,
) -> io::Result<()> {
    let current = match get_flags(f) {
        Ok(current) => current,
        // A backup records none for such a file either (`file_flags`): a
        // file system without flags, which is nothing to say of each file.
        Err(err) => {
            if !unsupported(&err) {
                debug!("file flags of {} left: {err}", path.display());
            }
            return Ok(());
        }
    };
    if casefold_differs(typ, current, 0) {
        warn!(
            "casefolding (F) not restored on {}: directory not empty or not supported",
            path.display()
        );
    }
    if current & KEPT_LATE == 0 {
        return Ok(());
    }
    let cleared = restore_flags_open(f, path, current, 0, compression);
    if current & FS_NOCOW_FL != 0
        && cleared.is_ok()
        && get_flags(f).is_ok_and(|now| now & FS_NOCOW_FL != 0)
    {
        warn!(
            "no-copy-on-write (C) not cleared on {}: the file has data",
            path.display()
        );
    }
    cleared
}

/// Gives the regular file or directory `f`, at `path`, the project ID
/// `projid`, unless it has it already ([`file_projid`]).
fn set_projid(path: &Path, f: &File, projid: u32) -> io::Result<()> {
    let classify = |op: &str, err: io::Error| {
        if unsupported(&err) {
            Unsupported::error(LINUX_PROJECT_ID, 0, err)
        } else {
            path_error(op, path, &err)
        }
    };
    let mut attr = get_fsxattr(f).map_err(|err| classify("FS_IOC_FSGETXATTR", err))?;
    if file_projid(f, &attr) != projid {
        attr.projid = projid;
        set_fsxattr(f, &attr).map_err(|err| classify("FS_IOC_FSSETXATTR", err))?;
    }
    Ok(())
}

/// Whether `path` (followed, if a symlink) is on bcachefs.
fn is_bcachefs_path(path: &Path) -> bool {
    statfs_type_path(path).is_ok_and(|t| t == BCACHEFS_SUPER_MAGIC)
}

/// Whether the extended attribute `name` is one of a bcachefs file's own
/// options (`bcachefs.compression`, `.data_replicas`, `.background_target`,
/// `.nocow` and the rest) that the restore sets.
fn is_bcachefs_option(name: &str) -> bool {
    name.starts_with("bcachefs.") && super::xattr_node_name(name.as_ref()).is_some()
}

/// Gives the directory at `path`, which the restore has just created or
/// found empty, the options its node has that bcachefs passes to the
/// entries a directory gets after they are set: its own `bcachefs.*`
/// options and its project ID, 0 where it has none in a snapshot of
/// BackOtter's (`known_bko`; in another, the one it inherited stays). Its
/// entries then inherit them as in the original, so their data is stored as
/// it was (compressed, replicated, on the same targets) and their project
/// ID comes back inherited. Only on bcachefs; errors are left for the
/// directory's metadata, which sets them all again, to report.
pub(super) fn prepare_dir_for_options(path: &Path, node: &Node, known_bko: bool) {
    if !matches!(node.node_type, NodeType::Dir) || !is_bcachefs_path(path) {
        return;
    }
    let f = match open_for_flags(path, &NodeType::Dir, None) {
        Ok(f) => f,
        Err(err) => {
            debug!("options of {} not set early: {err}", path.display());
            return;
        }
    };
    for ExtendedAttribute { name, value } in &node.meta.extended_attributes {
        if !is_bcachefs_option(name) {
            continue;
        }
        if let Err(err) = set_xattr(&f, name, value.as_deref().unwrap_or_default()) {
            debug!("{name} of {} not set early: {err}", path.display());
        }
    }
    let Some(projid) = node
        .meta
        .generic_attributes
        .number(LINUX_PROJECT_ID)
        .or_else(|| known_bko.then_some(0))
    else {
        return;
    };
    if let Err(err) = set_projid(path, &f, projid) {
        debug!("project ID of {} not set early: {err}", path.display());
    }
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "the signature every system's module has"
)]
pub(super) fn restore_acls(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "the signature every system's module has"
)]
pub(super) fn restore_symlink_mode(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

/// Linux reads birth times (`statx(2)`), but has no call that sets one.
pub(super) fn restore_birthtime(_path: &Path, _node: &Node, _birth: Timestamp) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Linux can't set birth times",
    ))
}

/// Extended attributes have no metadata of their own here.
pub(super) fn fill_xattr_meta(_path: &Path, _node: &mut Node) {}

/// Extended attributes go through the xattr crate here.
pub(super) fn xattrs(_path: &Path) -> io::Result<Vec<ExtendedAttribute>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "extended attributes go through xattr",
    ))
}

/// Extended attributes go through the xattr crate here.
pub(super) fn set_xattrs(_path: &Path, _attrs: &[ExtendedAttribute]) -> Result<(), XattrErrors> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "extended attributes go through xattr",
    )
    .into())
}

/// Reads what `getxattr(2)`-like `call` gives into a buffer of the size it
/// gives for none, again while the value grows in between (`ERANGE`): the
/// whole value, however large. The xattr crate before 1.7 (1.6, on rustix
/// 1.1) took a first 4 KiB and, for a larger value, asked rustix for its
/// size with an empty buffer, which rustix 1.1 answered with 0: every value
/// over 4 KiB was read as empty, and a backup kept a 15000-byte `user.*`
/// attribute as empty (rocky10, tumbleweed). restic reads it whole. xattr
/// 1.7 asks for the size as this does (rustix's `*_query` calls), and is
/// what `Cargo.lock` has now; this stays while `Cargo.toml` takes any
/// xattr 1.x.
///
/// `call` is only ever given a null pointer and 0, or a pointer to a
/// writable buffer of exactly that many bytes, which lives until it
/// returns: what the callers' SAFETY comments rely on.
fn read_whole(mut call: impl FnMut(*mut libc::c_void, usize) -> isize) -> io::Result<Vec<u8>> {
    loop {
        let size = call(std::ptr::null_mut(), 0);
        let size = usize::try_from(size).map_err(|_| io::Error::last_os_error())?;
        let mut buf = vec![0_u8; size];
        let got = call(buf.as_mut_ptr().cast(), buf.len());
        match usize::try_from(got) {
            // (with an empty buffer, the call gives the size again)
            Ok(got) if got <= buf.len() => {
                buf.truncate(got);
                return Ok(buf);
            }
            Ok(_) => {}
            Err(_) => {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ERANGE) {
                    return Err(err);
                }
            }
        }
    }
}

/// The value of the extended attribute `name` of the file at `path`, not
/// following a symlink, whole ([`read_whole`]); `None` where it has none.
pub(super) fn xattr_get(path: &Path, name: &std::ffi::OsStr) -> io::Result<Option<Vec<u8>>> {
    use std::os::unix::ffi::OsStrExt;
    let p = super::c_path(path)?;
    let n = std::ffi::CString::new(name.as_bytes()).map_err(io::Error::from)?;
    // SAFETY: p and n are C strings, and value has room for size bytes, or
    // is null with size 0 (read_whole's contract).
    let value =
        read_whole(|value, size| unsafe { libc::lgetxattr(p.as_ptr(), n.as_ptr(), value, size) });
    match value {
        Err(err) if err.raw_os_error() == Some(libc::ENODATA) => Ok(None),
        result => result.map(Some),
    }
}

/// The names of the extended attributes of the file at `path`, not
/// following a symlink, all of them ([`read_whole`]).
pub(super) fn xattr_list(path: &Path) -> io::Result<Vec<std::ffi::OsString>> {
    use std::os::unix::ffi::OsStrExt;
    let p = super::c_path(path)?;
    // SAFETY: p is a C string, and list has room for size bytes, or is null
    // with size 0 (read_whole's contract).
    let names =
        read_whole(|list, size| unsafe { libc::llistxattr(p.as_ptr(), list.cast(), size) })?;
    Ok(names
        .split(|&b| b == 0)
        .filter(|name| !name.is_empty())
        .map(|name| std::ffi::OsStr::from_bytes(name).to_os_string())
        .collect())
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, ffi::OsStr, os::unix::fs::PermissionsExt, path::PathBuf};

    use super::*;
    use crate::backend::node::Metadata as NodeMetadata;

    const EXTENTS: u32 = 0x0008_0000; // FS_EXTENT_FL, ext4's own
    const COMPR: u32 = 0x0000_0004;
    const NODUMP: u32 = 0x0000_0040;
    const NOCOW: u32 = FS_NOCOW_FL;

    /// An ioctl's number as the headers write it, 32 bits: `libc::Ioctl` is
    /// an `unsigned long` on glibc and an `int` on musl, where a number with
    /// bit 31 set (a read) is negative. The numbers are checked where the
    /// direction and size are encoded as asm-generic does (not on powerpc,
    /// mips or sparc).
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn ioctl_number(ioctl: libc::Ioctl) -> i128 {
        i128::from(ioctl) & 0xffff_ffff
    }

    #[test]
    fn fsxattr_ioctls() {
        assert_eq!(size_of::<FsXattr>(), 28);
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            assert_eq!(ioctl_number(FS_IOC_FSGETXATTR), 0x801c_581f);
            assert_eq!(ioctl_number(FS_IOC_FSSETXATTR), 0x401c_5820);
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
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            assert_eq!(ioctl_number(ZFS_IOC_GETDOSFLAGS), 0x8008_8301);
            assert_eq!(ioctl_number(ZFS_IOC_SETDOSFLAGS), 0x4008_8302);
        }
    }

    #[test]
    fn dos_flags_attribute_unless_archive_alone() {
        // A new or written file: no attribute.
        assert_eq!(dos_flags_attribute(ZFS_ARCHIVE), None);
        // Archive cleared: an attribute of 0.
        assert_eq!(dos_flags_attribute(0), Some(0));
        assert_eq!(
            dos_flags_attribute(ZFS_ARCHIVE | ZFS_HIDDEN),
            Some(ZFS_ARCHIVE | ZFS_HIDDEN)
        );
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
        assert_eq!(
            wanted_dos_flags(iad | ZFS_ARCHIVE, ZFS_HIDDEN),
            iad | ZFS_HIDDEN
        );
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
        assert!(
            err.to_string().contains("0x100000000 of 0x300000000"),
            "{err}"
        );
        assert_eq!(calls.last(), Some(&ZFS_HIDDEN));
        // Sparse not supported: a warning once.
        let (result, calls) =
            restore_dos_flags_calls(ZFS_NODUMP, ZFS_SPARSE | ZFS_SYSTEM, ZFS_SPARSE);
        let err = result.unwrap_err();
        let unsupported = err
            .get_ref()
            .unwrap()
            .downcast_ref::<Unsupported>()
            .unwrap();
        assert_eq!(
            (unsupported.attr, unsupported.bits),
            (LINUX_ZFS_DOS_FLAGS, ZFS_SPARSE)
        );
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
            assert_eq!(
                node.meta.generic_attributes.number_u64(LINUX_ZFS_DOS_FLAGS),
                None
            );
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
        assert_eq!(
            attribute(&path, &NodeType::File),
            Some(ZFS_HIDDEN | ZFS_SYSTEM)
        );
        restore_zfs_dos_flags(&path, &NodeType::File, 0).unwrap();
        assert_eq!(attribute(&path, &NodeType::File), Some(0));
        // A write sets archive again.
        std::fs::write(&path, b"y").unwrap();
        assert_eq!(attribute(&path, &NodeType::File), None);
        restore_zfs_dos_flags(dir.path(), &NodeType::Dir, ZFS_HIDDEN).unwrap();
        assert_eq!(attribute(dir.path(), &NodeType::Dir), Some(ZFS_HIDDEN));
    }

    #[test]
    fn fat_ioctls() {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            assert_eq!(ioctl_number(FAT_IOCTL_GET_ATTRIBUTES), 0x8004_7210);
            assert_eq!(ioctl_number(FAT_IOCTL_SET_ATTRIBUTES), 0x4004_7211);
        }
    }

    #[test]
    fn fat_attrs_kept_as_restic_keeps_them() {
        for (attrs, dir, want) in [
            (0x20, false, None),       // a new or written file: archive alone
            (0x21, false, None),       // read-only too, which its mode says
            (0x10, true, None),        // a new directory: ATTR_DIR alone
            (0x00, false, Some(0)),    // archive cleared
            (0x22, false, Some(0x22)), // hidden
            (0x24, false, Some(0x24)), // system
            (0x06, false, Some(0x06)), // hidden, system, archive cleared
            (0x01, false, Some(0x01)), // read-only, archive cleared
            (0x12, true, Some(0x02)),  // a hidden directory
            (0x11, true, Some(0x01)),  // a read-only directory
            (0x30, true, Some(0x20)),  // a directory with archive
            (0x28, false, None),       // volume label: never kept
        ] {
            assert_eq!(
                fat_attrs_attribute(attrs, dir),
                want,
                "{attrs:#x} dir {dir}"
            );
        }
        assert_eq!(wanted_fat_attrs(0x30, 0x06), 0x16);
        assert_eq!(wanted_fat_attrs(0x2f, 0), 0x08);

        let path = Path::new("f");
        let sets = RefCell::new(Vec::new());
        restore_fat_attrs_with(path, 0x22, 0x22, |a| {
            sets.borrow_mut().push(a);
            Ok(())
        })
        .unwrap();
        assert!(sets.borrow().is_empty(), "right already, but set");
        restore_fat_attrs_with(path, 0x10, 0x02, |a| {
            sets.borrow_mut().push(a);
            Ok(())
        })
        .unwrap();
        assert_eq!(*sets.borrow(), [0x12]);
        // The root directory takes none: EINVAL is unsupported.
        let err = restore_fat_attrs_with(path, 0x10, 0x02, |_| {
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        let err = restore_fat_attrs_with(path, 0x20, 0x02, |_| {
            Err(io::Error::from_raw_os_error(libc::EPERM))
        })
        .unwrap_err();
        assert_ne!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn xfs_options_kept_as_restic_keeps_them() {
        let fsx = |xflags, extsize, cowextsize| FsXattr {
            xflags,
            extsize,
            cowextsize,
            ..FsXattr::default()
        };
        // hasattr, prealloc, immutable, projinherit: none of them.
        for dir in [false, true] {
            assert_eq!(
                xfs_options(&fsx(0x8000_0002 | 0x8 | 0x200, 0, 0), dir),
                None
            );
            assert_eq!(
                xfs_options(&fsx(0x8000_0802, 1 << 20, 0), dir),
                Some(XfsOptions {
                    xflags: 0x800,
                    extsize: 1 << 20,
                    cowextsize: 0
                })
            );
            assert_eq!(
                xfs_options(&fsx(0x1000 | 0x4000 | 0x1_0000, 2 << 20, 4 << 20), dir),
                Some(XfsOptions {
                    xflags: 0x1_5000,
                    extsize: 2 << 20,
                    cowextsize: 4 << 20
                })
            );
            assert_eq!(
                xfs_options(&fsx(0x2000, 4096, 0), dir),
                Some(XfsOptions {
                    xflags: 0x2000,
                    extsize: 0,
                    cowextsize: 0
                })
            );
        }
        // Realtime (r) never; realtime inheritance (t) on a directory only.
        assert_eq!(xfs_options(&fsx(0x1, 0, 0), false), None);
        assert_eq!(xfs_options(&fsx(0x1, 0, 0), true), None);
        assert_eq!(xfs_options(&fsx(0x100, 0, 0), false), None);
        assert_eq!(
            xfs_options(&fsx(0x1 | 0x100 | 0x1000, 1 << 20, 0), true),
            Some(XfsOptions {
                xflags: 0x1100,
                extsize: 1 << 20,
                cowextsize: 0
            })
        );
        // The kept flags and sizes replaced; prealloc, immutable and the
        // project ID left as they are.
        let mut cur = fsx(0x8000_0002 | 0x8 | 0x2000, 0, 0);
        cur.projid = 7;
        let want = wanted_fsxattr(
            &cur,
            &XfsOptions {
                xflags: 0x800,
                extsize: 1 << 20,
                cowextsize: 0,
            },
            false,
        );
        assert_eq!(
            (want.xflags, want.extsize, want.cowextsize, want.projid),
            (0x8000_0002 | 0x8 | 0x800, 1 << 20, 0, 7)
        );
        assert!(!same_xfs_options(&cur, &want));
        let want = wanted_fsxattr(&fsx(0x800, 1 << 20, 0), &XfsOptions::default(), false);
        assert_eq!((want.xflags, want.extsize, want.cowextsize), (0, 0, 0));
        let cur = fsx(0x2000, 0, 0);
        assert!(same_xfs_options(
            &cur,
            &wanted_fsxattr(
                &cur,
                &XfsOptions {
                    xflags: 0x2000,
                    ..XfsOptions::default()
                },
                false
            )
        ));
        // Realtime inheritance goes on and off a directory, and never on a
        // regular file; realtime on neither.
        let rt = XfsOptions {
            xflags: 0x1 | 0x100 | 0x2000,
            ..XfsOptions::default()
        };
        assert_eq!(wanted_fsxattr(&fsx(0, 0, 0), &rt, true).xflags, 0x2100);
        assert_eq!(wanted_fsxattr(&fsx(0, 0, 0), &rt, false).xflags, 0x2000);
        assert_eq!(
            wanted_fsxattr(&fsx(0x100, 0, 0), &XfsOptions::default(), true).xflags,
            0
        );
    }

    #[test]
    fn fat_attrs_and_xfs_options_elsewhere_are_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        let f = File::open(&path).unwrap();
        if is_on(&f, MSDOS_SUPER_MAGIC).unwrap() || is_on(&f, XFS_SUPER_MAGIC).unwrap() {
            return; // TMPDIR on FAT or XFS
        }
        let err = restore_fat_attrs(&path, &NodeType::File, 0x22).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(
            err.to_string()
                .contains("linux.fat_attrs not supported by the file system: not FAT"),
            "{err}"
        );
        let opts = XfsOptions {
            xflags: 0x2000,
            ..XfsOptions::default()
        };
        let err = restore_xfs_options(dir.path(), &NodeType::Dir, &opts).unwrap_err();
        assert!(
            err.to_string()
                .contains("linux.xfs_options not supported by the file system: not XFS"),
            "{err}"
        );
        // Early, nothing happens: the file is left as it is.
        prepare_file_for_xfs(
            &path,
            &XfsOptions {
                xflags: 0x800,
                extsize: 1 << 20,
                cowextsize: 0,
            },
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
    }

    /// A file system made with `mkfs` (and `args`) on an image of `size`
    /// bytes, mounted on a loop device until it is dropped. `None` without
    /// root or the tools.
    struct LoopMount {
        dir: tempfile::TempDir,
    }

    impl LoopMount {
        fn new(size: u64, mkfs: &str, args: &[&str]) -> Option<Self> {
            // SAFETY: geteuid has no preconditions.
            if unsafe { libc::geteuid() } != 0 {
                eprintln!("skipped: needs root, to mount a file system");
                return None;
            }
            let dir = tempfile::tempdir().unwrap();
            let img = dir.path().join("fs.img");
            File::create(&img).unwrap().set_len(size).unwrap();
            std::fs::create_dir(dir.path().join("mnt")).unwrap();
            let ok =
                |cmd: &mut std::process::Command| cmd.output().is_ok_and(|o| o.status.success());
            if !ok(std::process::Command::new(mkfs).args(args).arg(&img)) {
                eprintln!("skipped: no {mkfs}");
                return None;
            }
            if !ok(std::process::Command::new("mount")
                .args(["-o", "loop"])
                .arg(&img)
                .arg(dir.path().join("mnt")))
            {
                eprintln!("skipped: mount failed");
                return None;
            }
            Some(Self { dir })
        }

        fn path(&self) -> PathBuf {
            self.dir.path().join("mnt")
        }
    }

    impl Drop for LoopMount {
        fn drop(&mut self) {
            _ = std::process::Command::new("umount")
                .arg(self.path())
                .status();
        }
    }

    fn filled(path: &Path, typ: &NodeType) -> Node {
        let m = std::fs::symlink_metadata(path).unwrap();
        let mut node = Node::new_node(OsStr::new("x"), typ.clone(), NodeMetadata::default());
        let f = open_for_attrs(path, typ, &m);
        fill_attributes(path, &mut node, f.as_ref()).unwrap();
        node
    }

    // With root, on a loop vfat: the attributes a backup keeps, and a
    // restore putting them back.
    #[test]
    fn fat_attrs_on_vfat() {
        let Some(mnt) = LoopMount::new(64 << 20, "mkfs.vfat", &[]) else {
            return;
        };
        let mnt = mnt.path();
        let get = |p: &Path| get_u32(&File::open(p).unwrap(), FAT_IOCTL_GET_ATTRIBUTES).unwrap();
        let set =
            |p: &Path, a| set_u32(&File::open(p).unwrap(), FAT_IOCTL_SET_ATTRIBUTES, a).unwrap();
        for (name, dir, attrs, kept) in [
            ("plain", false, 0x20, false),
            ("hidden", false, 0x22, true),
            ("cleared", false, 0, true),
            ("system", false, 0x24, true),
            ("pdir", true, 0x10, false),
            ("hdir", true, 0x12, true),
            ("rodir", true, 0x11, true),
        ] {
            let (src, dst) = (mnt.join(name), mnt.join(format!("restored-{name}")));
            let typ = if dir {
                std::fs::create_dir(&src).unwrap();
                std::fs::create_dir(&dst).unwrap();
                NodeType::Dir
            } else {
                std::fs::write(&src, name).unwrap();
                std::fs::write(&dst, name).unwrap();
                NodeType::File
            };
            set(&src, attrs);
            let got = filled(&src, &typ)
                .meta
                .generic_attributes
                .number(LINUX_FAT_ATTRS);
            assert_eq!(got.is_some(), kept, "{name}: {got:?}");
            if let Some(a) = got {
                restore_fat_attrs(&dst, &typ, a).unwrap();
                assert_eq!(get(&src), get(&dst), "{name}");
            }
        }
        assert_eq!(
            filled(&mnt, &NodeType::Dir)
                .meta
                .generic_attributes
                .number(LINUX_FAT_ATTRS),
            None
        );
        let err = restore_fat_attrs(&mnt, &NodeType::Dir, 0x02).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{err}");
    }

    // With root, on a loop XFS: the options a backup keeps, set early on an
    // empty file (an extent size hint) and late on a directory.
    #[test]
    fn xfs_options_on_xfs() {
        let Some(mnt) = LoopMount::new(320 << 20, "mkfs.xfs", &["-q", "-f"]) else {
            return;
        };
        let mnt = mnt.path();
        let xfs_io = |args: &[&str]| {
            let st = std::process::Command::new("xfs_io")
                .args(args)
                .status()
                .unwrap();
            assert!(st.success(), "xfs_io {args:?}");
        };
        let (file, dir) = (mnt.join("extsize"), mnt.join("dir"));
        std::fs::write(&file, b"").unwrap();
        std::fs::create_dir(&dir).unwrap();
        xfs_io(&[
            "-c",
            "extsize 1m",
            "-c",
            "chattr +f",
            file.to_str().unwrap(),
        ]);
        xfs_io(&[
            "-c",
            "extsize 2m",
            "-c",
            "chattr +St",
            dir.to_str().unwrap(),
        ]);
        std::fs::write(&file, vec![0_u8; 65536]).unwrap();
        let opts = |p: &Path, typ: NodeType| {
            filled(p, &typ)
                .meta
                .generic_attributes
                .decoded::<XfsOptions>(LINUX_XFS_OPTIONS)
        };
        let fopts = opts(&file, NodeType::File).expect("file's XFS options not kept");
        assert_eq!(
            fopts,
            XfsOptions {
                xflags: 0x2800,
                extsize: 1 << 20,
                cowextsize: 0
            }
        );
        let dopts = opts(&dir, NodeType::Dir).expect("directory's XFS options not kept");
        // Realtime inheritance (t) too, without a realtime device.
        assert_eq!(
            dopts,
            XfsOptions {
                xflags: 0x5100,
                extsize: 2 << 20,
                cowextsize: 0
            }
        );
        let plain = mnt.join("plain");
        {
            let mut f = File::create(&plain).unwrap();
            io::Write::write_all(&mut f, b"x").unwrap();
            f.sync_all().unwrap(); // its extent allocated, not delayed
        }
        assert_eq!(opts(&plain, NodeType::File), None);

        // Early on a new file, then its data, then late: as the restore does.
        let (rfile, rdir) = (mnt.join("rfile"), mnt.join("rdir"));
        prepare_file_for_xfs(&rfile, &fopts);
        std::fs::write(&rfile, vec![0_u8; 65536]).unwrap();
        restore_xfs_options(&rfile, &NodeType::File, &fopts).unwrap();
        assert_eq!(opts(&rfile, NodeType::File), Some(fopts));
        std::fs::create_dir(&rdir).unwrap();
        restore_xfs_options(&rdir, &NodeType::Dir, &dopts).unwrap();
        assert_eq!(opts(&rdir, NodeType::Dir), Some(dopts));
        // A regular file takes no realtime inheritance: left out, no error.
        let tfile = mnt.join("tfile");
        let topts = XfsOptions {
            xflags: 0x2100,
            ..XfsOptions::default()
        };
        prepare_file_for_xfs(&tfile, &topts);
        restore_xfs_options(&tfile, &NodeType::File, &topts).unwrap();
        assert_eq!(
            opts(&tfile, NodeType::File),
            Some(XfsOptions {
                xflags: 0x2000,
                ..topts
            })
        );
        // Too late for a file with data: unsupported (EINVAL).
        let err = restore_xfs_options(&plain, &NodeType::File, &fopts).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{err}");
        // Taken off again.
        restore_xfs_options(&rdir, &NodeType::Dir, &XfsOptions::default()).unwrap();
        assert_eq!(opts(&rdir, NodeType::Dir), None);
        // An existing directory's come off before the restore puts entries
        // in it, and are given back as they were.
        assert_eq!(clear_dir_xfs_options(&rdir), None);
        restore_xfs_options(&rdir, &NodeType::Dir, &dopts).unwrap();
        assert_eq!(clear_dir_xfs_options(&rdir), Some(dopts));
        assert_eq!(opts(&rdir, NodeType::Dir), None);
        restore_xfs_options(&rdir, &NodeType::Dir, &dopts).unwrap();
        assert_eq!(opts(&rdir, NodeType::Dir), Some(dopts));
        let elsewhere = tempfile::tempdir().unwrap();
        assert_eq!(clear_dir_xfs_options(elsewhere.path()), None);
    }

    // With root, on a loop XFS whose realtime extent size (64k, without a
    // realtime device) is no multiple of a directory's 12k extent size
    // hint: XFS refuses realtime inheritance along with that hint's
    // inheritance (EINVAL), so the directory gets the rest, and only
    // realtime inheritance is unsupported. As in BackOtter's restic.
    #[test]
    fn xfs_rtinherit_refused_alone() {
        let Some(mnt) = LoopMount::new(320 << 20, "mkfs.xfs", &["-q", "-f", "-r", "extsize=64k"])
        else {
            return;
        };
        let dir = mnt.path().join("dir");
        std::fs::create_dir(&dir).unwrap();
        let mut want = XfsOptions {
            xflags: 0x100 | 0x1000 | 0x2000,
            extsize: 12 << 10,
            cowextsize: 0,
        };
        let err = restore_xfs_options(&dir, &NodeType::Dir, &want).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{err}");
        let refused = err
            .get_ref()
            .and_then(|e| e.downcast_ref::<Unsupported>())
            .map(|u| u.bits);
        assert_eq!(refused, Some(0x100), "{err}");
        let opts = |p: &Path| {
            filled(p, &NodeType::Dir)
                .meta
                .generic_attributes
                .decoded::<XfsOptions>(LINUX_XFS_OPTIONS)
        };
        assert_eq!(
            opts(&dir),
            Some(XfsOptions {
                xflags: 0x3000,
                ..want
            })
        );
        // A hint that is a multiple goes on with it.
        want.extsize = 128 << 10;
        restore_xfs_options(&dir, &NodeType::Dir, &want).unwrap();
        assert_eq!(opts(&dir), Some(want));
    }

    // BackOtter (RustAudit1 R2-11): what open_for_flags found says which it
    // was: another type of file, or another file than the one listed.
    #[test]
    fn open_for_flags_says_what_it_found() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let listed = std::fs::symlink_metadata(&a).unwrap();
        _ = open_for_flags(&a, &NodeType::File, Some(&listed)).unwrap();
        _ = open_for_flags(dir.path(), &NodeType::Dir, None).unwrap();
        // A directory where the node is a file (a restore gives no lstat).
        let err = open_for_flags(dir.path(), &NodeType::File, None).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("{} is not a regular file", dir.path().display())
        );
        // A file where the node is a directory: O_DIRECTORY refuses it.
        let err = open_for_flags(&a, &NodeType::Dir, None).unwrap_err();
        assert_eq!(
            err.raw_os_error().or_else(|| super::super::errno(&err)),
            Some(libc::ENOTDIR)
        );
        // Another file than the backup listed under that name.
        let err = open_for_flags(&b, &NodeType::File, Some(&listed)).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("{} was replaced since it was listed", b.display())
        );
    }

    #[test]
    fn wanted_flags_keep_the_file_systems_own_and_casefolding() {
        assert_eq!(
            wanted_flags(EXTENTS | FS_IMMUTABLE_FL, FS_IMMUTABLE_FL),
            EXTENTS | FS_IMMUTABLE_FL
        );
        assert_eq!(
            wanted_flags(EXTENTS, FS_IMMUTABLE_FL | EXTENTS),
            EXTENTS | FS_IMMUTABLE_FL
        );
        assert_eq!(
            wanted_flags(EXTENTS | NOCOW, FS_IMMUTABLE_FL),
            EXTENTS | FS_IMMUTABLE_FL
        );
        // Casefolding stays as the directory has it, both ways.
        assert_eq!(
            wanted_flags(FS_CASEFOLD_FL, FS_IMMUTABLE_FL),
            FS_CASEFOLD_FL | FS_IMMUTABLE_FL
        );
        assert_eq!(
            wanted_flags(0, FS_CASEFOLD_FL | FS_IMMUTABLE_FL),
            FS_IMMUTABLE_FL
        );
    }

    #[test]
    fn casefold_differs_on_directories() {
        assert!(casefold_differs(&NodeType::Dir, 0, FS_CASEFOLD_FL));
        assert!(casefold_differs(&NodeType::Dir, FS_CASEFOLD_FL, NODUMP));
        assert!(!casefold_differs(
            &NodeType::Dir,
            FS_CASEFOLD_FL | EXTENTS,
            FS_CASEFOLD_FL
        ));
        assert!(!casefold_differs(&NodeType::Dir, EXTENTS, NODUMP));
        assert!(!casefold_differs(&NodeType::File, 0, FS_CASEFOLD_FL));
    }

    /// Runs [`restore_flags_with`] on a file with the flags `current` and
    /// returns the calls it made (but the reads).
    fn restore_flags_calls(current: u32, flags: u32, compression: Option<&[u8]>) -> Vec<String> {
        let calls = RefCell::new(Vec::new());
        let now = std::cell::Cell::new(current);
        restore_flags_with(
            Path::new("f"),
            current,
            flags,
            compression,
            || Ok(now.get()),
            |f| {
                calls.borrow_mut().push(format!("set {f:#x}"));
                now.set(f);
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
                if x & FS_XFLAG_IMMUTABLE != 0 {
                    now.set(now.get() | FS_IMMUTABLE_FL);
                }
                if x & FS_XFLAG_APPEND != 0 {
                    now.set(now.get() | FS_APPEND_FL);
                }
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
        assert_eq!(
            restore_flags_calls(EXTENTS, FS_CASEFOLD_FL | NODUMP, None),
            ["set 0x80040"]
        );
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
        // Immutable last, through FS_IOC_FSSETXATTR. No FS_IOC_SETFLAGS ran,
        // so nothing rewrote the property: it isn't set again.
        assert_eq!(
            restore_flags_calls(COMPR, COMPR | FS_IMMUTABLE_FL, zstd),
            ["xflags 0x8"]
        );
        assert_eq!(
            restore_flags_calls(COMPR, COMPR | NODUMP | FS_APPEND_FL, zstd),
            ["set 0x44", "compression zstd", "xflags 0x10"]
        );
        // Without the property, as on any other file system.
        assert_eq!(
            restore_flags_calls(COMPR, COMPR | FS_IMMUTABLE_FL, None),
            ["set 0x14"]
        );
    }

    // A btrfs file's compression property and i/a, restored onto a file
    // system without the property, where FS_IOC_FSSETXATTR isn't there or
    // doesn't set the two right (ZFS 2.2 takes fsx_xflags for
    // FS_IOC_GETFLAGS's flags: FS_XFLAG_APPEND is FS_IMMUTABLE_FL, and
    // FS_XFLAG_IMMUTABLE FS_SYNC_FL, which it refuses): the file still gets
    // its flags, not others.
    #[test]
    fn restore_flags_compression_on_zfs_xflags() {
        const SYNC: u32 = 0x0000_0008;
        let ia = FS_IMMUTABLE_FL | FS_APPEND_FL;
        for (name, zfs, no_xattr, flags, want_sets) in [
            // The flags but i and a, then i and a through FS_IOC_FSSETXATTR.
            ("btrfs a", false, false, COMPR | FS_APPEND_FL, 1),
            ("btrfs i+a", false, false, COMPR | NODUMP | ia, 1),
            // Then all of them through FS_IOC_SETFLAGS.
            ("zfs a", true, false, COMPR | FS_APPEND_FL, 2),
            ("zfs i", true, false, COMPR | FS_IMMUTABLE_FL, 2),
            ("zfs i+a", true, false, COMPR | NODUMP | ia, 2),
            ("no FSSETXATTR a", false, true, COMPR | FS_APPEND_FL, 2),
        ] {
            let now = std::cell::Cell::new(EXTENTS);
            let sets = std::cell::Cell::new(0);
            let result = restore_flags_with(
                Path::new("f"),
                EXTENTS,
                flags,
                Some(&b"zstd"[..]),
                || Ok(now.get()),
                |f| {
                    sets.set(sets.get() + 1);
                    now.set(f);
                    Ok(())
                },
                |_| {
                    if zfs {
                        // ZFS has no handler for btrfs.* names.
                        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
                    } else {
                        Ok(())
                    }
                },
                |xflags| {
                    if no_xattr {
                        return Err(io::Error::from_raw_os_error(libc::ENOTTY));
                    }
                    let mut f = now.get();
                    if zfs {
                        if xflags & SYNC != 0 {
                            return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
                        }
                        f |= xflags;
                    } else {
                        if xflags & FS_XFLAG_IMMUTABLE != 0 {
                            f |= FS_IMMUTABLE_FL;
                        }
                        if xflags & FS_XFLAG_APPEND != 0 {
                            f |= FS_APPEND_FL;
                        }
                    }
                    now.set(f);
                    Ok(())
                },
            );
            assert_eq!(now.get(), EXTENTS | flags, "{name}");
            assert_eq!(sets.get(), want_sets, "{name}");
            // A file system without the property is no error, as in
            // BackOtter's restic (setCompression).
            assert!(result.is_ok(), "{name}: {result:?}");
        }
    }

    /// Runs [`restore_flags_with`] for a file with the flags `current`, a
    /// node with `flags` and `btrfs.compression`, where `FS_IOC_SETFLAGS`
    /// fails with `set`'s errno, setting the property with `property`'s and
    /// `FS_IOC_FSSETXATTR` with `xflags`' (0: it works).
    fn restore_flags_failing(
        current: u32,
        flags: u32,
        set: i32,
        property: i32,
        xflags: i32,
    ) -> io::Result<()> {
        let fails = |errno: i32| match errno {
            0 => Ok(()),
            errno => Err(io::Error::from_raw_os_error(errno)),
        };
        restore_flags_with(
            Path::new("f"),
            current,
            flags,
            Some(&b"zstd"[..]),
            || Ok(current),
            |_| fails(set),
            |_| fails(property),
            |_| fails(xflags),
        )
    }

    // BackOtter (ForkAudit1 G3-01): each step's error is kept, as BackOtter's
    // restic joins them (setLateFlags), where only the first was.
    #[test]
    fn restore_flags_keep_every_error() {
        use crate::backend::osattrs::{NotRoot, restore_error_counts};

        // A c+i file restored onto XFS, not as root: FS_IOC_SETFLAGS has no
        // FS_COMPR_FL there (unsupported: warned once, never counted), there
        // is no btrfs.compression (nothing said), and FS_IOC_FSSETXATTR
        // refuses immutable (EPERM), which is the file's error and counts.
        let err = restore_flags_failing(
            EXTENTS,
            COMPR | FS_IMMUTABLE_FL,
            libc::EOPNOTSUPP,
            libc::EOPNOTSUPP,
            libc::EPERM,
        )
        .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("linux.inode_flags 0x4 not supported"),
            "{text}"
        );
        assert!(text.contains("FS_IOC_FSSETXATTR f: "), "{text}");
        assert!(!text.contains(BTRFS_COMPRESSION), "{text}");
        assert!(
            restore_error_counts(&err, NotRoot::Counted, false),
            "{text}"
        );
        // The unsupported flag alone doesn't count.
        let err = restore_flags_failing(EXTENTS, COMPR | FS_IMMUTABLE_FL, libc::EOPNOTSUPP, 0, 0)
            .unwrap_err();
        assert!(
            !restore_error_counts(&err, NotRoot::Counted, false),
            "{err}"
        );

        // The property refused for another reason is an error of its own,
        // beside the flags'.
        let err = restore_flags_failing(
            EXTENTS,
            COMPR | NODUMP | FS_APPEND_FL,
            0,
            libc::EIO,
            libc::EPERM,
        )
        .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("set btrfs.compression of f: "), "{text}");
        assert!(text.contains("FS_IOC_FSSETXATTR f: "), "{text}");
        assert!(
            restore_error_counts(&err, NotRoot::Counted, false),
            "{text}"
        );
        // No such property (ENOTSUP, or ENODATA from an SMB mount): nothing.
        for errno in [libc::ENOTSUP, libc::EOPNOTSUPP, libc::ENODATA] {
            restore_flags_failing(EXTENTS, COMPR | NODUMP, 0, errno, 0).unwrap();
        }
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
        let (result, set) = prepare_dir_sets(
            Err(io::Error::from_raw_os_error(libc::ENOTTY)),
            FS_CASEFOLD_FL,
        );
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
        if f.as_ref()
            .and_then(|f| get_fsxattr(f).ok())
            .is_some_and(|attr| attr.projid != 0)
        {
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

    /// BackOtter: in a snapshot not BackOtter's, a node without a project
    /// ID says nothing: the file isn't even looked at (a path that doesn't
    /// exist is no error), on bcachefs either.
    #[test]
    fn project_id_unknown_is_left_alone() {
        let node = Node::default();
        restore_attributes(Path::new("/nonexistent/bko"), &node, false).unwrap();
        prepare_dir_for_options(Path::new("/nonexistent/bko"), &node, false);
    }

    #[test]
    fn project_id_0_is_left_alone() {
        // Not even opened: a path that doesn't exist is no error.
        let mut node = Node::default();
        node.meta
            .generic_attributes
            .set(LINUX_PROJECT_ID, &0)
            .unwrap();
        restore_project_id(Path::new("/nonexistent/bko"), &node, true).unwrap();
        // Nor for the flags the node hasn't got, which are looked for: a
        // file that can't be opened is left as it is.
        restore_attributes(Path::new("/nonexistent/bko"), &node, true).unwrap();
    }

    /// The change time of the file at `path`, a moment later, so that a
    /// write after this moves it.
    fn ctime_of(path: &Path) -> (i64, i64) {
        std::thread::sleep(std::time::Duration::from_millis(30));
        let m = std::fs::symlink_metadata(path).unwrap();
        (m.ctime(), m.ctime_nsec())
    }

    fn flags_of(path: &Path, typ: &NodeType) -> u32 {
        get_flags(&open_for_flags(path, typ, None).unwrap()).unwrap() & INODE_FLAGS
    }

    /// G4-03: what a node without the attribute stands for is what a backup
    /// records no attribute for, whatever the file has now, and leaves the
    /// attributes that aren't kept as they are.
    #[test]
    fn no_attribute_values_get_no_attribute() {
        assert_eq!(dos_flags_attribute(NO_DOS_FLAGS), None);
        for current in [
            0,
            ZFS_ARCHIVE,
            ZFS_HIDDEN | ZFS_SYSTEM,
            ZFS_DOS_KEPT,
            u64::MAX,
        ] {
            let reset = wanted_dos_flags(current, NO_DOS_FLAGS);
            assert_eq!(dos_flags_attribute(reset), None, "{current:#x}");
            assert_eq!(
                reset & !ZFS_DOS_KEPT,
                current & !ZFS_DOS_KEPT,
                "{current:#x}"
            );
        }
        for current in 0..0x80_u32 {
            for dir in [false, true] {
                let reset = wanted_fat_attrs(current, no_fat_attrs(current, dir));
                assert_eq!(fat_attrs_attribute(reset, dir), None, "{current:#x} {dir}");
                assert_eq!(reset & !FAT_KEPT, current & !FAT_KEPT, "{current:#x} {dir}");
                // A regular file's read-only is its mode's.
                if !dir {
                    assert_eq!(reset & FAT_READONLY, current & FAT_READONLY);
                }
                // What has no attribute already is not written to.
                if fat_attrs_attribute(current, dir).is_none() {
                    assert_eq!(reset, current, "{current:#x} {dir}");
                }
            }
        }
    }

    /// G4-03: an inode flag a file has and its node doesn't goes in a
    /// snapshot of BackOtter's, where a node without flags says its file
    /// had none, and stays in any other; a file without such a flag isn't
    /// written to, and a node's own flags are the late pass's. The late
    /// flags pass alone, which sets a node's own flags, left it. Where the
    /// tests' directory has `chattr +d` (ext4, XFS, btrfs, tmpfs).
    #[test]
    fn restore_takes_off_flags_the_node_lacks() {
        let dir = tempfile::tempdir().unwrap();
        for typ in [NodeType::File, NodeType::Dir] {
            let path = dir.path().join(format!("{typ:?}"));
            match typ {
                NodeType::File => std::fs::write(&path, "x").unwrap(),
                _ => std::fs::create_dir(&path).unwrap(),
            }
            let f = open_for_flags(&path, &typ, None).unwrap();
            let set = get_flags(&f).and_then(|new_file| {
                if new_file & KEPT_LATE != 0 {
                    return Err(io::Error::other("the directory hands down flags"));
                }
                set_flags(&f, new_file | NODUMP)
            });
            if let Err(err) = set {
                eprintln!("restore_takes_off_flags_the_node_lacks: {err}: nothing tested");
                return;
            }
            let node = Node::new_node(OsStr::new("n"), typ.clone(), NodeMetadata::default());

            restore_attributes(&path, &node, false).unwrap();
            assert_eq!(flags_of(&path, &typ), NODUMP, "not BackOtter's: kept");
            let mut own = node.clone();
            own.meta
                .generic_attributes
                .set_u64(LINUX_INODE_FLAGS, NODUMP.into());
            let before = ctime_of(&path);
            restore_attributes(&path, &own, true).unwrap();
            assert_eq!(flags_of(&path, &typ), NODUMP, "the node's own: kept");
            assert_eq!(ctime_of(&path), before, "the node's own: written to");

            restore_attributes(&path, &node, true).unwrap();
            assert_eq!(flags_of(&path, &typ), 0, "{}", path.display());
            let after = ctime_of(&path);
            restore_attributes(&path, &node, true).unwrap();
            assert_eq!(ctime_of(&path), after, "a second restore wrote to the file");
        }
        // A symlink has no flags, and what it points at keeps its own.
        let (target, link) = (dir.path().join("File"), dir.path().join("link"));
        let f = open_for_flags(&target, &NodeType::File, None).unwrap();
        set_flags(&f, get_flags(&f).unwrap() | NODUMP).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let node = Node::new_node(
            OsStr::new("n"),
            NodeType::from_link(&target),
            NodeMetadata::default(),
        );
        restore_attributes(&link, &node, true).unwrap();
        // A regular file's node where a symlink is: not followed.
        let node = Node::new_node(OsStr::new("n"), NodeType::File, NodeMetadata::default());
        restore_attributes(&link, &node, true).unwrap();
        assert_eq!(flags_of(&target, &NodeType::File), NODUMP);
    }

    /// G4-03, with root, on a loop vfat: a node without `linux.fat_attrs`
    /// in a snapshot of BackOtter's gives a file archive alone and a
    /// directory nothing, where they have other attributes; read-only stays
    /// the mode's.
    #[test]
    fn restore_takes_off_fat_attrs_the_node_lacks() {
        let Some(mnt) = LoopMount::new(64 << 20, "mkfs.vfat", &[]) else {
            return;
        };
        let mnt = mnt.path();
        let get = |p: &Path| get_u32(&File::open(p).unwrap(), FAT_IOCTL_GET_ATTRIBUTES).unwrap();
        let set =
            |p: &Path, a| set_u32(&File::open(p).unwrap(), FAT_IOCTL_SET_ATTRIBUTES, a).unwrap();
        for (name, dir, attrs, want) in [
            ("plain", false, 0x20, 0x20),
            ("readonly", false, 0x21, 0x21),
            ("hidden", false, 0x22, 0x20),
            ("cleared", false, 0, 0x20),
            ("rosystem", false, 0x05, 0x21),
            ("pdir", true, 0x10, 0x10),
            ("hdir", true, 0x12, 0x10),
            ("adir", true, 0x30, 0x10),
        ] {
            let path = mnt.join(name);
            let typ = if dir {
                std::fs::create_dir(&path).unwrap();
                NodeType::Dir
            } else {
                std::fs::write(&path, name).unwrap();
                NodeType::File
            };
            set(&path, attrs);
            assert_eq!(get(&path), attrs, "{name}");
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            let node = Node::new_node(OsStr::new("n"), typ.clone(), NodeMetadata::default());
            restore_attributes(&path, &node, false).unwrap();
            assert_eq!(get(&path), attrs, "{name}: not BackOtter's: kept");
            let mut own = node.clone();
            own.meta
                .generic_attributes
                .set_u64(LINUX_FAT_ATTRS, (attrs & FAT_KEPT).into());
            restore_attributes(&path, &own, true).unwrap();
            assert_eq!(get(&path), attrs, "{name}: the node's own: kept");
            restore_attributes(&path, &node, true).unwrap();
            assert_eq!(get(&path), want, "{name}");
            assert_eq!(
                filled(&path, &typ)
                    .meta
                    .generic_attributes
                    .number(LINUX_FAT_ATTRS),
                None,
                "{name}"
            );
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode(),
                mode,
                "{name}"
            );
        }
        // The root directory, which takes none, is not asked to.
        let node = Node::new_node(OsStr::new("n"), NodeType::Dir, NodeMetadata::default());
        restore_attributes(&mnt, &node, true).unwrap();
    }

    /// G4-03, with root, on a loop btrfs: the flags a new file gets from
    /// its directory go where its node has none, and with compression its
    /// property; no-copy-on-write goes from an empty file and a directory,
    /// and stays on a file with data, which btrfs keeps it on.
    #[test]
    fn restore_takes_off_inherited_flags_on_btrfs() {
        let Some(mnt) = LoopMount::new(256 << 20, "mkfs.btrfs", &["-q", "-f"]) else {
            return;
        };
        let mnt = mnt.path();
        let dir_node = Node::new_node(OsStr::new("n"), NodeType::Dir, NodeMetadata::default());
        let file_node = Node::new_node(OsStr::new("n"), NodeType::File, NodeMetadata::default());
        let set = |path: &Path, typ: &NodeType, flags: u32| {
            let f = open_for_flags(path, typ, None).unwrap();
            set_flags(&f, get_flags(&f).unwrap() | flags).unwrap();
        };
        let compression = |path: &Path| xattr_get(path, OsStr::new(BTRFS_COMPRESSION)).unwrap();

        // Compression: the flag and the property, both handed down.
        let c = mnt.join("c");
        std::fs::create_dir(&c).unwrap();
        set(&c, &NodeType::Dir, COMPR);
        std::fs::write(c.join("f"), "data").unwrap();
        set(&c.join("f"), &NodeType::File, NODUMP);
        assert_eq!(flags_of(&c.join("f"), &NodeType::File), COMPR | NODUMP);
        assert!(compression(&c.join("f")).is_some());
        restore_attributes(&c.join("f"), &file_node, true).unwrap();
        assert_eq!(flags_of(&c.join("f"), &NodeType::File), 0);
        assert_eq!(compression(&c.join("f")), None);
        restore_attributes(&c, &dir_node, true).unwrap();
        assert_eq!(flags_of(&c, &NodeType::Dir), 0);
        assert_eq!(compression(&c), None);

        // No-copy-on-write.
        let n = mnt.join("n");
        std::fs::create_dir(&n).unwrap();
        set(&n, &NodeType::Dir, NOCOW);
        std::fs::write(n.join("empty"), "").unwrap();
        std::fs::write(n.join("data"), "data").unwrap();
        assert_eq!(flags_of(&n.join("data"), &NodeType::File), NOCOW);
        restore_attributes(&n.join("empty"), &file_node, true).unwrap();
        assert_eq!(flags_of(&n.join("empty"), &NodeType::File), 0);
        restore_attributes(&n.join("data"), &file_node, true).unwrap();
        assert_eq!(
            flags_of(&n.join("data"), &NodeType::File),
            NOCOW,
            "btrfs took no-copy-on-write off a file with data: the warning is out of date"
        );
        restore_attributes(&n, &dir_node, true).unwrap();
        assert_eq!(flags_of(&n, &NodeType::Dir), 0);
    }

    /// G4-03, with root, on a loop ext4 that folds case: the flags a
    /// directory with entries has and its node doesn't go, but casefolding,
    /// which ext4 changes on no directory with entries: it stays (with a
    /// warning), and doesn't keep the others.
    #[test]
    fn restore_leaves_casefolding_the_node_lacks() {
        let args = ["-q", "-F", "-O", "casefold"];
        let Some(mnt) = LoopMount::new(64 << 20, "mkfs.ext4", &args) else {
            return;
        };
        let d = mnt.path().join("d");
        std::fs::create_dir(&d).unwrap();
        let f = open_for_flags(&d, &NodeType::Dir, None).unwrap();
        let new_dir = get_flags(&f).unwrap();
        if let Err(err) = set_flags(&f, new_dir | FS_CASEFOLD_FL | NODUMP) {
            eprintln!("restore_leaves_casefolding_the_node_lacks: {err}: nothing tested");
            return;
        }
        std::fs::write(d.join("entry"), "x").unwrap();
        assert_eq!(flags_of(&d.join("entry"), &NodeType::File), NODUMP);
        let node = Node::new_node(OsStr::new("n"), NodeType::Dir, NodeMetadata::default());
        restore_attributes(&d, &node, true).unwrap();
        assert_eq!(flags_of(&d, &NodeType::Dir), FS_CASEFOLD_FL);
        let after = ctime_of(&d);
        restore_attributes(&d, &node, true).unwrap();
        assert_eq!(
            ctime_of(&d),
            after,
            "a second restore wrote to the directory"
        );
        // What it handed down goes from the file.
        let node = Node::new_node(OsStr::new("n"), NodeType::File, NodeMetadata::default());
        restore_attributes(&d.join("entry"), &node, true).unwrap();
        assert_eq!(flags_of(&d.join("entry"), &NodeType::File), 0);
    }

    /// G4-03, where the tests run on ZFS (TMPDIR on a ZFS data set): a node
    /// without `linux.zfs_dos_flags` in a snapshot of BackOtter's gives the
    /// file archive alone, where it has other DOS flags.
    #[test]
    fn restore_takes_off_dos_flags_the_node_lacks() {
        let dir = tempfile::tempdir().unwrap();
        let (file, sub) = (dir.path().join("f"), dir.path().join("d"));
        std::fs::write(&file, b"x").unwrap();
        std::fs::create_dir(&sub).unwrap();
        if !is_zfs(&File::open(&file).unwrap()).unwrap() {
            return;
        }
        let attribute = |path: &Path, typ: &NodeType| {
            filled(path, typ)
                .meta
                .generic_attributes
                .number_u64(LINUX_ZFS_DOS_FLAGS)
        };
        for (path, typ) in [(&file, NodeType::File), (&sub, NodeType::Dir)] {
            let node = Node::new_node(OsStr::new("n"), typ.clone(), NodeMetadata::default());
            for flags in [ZFS_HIDDEN | ZFS_SYSTEM | ZFS_ARCHIVE, 0] {
                restore_zfs_dos_flags(path, &typ, flags).unwrap();
                let had = attribute(path, &typ);
                assert_eq!(had, Some(flags), "{}", path.display());
                restore_attributes(path, &node, false).unwrap();
                assert_eq!(attribute(path, &typ), had, "not BackOtter's: kept");
                let mut own = node.clone();
                own.meta
                    .generic_attributes
                    .set_u64(LINUX_ZFS_DOS_FLAGS, flags);
                restore_attributes(path, &own, true).unwrap();
                assert_eq!(attribute(path, &typ), had, "the node's own: kept");
                restore_attributes(path, &node, true).unwrap();
                assert_eq!(attribute(path, &typ), None, "{}", path.display());
                let f = open_for_flags(path, &typ, None).unwrap();
                assert_eq!(get_dos_flags(&f).unwrap() & ZFS_DOS_KEPT, ZFS_ARCHIVE);
                let after = ctime_of(path);
                restore_attributes(path, &node, true).unwrap();
                assert_eq!(ctime_of(path), after, "a second restore wrote to the file");
            }
        }
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

    #[test]
    fn clear_restricting_flags_clears_i_and_a_only() {
        // Nothing there and a symlink: nothing to do.
        assert!(clear_restricting_flags(Path::new("/nonexistent/bko")).is_err());
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("nowhere", dir.path().join("l")).unwrap();
        clear_restricting_flags(&dir.path().join("l")).unwrap();
        // Setting i or a takes CAP_LINUX_IMMUTABLE (root), and a file
        // system with flags.
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        let f = open_for_flags(&path, &NodeType::File, None).unwrap();
        let Ok(current) = get_flags(&f) else { return };
        if set_flags(&f, current | FS_IMMUTABLE_FL | FS_APPEND_FL | NODUMP).is_err() {
            return;
        }
        clear_restricting_flags(&path).unwrap();
        let after = get_flags(&f).unwrap();
        assert_eq!(after & (FS_IMMUTABLE_FL | FS_APPEND_FL), 0, "{after:#x}");
        assert_ne!(after & NODUMP, 0, "nodump cleared: {after:#x}");
        std::fs::write(&path, b"rewritten").unwrap();
    }

    #[test]
    fn clear_restricting_with_zfs_xflags() {
        // BackOtter: OpenZFS 2.2 behaves as if it took fsx_xflags for
        // FS_IOC_GETFLAGS's flags, where FS_XFLAG_APPEND clears immutable and
        // append-only stays: the flags clear it then. Elsewhere fsx_xflags clear both, or a file
        // system without FS_IOC_FSSETXATTR (ENOTTY) takes the flags.
        const EXTENTS: u32 = 0x0008_0000;
        let ia = FS_IMMUTABLE_FL | FS_APPEND_FL;
        for (name, start, zfs, no_xattr, want_sets) in [
            ("ext4 i+a", EXTENTS | ia, false, false, 0),
            ("ext4 none", EXTENTS, false, false, 0),
            ("no FSSETXATTR", EXTENTS | FS_APPEND_FL, false, true, 1),
            ("zfs a", FS_APPEND_FL, true, false, 1),
            ("zfs i+a", ia, true, false, 1),
            ("zfs i", FS_IMMUTABLE_FL, true, false, 0),
        ] {
            let flags = std::cell::Cell::new(start);
            let sets = std::cell::Cell::new(0);
            let cleared = clear_restricting_with(
                Path::new("f"),
                || Ok(flags.get()),
                |f| {
                    sets.set(sets.get() + 1);
                    flags.set(f);
                    Ok(())
                },
                |xflags| {
                    if no_xattr {
                        return Err(io::Error::from_raw_os_error(libc::ENOTTY));
                    }
                    let mut f = flags.get();
                    if zfs {
                        f &= !xflags;
                    } else {
                        if xflags & FS_XFLAG_IMMUTABLE != 0 {
                            f &= !FS_IMMUTABLE_FL;
                        }
                        if xflags & FS_XFLAG_APPEND != 0 {
                            f &= !FS_APPEND_FL;
                        }
                    }
                    flags.set(f);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(cleared, start & ia, "{name}");
            assert_eq!(flags.get(), start & !ia, "{name}");
            assert_eq!(sets.get(), want_sets, "{name}");
        }
    }

    /// BackOtter: the flags cleared go back on the file, wherever its other
    /// names are, once the name they came off for is gone; a file left
    /// without a name needs none.
    #[test]
    fn restricting_flags_held_go_back_on_other_names() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::write(&a, b"x").unwrap();
        std::fs::hard_link(&a, &b).unwrap();
        let f = open_for_flags(&a, &NodeType::File, None).unwrap();
        let Ok(current) = get_flags(&f) else { return };
        // Setting i takes CAP_LINUX_IMMUTABLE (root), and flags.
        if set_flags(&f, current | FS_IMMUTABLE_FL).is_err() {
            return;
        }
        let held = clear_restricting_flags_held(&a).unwrap();
        assert!(
            matches!(
                held,
                HeldFlags::Held {
                    cleared: FS_IMMUTABLE_FL,
                    ..
                }
            ),
            "{held:?}"
        );
        std::fs::remove_file(&a).unwrap();
        held.put_back().unwrap();
        assert_ne!(
            get_flags(&f).unwrap() & FS_IMMUTABLE_FL,
            0,
            "b lost immutable"
        );
        assert!(OpenOptions::new().write(true).open(&b).is_err());
        let held = clear_restricting_flags_held(&b).unwrap();
        std::fs::remove_file(&b).unwrap();
        held.put_back().unwrap();
    }

    #[test]
    fn put_back_restricting_with_zfs_xflags() {
        // OpenZFS 2.2 takes fsx_xflags for FS_IOC_GETFLAGS's flags: the
        // flags put append-only back there.
        let ia = FS_IMMUTABLE_FL | FS_APPEND_FL;
        for (name, zfs, no_xattr, cleared, want_sets) in [
            ("ext4 i+a", false, false, ia, 0),
            ("no FSSETXATTR", false, true, FS_APPEND_FL, 1),
            ("zfs a", true, false, FS_APPEND_FL, 1),
            ("nothing", false, false, 0, 0),
        ] {
            let flags = std::cell::Cell::new(0x0008_0000);
            let sets = std::cell::Cell::new(0);
            put_back_restricting_with(
                Path::new("f"),
                || Ok(flags.get()),
                |f| {
                    sets.set(sets.get() + 1);
                    flags.set(f);
                    Ok(())
                },
                |xflags| {
                    if no_xattr {
                        return Err(io::Error::from_raw_os_error(libc::ENOTTY));
                    }
                    let mut f = flags.get();
                    if zfs {
                        f |= xflags;
                    } else {
                        if xflags & FS_XFLAG_IMMUTABLE != 0 {
                            f |= FS_IMMUTABLE_FL;
                        }
                        if xflags & FS_XFLAG_APPEND != 0 {
                            f |= FS_APPEND_FL;
                        }
                    }
                    flags.set(f);
                    Ok(())
                },
                cleared,
            )
            .unwrap();
            assert_eq!(flags.get(), 0x0008_0000 | cleared, "{name}");
            assert_eq!(sets.get(), want_sets, "{name}");
        }
    }

    #[test]
    fn bcachefs_options_and_own_project() {
        assert!(is_bcachefs_option("bcachefs.compression"));
        assert!(is_bcachefs_option("bcachefs.background_target"));
        assert!(!is_bcachefs_option("bcachefs.project"));
        assert!(!is_bcachefs_option("bcachefs_effective.compression"));
        assert!(!is_bcachefs_option("user.bcachefs.compression"));
        assert_eq!(
            super::super::xattr_node_name("bcachefs.project".as_ref()),
            None
        );
        assert_eq!(
            super::super::xattr_node_name("bcachefs.projectx".as_ref()).as_deref(),
            Some("bcachefs.projectx")
        );
        assert_eq!(
            super::super::xattr_node_name("bcachefs.compression".as_ref()).as_deref(),
            Some("bcachefs.compression")
        );
    }

    /// Off bcachefs a directory gets nothing early, and a file without a
    /// project ID isn't opened for one.
    #[test]
    fn no_options_early_off_bcachefs() {
        let dir = tempfile::tempdir().unwrap();
        if is_bcachefs_path(dir.path()) {
            return;
        }
        let mut node = Node::new_node(OsStr::new("d"), NodeType::Dir, NodeMetadata::default());
        node.meta.extended_attributes = vec![ExtendedAttribute {
            name: "user.backotter".into(),
            value: Some(b"x".to_vec()),
        }];
        prepare_dir_for_options(dir.path(), &node, true);
        assert!(xattr::get(dir.path(), "user.backotter").unwrap().is_none());
        let path = dir.path().join("f");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let file = Node::new_node(OsStr::new("f"), NodeType::File, NodeMetadata::default());
        restore_attributes(&path, &file, true).unwrap();
    }

    /// The effective project ID of the file at `path`, on bcachefs.
    fn effective_projid(path: &Path) -> u32 {
        let f = File::open(path).unwrap();
        file_projid(&f, &get_fsxattr(&f).unwrap())
    }

    /// On bcachefs (an empty directory on one in `$BKO_BCACHEFS_TEST_DIR`,
    /// as root) a directory's options and project ID go on before its
    /// entries, which inherit them; an entry whose project ID is its
    /// directory's isn't given it again (it stays inherited, with no
    /// `bcachefs.project` of its own), one without a project ID gets 0, and
    /// a snapshot's `bcachefs.project` is neither set nor an error.
    #[test]
    fn bcachefs_dir_options_inherited() {
        let Some(base) = std::env::var_os("BKO_BCACHEFS_TEST_DIR") else {
            return;
        };
        let d = Path::new(&base).join("rustic-d");
        std::fs::create_dir(&d).unwrap();
        assert!(is_bcachefs_path(&d), "{} is not on bcachefs", d.display());
        let mut dir = Node::new_node(OsStr::new("d"), NodeType::Dir, NodeMetadata::default());
        dir.meta.extended_attributes = vec![
            ExtendedAttribute {
                name: "bcachefs.compression".into(),
                value: Some(b"zstd".to_vec()),
            },
            ExtendedAttribute {
                name: "bcachefs.project".into(),
                value: Some(b"43".to_vec()),
            },
        ];
        dir.meta.generic_attributes.set_number(LINUX_PROJECT_ID, 43);
        prepare_dir_for_options(&d, &dir, true);
        assert_eq!(effective_projid(&d), 43);

        let kid = d.join("kid");
        std::fs::write(&kid, b"data").unwrap();
        let zero = d.join("zero");
        std::fs::write(&zero, b"data").unwrap();
        let stock = d.join("stock");
        std::fs::write(&stock, b"data").unwrap();
        let compression = xattr::get(&kid, "bcachefs_effective.compression")
            .unwrap()
            .unwrap();
        assert!(compression.starts_with(b"zstd"), "{compression:?}");

        let mut kid_node =
            Node::new_node(OsStr::new("kid"), NodeType::File, NodeMetadata::default());
        kid_node
            .meta
            .generic_attributes
            .set_number(LINUX_PROJECT_ID, 43);
        restore_attributes(&kid, &kid_node, true).unwrap();
        let zero_node = Node::new_node(OsStr::new("zero"), NodeType::File, NodeMetadata::default());
        restore_attributes(&zero, &zero_node, true).unwrap();
        // A node without one in a snapshot not BackOtter's: it stays inherited.
        restore_attributes(&stock, &zero_node, false).unwrap();
        restore_attributes(&d, &dir, true).unwrap();

        assert_eq!(effective_projid(&kid), 43);
        assert_eq!(effective_projid(&zero), 0);
        assert_eq!(effective_projid(&stock), 43);
        let names: Vec<_> = xattr::list(&kid).unwrap().collect();
        assert!(!names.iter().any(|n| n == "bcachefs.project"), "{names:?}");
        assert!(
            !names.iter().any(|n| n == "bcachefs.compression"),
            "{names:?}"
        );
        assert_eq!(
            xattr::get(&d, "bcachefs.compression").unwrap().as_deref(),
            Some(&b"zstd"[..])
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn xattr_values_are_read_whole() {
        // BackOtter: values over the xattr crate's first 4 KiB, which it read
        // as empty, and every name.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"data").unwrap();
        assert_eq!(xattr_get(&path, "user.none".as_ref()).unwrap(), None);
        assert!(xattr_get(&dir.path().join("nonexistent"), "user.x".as_ref()).is_err());
        let small = b"small".to_vec();
        if xattr::set(&path, "user.small", &small).is_err() {
            return; // no user.* attributes here
        }
        assert_eq!(
            xattr_get(&path, "user.small".as_ref()).unwrap(),
            Some(small)
        );
        assert_eq!(xattr_get(&path, "user.empty".as_ref()).unwrap(), None);
        xattr::set(&path, "user.empty", b"").unwrap();
        assert_eq!(
            xattr_get(&path, "user.empty".as_ref()).unwrap(),
            Some(Vec::new())
        );
        let mut names = xattr_list(&path).unwrap();
        names.sort();
        assert_eq!(names, ["user.empty", "user.small"]);
        // ext4 without ea_inode holds a block's worth; XFS, btrfs and tmpfs
        // more.
        for size in [4095, 4096, 4097, 15000, 60000] {
            let big: Vec<u8> = (0..size)
                .map(|i| u8::try_from(i % 251 + 1).unwrap())
                .collect();
            if xattr::set(&path, "user.big", &big).is_err() {
                continue;
            }
            assert_eq!(
                xattr_get(&path, "user.big".as_ref()).unwrap(),
                Some(big),
                "{size}"
            );
        }
    }
}
