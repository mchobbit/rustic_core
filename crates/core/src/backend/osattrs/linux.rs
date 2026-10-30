//! Linux: the inode flags `chattr(1)` sets (`FS_IOC_GETFLAGS`), and the
//! project ID (`FS_IOC_FSGETXATTR`) that project quotas count by.

use std::{
    fs::{File, Metadata, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

use log::{debug, warn};

use super::{Unsupported, path_error, set_flags_best_effort, unsupported};
use crate::backend::node::{
    ExtendedAttribute, Node, NodeType,
    generic_attributes::{LINUX_INODE_FLAGS, LINUX_PROJECT_ID},
};

pub(super) const FILE_FLAGS: Option<&str> = Some(LINUX_INODE_FLAGS);

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
) -> io::Result<u32> {
    let Some(f) = f else {
        return Ok(0);
    };
    // A file system without inode flags (ENOTTY, EOPNOTSUPP, ...).
    let flags = get_flags(f);
    Ok(flags
        .inspect_err(|err| debug!("no file flags for {}: {err}", path.display()))
        .unwrap_or_default()
        & INODE_FLAGS)
}

/// Records the project ID of a regular file or directory, unless it is 0.
pub(super) fn fill_attributes(path: &Path, node: &mut Node, f: Option<&File>) -> io::Result<()> {
    let Some(f) = f else {
        return Ok(());
    };
    match get_fsxattr(f) {
        Ok(attr) => node.meta.generic_attributes.set_number(LINUX_PROJECT_ID, attr.projid),
        Err(err) if unsupported(&err) => {}
        Err(err) => return Err(path_error("FS_IOC_FSGETXATTR", path, &err)),
    }
    Ok(())
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
            Unsupported::error(LINUX_INODE_FLAGS, flags & INODE_FLAGS, err)
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
            flags & KEPT_LATE,
            |f| set(own | f),
        );
    };
    let late = flags & (FS_IMMUTABLE_FL | FS_APPEND_FL);
    let first = flags & KEPT_LATE & !late;
    let set_first = if own | first == current {
        Ok(())
    } else {
        set_flags_best_effort(LINUX_INODE_FLAGS, path, "FS_IOC_SETFLAGS", first, |f| {
            set(own | f)
        })
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
                Unsupported::error(LINUX_INODE_FLAGS, late, err)
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
    if attr.projid != projid {
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
