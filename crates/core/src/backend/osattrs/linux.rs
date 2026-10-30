//! Linux: the inode flags `chattr(1)` sets (`FS_IOC_GETFLAGS`), and the
//! project ID (`FS_IOC_FSGETXATTR`) that project quotas count by.

use std::{
    fs::{File, OpenOptions},
    io,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
};

use log::debug;

use super::{path_error, set_flags_best_effort};
use crate::backend::node::{
    Node, NodeType,
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
    | 0x0000_0010 // FS_IMMUTABLE_FL    i
    | 0x0000_0020 // FS_APPEND_FL       a
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

/// Case-insensitive names in a directory (ext4, f2fs).
const FS_CASEFOLD_FL: u32 = 0x4000_0000;

/// The flags a file system only takes while a file is empty: btrfs ignores
/// `FS_NOCOW_FL` on a file with data, without an error.
pub(super) const FLAGS_BEFORE_DATA: u32 = 0x0080_0000; // FS_NOCOW_FL

/// The flags a file system only takes while a directory is empty: ext4 and
/// f2fs refuse to change `FS_CASEFOLD_FL` on one with entries.
pub(super) const FLAGS_BEFORE_ENTRIES: u32 = FS_CASEFOLD_FL;

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

/// Opens a regular file or directory for `FS_IOC_GETFLAGS` and
/// `FS_IOC_SETFLAGS`, as `lsattr(1)` and `chattr(1)` do. Other types of file
/// have no flags, and opening a device or FIFO could have side effects.
fn open_for_flags(path: &Path, typ: &NodeType) -> io::Result<File> {
    let mut how = libc::O_NOFOLLOW | libc::O_NONBLOCK;
    match typ {
        NodeType::File => {}
        NodeType::Dir => how |= libc::O_DIRECTORY,
        _ => return Err(io::Error::from(io::ErrorKind::Unsupported)),
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(how)
        .open(path)
        .map_err(|err| path_error("open", path, &err))
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

/// Errors that mean the file system doesn't have these flags or attributes
/// (ext4 and XFS have no no-copy-on-write, btrfs no project IDs).
fn unsupported(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::ENOTTY | libc::EOPNOTSUPP | libc::EINVAL))
}

/// The flags a file that has `current` gets for `flags`: the
/// [`INODE_FLAGS`] of `flags`, and the file system's own as they are.
const fn wanted_flags(current: u32, flags: u32) -> u32 {
    (current & !INODE_FLAGS) | (flags & INODE_FLAGS)
}

pub(super) fn file_flags(path: &Path, typ: &NodeType, _m: &std::fs::Metadata) -> io::Result<u32> {
    if !matches!(typ, NodeType::File | NodeType::Dir) {
        return Ok(0);
    }
    // Not readable (not root), gone, or a file system without inode flags
    // (ENOTTY, EOPNOTSUPP, ...): the backup reports the first two for the
    // contents, if it matters.
    let flags = open_for_flags(path, typ).and_then(|f| get_flags(&f));
    Ok(flags.inspect_err(|err| debug!("no file flags for {}: {err}", path.display()))
        .unwrap_or_default()
        & INODE_FLAGS)
}

/// Records the project ID of a regular file or directory, unless it is 0.
pub(super) fn fill_attributes(path: &Path, node: &mut Node) -> io::Result<()> {
    if !matches!(node.node_type, NodeType::File | NodeType::Dir) {
        return Ok(());
    }
    // Not readable (not root) or gone: as for the flags.
    let f = match open_for_flags(path, &node.node_type) {
        Ok(f) => f,
        Err(err) => {
            debug!("no project ID for {}: {err}", path.display());
            return Ok(());
        }
    };
    match get_fsxattr(&f) {
        Ok(attr) => node.meta.generic_attributes.set_number(LINUX_PROJECT_ID, attr.projid),
        Err(err) if unsupported(&err) => {}
        Err(err) => return Err(path_error("FS_IOC_FSGETXATTR", path, &err)),
    }
    Ok(())
}

pub(super) fn restore_file_flags(path: &Path, typ: &NodeType, flags: u32) -> io::Result<()> {
    let f = open_for_flags(path, typ)?;
    let current = get_flags(&f).map_err(|err| path_error("FS_IOC_GETFLAGS", path, &err))?;
    // Nothing to change: on btrfs every FS_IOC_SETFLAGS rewrites the
    // btrfs.compression property, restored before as an extended attribute
    // (or, without FS_COMPR_FL, deletes it).
    if wanted_flags(current, flags) == current {
        return Ok(());
    }
    // Keep the file system's own flags as they are.
    let own = current & !INODE_FLAGS;
    set_flags_best_effort(flags & INODE_FLAGS, |f2| set_flags(&f, own | f2))
        .map_err(|err| path_error("FS_IOC_SETFLAGS", path, &err))
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
    add_flags(&f, path, flags)
}

pub(super) fn prepare_dir_for_flags(path: &Path, flags: u32) -> io::Result<()> {
    let f = open_for_flags(path, &NodeType::Dir)?;
    add_flags(&f, path, flags)
}

/// Adds `flags` to those of the file `f` at `path`. A file system without
/// them (ext4 and XFS have no no-copy-on-write, btrfs and XFS no
/// casefolding) is no error here: restore_file_flags reports that later.
fn add_flags(f: &File, path: &Path, flags: u32) -> io::Result<()> {
    let current = match get_flags(f) {
        Ok(current) => current,
        Err(err) if unsupported(&err) => return Ok(()),
        Err(err) => return Err(path_error("FS_IOC_GETFLAGS", path, &err)),
    };
    match set_flags(f, current | flags) {
        Err(err) if !unsupported(&err) => Err(path_error("FS_IOC_SETFLAGS", path, &err)),
        _ => Ok(()),
    }
}

/// Restores the project ID, along with the extended attributes.
pub(super) fn restore_attributes(path: &Path, node: &Node) -> io::Result<()> {
    let Some(projid) = node.meta.generic_attributes.number(LINUX_PROJECT_ID) else {
        return Ok(());
    };
    let f = open_for_flags(path, &node.node_type)?;
    let mut attr = get_fsxattr(&f).map_err(|err| path_error("FS_IOC_FSGETXATTR", path, &err))?;
    if attr.projid != projid {
        attr.projid = projid;
        set_fsxattr(&f, &attr).map_err(|err| path_error("FS_IOC_FSSETXATTR", path, &err))?;
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
    use super::*;

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
    fn wanted_flags_keep_the_file_systems_own() {
        const EXTENTS: u32 = 0x0008_0000; // FS_EXTENT_FL, ext4's own
        const IMMUTABLE: u32 = 0x0000_0010;
        const NOCOW: u32 = 0x0080_0000;
        assert_eq!(wanted_flags(EXTENTS | IMMUTABLE, IMMUTABLE), EXTENTS | IMMUTABLE);
        assert_eq!(wanted_flags(EXTENTS, IMMUTABLE | EXTENTS), EXTENTS | IMMUTABLE);
        assert_eq!(wanted_flags(EXTENTS | NOCOW, IMMUTABLE), EXTENTS | IMMUTABLE);
        assert_eq!(
            wanted_flags(FS_CASEFOLD_FL, FS_CASEFOLD_FL | IMMUTABLE),
            FS_CASEFOLD_FL | IMMUTABLE
        );
    }

    #[test]
    fn no_project_id_no_attribute() {
        // A file a user creates has project ID 0, or the file system has no
        // project IDs: either way, no attribute.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        let mut node = Node::default();
        fill_attributes(&path, &mut node).unwrap();
        assert_eq!(node.meta.generic_attributes.number(LINUX_PROJECT_ID), None);
    }
}
