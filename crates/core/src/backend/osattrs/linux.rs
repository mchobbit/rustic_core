//! Linux: the inode flags `chattr(1)` sets (`FS_IOC_GETFLAGS`).

use std::{
    fs::{File, OpenOptions},
    io,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
};

use log::debug;

use super::{path_error, set_flags_best_effort};
use crate::backend::node::{Node, NodeType, generic_attributes::LINUX_INODE_FLAGS};

pub(super) const FILE_FLAGS: Option<&str> = Some(LINUX_INODE_FLAGS);

/// From `<linux/fs.h>`: the inode flags `chattr(1)` sets, s u c S i a d A m
/// j t D T C P. The rest belong to the file system (extents, inline data,
/// ...) or need more than setting (DAX, casefolding, verity, encryption).
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
    | 0x2000_0000; // FS_PROJINHERIT_FL P

/// The flags a file system only takes while a file is empty: btrfs ignores
/// `FS_NOCOW_FL` on a file with data, without an error.
pub(super) const FLAGS_BEFORE_DATA: u32 = 0x0080_0000; // FS_NOCOW_FL

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

pub(super) fn fill_attributes(_path: &Path, _node: &mut Node) -> io::Result<()> {
    Ok(())
}

pub(super) fn restore_file_flags(path: &Path, typ: &NodeType, flags: u32) -> io::Result<()> {
    let f = open_for_flags(path, typ)?;
    let current = get_flags(&f).map_err(|err| path_error("FS_IOC_GETFLAGS", path, &err))?;
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
    // A file system without the flags (ext4 and XFS have no
    // no-copy-on-write): restore_file_flags reports that later.
    let unsupported = |err: &io::Error| {
        matches!(err.raw_os_error(), Some(libc::ENOTTY | libc::EOPNOTSUPP | libc::EINVAL))
    };
    let current = match get_flags(&f) {
        Ok(current) => current,
        Err(err) if unsupported(&err) => return Ok(()),
        Err(err) => return Err(path_error("FS_IOC_GETFLAGS", path, &err)),
    };
    match set_flags(&f, current | flags) {
        Err(err) if !unsupported(&err) => Err(path_error("FS_IOC_SETFLAGS", path, &err)),
        _ => Ok(()),
    }
}

pub(super) fn restore_attributes(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

pub(super) fn restore_acls(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

pub(super) fn restore_symlink_mode(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}
