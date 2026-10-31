//! NetBSD: file flags (`st_flags`), symlinks' own permissions, and the ACLs
//! and system extended attributes it shares with FreeBSD
//! (`freebsd_netbsd.rs`), which FFSv2ea has (`newfs -O 2ea`) and FFSv2 not.

use std::{io, os::netbsd::fs::MetadataExt, path::Path};

use jiff::Timestamp;

use super::{
    bsd_flags::NETBSD_KEPT_FLAGS, c_path, check, chmod_symlink, freebsd_netbsd, lower_birthtime,
    path_error, set_flags_best_effort,
};
use crate::backend::node::{
    ExtendedAttribute, Node, NodeType, generic_attributes::NETBSD_FILE_FLAGS,
};

pub(super) const FILE_FLAGS: Option<&str> = Some(NETBSD_FILE_FLAGS);
pub(super) const FLAGS_BEFORE_DATA: u32 = 0;
pub(super) const FLAGS_BEFORE_ENTRIES: u32 = 0;
pub(super) const FLAGS_XATTRS: &[&str] = &[];
pub(super) const ZFS_DOS_FLAGS: Option<&str> = None;

/// No file is opened for its attributes ahead of them here.
pub(super) fn open_for_attrs(
    _path: &Path,
    _typ: &NodeType,
    _m: &std::fs::Metadata,
) -> Option<std::fs::File> {
    None
}

pub(super) fn file_flags(
    _path: &Path,
    _typ: &NodeType,
    m: &std::fs::Metadata,
    _f: Option<&std::fs::File>,
) -> io::Result<u32> {
    Ok(m.st_flags() & NETBSD_KEPT_FLAGS)
}

pub(super) fn fill_attributes(
    path: &Path,
    node: &mut Node,
    _f: Option<&std::fs::File>,
) -> io::Result<()> {
    freebsd_netbsd::fill_attributes(path, node)
}

pub(super) fn prepare_file_for_flags(_path: &Path, _flags: u32) -> io::Result<()> {
    Ok(())
}

pub(super) fn prepare_dir_for_flags(_path: &Path, _flags: u32) -> io::Result<()> {
    Ok(())
}

pub(super) fn restore_file_flags(
    path: &Path,
    _typ: &NodeType,
    flags: u32,
    _xattrs: &[ExtendedAttribute],
) -> io::Result<()> {
    // Leave the flags that aren't kept as the file has them.
    let own = std::fs::symlink_metadata(path)
        .map_err(|err| path_error("lstat", path, &err))?
        .st_flags()
        & !NETBSD_KEPT_FLAGS;
    let p = c_path(path)?;
    set_flags_best_effort(
        NETBSD_FILE_FLAGS,
        path,
        "lchflags",
        flags & NETBSD_KEPT_FLAGS,
        |bits| {
            // SAFETY: p is a C string.
            check(unsafe { libc::lchflags(p.as_ptr(), (own | bits).into()) }).map(drop)
        },
    )
}

pub(super) fn restore_zfs_dos_flags(_path: &Path, _typ: &NodeType, _flags: u64) -> io::Result<()> {
    Ok(())
}

/// The numeric owner the restore gives is all there is.
pub(super) fn restore_owner(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

/// Restores the system extended attributes.
pub(super) fn restore_attributes(path: &Path, node: &Node) -> io::Result<()> {
    freebsd_netbsd::restore_system_extattrs(path, node)
}

/// Restores the ACLs, a symlink's too.
pub(super) fn restore_acls(path: &Path, node: &Node) -> io::Result<()> {
    freebsd_netbsd::restore_acls(path, node)
}

pub(super) fn restore_symlink_mode(path: &Path, node: &Node) -> io::Result<()> {
    chmod_symlink(path, node)
}

/// Sets the birth time as an earlier mtime, which the final times replace
/// (`osattrs.rs`).
pub(super) fn restore_birthtime(path: &Path, node: &Node, birth: Timestamp) -> io::Result<()> {
    lower_birthtime(path, node, birth)
}
