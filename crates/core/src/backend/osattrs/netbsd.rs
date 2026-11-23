//! NetBSD: file flags (`st_flags`), symlinks' own permissions, and the ACLs
//! and system extended attributes it shares with FreeBSD
//! (`freebsd_netbsd.rs`), which FFSv2ea has (`newfs -O 2ea`) and FFSv2 not.

#![allow(
    clippy::unnecessary_wraps,
    reason = "the os:: interface: every system's module has the same signatures"
)]

use std::{io, os::netbsd::fs::MetadataExt, path::Path};

use jiff::Timestamp;

use super::{
    RestoreErrors, XattrErrors, bsd_held::restore_no_flags,
    bsd_flags::NETBSD_KEPT_FLAGS,
    c_path, check, chmod_symlink, freebsd_netbsd,
    lower_birthtime, path_error, set_flags_best_effort,
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
) -> io::Result<Option<u32>> {
    Ok(Some(m.st_flags() & NETBSD_KEPT_FLAGS).filter(|&flags| flags != 0))
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
    let current = std::fs::symlink_metadata(path)
        .map_err(|err| path_error("lstat", path, &err))?
        .st_flags();
    let own = current & !NETBSD_KEPT_FLAGS;
    let p = c_path(path)?;
    set_flags_best_effort(
        NETBSD_FILE_FLAGS,
        path,
        "lchflags",
        Some(current & NETBSD_KEPT_FLAGS),
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

pub(super) use super::bsd_held::clear_restricting_flags;

/// The numeric owner the restore gives is all there is.
pub(super) fn restore_owner(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

/// Restores the system extended attributes. In a snapshot of BackOtter's
/// (`known_bko`), a file whose node holds no `netbsd.file_flags` had none,
/// and loses those it has now ([`restore_no_flags`]).
///
/// # Errors
///
/// * If either couldn't be set: the attributes' error, the flags', or one
///   that holds both ([`RestoreErrors`]).
pub(super) fn restore_attributes(path: &Path, node: &Node, known_bko: bool) -> io::Result<()> {
    let extattrs = freebsd_netbsd::restore_system_extattrs(path, node);
    let flags = if known_bko && node.meta.generic_attributes.value(NETBSD_FILE_FLAGS).is_none() {
        restore_no_flags(path, NETBSD_FILE_FLAGS, NETBSD_KEPT_FLAGS, 0)
    } else {
        Ok(())
    };
    RestoreErrors::result([extattrs, flags].into_iter().filter_map(Result::err).collect())
}

/// Restores the ACLs, a symlink's too; in a snapshot of BackOtter's
/// (`known_bko`), one the node hasn't got goes.
pub(super) fn restore_acls(path: &Path, node: &Node, known_bko: bool) -> io::Result<()> {
    freebsd_netbsd::restore_acls(path, node, known_bko)
}

pub(super) fn restore_symlink_mode(path: &Path, node: &Node) -> io::Result<()> {
    chmod_symlink(path, node)
}

/// Sets the birth time as an earlier mtime, which the final times replace
/// (`osattrs.rs`).
pub(super) fn restore_birthtime(path: &Path, node: &Node, birth: Timestamp) -> io::Result<()> {
    lower_birthtime(path, node, birth)
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
