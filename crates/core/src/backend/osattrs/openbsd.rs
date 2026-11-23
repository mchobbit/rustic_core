//! OpenBSD: file flags (`st_flags`) and symlinks' own permissions.

#![allow(
    clippy::unnecessary_wraps,
    reason = "the os:: interface: every system's module has the same signatures"
)]

use std::{io, os::openbsd::fs::MetadataExt, path::Path};

use jiff::Timestamp;

use super::{
    XattrErrors, bsd_flags::OPENBSD_KEPT_FLAGS as KEPT_FLAGS, bsd_held::restore_no_flags, c_path,
    check, chmod_symlink, set_flags_best_effort,
};
use crate::backend::node::{
    ExtendedAttribute, Node, NodeType, generic_attributes::OPENBSD_FILE_FLAGS,
};

pub(super) const FILE_FLAGS: Option<&str> = Some(OPENBSD_FILE_FLAGS);
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
    Ok(Some(m.st_flags() & KEPT_FLAGS).filter(|&flags| flags != 0))
}

pub(super) fn fill_attributes(
    _path: &Path,
    _node: &mut Node,
    _f: Option<&std::fs::File>,
) -> io::Result<()> {
    Ok(())
}

pub(super) fn prepare_file_for_flags(_path: &Path, _flags: u32) -> io::Result<()> {
    Ok(())
}

pub(super) fn prepare_dir_for_flags(_path: &Path, _flags: u32) -> io::Result<()> {
    Ok(())
}

/// Sets the flags without following a symlink, whatever the node's type,
/// as `lchflags(2)` does on the other BSDs: a path replaced by a symlink
/// since it was made doesn't pass them on to its target.
pub(super) fn restore_file_flags(
    path: &Path,
    _typ: &NodeType,
    flags: u32,
    _xattrs: &[ExtendedAttribute],
) -> io::Result<()> {
    let p = c_path(path)?;
    set_flags_best_effort(OPENBSD_FILE_FLAGS, path, "chflagsat", None, flags & KEPT_FLAGS, |bits| {
        // SAFETY: p is a C string.
        let r = unsafe {
            libc::chflagsat(libc::AT_FDCWD, p.as_ptr(), bits, libc::AT_SYMLINK_NOFOLLOW)
        };
        check(r).map(drop)
    })
}

pub(super) fn restore_zfs_dos_flags(_path: &Path, _typ: &NodeType, _flags: u64) -> io::Result<()> {
    Ok(())
}

pub(super) use super::bsd_held::clear_restricting_flags;

pub(super) fn restore_owner(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

/// In a snapshot of BackOtter's (`known_bko`), a file whose node holds no
/// `openbsd.file_flags` had none, and loses those it has now
/// ([`restore_no_flags`]). Nothing else to restore here.
pub(super) fn restore_attributes(path: &Path, node: &Node, known_bko: bool) -> io::Result<()> {
    if known_bko && node.meta.generic_attributes.value(OPENBSD_FILE_FLAGS).is_none() {
        return restore_no_flags(path, OPENBSD_FILE_FLAGS, KEPT_FLAGS, 0);
    }
    Ok(())
}

pub(super) fn restore_acls(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

pub(super) fn restore_symlink_mode(path: &Path, node: &Node) -> io::Result<()> {
    chmod_symlink(path, node)
}

/// OpenBSD's FFS2 reports a birth time of 0.
pub(super) fn restore_birthtime(_path: &Path, _node: &Node, _birth: Timestamp) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "OpenBSD keeps no birth times"))
}

/// Extended attributes have no metadata of their own here.
pub(super) fn fill_xattr_meta(_path: &Path, _node: &mut Node) {}

/// OpenBSD has no extended attributes: nothing reads them here, nor
/// through the xattr crate, which has no OpenBSD backend.
pub(super) fn xattrs(_path: &Path) -> io::Result<Vec<ExtendedAttribute>> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "OpenBSD has no extended attributes"))
}

/// OpenBSD has no extended attributes: there are none to set.
pub(super) fn set_xattrs(_path: &Path, _attrs: &[ExtendedAttribute]) -> Result<(), XattrErrors> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "OpenBSD has no extended attributes").into())
}
