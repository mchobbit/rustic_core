//! OpenBSD: file flags (`st_flags`) and symlinks' own permissions.

use std::{io, os::openbsd::fs::MetadataExt, path::Path};

use jiff::Timestamp;

use super::{
    XattrErrors, bsd_flags::NETBSD_OPENBSD_RESTRICTING_FLAGS, c_path, check, chmod_symlink,
    path_error, set_flags_best_effort,
};
use crate::backend::node::{
    ExtendedAttribute, Node, NodeType, generic_attributes::OPENBSD_FILE_FLAGS,
};

pub(super) const FILE_FLAGS: Option<&str> = Some(OPENBSD_FILE_FLAGS);
pub(super) const FLAGS_BEFORE_DATA: u32 = 0;
pub(super) const FLAGS_BEFORE_ENTRIES: u32 = 0;
pub(super) const FLAGS_XATTRS: &[&str] = &[];
pub(super) const ZFS_DOS_FLAGS: Option<&str> = None;

/// From `<sys/stat.h>`: the flags an owner may set (nodump, immutable,
/// append, opaque) and those only root may (archived, immutable, append; the
/// last two can't be cleared again above securelevel 0).
const KEPT_FLAGS: u32 = 0x0000_ffff | 0xffff_0000;

unsafe extern "C" {
    fn chflagsat(
        fd: libc::c_int,
        path: *const libc::c_char,
        flags: libc::c_uint,
        atflags: libc::c_int,
    ) -> libc::c_int;
}

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

pub(super) fn restore_file_flags(
    path: &Path,
    typ: &NodeType,
    flags: u32,
    _xattrs: &[ExtendedAttribute],
) -> io::Result<()> {
    let p = c_path(path)?;
    let symlink = matches!(typ, NodeType::Symlink { .. });
    set_flags_best_effort(OPENBSD_FILE_FLAGS, path, "chflags", None, flags & KEPT_FLAGS, |bits| {
        // SAFETY: p is a C string.
        let r = unsafe {
            if symlink {
                chflagsat(libc::AT_FDCWD, p.as_ptr(), bits, libc::AT_SYMLINK_NOFOLLOW)
            } else {
                libc::chflags(p.as_ptr(), bits)
            }
        };
        check(r).map(drop)
    })
}

pub(super) fn restore_zfs_dos_flags(_path: &Path, _typ: &NodeType, _flags: u64) -> io::Result<()> {
    Ok(())
}

/// Clears the flags of the file at `path` that keep a restore from
/// rewriting, replacing or changing it
/// ([`NETBSD_OPENBSD_RESTRICTING_FLAGS`]), leaving the others as they are;
/// the late flags pass sets the node's.
pub(super) fn clear_restricting_flags(path: &Path) -> io::Result<()> {
    let flags = std::fs::symlink_metadata(path)?.st_flags();
    if flags & NETBSD_OPENBSD_RESTRICTING_FLAGS == 0 {
        return Ok(());
    }
    let p = c_path(path)?;
    // SAFETY: p is a C string.
    let r = unsafe {
        chflagsat(
            libc::AT_FDCWD,
            p.as_ptr(),
            flags & !NETBSD_OPENBSD_RESTRICTING_FLAGS,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    check(r).map(drop).map_err(|err| path_error("chflagsat", path, &err))
}

pub(super) fn restore_owner(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

pub(super) fn restore_attributes(_path: &Path, _node: &Node) -> io::Result<()> {
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

/// Extended attributes go through the xattr crate here.
pub(super) fn xattrs(_path: &Path) -> io::Result<Vec<ExtendedAttribute>> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "extended attributes go through xattr"))
}

/// Extended attributes go through the xattr crate here.
pub(super) fn set_xattrs(_path: &Path, _attrs: &[ExtendedAttribute]) -> Result<(), XattrErrors> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "extended attributes go through xattr").into())
}
