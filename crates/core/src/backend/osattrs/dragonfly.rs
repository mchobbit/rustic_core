//! DragonFly: file flags (`st_flags`) and symlinks' own permissions. Its
//! file systems (HAMMER2, UFS) have no extended attributes and no ACLs.

use std::{io, os::dragonfly::fs::MetadataExt, path::Path};

use super::{bsd_flags::DRAGONFLY_KEPT_FLAGS, c_path, check, chmod_symlink, set_flags_best_effort};
use crate::backend::node::{
    ExtendedAttribute, Node, NodeType, generic_attributes::DRAGONFLY_FILE_FLAGS,
};

pub(super) const FILE_FLAGS: Option<&str> = Some(DRAGONFLY_FILE_FLAGS);
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
    Ok(m.st_flags() & DRAGONFLY_KEPT_FLAGS)
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
    _typ: &NodeType,
    flags: u32,
    _xattrs: &[ExtendedAttribute],
) -> io::Result<()> {
    let p = c_path(path)?;
    set_flags_best_effort(
        DRAGONFLY_FILE_FLAGS,
        path,
        "lchflags",
        flags & DRAGONFLY_KEPT_FLAGS,
        |bits| {
            // SAFETY: p is a C string.
            check(unsafe { libc::lchflags(p.as_ptr(), bits.into()) }).map(drop)
        },
    )
}

pub(super) fn restore_zfs_dos_flags(_path: &Path, _typ: &NodeType, _flags: u64) -> io::Result<()> {
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
