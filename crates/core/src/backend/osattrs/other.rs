//! Systems without file flags or ACLs that BackOtter keeps.

use std::{fs::File, io, path::Path};

use jiff::Timestamp;

use super::XattrErrors;
use crate::backend::node::{ExtendedAttribute, Node, NodeType};

pub(super) const FILE_FLAGS: Option<&str> = None;
pub(super) const FLAGS_BEFORE_DATA: u32 = 0;
pub(super) const FLAGS_BEFORE_ENTRIES: u32 = 0;
pub(super) const FLAGS_XATTRS: &[&str] = &[];
pub(super) const ZFS_DOS_FLAGS: Option<&str> = None;

pub(super) fn open_for_attrs(_path: &Path, _typ: &NodeType, _m: &std::fs::Metadata) -> Option<File> {
    None
}

pub(super) fn file_flags(
    _path: &Path,
    _typ: &NodeType,
    _m: &std::fs::Metadata,
    _f: Option<&File>,
) -> io::Result<Option<u32>> {
    Ok(None)
}

pub(super) fn fill_attributes(_path: &Path, _node: &mut Node, _f: Option<&File>) -> io::Result<()> {
    Ok(())
}

pub(super) fn prepare_file_for_flags(_path: &Path, _flags: u32) -> io::Result<()> {
    Ok(())
}

pub(super) fn prepare_dir_for_flags(_path: &Path, _flags: u32) -> io::Result<()> {
    Ok(())
}

pub(super) fn restore_file_flags(
    _path: &Path,
    _typ: &NodeType,
    _flags: u32,
    _xattrs: &[ExtendedAttribute],
) -> io::Result<()> {
    Ok(())
}

pub(super) fn restore_zfs_dos_flags(_path: &Path, _typ: &NodeType, _flags: u64) -> io::Result<()> {
    Ok(())
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

pub(super) fn restore_symlink_mode(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

pub(super) fn restore_birthtime(_path: &Path, _node: &Node, _birth: Timestamp) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "no birth times on this system"))
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
