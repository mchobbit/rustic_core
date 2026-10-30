//! Systems without file flags or ACLs that BackOtter keeps.

use std::{io, path::Path};

use crate::backend::node::{Node, NodeType};

pub(super) const FILE_FLAGS: Option<&str> = None;
pub(super) const FLAGS_BEFORE_DATA: u32 = 0;

pub(super) fn file_flags(_path: &Path, _typ: &NodeType, _m: &std::fs::Metadata) -> io::Result<u32> {
    Ok(0)
}

pub(super) fn fill_attributes(_path: &Path, _node: &mut Node) -> io::Result<()> {
    Ok(())
}

pub(super) fn prepare_file_for_flags(_path: &Path, _flags: u32) -> io::Result<()> {
    Ok(())
}

pub(super) fn restore_file_flags(_path: &Path, _typ: &NodeType, _flags: u32) -> io::Result<()> {
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
