//! OpenBSD: file flags (`st_flags`).

use std::{io, os::openbsd::fs::MetadataExt, path::Path};

use super::{c_path, check, path_error, set_flags_best_effort};
use crate::backend::node::{Node, NodeType, generic_attributes::OPENBSD_FILE_FLAGS};

pub(super) const FILE_FLAGS: Option<&str> = Some(OPENBSD_FILE_FLAGS);
pub(super) const FLAGS_BEFORE_DATA: u32 = 0;
pub(super) const FLAGS_BEFORE_ENTRIES: u32 = 0;

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

pub(super) fn file_flags(_path: &Path, _typ: &NodeType, m: &std::fs::Metadata) -> io::Result<u32> {
    Ok(m.st_flags() & KEPT_FLAGS)
}

pub(super) fn fill_attributes(_path: &Path, _node: &mut Node) -> io::Result<()> {
    Ok(())
}

pub(super) fn prepare_file_for_flags(_path: &Path, _flags: u32) -> io::Result<()> {
    Ok(())
}

pub(super) fn prepare_dir_for_flags(_path: &Path, _flags: u32) -> io::Result<()> {
    Ok(())
}

pub(super) fn restore_file_flags(path: &Path, typ: &NodeType, flags: u32) -> io::Result<()> {
    let p = c_path(path)?;
    let symlink = matches!(typ, NodeType::Symlink { .. });
    set_flags_best_effort(flags & KEPT_FLAGS, |bits| {
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
    .map_err(|err| path_error("chflags", path, &err))
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
