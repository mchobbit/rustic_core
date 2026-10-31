//! FreeBSD: file flags (`st_flags`), and the ACLs and system extended
//! attributes it shares with NetBSD (`freebsd_netbsd.rs`).

use std::{io, os::freebsd::fs::MetadataExt, path::Path};

use super::{c_path, check, freebsd_netbsd, path_error, set_flags_best_effort};
use crate::backend::{
    ignore::mapper::nix_mapper::map_mode_from_go,
    node::{ExtendedAttribute, Node, NodeType, generic_attributes::FREEBSD_FILE_FLAGS},
};

pub(super) const FILE_FLAGS: Option<&str> = Some(FREEBSD_FILE_FLAGS);
pub(super) const FLAGS_BEFORE_DATA: u32 = 0;
pub(super) const FLAGS_BEFORE_ENTRIES: u32 = 0;
pub(super) const FLAGS_XATTRS: &[&str] = &[];

// From <sys/stat.h>.
const UF_SETTABLE: u32 = 0x0000_ffff; // the flags an owner may set
const SF_SETTABLE: u32 = 0xffff_0000; // the flags only root may set
const UF_ARCHIVE: u32 = 0x0000_0800; // "uarch"
const SF_SNAPSHOT: u32 = 0x0020_0000; // a UFS snapshot file

/// The flags kept: all that an owner or root can set, which leaves out
/// `SF_SNAPSHOT`.
const KEPT_FLAGS: u32 = (UF_SETTABLE | SF_SETTABLE) & !SF_SNAPSHOT;

unsafe extern "C" {
    fn lchmod(path: *const libc::c_char, mode: libc::mode_t) -> libc::c_int;
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
) -> io::Result<u32> {
    let flags = m.st_flags() & KEPT_FLAGS;
    // ZFS sets UF_ARCHIVE on every file it writes, as Windows does its
    // archive bit. On its own it would give nearly every file an attribute,
    // and a restore onto ZFS sets it again anyway, so it's kept only along
    // with other flags, which are set exactly as they were.
    if flags & !UF_ARCHIVE == 0 {
        return Ok(0);
    }
    Ok(flags)
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
        & !KEPT_FLAGS;
    let p = c_path(path)?;
    set_flags_best_effort(FREEBSD_FILE_FLAGS, path, "lchflags", flags & KEPT_FLAGS, |bits| {
        // SAFETY: p is a C string.
        check(unsafe { libc::lchflags(p.as_ptr(), (own | bits).into()) }).map(drop)
    })
}

/// Restores the system extended attributes.
pub(super) fn restore_attributes(path: &Path, node: &Node) -> io::Result<()> {
    freebsd_netbsd::restore_system_extattrs(path, node)
}

/// Restores the ACLs (FreeBSD has none on symlinks).
pub(super) fn restore_acls(path: &Path, node: &Node) -> io::Result<()> {
    freebsd_netbsd::restore_acls(path, node)
}

/// Gives a symlink its own permissions back: FreeBSD keeps them
/// (`lchmod(2)`), and `ls(1)` and `mtree(8)` show them, though access doesn't
/// depend on them. Without this a restored symlink gets 0755.
pub(super) fn restore_symlink_mode(path: &Path, node: &Node) -> io::Result<()> {
    let Some(mode) = node.meta.mode else {
        return Ok(());
    };
    let p = c_path(path)?;
    let mode = libc::mode_t::try_from(map_mode_from_go(mode) & 0o7777).unwrap_or(0o755);
    // SAFETY: p is a C string.
    _ = check(unsafe { lchmod(p.as_ptr(), mode) })
        .map_err(|err| path_error("lchmod", path, &err))?;
    Ok(())
}
