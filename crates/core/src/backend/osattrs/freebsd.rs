//! FreeBSD: file flags (`st_flags`), and the ACLs and system extended
//! attributes it shares with NetBSD (`freebsd_netbsd.rs`).

use std::{
    collections::BTreeMap,
    ffi::CStr,
    io,
    os::freebsd::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Mutex,
};

use jiff::Timestamp;
use log::debug;

use super::{
    bsd_flags::{FREEBSD_KEPT_FLAGS as KEPT_FLAGS, freebsd_file_flags},
    c_path, check, freebsd_netbsd, lower_birthtime, path_error, set_flags_best_effort,
};
use crate::backend::{
    ignore::mapper::nix_mapper::map_mode_from_go,
    node::{ExtendedAttribute, Node, NodeType, generic_attributes::FREEBSD_FILE_FLAGS},
};

pub(super) const FILE_FLAGS: Option<&str> = Some(FREEBSD_FILE_FLAGS);
pub(super) const FLAGS_BEFORE_DATA: u32 = 0;
pub(super) const FLAGS_BEFORE_ENTRIES: u32 = 0;
pub(super) const FLAGS_XATTRS: &[&str] = &[];
// ZFS keeps its DOS flags in the file flags here (`uarch`, `uhidden`, ...).
pub(super) const ZFS_DOS_FLAGS: Option<&str> = None;

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
    path: &Path,
    _typ: &NodeType,
    m: &std::fs::Metadata,
    _f: Option<&std::fs::File>,
) -> io::Result<Option<u32>> {
    Ok(freebsd_file_flags(m.st_flags(), on_zfs(path, m)))
}

/// Whether the file at `path`, with metadata `m` (its lstat), is on ZFS,
/// by `statfs(2)`'s `f_fstypename`, once per file system (device): it
/// decides what the archive flag alone means ([`freebsd_file_flags`]). A
/// symlink is on the file system of its directory (`statfs(2)` follows it).
/// When `statfs(2)` fails, it isn't.
fn on_zfs(path: &Path, m: &std::fs::Metadata) -> bool {
    static ZFS: Mutex<BTreeMap<u64, bool>> = Mutex::new(BTreeMap::new());
    let mut known = ZFS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(&zfs) = known.get(&m.st_dev()) {
        return zfs;
    }
    let on = if m.file_type().is_symlink() {
        match path.parent() {
            Some(dir) if dir.as_os_str().is_empty() => PathBuf::from("."),
            Some(dir) => dir.to_path_buf(),
            None => path.to_path_buf(),
        }
    } else {
        path.to_path_buf()
    };
    match fs_type(&on) {
        Ok(name) => *known.entry(m.st_dev()).or_insert(name == "zfs"),
        Err(err) => {
            debug!("statfs {}: {err}", on.display());
            false
        }
    }
}

/// The type of the file system the file at `path` is on (`zfs`, `ufs`).
fn fs_type(path: &Path) -> io::Result<String> {
    let p = c_path(path)?;
    // SAFETY: a statfs is plain data, for statfs(2) to fill in.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: p is a C string, fs a statfs.
    _ = check(unsafe { libc::statfs(p.as_ptr(), &raw mut fs) })?;
    // SAFETY: the kernel ends f_fstypename with a NUL.
    let name = unsafe { CStr::from_ptr(fs.f_fstypename.as_ptr()) };
    Ok(name.to_string_lossy().into_owned())
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
pub(super) fn set_xattrs(_path: &Path, _attrs: &[ExtendedAttribute]) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "extended attributes go through xattr"))
}
