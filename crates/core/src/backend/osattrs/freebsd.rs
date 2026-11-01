//! FreeBSD: file flags (`st_flags`), ZFS project IDs, and the ACLs and
//! system extended attributes it shares with NetBSD (`freebsd_netbsd.rs`).

use std::{
    collections::BTreeMap,
    ffi::CStr,
    fs::{File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        freebsd::fs::MetadataExt,
        unix::fs::{MetadataExt as _, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    ptr,
    sync::Mutex,
};

use jiff::Timestamp;
use log::debug;

use super::{
    Unsupported, XattrErrors,
    bsd_flags::{
        FREEBSD_KEPT_FLAGS as KEPT_FLAGS, FREEBSD_RESTRICTING_FLAGS, freebsd_file_flags,
    },
    c_path, check, freebsd_netbsd,
    illumos_project::ZfsProject,
    lower_birthtime, path_error, set_flags_best_effort,
};
use crate::backend::{
    ignore::mapper::nix_mapper::map_mode_from_go,
    node::{
        ExtendedAttribute, Node, NodeType,
        generic_attributes::{FREEBSD_FILE_FLAGS, FREEBSD_ZFS_PROJECT},
    },
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

/// Opens a regular file or directory on ZFS for its ZFS project
/// ([`fill_attributes`]). `None` for other types of file, on other file
/// systems, and where it can't be opened (not readable, gone, replaced).
pub(super) fn open_for_attrs(path: &Path, typ: &NodeType, m: &std::fs::Metadata) -> Option<File> {
    if !matches!(typ, NodeType::File | NodeType::Dir) || !on_zfs(path, m) {
        return None;
    }
    open_for_project(path, typ, Some(m))
        .inspect_err(|err| debug!("no ZFS project for {}: {err}", path.display()))
        .ok()
        .flatten()
}

/// `zfsxattr`, the struct OpenZFS's project ioctls take on FreeBSD: Linux's
/// `struct fsxattr`, 28 bytes, with ioctls `'X'` 31 and 32, as `truss(1)`
/// shows `zfs project` calling them on FreeBSD 15.1. Of the flags, only
/// inheritance (`ZFS_PROJINHERIT_FL`) is changed; the others are given back
/// as read.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct ZfsXattr {
    xflags: u32,
    extsize: u32,
    nextents: u32,
    projid: u32,
    cowextsize: u32,
    pad: [u8; 8],
}

// The ioctls carry the struct's size (28): it must be that.
const _: () = assert!(size_of::<ZfsXattr>() == 28);

const ZFS_IOC_FSGETXATTR: libc::c_ulong = 0x401c_581f; // _IOR('X', 31, zfsxattr_t)
const ZFS_IOC_FSSETXATTR: libc::c_ulong = 0x801c_5820; // _IOW('X', 32, zfsxattr_t)

fn zfs_xattr(f: &File, request: libc::c_ulong, zx: &mut ZfsXattr) -> io::Result<()> {
    // SAFETY: both ioctls take a ZfsXattr.
    check(unsafe { libc::ioctl(f.as_raw_fd(), request, ptr::from_mut(zx)) }).map(drop)
}

/// Opens the regular file or directory at `path`, of type `typ`, for its
/// project ioctls, with `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY|O_CLOEXEC`
/// (and `O_DIRECTORY`), so as not to follow a symlink, wait on a lock or take
/// a terminal. `None` if it isn't of type `typ`, or, given `listed` (at
/// backup: the lstat), not that file.
fn open_for_project(
    path: &Path,
    typ: &NodeType,
    listed: Option<&std::fs::Metadata>,
) -> io::Result<Option<File>> {
    let mut how = libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY;
    let dir = matches!(typ, NodeType::Dir);
    if dir {
        how |= libc::O_DIRECTORY;
    } else if !matches!(typ, NodeType::File) {
        return Ok(None);
    }
    let f = OpenOptions::new().read(true).custom_flags(how).open(path)?;
    let m = f.metadata()?;
    let same_type = if dir { m.is_dir() } else { m.is_file() };
    if !same_type || listed.is_some_and(|l| (l.dev(), l.ino()) != (m.dev(), m.ino())) {
        return Ok(None);
    }
    Ok(Some(f))
}

/// Records the ZFS project of a regular file or directory on ZFS (`f`,
/// opened by [`open_for_attrs`]), when it has one: an ID or inheritance.
fn fill_zfs_project(path: &Path, node: &mut Node, f: &File) {
    let mut zx = ZfsXattr::default();
    if let Err(err) = zfs_xattr(f, ZFS_IOC_FSGETXATTR, &mut zx) {
        debug!("no ZFS project for {}: {err}", path.display());
        return;
    }
    if let Some(p) = ZfsProject::of(zx.xflags, zx.projid) {
        _ = node.meta.generic_attributes.set(FREEBSD_ZFS_PROJECT, &p);
    }
}

/// Gives the regular file or directory at `path` its ZFS project: its own
/// ID and inheritance, whatever it got from the directory it was created
/// in, as on illumos. It goes before the file flags. A file system other
/// than ZFS (UFS: `ENOTTY`) gives an [`Unsupported`] error.
fn restore_zfs_project(path: &Path, node: &Node) -> io::Result<()> {
    let Some(p) = node.meta.generic_attributes.get::<ZfsProject>(FREEBSD_ZFS_PROJECT) else {
        return Ok(());
    };
    let p = p.map_err(io::Error::other)?;
    let Some(f) = open_for_project(path, &node.node_type, None)
        .map_err(|err| path_error("open", path, &err))?
    else {
        return Ok(());
    };
    let error = |op, err| {
        if super::unsupported(&err) {
            Unsupported::error(FREEBSD_ZFS_PROJECT, 0, err)
        } else {
            path_error(op, path, &err)
        }
    };
    let mut zx = ZfsXattr::default();
    zfs_xattr(&f, ZFS_IOC_FSGETXATTR, &mut zx).map_err(|err| error("ioctl get ZFS project", err))?;
    let mut want = ZfsXattr {
        xflags: p.xflags(zx.xflags),
        projid: p.id,
        ..zx
    };
    if want == zx {
        return Ok(());
    }
    zfs_xattr(&f, ZFS_IOC_FSSETXATTR, &mut want).map_err(|err| error("ioctl set ZFS project", err))
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

pub(super) fn fill_attributes(path: &Path, node: &mut Node, f: Option<&File>) -> io::Result<()> {
    if let Some(f) = f {
        fill_zfs_project(path, node, f);
    }
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
    let own = current & !KEPT_FLAGS;
    let p = c_path(path)?;
    set_flags_best_effort(
        FREEBSD_FILE_FLAGS,
        path,
        "lchflags",
        Some(current & KEPT_FLAGS),
        flags & KEPT_FLAGS,
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

/// Restores the system extended attributes and the ZFS project.
pub(super) fn restore_attributes(path: &Path, node: &Node) -> io::Result<()> {
    let extattrs = freebsd_netbsd::restore_system_extattrs(path, node);
    restore_zfs_project(path, node).and(extattrs)
}

/// Clears the flags of the file at `path` that keep a restore from
/// rewriting, replacing or changing it ([`FREEBSD_RESTRICTING_FLAGS`]),
/// leaving the others as they are; the late flags pass sets the node's.
pub(super) fn clear_restricting_flags(path: &Path) -> io::Result<()> {
    let flags = std::fs::symlink_metadata(path)?.st_flags();
    if flags & FREEBSD_RESTRICTING_FLAGS == 0 {
        return Ok(());
    }
    let p = c_path(path)?;
    // SAFETY: p is a C string.
    check(unsafe { libc::lchflags(p.as_ptr(), (flags & !FREEBSD_RESTRICTING_FLAGS).into()) })
        .map(drop)
        .map_err(|err| path_error("lchflags", path, &err))
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
pub(super) fn set_xattrs(_path: &Path, _attrs: &[ExtendedAttribute]) -> Result<(), XattrErrors> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "extended attributes go through xattr").into())
}
