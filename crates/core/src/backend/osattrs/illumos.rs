//! illumos: the ACLs ZFS keeps (NFSv4-style ACEs), and the system attributes
//! (immutable, appendonly, nounlink, nodump, hidden, readonly, ...), which
//! are kept and restored as file flags. Without its ACL a file comes back
//! with its mode alone, which loses named users and groups and, worse, deny
//! entries: access the ACL denied can come back allowed.
//!
//! libc's `fgetattr(3C)` and `fsetattr(3C)` read and write the system
//! attributes through each file's `SUNWattr_rw` extended attribute, a packed
//! nvlist; this does the same, without libnvpair.

use std::{
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileExt, OpenOptionsExt},
    },
    path::Path,
    ptr,
};

use log::debug;

use super::{
    c_path, check,
    illumos_acl::{self, AceEntry},
    illumos_sysattr, path_error, set_flags_best_effort,
};
use crate::backend::node::{
    ExtendedAttribute, Node, NodeType,
    generic_attributes::{ILLUMOS_ACL, ILLUMOS_SYSTEM_ATTRIBUTES},
};

pub(super) const FILE_FLAGS: Option<&str> = Some(ILLUMOS_SYSTEM_ATTRIBUTES);
pub(super) const FLAGS_BEFORE_DATA: u32 = 0;
pub(super) const FLAGS_BEFORE_ENTRIES: u32 = 0;
pub(super) const FLAGS_XATTRS: &[&str] = &[];

const ACE_GETACL: libc::c_int = 4;
const ACE_SETACL: libc::c_int = 5;
const ACE_GETACLCNT: libc::c_int = 6;
const O_XATTR: libc::c_int = 0x4000;

/// `ace_t` from `<sys/acl.h>`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawAce {
    who: u32,
    mask: u32,
    flags: u16,
    ace_type: u16,
}

unsafe extern "C" {
    fn acl(
        path: *const libc::c_char,
        cmd: libc::c_int,
        nentries: libc::c_int,
        aclbufp: *mut libc::c_void,
    ) -> libc::c_int;
}

/// The ACEs of the file at `path`; `acl(2)` follows symlinks, which have no
/// ACL of their own anyway.
fn get_ace(path: &Path) -> io::Result<Vec<AceEntry>> {
    let p = c_path(path)?;
    // SAFETY: ACE_GETACLCNT takes no buffer.
    let n = check(unsafe { acl(p.as_ptr(), ACE_GETACLCNT, 0, ptr::null_mut()) })?;
    if n <= 0 {
        return Ok(Vec::new());
    }
    let mut raw = vec![RawAce::default(); usize::try_from(n).unwrap_or_default()];
    // SAFETY: raw holds n ace_t.
    let n = check(unsafe { acl(p.as_ptr(), ACE_GETACL, n, raw.as_mut_ptr().cast()) })?;
    raw.truncate(usize::try_from(n).unwrap_or_default());
    Ok(raw
        .iter()
        .map(|r| AceEntry {
            who: r.who,
            mask: r.mask,
            flags: r.flags,
            ace_type: r.ace_type,
        })
        .collect())
}

fn set_ace(path: &Path, entries: &[AceEntry]) -> io::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let p = c_path(path)?;
    let mut raw: Vec<_> = entries
        .iter()
        .map(|e| RawAce {
            who: e.who,
            mask: e.mask,
            flags: e.flags,
            ace_type: e.ace_type,
        })
        .collect();
    let n = libc::c_int::try_from(raw.len()).map_err(io::Error::other)?;
    // SAFETY: raw holds n ace_t.
    _ = check(unsafe { acl(p.as_ptr(), ACE_SETACL, n, raw.as_mut_ptr().cast()) })
        .map_err(|err| path_error("acl ACE_SETACL", path, &err))?;
    Ok(())
}

/// Errors that mean the file system or the user can't have this kind of
/// metadata, rather than that reading it failed.
fn unsupported(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::ENOSYS | libc::ENOTSUP | libc::EINVAL | libc::EPERM | libc::EACCES)
    )
}

/// Opens the `SUNWattr_rw` view of the file at `path`, a regular file or
/// directory; other types of file have no system attributes worth keeping,
/// and opening a device or FIFO could have side effects.
fn sysattr_view(path: &Path, typ: &NodeType, write: bool) -> io::Result<File> {
    if !matches!(typ, NodeType::File | NodeType::Dir) {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|err| path_error("open", path, &err))?;
    let how = O_XATTR | libc::O_CLOEXEC | if write { libc::O_RDWR } else { libc::O_RDONLY };
    // SAFETY: the name is a C string.
    let fd = check(unsafe { libc::openat(f.as_raw_fd(), c"SUNWattr_rw".as_ptr(), how) })
        .map_err(|err| path_error("openat SUNWattr_rw", path, &err))?;
    // SAFETY: fd is a new file descriptor, owned by nothing else.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn read_view(f: &mut File, path: &Path) -> io::Result<Vec<u8>> {
    let mut view = Vec::new();
    _ = f
        .read_to_end(&mut view)
        .map_err(|err| path_error("read SUNWattr_rw", path, &err))?;
    Ok(view)
}

/// No file is opened for its attributes ahead of them here.
pub(super) fn open_for_attrs(
    _path: &Path,
    _typ: &NodeType,
    _m: &std::fs::Metadata,
) -> Option<File> {
    None
}

pub(super) fn file_flags(
    path: &Path,
    typ: &NodeType,
    _m: &std::fs::Metadata,
    _f: Option<&File>,
) -> io::Result<u32> {
    if !matches!(typ, NodeType::File | NodeType::Dir) {
        return Ok(0);
    }
    let mut f = match sysattr_view(path, typ, false) {
        Ok(f) => f,
        Err(err) => {
            // A file system without them.
            debug!("no system attributes for {}: {err}", path.display());
            return Ok(0);
        }
    };
    let view = read_view(&mut f, path)?;
    let mask =
        illumos_sysattr::mask(&view).map_err(|err| path_error("read SUNWattr_rw", path, &err))?;
    if mask & !illumos_sysattr::AUTOMATIC == 0 {
        return Ok(0);
    }
    Ok(mask)
}

pub(super) fn fill_attributes(path: &Path, node: &mut Node, _f: Option<&File>) -> io::Result<()> {
    if node.is_symlink() {
        return Ok(());
    }
    let entries = match get_ace(path) {
        Ok(entries) => entries,
        Err(err) if unsupported(&err) => {
            debug!("no ACL for {}: {err}", path.display());
            return Ok(());
        }
        Err(err) => return Err(path_error("acl ACE_GETACL", path, &err)),
    };
    if entries.is_empty() || illumos_acl::is_trivial(&entries) {
        return Ok(());
    }
    node.meta
        .generic_attributes
        .set(ILLUMOS_ACL, &entries)
        .map_err(io::Error::other)
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
    let mut f = sysattr_view(path, typ, true)?;
    let mut view = read_view(&mut f, path)?;
    set_flags_best_effort(ILLUMOS_SYSTEM_ATTRIBUTES, path, "write SUNWattr_rw", flags, |mask| {
        illumos_sysattr::set_mask(&mut view, mask)?;
        f.write_all_at(&view, 0)
    })
}

/// Nothing to restore along with the extended attributes on illumos.
pub(super) fn restore_attributes(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

/// Restores the ACL, after the mode, since `chmod(2)` rewrites a ZFS ACL.
pub(super) fn restore_acls(path: &Path, node: &Node) -> io::Result<()> {
    if node.is_symlink() {
        return Ok(());
    }
    match node.meta.generic_attributes.get::<Vec<AceEntry>>(ILLUMOS_ACL) {
        Some(entries) => set_ace(path, &entries.map_err(io::Error::other)?),
        None => Ok(()),
    }
}

/// A symlink's own permissions don't matter on illumos.
pub(super) fn restore_symlink_mode(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

/// The system attribute views in every attribute directory, which aren't
/// extended attributes of their own.
const SYSTEM_VIEWS: [&str; 2] = ["SUNWattr_ro", "SUNWattr_rw"];

/// Opens the attribute directory of the file at `path`, a regular file or
/// directory. `None` for other types of file, which have none worth keeping
/// (and opening a device could have side effects), and on a file system
/// without them.
fn attr_dir(path: &Path) -> io::Result<Option<File>> {
    let m = std::fs::symlink_metadata(path)?;
    if !(m.is_file() || m.is_dir()) {
        return Ok(None);
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let how = O_XATTR | libc::O_RDONLY | libc::O_CLOEXEC;
    // SAFETY: "." is a C string.
    match check(unsafe { libc::openat(f.as_raw_fd(), c".".as_ptr(), how) }) {
        // SAFETY: fd is a new file descriptor, owned by nothing else.
        Ok(fd) => Ok(Some(unsafe { File::from_raw_fd(fd) })),
        Err(err) if matches!(err.raw_os_error(), Some(libc::EINVAL | libc::ENOTSUP)) => Ok(None),
        Err(err) => Err(err),
    }
}

/// The names in an attribute directory, without the system attribute views.
fn attr_names(dir: &File) -> io::Result<Vec<String>> {
    // fdopendir(3C) takes over the descriptor it's given: give it its own.
    // SAFETY: dir is an open descriptor.
    let fd = check(unsafe { libc::dup(dir.as_raw_fd()) })?;
    // SAFETY: fd is an open directory descriptor.
    let d = unsafe { libc::fdopendir(fd) };
    if d.is_null() {
        let err = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so fd is still ours.
        _ = unsafe { libc::close(fd) };
        return Err(err);
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: d is an open DIR.
        let e = unsafe { libc::readdir(d) };
        if e.is_null() {
            break;
        }
        // SAFETY: d_name is a C string, valid until the next readdir.
        let name = unsafe { CStr::from_ptr((*e).d_name.as_ptr()) }.to_string_lossy();
        if name != "." && name != ".." && !SYSTEM_VIEWS.contains(&&*name) {
            names.push(name.into_owned());
        }
    }
    // SAFETY: d is an open DIR, closed once.
    _ = unsafe { libc::closedir(d) };
    Ok(names)
}

fn open_attr(dir: &File, name: &str, how: libc::c_int) -> io::Result<File> {
    let n = CString::new(name)?;
    let mode: libc::c_uint = 0o666;
    // SAFETY: n is a C string.
    let fd = check(unsafe { libc::openat(dir.as_raw_fd(), n.as_ptr(), how | libc::O_CLOEXEC, mode) })?;
    // SAFETY: fd is a new file descriptor, owned by nothing else.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// The extended attributes of the file at `path`: on illumos, named
/// attribute files (`runat(1)`, `fsattr(5)`), which the xattr crate doesn't
/// support.
pub(super) fn xattrs(path: &Path) -> io::Result<Vec<ExtendedAttribute>> {
    let Some(dir) = attr_dir(path)? else {
        return Ok(Vec::new());
    };
    attr_names(&dir)?
        .into_iter()
        .map(|name| {
            let mut value = Vec::new();
            _ = open_attr(&dir, &name, libc::O_RDONLY)?.read_to_end(&mut value)?;
            Ok(ExtendedAttribute {
                name,
                value: Some(value),
            })
        })
        .collect()
}

/// Gives the file at `path` exactly the extended attributes `attrs`.
pub(super) fn set_xattrs(path: &Path, attrs: &[ExtendedAttribute]) -> io::Result<()> {
    let Some(dir) = attr_dir(path)? else {
        if attrs.is_empty() {
            return Ok(());
        }
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no extended attributes on this file system",
        ));
    };
    for name in attr_names(&dir)? {
        if !attrs.iter().any(|a| a.name == name) {
            let n = CString::new(name)?;
            // SAFETY: n is a C string.
            _ = check(unsafe { libc::unlinkat(dir.as_raw_fd(), n.as_ptr(), 0) })?;
        }
    }
    for a in attrs {
        let mut f = open_attr(&dir, &a.name, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC)?;
        f.write_all(a.value.as_deref().unwrap_or_default())?;
    }
    Ok(())
}
