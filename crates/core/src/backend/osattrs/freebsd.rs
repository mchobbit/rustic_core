//! FreeBSD: file flags (`st_flags`), ACLs, POSIX.1e (UFS mounted with
//! "acls") or NFSv4 (ZFS, UFS mounted with "nfsv4acls"), and extended
//! attributes in the system namespace, which rustic otherwise misses (it
//! keeps the user namespace). Without its ACL a file comes back with its mode
//! alone, and a POSIX.1e ACL's mode holds the mask in its group bits, so the
//! owning group can end up with more access than it had.

use std::{
    collections::BTreeMap,
    ffi::CString,
    io,
    os::freebsd::fs::MetadataExt,
    path::Path,
    ptr,
};

use log::debug;
use serde_derive::{Deserialize, Serialize};
use serde_with::{DefaultOnNull, base64::Base64, serde_as};

use super::{
    c_path, check,
    freebsd_acl::{self, AclEntry, MAX_ENTRIES},
    path_error, set_flags_best_effort,
};
use crate::backend::{
    ignore::mapper::nix_mapper::map_mode_from_go,
    node::{
        ExtendedAttribute, Node, NodeType,
        generic_attributes::{
            FREEBSD_ACL_ACCESS, FREEBSD_ACL_DEFAULT, FREEBSD_ACL_NFS4, FREEBSD_FILE_FLAGS,
            FREEBSD_SYSTEM_EXTATTRS,
        },
    },
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

const ACL_TYPE_ACCESS: libc::c_int = 2;
const ACL_TYPE_DEFAULT: libc::c_int = 3;
const ACL_TYPE_NFS4: libc::c_int = 4;
const PC_ACL_EXTENDED: libc::c_int = 59;
const PC_ACL_NFS4: libc::c_int = 64;

/// The system extended attributes UFS stores ACLs in. They are kept as ACLs
/// instead, and set through the ACL system calls, which check them.
const UFS_ACL_EXTATTRS: [&str; 3] = ["posix1e.acl_access", "posix1e.acl_default", "nfs4.acl"];

/// `struct acl` from `<sys/acl.h>`, as `__acl_get_link(2)` and
/// `__acl_set_link(2)` take it.
#[repr(C)]
struct RawAcl {
    maxcnt: u32,
    cnt: u32,
    spare: [i32; 4],
    entries: [RawAclEntry; MAX_ENTRIES],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawAclEntry {
    tag: u32,
    id: u32,
    perm: u32,
    entry_type: u16,
    flags: u16,
}

unsafe extern "C" {
    fn __acl_get_link(path: *const libc::c_char, typ: libc::c_int, acl: *mut RawAcl) -> libc::c_int;
    fn __acl_set_link(path: *const libc::c_char, typ: libc::c_int, acl: *mut RawAcl) -> libc::c_int;
    fn lpathconf(path: *const libc::c_char, name: libc::c_int) -> libc::c_long;
    fn lchmod(path: *const libc::c_char, mode: libc::mode_t) -> libc::c_int;
}

fn new_raw_acl() -> Box<RawAcl> {
    Box::new(RawAcl {
        maxcnt: u32::try_from(MAX_ENTRIES).unwrap(),
        cnt: 0,
        spare: [0; 4],
        entries: [RawAclEntry::default(); MAX_ENTRIES],
    })
}

/// The ACL of type `typ` of the file at `path`, without following a symlink.
fn get_acl(path: &Path, typ: libc::c_int) -> io::Result<Vec<AclEntry>> {
    let p = c_path(path)?;
    let mut raw = new_raw_acl();
    // SAFETY: raw is a struct acl with maxcnt set.
    _ = check(unsafe { __acl_get_link(p.as_ptr(), typ, &raw mut *raw) })?;
    let n = usize::try_from(raw.cnt).unwrap_or(usize::MAX);
    let entries = raw.entries.get(..n).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("ACL with {n} entries"))
    })?;
    Ok(entries
        .iter()
        .map(|e| AclEntry {
            tag: e.tag,
            id: e.id,
            perm: e.perm,
            entry_type: e.entry_type,
            flags: e.flags,
        })
        .collect())
}

/// Sets the ACL of type `typ` of the file at `path`.
fn set_acl(path: &Path, typ: libc::c_int, acl: &[AclEntry]) -> io::Result<()> {
    if acl.len() > MAX_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}: ACL with {} entries", path.display(), acl.len()),
        ));
    }
    let p = c_path(path)?;
    let mut raw = new_raw_acl();
    raw.cnt = u32::try_from(acl.len()).unwrap();
    for (r, e) in raw.entries.iter_mut().zip(acl) {
        *r = RawAclEntry {
            tag: e.tag,
            id: e.id,
            perm: e.perm,
            entry_type: e.entry_type,
            flags: e.flags,
        };
    }
    // SAFETY: raw is a struct acl holding cnt entries.
    _ = check(unsafe { __acl_set_link(p.as_ptr(), typ, &raw mut *raw) })
        .map_err(|err| path_error("__acl_set_link", path, &err))?;
    Ok(())
}

fn path_conf(path: &Path, name: libc::c_int) -> io::Result<i64> {
    let p = c_path(path)?;
    // SAFETY: p is a C string.
    check(unsafe { lpathconf(p.as_ptr(), name) })
}

/// Errors that mean the file system or the user can't have this kind of
/// metadata, rather than that reading it failed.
fn unsupported(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EOPNOTSUPP | libc::EINVAL | libc::EPERM | libc::EACCES)
    )
}

/// Calls an `extattr_*_link(2)` function with a buffer of `size`, or no
/// buffer when `size` is 0, and returns what it returns.
fn extattr_call(
    size: usize,
    f: impl FnOnce(*mut libc::c_void, usize) -> libc::ssize_t,
) -> io::Result<Vec<u8>> {
    let mut buf = vec![0_u8; size];
    let ptr = if size == 0 {
        ptr::null_mut()
    } else {
        buf.as_mut_ptr().cast()
    };
    let n = usize::try_from(check(f(ptr, size))?).unwrap_or(usize::MAX);
    buf.truncate(n.min(size));
    if size == 0 {
        buf.resize(n, 0); // just the size
    }
    Ok(buf)
}

/// Reads a system extended attribute list or value: first its size, then
/// the data.
fn extattr_read(
    f: impl Fn(*mut libc::c_void, usize) -> libc::ssize_t,
) -> io::Result<Vec<u8>> {
    let size = extattr_call(0, &f)?.len();
    if size == 0 {
        return Ok(Vec::new());
    }
    extattr_call(size, f)
}

/// The names of the user extended attributes of the file at `path`,
/// without following a symlink.
pub(super) fn user_extattr_names(path: &Path) -> io::Result<Vec<String>> {
    list_extattrs(path, libc::EXTATTR_NAMESPACE_USER)
}

/// The names of the extended attributes in `namespace` of the file at
/// `path`, without following a symlink.
fn list_extattrs(path: &Path, namespace: libc::c_int) -> io::Result<Vec<String>> {
    let p = c_path(path)?;
    let list = extattr_read(|data, n| {
        // SAFETY: data is null or points to n bytes.
        unsafe { libc::extattr_list_link(p.as_ptr(), namespace, data, n) }
    })?;
    // Each name follows a byte holding its length.
    let mut names = Vec::new();
    let mut rest = list.as_slice();
    while let Some((&n, tail)) = rest.split_first() {
        let Some(name) = tail.get(..usize::from(n)) else {
            break;
        };
        names.push(String::from_utf8_lossy(name).into_owned());
        rest = &tail[usize::from(n)..];
    }
    Ok(names)
}

fn get_system_extattr(path: &Path, name: &str) -> io::Result<Vec<u8>> {
    let p = c_path(path)?;
    let n = CString::new(name)?;
    extattr_read(|data, size| {
        // SAFETY: data is null or points to size bytes.
        unsafe {
            libc::extattr_get_link(p.as_ptr(), libc::EXTATTR_NAMESPACE_SYSTEM, n.as_ptr(), data, size)
        }
    })
}

fn set_system_extattr(path: &Path, name: &str, value: &[u8]) -> io::Result<()> {
    let p = c_path(path)?;
    let n = CString::new(name)?;
    // SAFETY: value points to value.len() bytes.
    let r = unsafe {
        libc::extattr_set_link(
            p.as_ptr(),
            libc::EXTATTR_NAMESPACE_SYSTEM,
            n.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
        )
    };
    _ = check(r).map_err(|err| path_error(&format!("extattr_set_link system.{name}"), path, &err))?;
    Ok(())
}

/// The system extended attributes, by name, as BackOtter's restic keeps them
/// (a Go `map[string][]byte`: base64 values).
#[serde_as]
#[derive(Serialize, Deserialize, Default)]
#[serde(transparent)]
struct SystemExtattrs(#[serde_as(as = "BTreeMap<_, DefaultOnNull<Base64>>")] BTreeMap<String, Vec<u8>>);

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
    let extattrs = fill_system_extattrs(path, node);
    let acls = fill_acls(path, node);
    extattrs.and(acls)
}

fn fill_system_extattrs(path: &Path, node: &mut Node) -> io::Result<()> {
    let names = match list_extattrs(path, libc::EXTATTR_NAMESPACE_SYSTEM) {
        Ok(names) => names,
        Err(err) if unsupported(&err) => {
            // Not root, or no extended attributes on this file system.
            debug!("no system extended attributes for {}: {err}", path.display());
            return Ok(());
        }
        Err(err) => return Err(path_error("extattr_list_link system", path, &err)),
    };
    let mut attrs = SystemExtattrs::default();
    for name in names {
        if UFS_ACL_EXTATTRS.contains(&name.as_str()) {
            continue;
        }
        match get_system_extattr(path, &name) {
            Ok(value) => _ = attrs.0.insert(name, value),
            Err(err) if err.raw_os_error() == Some(libc::ENOATTR) => {} // removed since the listing
            Err(err) => {
                return Err(path_error(&format!("extattr_get_link system.{name}"), path, &err));
            }
        }
    }
    if attrs.0.is_empty() {
        return Ok(());
    }
    node.meta
        .generic_attributes
        .set(FREEBSD_SYSTEM_EXTATTRS, &attrs)
        .map_err(io::Error::other)
}

fn fill_acls(path: &Path, node: &mut Node) -> io::Result<()> {
    if node.is_symlink() {
        return Ok(()); // FreeBSD has no ACLs on symlinks
    }
    let attrs = &mut node.meta.generic_attributes;
    let ignore_unsupported = |err: io::Error| {
        if unsupported(&err) {
            debug!("no ACL for {}: {err}", path.display());
            Ok(())
        } else {
            Err(path_error("__acl_get_link", path, &err))
        }
    };
    if path_conf(path, PC_ACL_NFS4).ok() == Some(1) {
        return match get_acl(path, ACL_TYPE_NFS4) {
            Ok(acl) if freebsd_acl::nfs4_is_trivial(&acl) => Ok(()),
            Ok(acl) => attrs.set(FREEBSD_ACL_NFS4, &acl).map_err(io::Error::other),
            Err(err) => ignore_unsupported(err),
        };
    }
    if path_conf(path, PC_ACL_EXTENDED).ok() != Some(1) {
        return Ok(()); // no ACLs on this file system
    }
    match get_acl(path, ACL_TYPE_ACCESS) {
        // Three entries are just the mode: user_obj, group_obj and other.
        Ok(acl) if acl.len() > 3 => attrs.set(FREEBSD_ACL_ACCESS, &acl).map_err(io::Error::other)?,
        Ok(_) => {}
        Err(err) => return ignore_unsupported(err),
    }
    if !matches!(node.node_type, NodeType::Dir) {
        return Ok(());
    }
    match get_acl(path, ACL_TYPE_DEFAULT) {
        Ok(acl) if acl.is_empty() => Ok(()),
        Ok(acl) => attrs.set(FREEBSD_ACL_DEFAULT, &acl).map_err(io::Error::other),
        Err(err) => ignore_unsupported(err),
    }
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
    let Some(attrs) = node.meta.generic_attributes.get::<SystemExtattrs>(FREEBSD_SYSTEM_EXTATTRS)
    else {
        return Ok(());
    };
    let attrs = attrs.map_err(io::Error::other)?;
    let mut first_err = None;
    for (name, value) in &attrs.0 {
        if let Err(err) = set_system_extattr(path, name, value) {
            _ = first_err.get_or_insert(err);
        }
    }
    first_err.map_or(Ok(()), Err)
}

/// Restores the ACLs. If a POSIX.1e access ACL can't be set, the mode
/// restored before it has the ACL's mask in its group bits, which would give
/// the owning group all that named users and groups had; they are narrowed
/// to the group's own access.
pub(super) fn restore_acls(path: &Path, node: &Node) -> io::Result<()> {
    if node.is_symlink() {
        return Ok(());
    }
    let mut first_err = None;
    let mut restore = |name: &str, typ: libc::c_int, failed: &dyn Fn(&[AclEntry]) -> io::Result<()>| {
        let Some(acl) = node.meta.generic_attributes.get::<Vec<AclEntry>>(name) else {
            return;
        };
        let result = acl.map_err(io::Error::other).and_then(|acl| {
            set_acl(path, typ, &acl).or_else(|err| failed(&acl).and(Err(err)))
        });
        if let Err(err) = result {
            _ = first_err.get_or_insert(err);
        }
    };
    restore(FREEBSD_ACL_NFS4, ACL_TYPE_NFS4, &|_| Ok(()));
    restore(FREEBSD_ACL_ACCESS, ACL_TYPE_ACCESS, &|acl| {
        let (Some(perms), Some(mode)) = (freebsd_acl::posix_owning_group_perms(acl), node.meta.mode)
        else {
            return Ok(());
        };
        let mode = map_mode_from_go(mode) & 0o7777 & !0o070 | perms << 3;
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))
            .map_err(|err| path_error("chmod", path, &err))
    });
    restore(FREEBSD_ACL_DEFAULT, ACL_TYPE_DEFAULT, &|_| Ok(()));
    first_err.map_or(Ok(()), Err)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_acl_is_struct_acl() {
        assert_eq!(size_of::<RawAcl>(), 4088);
    }

    #[test]
    fn system_extattrs_json_as_restic_writes_it() {
        let mut attrs = SystemExtattrs::default();
        _ = attrs.0.insert("a".to_string(), b"hi".to_vec());
        _ = attrs.0.insert("b".to_string(), Vec::new());
        assert_eq!(serde_json::to_string(&attrs).unwrap(), r#"{"a":"aGk=","b":""}"#);
        let back: SystemExtattrs = serde_json::from_str(r#"{"a":"aGk=","b":null}"#).unwrap();
        assert_eq!(back.0["a"], b"hi");
        assert!(back.0["b"].is_empty());
    }
}
