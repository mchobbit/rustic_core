//! What FreeBSD and NetBSD share: ACLs, POSIX.1e (FreeBSD's UFS mounted with
//! "acls", NetBSD's FFSv2ea mounted with "posix1eacls") or NFSv4 (ZFS, UFS
//! and FFSv2ea mounted for them), and extended attributes, both the user
//! namespace, which the xattr crate misnames, and the system namespace,
//! which rustic otherwise misses. NetBSD took FreeBSD's system calls and
//! `struct acl`; they differ in numbers and in the names the attributes are
//! kept under ([`Os`]). Without its ACL a file comes back with its mode
//! alone, and a POSIX.1e ACL's mode holds the mask in its group bits, so
//! the owning group can end up with more access than it had.

use std::{
    collections::BTreeMap,
    ffi::{CString, OsString},
    io,
    path::Path,
    ptr,
};

use log::debug;
use serde_derive::{Deserialize, Serialize};
use serde_with::{DefaultOnNull, base64::Base64, serde_as};

use super::{
    acl_set_error, bsd_extattr, c_path, check,
    freebsd_acl::{self, AclEntry, AclType, MAX_ENTRIES, Os},
    path_error,
};
use crate::backend::{
    ignore::mapper::nix_mapper::map_mode_from_go,
    node::{Node, NodeType},
};

#[cfg(target_os = "freebsd")]
use freebsd_sys as sys;
#[cfg(target_os = "netbsd")]
use netbsd_sys as sys;

/// The system extended attributes UFS and FFSv2ea store ACLs in. They are
/// kept as ACLs instead, and set through the ACL system calls, which check
/// them.
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

#[cfg(target_os = "freebsd")]
mod freebsd_sys {
    use super::RawAcl;

    pub(super) const OS: &super::Os = &super::freebsd_acl::FREEBSD;

    unsafe extern "C" {
        #[link_name = "__acl_get_link"]
        pub(super) fn acl_get_link(
            path: *const libc::c_char,
            typ: libc::c_int,
            acl: *mut RawAcl,
        ) -> libc::c_int;
        #[link_name = "__acl_set_link"]
        pub(super) fn acl_set_link(
            path: *const libc::c_char,
            typ: libc::c_int,
            acl: *mut RawAcl,
        ) -> libc::c_int;
        pub(super) fn lpathconf(path: *const libc::c_char, name: libc::c_int) -> libc::c_long;
        #[link_name = "__acl_delete_link"]
        pub(super) fn acl_delete_link(path: *const libc::c_char, typ: libc::c_int) -> libc::c_int;
    }
}

/// NetBSD's ACL system calls, by their numbers in `<sys/syscall.h>`.
#[cfg(target_os = "netbsd")]
mod netbsd_sys {
    use super::RawAcl;

    pub(super) const OS: &super::Os = &super::freebsd_acl::NETBSD;

    const SYS_ACL_GET_LINK: libc::c_int = 487;
    const SYS_ACL_SET_LINK: libc::c_int = 488;
    const SYS_ACL_DELETE_LINK: libc::c_int = 489;
    const SYS_LPATHCONF: libc::c_int = 499;

    pub(super) unsafe fn acl_get_link(
        path: *const libc::c_char,
        typ: libc::c_int,
        acl: *mut RawAcl,
    ) -> libc::c_int {
        // SAFETY: as __acl_get_link(2), for which the caller vouches.
        unsafe { libc::syscall(SYS_ACL_GET_LINK, path, typ, acl) }
    }

    pub(super) unsafe fn acl_set_link(
        path: *const libc::c_char,
        typ: libc::c_int,
        acl: *mut RawAcl,
    ) -> libc::c_int {
        // SAFETY: as __acl_set_link(2), for which the caller vouches.
        unsafe { libc::syscall(SYS_ACL_SET_LINK, path, typ, acl) }
    }

    pub(super) unsafe fn lpathconf(path: *const libc::c_char, name: libc::c_int) -> libc::c_long {
        // SAFETY: as lpathconf(2), for which the caller vouches.
        libc::c_long::from(unsafe { libc::syscall(SYS_LPATHCONF, path, name) })
    }

    pub(super) unsafe fn acl_delete_link(path: *const libc::c_char, typ: libc::c_int) -> libc::c_int {
        // SAFETY: as __acl_delete_link(2), for which the caller vouches.
        unsafe { libc::syscall(SYS_ACL_DELETE_LINK, path, typ) }
    }
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
fn get_acl(path: &Path, typ: AclType) -> io::Result<Vec<AclEntry>> {
    let p = c_path(path)?;
    let mut raw = new_raw_acl();
    // SAFETY: raw is a struct acl with maxcnt set.
    _ = check(unsafe { sys::acl_get_link(p.as_ptr(), typ as libc::c_int, &raw mut *raw) })?;
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

/// Sets the ACL of type `typ` of the file at `path`, without following a
/// symlink.
fn set_acl(path: &Path, typ: AclType, acl: &[AclEntry]) -> io::Result<()> {
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
    _ = check(unsafe { sys::acl_set_link(p.as_ptr(), typ as libc::c_int, &raw mut *raw) })
        .map_err(|err| acl_set_error(path_error("__acl_set_link", path, &err), &err))?;
    Ok(())
}

/// Removes the default ACL of the directory at `path`
/// (`__acl_delete_link(2)`, as `setfacl -k`): setting one without entries is
/// refused.
fn delete_default_acl(path: &Path) -> io::Result<()> {
    let p = c_path(path)?;
    // SAFETY: p is a C string.
    _ = check(unsafe { sys::acl_delete_link(p.as_ptr(), AclType::Default as libc::c_int) })
        .map_err(|err| path_error("__acl_delete_link", path, &err))?;
    Ok(())
}

fn path_conf(path: &Path, name: i32) -> io::Result<libc::c_long> {
    let p = c_path(path)?;
    // SAFETY: p is a C string.
    check(unsafe { sys::lpathconf(p.as_ptr(), name) })
}

/// Errors listing the system extended attributes that mean the file system
/// or the user can't have them, rather than that reading them failed: only
/// root may list that namespace (`EPERM`, `EACCES`).
fn unsupported(err: &io::Error) -> bool {
    no_acls(err) || matches!(err.raw_os_error(), Some(libc::EPERM | libc::EACCES))
}

/// Errors reading an ACL that mean the file system has none of that type,
/// rather than that reading it failed. A refusal (`EACCES` where an NFSv4
/// ACL denies the user `read_acl`, `EPERM`) is not among them: such an ACL
/// is there, and a backup that can't read it says so.
fn no_acls(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::EOPNOTSUPP | libc::EINVAL))
}

/// How many times [`extattr_read`] reads a list or value whose size keeps
/// changing before it gives up.
const EXTATTR_READS: usize = 4;

/// The size of an extended attribute list or value: what an
/// `extattr_*_link(2)` function `f` returns when given no buffer.
fn extattr_size(f: impl Fn(*mut libc::c_void, usize) -> libc::ssize_t) -> io::Result<usize> {
    Ok(usize::try_from(check(f(ptr::null_mut(), 0))?).unwrap_or(usize::MAX))
}

/// Reads an extended attribute list or value through an
/// `extattr_*_link(2)` function `f`: first its size, then the data into a
/// buffer of that size. `extattr_get_link(2)` and `extattr_list_link(2)`
/// copy what fits and say nothing of the rest, so a read that fills the
/// buffer is checked against the size again: if it changed meanwhile, as a
/// value rewritten or a name added does, the list or value is read again,
/// up to [`EXTATTR_READS`] times.
///
/// # Errors
///
/// * If `f` fails (its errno, without the path), or the size changed with
///   each read.
fn extattr_read(
    f: impl Fn(*mut libc::c_void, usize) -> libc::ssize_t,
) -> io::Result<Vec<u8>> {
    let mut size = extattr_size(&f)?;
    for _ in 0..EXTATTR_READS {
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0_u8; size];
        let n = usize::try_from(check(f(buf.as_mut_ptr().cast(), size))?).unwrap_or(usize::MAX);
        if n < size {
            buf.truncate(n);
            return Ok(buf);
        }
        let now = extattr_size(&f)?;
        if now == size {
            return Ok(buf);
        }
        size = now;
    }
    Err(io::Error::other(format!(
        "its size changed with each of {EXTATTR_READS} reads"
    )))
}

/// The names of the user extended attributes of the file at `path`, as the
/// xattr crate names them (`user.NAME`, by the name's bytes), without
/// following a symlink.
pub(super) fn user_extattr_names(path: &Path) -> io::Result<Vec<OsString>> {
    let names = list_extattrs(path, libc::EXTATTR_NAMESPACE_USER)?;
    Ok(names.iter().map(|n| bsd_extattr::user_name(n)).collect())
}

/// The names of the extended attributes in `namespace` of the file at
/// `path`, without following a symlink: bytes, which needn't be UTF-8.
fn list_extattrs(path: &Path, namespace: libc::c_int) -> io::Result<Vec<Vec<u8>>> {
    let p = c_path(path)?;
    let list = extattr_read(|data, n| {
        // SAFETY: data is null or points to n bytes.
        unsafe { libc::extattr_list_link(p.as_ptr(), namespace, data, n) }
    })?;
    Ok(bsd_extattr::list_names(&list))
}

fn get_system_extattr(path: &Path, name: &[u8]) -> io::Result<Vec<u8>> {
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

fn delete_system_extattr(path: &Path, name: &[u8]) -> io::Result<()> {
    let p = c_path(path)?;
    let n = CString::new(name)?;
    // SAFETY: p and n are C strings.
    let r = unsafe {
        libc::extattr_delete_link(p.as_ptr(), libc::EXTATTR_NAMESPACE_SYSTEM, n.as_ptr())
    };
    match check(r) {
        Ok(_) => Ok(()),
        Err(err) if err.raw_os_error() == Some(libc::ENOATTR) => Ok(()), // gone already
        Err(err) => {
            let op = format!("extattr_delete_link system.{}", bsd_extattr::node_name(name));
            Err(path_error(&op, path, &err))
        }
    }
}

/// The system extended attributes, by name, as BackOtter's restic keeps them
/// (a Go `map[string][]byte`: base64 values).
#[serde_as]
#[derive(Serialize, Deserialize, Default)]
#[serde(transparent)]
struct SystemExtattrs(#[serde_as(as = "BTreeMap<_, DefaultOnNull<Base64>>")] BTreeMap<String, Vec<u8>>);

/// Records the system extended attributes and ACLs of the file at `path`
/// in `node`.
///
/// # Errors
///
/// * If they can't be read, other than because the file system or the user
///   can't have them.
pub(super) fn fill_attributes(path: &Path, node: &mut Node) -> io::Result<()> {
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
        if UFS_ACL_EXTATTRS.iter().any(|acl| acl.as_bytes() == name) {
            continue;
        }
        // Read by its own bytes, kept by a name that is valid UTF-8.
        let node_name = bsd_extattr::node_name(&name);
        match get_system_extattr(path, &name) {
            Ok(value) => _ = attrs.0.insert(node_name, value),
            Err(err) if err.raw_os_error() == Some(libc::ENOATTR) => {} // removed since the listing
            Err(err) => {
                let op = format!("extattr_get_link system.{node_name}");
                return Err(path_error(&op, path, &err));
            }
        }
    }
    if attrs.0.is_empty() {
        return Ok(());
    }
    node.meta
        .generic_attributes
        .set(sys::OS.system_extattrs, &attrs)
        .map_err(io::Error::other)
}

/// Records the ACLs of the file at `path` in `node`, a symlink's own too:
/// both systems give a symlink ACLs (`setfacl -h`), and on UFS mounted
/// `acls` one made in a directory with a default ACL inherits an access
/// ACL (`ufs_makeinode`), as a file does.
fn fill_acls(path: &Path, node: &mut Node) -> io::Result<()> {
    let attrs = &mut node.meta.generic_attributes;
    let mut keep = |typ| match get_acl(path, typ) {
        Ok(acl) => freebsd_acl::keep_acl(sys::OS, attrs, typ, &acl).map_err(io::Error::other),
        Err(err) if no_acls(&err) => {
            debug!("no ACL for {}: {err}", path.display());
            Ok(())
        }
        Err(err) => Err(path_error("__acl_get_link", path, &err)),
    };
    if path_conf(path, sys::OS.pc_acl_nfs4).ok() == Some(1) {
        return keep(AclType::Nfs4);
    }
    if path_conf(path, sys::OS.pc_acl_extended).ok() != Some(1) {
        return Ok(()); // no ACLs on this file system
    }
    keep(AclType::Access)?;
    if !matches!(node.node_type, NodeType::Dir) {
        return Ok(());
    }
    keep(AclType::Default)
}

/// Restores the system extended attributes: the file gets exactly the
/// node's, each set unless it has that value already, and any other it has
/// removed, but for those the file system stores ACLs in
/// ([`UFS_ACL_EXTATTRS`]), which the ACLs' restore sees to. A node without
/// the attribute leaves the file's as they are: its file had none, or the
/// backup, not running as root, couldn't list them, and the node doesn't say
/// which ([`absent_is_unknown`]).
///
/// # Errors
///
/// * If one couldn't be set or removed, or they couldn't be listed: the
///   first error.
pub(super) fn restore_system_extattrs(path: &Path, node: &Node) -> io::Result<()> {
    let Some(attrs) = node
        .meta
        .generic_attributes
        .get::<SystemExtattrs>(sys::OS.system_extattrs)
    else {
        return Ok(());
    };
    let attrs = attrs.map_err(io::Error::other)?;
    let mut first_err = None;
    for (name, value) in &attrs.0 {
        // One with that value already is left: no change time moves.
        if get_system_extattr(path, name.as_bytes()).is_ok_and(|has| &has == value) {
            continue;
        }
        if let Err(err) = set_system_extattr(path, name, value) {
            _ = first_err.get_or_insert(err);
        }
    }
    match list_extattrs(path, libc::EXTATTR_NAMESPACE_SYSTEM) {
        Ok(names) => {
            for name in names {
                if UFS_ACL_EXTATTRS.iter().any(|acl| acl.as_bytes() == name)
                    || attrs.0.contains_key(&bsd_extattr::node_name(&name))
                {
                    continue;
                }
                if let Err(err) = delete_system_extattr(path, &name) {
                    _ = first_err.get_or_insert(err);
                }
            }
        }
        // Not root, or no extended attributes here: the sets said so.
        Err(err) if unsupported(&err) => {}
        Err(err) => {
            _ = first_err.get_or_insert(path_error("extattr_list_link system", path, &err));
        }
    }
    first_err.map_or(Ok(()), Err)
}

/// Whether a node without the generic attribute `name` leaves what the
/// file has as it is in a snapshot of BackOtter's too, where a missing
/// attribute otherwise says the file had none: the system extended
/// attributes, which only root can list, so that a backup by another user
/// records none for a file that has some. `restore --exact` then doesn't
/// count them as a difference.
pub(super) fn absent_is_unknown(name: &str) -> bool {
    name == sys::OS.system_extattrs
}

/// Restores the ACLs, a symlink's own too. If a POSIX.1e access ACL can't
/// be set, the mode restored before it has the ACL's mask in its group bits,
/// which would give the owning group all that named users and groups had;
/// they are narrowed to the group's own access.
///
/// A node without an ACL attribute had no ACL of that type in a snapshot of
/// BackOtter's (`known_bko`), which records each that says more than the
/// mode: what the file has of that type then goes ([`strip_acls`]). In any
/// other snapshot it is unknown, and stays.
///
/// # Errors
///
/// * If an ACL couldn't be set or removed: the first error.
pub(super) fn restore_acls(path: &Path, node: &Node, known_bko: bool) -> io::Result<()> {
    let mut first_err = known_bko.then(|| strip_acls(path, node).err()).flatten();
    let mut restore = |typ: AclType, failed: &dyn Fn(&[AclEntry]) -> io::Result<()>| {
        let name = sys::OS.attribute(typ);
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
    restore(AclType::Nfs4, &|_| Ok(()));
    restore(AclType::Access, &|acl| {
        let (Some(perms), Some(mode)) = (freebsd_acl::posix_owning_group_perms(acl), node.meta.mode)
        else {
            return Ok(());
        };
        let mode = map_mode_from_go(mode) & 0o7777 & !0o070 | perms << 3;
        let p = c_path(path)?;
        let mode = libc::mode_t::try_from(mode).map_err(io::Error::other)?;
        // SAFETY: p is a C string. Without following a symlink, which can
        // have an ACL of its own.
        _ = check(unsafe {
            libc::fchmodat(libc::AT_FDCWD, p.as_ptr(), mode, libc::AT_SYMLINK_NOFOLLOW)
        })
        .map_err(|err| path_error("chmod", path, &err))?;
        Ok(())
    });
    restore(AclType::Default, &|_| Ok(()));
    first_err.map_or(Ok(()), Err)
}

/// Takes from the file at `path` the ACLs its file system has a type of and
/// `node` holds no attribute for, where they say more than its mode, which
/// the restore set before and which stays as it is: an NFSv4 ACL that isn't
/// trivial becomes the trivial one of the mode (`chmod(2)` leaves the other
/// entries on ZFS with `aclmode=passthrough`); a POSIX.1e access ACL of more
/// than three entries becomes those three, the mode's (`chmod(2)` only
/// narrows the mask, so a named user keeps what the mode's group bits
/// allow); a directory's default ACL is removed. So an ACL the file was given
/// since the backup, or inherited from the directory the restore made it in,
/// goes, as an extended attribute the node hasn't got does. One that says no
/// more than the mode is left untouched: no change time moves.
///
/// # Errors
///
/// * If an ACL couldn't be read (but not where the file system has none),
///   set or removed: the first error.
fn strip_acls(path: &Path, node: &Node) -> io::Result<()> {
    let has = |typ| node.meta.generic_attributes.value(sys::OS.attribute(typ)).is_some();
    let current = |typ| match get_acl(path, typ) {
        Ok(acl) => Ok(acl),
        Err(err) if no_acls(&err) => Ok(Vec::new()),
        Err(err) => Err(path_error("__acl_get_link", path, &err)),
    };
    let mode = || {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(path).map_err(|err| path_error("lstat", path, &err))?;
        Ok::<_, io::Error>(m.mode() & 0o777)
    };
    if path_conf(path, sys::OS.pc_acl_nfs4).ok() == Some(1) {
        if has(AclType::Nfs4) {
            return Ok(());
        }
        let acl = current(AclType::Nfs4)?;
        if acl.is_empty() || freebsd_acl::nfs4_is_trivial(&acl) {
            return Ok(());
        }
        return set_acl(path, AclType::Nfs4, &freebsd_acl::nfs4_trivial_acl(mode()?));
    }
    if path_conf(path, sys::OS.pc_acl_extended).ok() != Some(1) {
        return Ok(()); // no ACLs on this file system
    }
    let access = if has(AclType::Access) {
        Ok(())
    } else {
        current(AclType::Access).and_then(|acl| {
            if acl.len() <= 3 {
                return Ok(());
            }
            set_acl(path, AclType::Access, &freebsd_acl::posix_trivial_acl(mode()?))
        })
    };
    if !node.is_dir() || has(AclType::Default) {
        return access;
    }
    let default = current(AclType::Default).and_then(|acl| {
        if acl.is_empty() {
            return Ok(());
        }
        delete_default_acl(path)
    });
    access.and(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ACL the user may not read is not "no ACL" (G4-05): only the
    /// listing of the system namespace takes a refusal for that.
    #[test]
    fn a_refused_acl_read_is_an_error() {
        let err = io::Error::from_raw_os_error;
        for code in [libc::EOPNOTSUPP, libc::EINVAL] {
            assert!(no_acls(&err(code)) && unsupported(&err(code)), "{code}");
        }
        for code in [libc::EACCES, libc::EPERM] {
            assert!(!no_acls(&err(code)) && unsupported(&err(code)), "{code}");
        }
        assert!(!no_acls(&err(libc::EIO)) && !unsupported(&err(libc::EIO)));
    }

    /// A directory for a test that sets ACLs, and the type of ACL its file
    /// system has (`TMPDIR`'s: UFS mounted `acls` or FFSv2ea mounted
    /// `posix1eacls` for POSIX.1e, ZFS for NFSv4). `None`, and a line on
    /// stderr, where it has none: the test then tests nothing.
    fn acl_dir(test: &str) -> Option<(tempfile::TempDir, AclType)> {
        let dir = tempfile::tempdir().unwrap();
        let typ = if path_conf(dir.path(), sys::OS.pc_acl_nfs4).ok() == Some(1) {
            AclType::Nfs4
        } else if path_conf(dir.path(), sys::OS.pc_acl_extended).ok() == Some(1) {
            AclType::Access
        } else {
            eprintln!("{test}: no ACLs on {}: nothing tested", dir.path().display());
            return None;
        };
        Some((dir, typ))
    }

    /// An ACL of type `typ` that gives user 4242 read access on top of
    /// `mode`: more than the mode says.
    fn acl_with_a_user(typ: AclType, mode: u32) -> Vec<AclEntry> {
        let entry = |tag, id, perm, entry_type| AclEntry { tag, id, perm, entry_type, flags: 0 };
        if typ == AclType::Nfs4 {
            // user:4242:r-----:allow, ahead of the mode's own entries.
            let mut acl = vec![entry(0x02, 4242, 0x08, 0x0100)];
            acl.extend(freebsd_acl::nfs4_trivial_acl(mode));
            acl
        } else {
            let none = freebsd_acl::UNDEFINED_ID;
            vec![
                entry(freebsd_acl::USER_OBJ, none, mode >> 6 & 7, 0),
                entry(0x02, 4242, 4, 0),
                entry(freebsd_acl::GROUP_OBJ, none, mode >> 3 & 7, 0),
                entry(freebsd_acl::MASK, none, 7, 0),
                entry(0x20, none, mode & 7, 0),
            ]
        }
    }

    fn node_of(name: &str, typ: NodeType, mode: u32) -> Node {
        let meta = crate::backend::node::Metadata { mode: Some(mode), ..Default::default() };
        Node::new_node(std::ffi::OsStr::new(name), typ, meta)
    }

    fn symlink_node() -> Node {
        let typ = NodeType::from_link(Path::new("target"));
        node_of("link", typ, 0o755)
    }

    /// A symlink's own ACL is recorded and set on another symlink, on
    /// FreeBSD as on NetBSD (G4-02), without a look at what it points to.
    #[test]
    fn symlink_acls_are_kept_and_restored() {
        let Some((dir, typ)) = acl_dir("symlink_acls_are_kept_and_restored") else {
            return;
        };
        let (target, link, restored) =
            (dir.path().join("target"), dir.path().join("link"), dir.path().join("restored"));
        std::fs::write(&target, "x").unwrap();
        std::os::unix::fs::symlink("target", &link).unwrap();
        std::os::unix::fs::symlink("target", &restored).unwrap();
        let acl = acl_with_a_user(typ, 0o755);
        set_acl(&link, typ, &acl).unwrap();
        let of_target = get_acl(&target, typ).unwrap();
        assert_ne!(of_target, acl, "the ACL went to the symlink's target");

        let mut node = symlink_node();
        fill_acls(&link, &mut node).unwrap();
        let kept = node.meta.generic_attributes.get::<Vec<AclEntry>>(sys::OS.attribute(typ));
        assert_eq!(kept.map(Result::unwrap), Some(acl.clone()), "the symlink's ACL not kept");

        restore_acls(&restored, &node, true).unwrap();
        assert_eq!(get_acl(&restored, typ).unwrap(), acl);
        assert_eq!(get_acl(&target, typ).unwrap(), of_target);

        // A symlink without an ACL of its own gets no attribute.
        let bare = dir.path().join("bare");
        std::os::unix::fs::symlink("target", &bare).unwrap();
        let mut plain = symlink_node();
        fill_acls(&bare, &mut plain).unwrap();
        let kept = plain.meta.generic_attributes.get::<Vec<AclEntry>>(sys::OS.attribute(typ));
        assert!(kept.is_none(), "a symlink without an ACL got one: {kept:?}");
    }

    /// The change time of the file at `path`, to tell whether a call after
    /// this one wrote to its inode: taken a moment later, so that a write
    /// then moves it (the kernel's timestamps go by its clock ticks).
    fn ctime(path: &Path) -> (i64, i64) {
        use std::os::unix::fs::MetadataExt;
        std::thread::sleep(std::time::Duration::from_millis(30));
        let m = std::fs::symlink_metadata(path).unwrap();
        (m.ctime(), m.ctime_nsec())
    }

    fn chmod(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Whether the file at `path` has no more ACL of type `typ` than its
    /// mode, 0640, says: what a backup keeps no attribute for.
    fn only_the_mode(path: &Path, typ: AclType) -> bool {
        use std::os::unix::fs::MetadataExt;
        let acl = get_acl(path, typ).unwrap();
        let mut now = node_of("now", NodeType::File, 0o640);
        fill_acls(path, &mut now).unwrap();
        let trivial = if typ == AclType::Nfs4 {
            freebsd_acl::nfs4_is_trivial(&acl)
        } else {
            acl == freebsd_acl::posix_trivial_acl(0o640)
        };
        let mode = std::fs::symlink_metadata(path).unwrap().mode() & 0o7777;
        trivial && mode == 0o640 && now.meta.generic_attributes.names().count() == 0
    }

    /// G4-01: a file's ACL that its node hasn't got goes in a snapshot of
    /// BackOtter's, where the node says the file had none, and stays in any
    /// other; a second restore writes nothing. `chmod(2)` alone, which the
    /// restore did before, left a named user's entry.
    #[test]
    fn restore_takes_off_an_acl_the_node_lacks() {
        let Some((dir, typ)) = acl_dir("restore_takes_off_an_acl_the_node_lacks") else {
            return;
        };
        let file = dir.path().join("f");
        std::fs::write(&file, "x").unwrap();
        chmod(&file, 0o640);
        assert!(only_the_mode(&file, typ));
        let node = node_of("f", NodeType::File, 0o640);
        let with_user = acl_with_a_user(typ, 0o640);
        set_acl(&file, typ, &with_user).unwrap();
        // As the restore does: the mode first, which leaves the user's entry
        // (ZFS with aclmode=passthrough; UFS, under the mask).
        chmod(&file, 0o640);
        let after_chmod = get_acl(&file, typ).unwrap();

        restore_acls(&file, &node, false).unwrap();
        assert_eq!(get_acl(&file, typ).unwrap(), after_chmod, "not BackOtter's: kept");

        restore_acls(&file, &node, true).unwrap();
        assert!(only_the_mode(&file, typ), "{:?}", get_acl(&file, typ));
        let before = ctime(&file);
        restore_acls(&file, &node, true).unwrap();
        assert_eq!(ctime(&file), before, "a second restore wrote to the file");

        // A node with the ACL sets it, as before.
        let mut keeps = node.clone();
        keeps.meta.generic_attributes.set(sys::OS.attribute(typ), &with_user).unwrap();
        restore_acls(&file, &keeps, true).unwrap();
        assert_eq!(get_acl(&file, typ).unwrap(), with_user);
    }

    /// G4-01: a directory's default ACL that its node hasn't got is
    /// removed, and what a file made under it inherited goes too (POSIX.1e).
    #[test]
    fn restore_removes_a_default_acl_the_node_lacks() {
        let Some((dir, typ)) = acl_dir("restore_removes_a_default_acl_the_node_lacks") else {
            return;
        };
        if typ != AclType::Access {
            eprintln!("restore_removes_a_default_acl_the_node_lacks: NFSv4 ACLs: nothing tested");
            return;
        }
        let (d, kid) = (dir.path().join("d"), dir.path().join("d/kid"));
        std::fs::create_dir(&d).unwrap();
        chmod(&d, 0o750);
        set_acl(&d, AclType::Default, &acl_with_a_user(typ, 0o750)).unwrap();
        std::fs::write(&kid, "x").unwrap();
        assert!(get_acl(&kid, typ).unwrap().len() > 3, "nothing inherited");

        let node = node_of("d", NodeType::Dir, 0o750);
        restore_acls(&d, &node, false).unwrap();
        assert!(!get_acl(&d, AclType::Default).unwrap().is_empty(), "not BackOtter's: kept");
        restore_acls(&d, &node, true).unwrap();
        assert!(get_acl(&d, AclType::Default).unwrap().is_empty());
        let before = ctime(&d);
        restore_acls(&d, &node, true).unwrap();
        assert_eq!(ctime(&d), before, "a second restore wrote to the directory");

        chmod(&kid, 0o640);
        restore_acls(&kid, &node_of("kid", NodeType::File, 0o640), true).unwrap();
        assert!(only_the_mode(&kid, typ), "{:?}", get_acl(&kid, typ));
    }

    /// The names of the system extended attributes of the file at `path`
    /// that aren't ACLs, sorted.
    fn system_names(path: &Path) -> Vec<String> {
        let mut names: Vec<_> = list_extattrs(path, libc::EXTATTR_NAMESPACE_SYSTEM)
            .unwrap()
            .iter()
            .map(|n| bsd_extattr::node_name(n))
            .filter(|n| !UFS_ACL_EXTATTRS.contains(&n.as_str()))
            .collect();
        names.sort();
        names
    }

    /// G4-01: a node with system extended attributes gives the file exactly
    /// those, writing nothing when it has them; a node without the
    /// attribute leaves the file's, which `restore --exact` doesn't count.
    #[test]
    fn system_extattrs_are_restored_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, "x").unwrap();
        if let Err(err) = set_system_extattr(&file, "bko.kept", b"old") {
            eprintln!("system_extattrs_are_restored_exactly: {err}: nothing tested");
            return;
        }
        set_system_extattr(&file, "bko.extra", b"x").unwrap();
        let bare = node_of("f", NodeType::File, 0o644);
        restore_system_extattrs(&file, &bare).unwrap();
        assert_eq!(system_names(&file), ["bko.extra", "bko.kept"], "no attribute: left");
        assert!(absent_is_unknown(sys::OS.system_extattrs));
        assert!(!absent_is_unknown(sys::OS.acl_access));

        let mut attrs = SystemExtattrs::default();
        _ = attrs.0.insert("bko.kept".to_string(), b"new".to_vec());
        _ = attrs.0.insert("bko.made".to_string(), b"m".to_vec());
        let mut node = bare.clone();
        node.meta.generic_attributes.set(sys::OS.system_extattrs, &attrs).unwrap();
        restore_system_extattrs(&file, &node).unwrap();
        assert_eq!(system_names(&file), ["bko.kept", "bko.made"]);
        assert_eq!(get_system_extattr(&file, b"bko.kept").unwrap(), b"new");
        let before = ctime(&file);
        restore_system_extattrs(&file, &node).unwrap();
        assert_eq!(ctime(&file), before, "a second restore wrote to the file");
    }

    #[test]
    fn raw_acl_is_struct_acl() {
        assert_eq!(size_of::<RawAcl>(), 4088);
    }

    /// A fake `extattr_*_link(2)`: the list or value is `values[i]` (the
    /// last one once they run out) at its `i`th call, and it copies what
    /// fits, as the real ones do.
    fn fake_extattr(values: &[&'static str]) -> impl Fn(*mut libc::c_void, usize) -> libc::ssize_t {
        let values: Vec<&'static [u8]> = values.iter().map(|v| v.as_bytes()).collect();
        let calls = std::cell::Cell::new(0);
        move |data, n| {
            let i = calls.get();
            calls.set(i + 1);
            let value = values[i.min(values.len() - 1)];
            let k = if data.is_null() {
                value.len()
            } else {
                let k = value.len().min(n);
                // SAFETY: data points to n bytes, and k is at most n.
                unsafe { ptr::copy_nonoverlapping(value.as_ptr(), data.cast::<u8>(), k) };
                k
            };
            libc::ssize_t::try_from(k).unwrap()
        }
    }

    #[test]
    fn extattr_read_rereads_what_changed() {
        // Read as it is.
        assert_eq!(extattr_read(fake_extattr(&["value"])).unwrap(), b"value");
        assert!(extattr_read(fake_extattr(&[""])).unwrap().is_empty());
        // Grown from 10 to 20 bytes between the size and the read: the read
        // that filled its 10 bytes is done again with 20.
        let (short, long) = ("0123456789", "0123456789abcdefghij");
        assert_eq!(extattr_read(fake_extattr(&[short, long])).unwrap(), long.as_bytes());
        // Shrunk: what was read is all there is.
        assert_eq!(extattr_read(fake_extattr(&[short, "01234"])).unwrap(), b"01234");
        // Gone after the size: nothing.
        assert!(extattr_read(fake_extattr(&[short, ""])).unwrap().is_empty());
        // Growing with each call: given up on, not kept cut short.
        let growing =
            ["a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg", "abcdefgh", "abcdefghi"];
        let err = extattr_read(fake_extattr(&growing)).unwrap_err();
        assert!(err.to_string().contains("changed with each"), "{err}");
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
