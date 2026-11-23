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
    }
}

/// NetBSD's ACL system calls, by their numbers in `<sys/syscall.h>`.
#[cfg(target_os = "netbsd")]
mod netbsd_sys {
    use super::RawAcl;

    pub(super) const OS: &super::Os = &super::freebsd_acl::NETBSD;

    const SYS_ACL_GET_LINK: libc::c_int = 487;
    const SYS_ACL_SET_LINK: libc::c_int = 488;
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

/// Reads an extended attribute list or value: first its size, then the
/// data.
fn extattr_read(
    f: impl Fn(*mut libc::c_void, usize) -> libc::ssize_t,
) -> io::Result<Vec<u8>> {
    let size = extattr_call(0, &f)?.len();
    if size == 0 {
        return Ok(Vec::new());
    }
    extattr_call(size, f)
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

/// Restores the system extended attributes.
///
/// # Errors
///
/// * If one couldn't be set: the first error.
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
        if let Err(err) = set_system_extattr(path, name, value) {
            _ = first_err.get_or_insert(err);
        }
    }
    first_err.map_or(Ok(()), Err)
}

/// Restores the ACLs, a symlink's own too. If a POSIX.1e access ACL can't
/// be set, the mode restored before it has the ACL's mask in its group bits,
/// which would give the owning group all that named users and groups had;
/// they are narrowed to the group's own access.
///
/// # Errors
///
/// * If an ACL couldn't be set: the first error.
pub(super) fn restore_acls(path: &Path, node: &Node) -> io::Result<()> {
    let mut first_err = None;
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

        restore_acls(&restored, &node).unwrap();
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
