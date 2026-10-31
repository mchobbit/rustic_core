//! FreeBSD ACLs as `<sys/acl.h>` has them, and the part of FreeBSD's ACL
//! code (`sys/kern/subr_acl_nfs4.c`) that tells a trivial NFSv4 ACL, one that
//! says no more than the file's mode, from one worth keeping. NetBSD took
//! FreeBSD's ACL code: the same `struct acl`, kept in the same form under
//! its own names ([`Os`]). Portable, so that it is tested on any system;
//! the system calls are in `freebsd_netbsd.rs`.

#![cfg_attr(not(any(target_os = "freebsd", target_os = "netbsd")), allow(dead_code))]

use serde::{Deserialize, Serialize};

use crate::backend::node::generic_attributes::{
    FREEBSD_ACL_ACCESS, FREEBSD_ACL_DEFAULT, FREEBSD_ACL_NFS4, FREEBSD_SYSTEM_EXTATTRS,
    GenericAttributes, NETBSD_ACL_ACCESS, NETBSD_ACL_DEFAULT, NETBSD_ACL_NFS4,
    NETBSD_SYSTEM_EXTATTRS,
};

pub(super) const MAX_ENTRIES: usize = 254; // ACL_MAX_ENTRIES
pub(super) const UNDEFINED_ID: u32 = 0xffff_ffff; // ACL_UNDEFINED_ID

// ae_tag
pub(super) const USER_OBJ: u32 = 0x01;
#[cfg(test)]
const USER: u32 = 0x02;
pub(super) const GROUP_OBJ: u32 = 0x04;
#[cfg(test)]
const GROUP: u32 = 0x08;
pub(super) const MASK: u32 = 0x10;
#[cfg(test)]
const OTHER: u32 = 0x20;
pub(super) const EVERYONE: u32 = 0x40;

/// ae_perm, POSIX.1e: the same bits as a mode's rwx
const POSIX_PERMS: u32 = 0x7;

// ae_perm, NFSv4
const EXECUTE: u32 = 0x0000_0001;
const READ_DATA: u32 = 0x0000_0008;
const WRITE_DATA: u32 = 0x0000_0010;
const APPEND_DATA: u32 = 0x0000_0020;
const READ_NAMED_ATTRS: u32 = 0x0000_0040;
const WRITE_NAMED_ATTRS: u32 = 0x0000_0080;
const READ_ATTRIBUTES: u32 = 0x0000_0200;
const WRITE_ATTRIBUTES: u32 = 0x0000_0400;
const READ_ACL: u32 = 0x0000_1000;
const WRITE_ACL: u32 = 0x0000_2000;
const WRITE_OWNER: u32 = 0x0000_4000;
const SYNCHRONIZE: u32 = 0x0000_8000;

// ae_entry_type, NFSv4
const ENTRY_TYPE_ALLOW: u16 = 0x0100;
const ENTRY_TYPE_DENY: u16 = 0x0200;

// ae_flags, NFSv4
const ENTRY_INHERIT_ONLY: u16 = 0x0008;

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero(v: &u16) -> bool {
    *v == 0
}

/// What FreeBSD's and NetBSD's ACLs and system extended attributes differ
/// in: the names they are kept under, and the numbers of `<sys/unistd.h>`.
pub(super) struct Os {
    /// The generic attribute of a POSIX.1e access ACL.
    pub acl_access: &'static str,
    /// The generic attribute of a directory's POSIX.1e default ACL.
    pub acl_default: &'static str,
    /// The generic attribute of an NFSv4 ACL.
    pub acl_nfs4: &'static str,
    /// The generic attribute of the system extended attributes.
    pub system_extattrs: &'static str,
    /// `_PC_ACL_EXTENDED`: whether a file system has POSIX.1e ACLs
    /// (`pathconf(2)`).
    pub pc_acl_extended: i32,
    /// `_PC_ACL_NFS4`: whether it has NFSv4 ACLs.
    pub pc_acl_nfs4: i32,
    /// Whether a symlink has ACLs of its own.
    pub symlink_acls: bool,
}

#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub(super) const FREEBSD: Os = Os {
    acl_access: FREEBSD_ACL_ACCESS,
    acl_default: FREEBSD_ACL_DEFAULT,
    acl_nfs4: FREEBSD_ACL_NFS4,
    system_extattrs: FREEBSD_SYSTEM_EXTATTRS,
    pc_acl_extended: 59,
    pc_acl_nfs4: 64,
    symlink_acls: false,
};

#[cfg_attr(not(target_os = "netbsd"), allow(dead_code))]
pub(super) const NETBSD: Os = Os {
    acl_access: NETBSD_ACL_ACCESS,
    acl_default: NETBSD_ACL_DEFAULT,
    acl_nfs4: NETBSD_ACL_NFS4,
    system_extattrs: NETBSD_SYSTEM_EXTATTRS,
    pc_acl_extended: 14,
    pc_acl_nfs4: 17,
    // `setfacl -h` gives a symlink its own on FFSv2ea.
    symlink_acls: true,
};

/// The types of ACL (`acl_type_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AclType {
    Access = 2,
    Default = 3,
    Nfs4 = 4,
}

impl Os {
    /// The generic attribute an ACL of type `typ` is kept in.
    pub(super) const fn attribute(&self, typ: AclType) -> &'static str {
        match typ {
            AclType::Access => self.acl_access,
            AclType::Default => self.acl_default,
            AclType::Nfs4 => self.acl_nfs4,
        }
    }
}

/// Keeps `acl`, an ACL of type `typ`, in `attrs` if it says more than the
/// file's mode.
///
/// # Errors
///
/// * If the ACL can't be encoded as JSON.
pub(super) fn keep_acl(
    os: &Os,
    attrs: &mut GenericAttributes,
    typ: AclType,
    acl: &[AclEntry],
) -> serde_json::Result<()> {
    let keep = match typ {
        // Three entries are just the mode: user_obj, group_obj and other.
        AclType::Access => acl.len() > 3,
        AclType::Default => !acl.is_empty(),
        AclType::Nfs4 => !nfs4_is_trivial(acl),
    };
    if keep {
        attrs.set(os.attribute(typ), &acl)?;
    }
    Ok(())
}

/// One entry of a FreeBSD ACL (`struct acl_entry`), as BackOtter's restic
/// keeps it: ids are numeric, as the file's owner and group are.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct AclEntry {
    pub tag: u32,
    pub id: u32,
    pub perm: u32,
    #[serde(rename = "type", default, skip_serializing_if = "is_zero")]
    pub entry_type: u16,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub flags: u16,
}

/// `acl_nfs4_sync_mode_from_acl()`: the permission bits of a file's mode as
/// FreeBSD derives them from its NFSv4 ACL.
pub(super) fn nfs4_mode_from_acl(acl: &[AclEntry]) -> u32 {
    let (mut mode, mut seen) = (0, 0);
    for e in acl {
        if e.entry_type != ENTRY_TYPE_ALLOW && e.entry_type != ENTRY_TYPE_DENY {
            continue;
        }
        if e.flags & ENTRY_INHERIT_ONLY != 0 {
            continue;
        }
        // The mode bits for read, write and execute this entry speaks for.
        let (r, w, x) = match e.tag {
            USER_OBJ => (0o400, 0o200, 0o100),
            GROUP_OBJ => (0o040, 0o020, 0o010),
            EVERYONE => (0o444, 0o222, 0o111),
            _ => continue,
        };
        // The first entry to mention a bit decides it.
        let mut decide = |bits: u32| {
            let bits = bits & !seen;
            seen |= bits;
            if e.entry_type == ENTRY_TYPE_ALLOW {
                mode |= bits;
            }
        };
        if e.perm & READ_DATA != 0 {
            decide(r);
        }
        if e.perm & WRITE_DATA != 0 {
            decide(w);
        }
        if e.perm & EXECUTE != 0 {
            decide(x);
        }
    }
    mode
}

/// `acl_nfs4_trivial_from_mode()`: the NFSv4 ACL FreeBSD gives a file with
/// this mode (PSARC/2010/029 semantics, FreeBSD's since 9.0).
pub(super) fn nfs4_trivial_acl(mode: u32) -> Vec<AclEntry> {
    let rwx = |perm: &mut u32, r: u32, w: u32, x: u32| {
        if mode & r != 0 {
            *perm |= READ_DATA;
        }
        if mode & w != 0 {
            *perm |= WRITE_DATA | APPEND_DATA;
        }
        if mode & x != 0 {
            *perm |= EXECUTE;
        }
    };
    let mut group = READ_ACL | READ_ATTRIBUTES | READ_NAMED_ATTRS | SYNCHRONIZE;
    let mut everyone = group;
    let mut user = group | WRITE_ACL | WRITE_OWNER | WRITE_ATTRIBUTES | WRITE_NAMED_ATTRS;
    rwx(&mut user, 0o400, 0o200, 0o100);
    rwx(&mut group, 0o040, 0o020, 0o010);
    rwx(&mut everyone, 0o004, 0o002, 0o001);

    let user_deny = (group | everyone) & !user;
    let group_deny = everyone & !group;
    let user_allow_first = group_deny & !user_deny;

    let entry = |tag, perm, entry_type| AclEntry {
        tag,
        id: UNDEFINED_ID,
        perm,
        entry_type,
        flags: 0,
    };
    let mut acl = Vec::new();
    if user_allow_first != 0 {
        acl.push(entry(USER_OBJ, user_allow_first, ENTRY_TYPE_ALLOW));
    }
    if user_deny != 0 {
        acl.push(entry(USER_OBJ, user_deny, ENTRY_TYPE_DENY));
    }
    if group_deny != 0 {
        acl.push(entry(GROUP_OBJ, group_deny, ENTRY_TYPE_DENY));
    }
    acl.push(entry(USER_OBJ, user, ENTRY_TYPE_ALLOW));
    acl.push(entry(GROUP_OBJ, group, ENTRY_TYPE_ALLOW));
    acl.push(entry(EVERYONE, everyone, ENTRY_TYPE_ALLOW));
    acl
}

/// Whether an NFSv4 ACL says no more than the mode it implies, as
/// `acl_is_trivial_np(3)` does, so that the mode alone restores it. (An ACL
/// in the older "canonical six" form counts as non-trivial here, and is
/// kept: that costs a little space, never metadata.)
pub(super) fn nfs4_is_trivial(acl: &[AclEntry]) -> bool {
    if acl.len() > 6 {
        return false;
    }
    // owner@, group@ and everyone@ carry no id; don't let a file system's
    // choice of filler for it matter.
    let special: Vec<_> = acl
        .iter()
        .map(|&e| match e.tag {
            USER_OBJ | GROUP_OBJ | EVERYONE => AclEntry {
                id: UNDEFINED_ID,
                ..e
            },
            _ => e,
        })
        .collect();
    special == nfs4_trivial_acl(nfs4_mode_from_acl(acl))
}

/// The permissions a POSIX.1e access ACL gives the file's owning group: its
/// `group_obj` entry, limited by the mask. With an ACL, a file's mode holds
/// the mask in its group bits, which is wider than this whenever a named
/// user or group has more access than the owning group.
pub(super) fn posix_owning_group_perms(acl: &[AclEntry]) -> Option<u32> {
    let mut mask = POSIX_PERMS;
    let mut perms = None;
    for e in acl {
        match e.tag {
            GROUP_OBJ => perms = Some(e.perm & POSIX_PERMS),
            MASK => mask = e.perm & POSIX_PERMS,
            _ => {}
        }
    }
    perms.map(|p| p & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(tag: u32, id: u32, perm: u32, entry_type: u16) -> AclEntry {
        AclEntry {
            tag,
            id,
            perm,
            entry_type,
            flags: 0,
        }
    }

    #[test]
    fn nfs4_trivial_acl_is_trivial() {
        for mode in [
            0o644, 0o755, 0o600, 0o000, 0o777, 0o604, 0o070, 0o007, 0o460,
        ] {
            let acl = nfs4_trivial_acl(mode);
            assert!(nfs4_is_trivial(&acl), "trivial ACL for {mode:o} not trivial");
            assert_eq!(mode, nfs4_mode_from_acl(&acl));
        }
        // What getfacl(1) shows ZFS giving a new 0644 file:
        //   owner@:rw-p--aARWcCos:-------:allow
        //   group@:r-----a-R-c--s:-------:allow
        //   everyone@:r-----a-R-c--s:-------:allow
        let read = READ_DATA | READ_ATTRIBUTES | READ_NAMED_ATTRS | READ_ACL | SYNCHRONIZE;
        let owner = read
            | WRITE_DATA
            | APPEND_DATA
            | WRITE_ATTRIBUTES
            | WRITE_NAMED_ATTRS
            | WRITE_ACL
            | WRITE_OWNER;
        let zfs = vec![
            entry(USER_OBJ, UNDEFINED_ID, owner, ENTRY_TYPE_ALLOW),
            entry(GROUP_OBJ, UNDEFINED_ID, read, ENTRY_TYPE_ALLOW),
            entry(EVERYONE, UNDEFINED_ID, read, ENTRY_TYPE_ALLOW),
        ];
        assert!(nfs4_is_trivial(&zfs), "ZFS's trivial ACL for 0644 not trivial");
        assert_eq!(0o644, nfs4_mode_from_acl(&zfs));

        let mut named = vec![entry(USER, 65534, READ_DATA, ENTRY_TYPE_ALLOW)];
        named.extend(&zfs);
        assert!(!nfs4_is_trivial(&named), "ACL with a named user is trivial");

        let mut inherit = zfs.clone();
        inherit[2].flags = 0x0001; // file_inherit
        assert!(!nfs4_is_trivial(&inherit), "ACL with an inheritable entry is trivial");

        let mut deny = vec![entry(GROUP_OBJ, UNDEFINED_ID, WRITE_ACL, ENTRY_TYPE_DENY)];
        deny.extend(&zfs);
        assert!(!nfs4_is_trivial(&deny), "ACL with an extra deny entry is trivial");
    }

    #[test]
    fn posix_owning_group_perms_takes_the_mask() {
        // setfacl -m u:nobody:rwx,g:wheel:r,m::rwx on a 0644 file: the mode's
        // group bits become the mask, rwx, though the owning group has only r.
        let mut acl = vec![
            entry(USER_OBJ, UNDEFINED_ID, 6, 0),
            entry(USER, 65534, 7, 0),
            entry(GROUP_OBJ, UNDEFINED_ID, 4, 0),
            entry(GROUP, 0, 4, 0),
            entry(MASK, UNDEFINED_ID, 7, 0),
            entry(OTHER, UNDEFINED_ID, 4, 0),
        ];
        assert_eq!(posix_owning_group_perms(&acl), Some(4));
        // A mask narrower than group_obj limits it.
        acl[2].perm = 7;
        acl[4].perm = 5;
        assert_eq!(posix_owning_group_perms(&acl), Some(5));
    }

    #[test]
    fn pathconf_names_per_system() {
        assert_eq!((FREEBSD.pc_acl_extended, FREEBSD.pc_acl_nfs4), (59, 64));
        assert_eq!((NETBSD.pc_acl_extended, NETBSD.pc_acl_nfs4), (14, 17));
    }

    #[test]
    fn kept_alike_on_freebsd_and_netbsd() {
        let base = vec![
            entry(USER_OBJ, UNDEFINED_ID, 6, 0),
            entry(GROUP_OBJ, UNDEFINED_ID, 4, 0),
            entry(OTHER, UNDEFINED_ID, 4, 0),
        ];
        let mut named = base.clone();
        named.insert(1, entry(USER, 1001, 7, 0));
        named.insert(3, entry(MASK, UNDEFINED_ID, 7, 0));
        let mut nfs4 = vec![entry(USER, 1001, READ_DATA, ENTRY_TYPE_DENY)];
        nfs4.extend(nfs4_trivial_acl(0o644));

        let mut json = Vec::new();
        for (os, prefix) in [(&FREEBSD, "freebsd"), (&NETBSD, "netbsd")] {
            let mut attrs = GenericAttributes::default();
            keep_acl(os, &mut attrs, AclType::Access, &base).unwrap();
            keep_acl(os, &mut attrs, AclType::Default, &[]).unwrap();
            keep_acl(os, &mut attrs, AclType::Nfs4, &nfs4_trivial_acl(0o750)).unwrap();
            assert!(attrs.is_empty(), "{prefix}: trivial ACLs kept");

            keep_acl(os, &mut attrs, AclType::Access, &named).unwrap();
            keep_acl(os, &mut attrs, AclType::Default, &base).unwrap();
            keep_acl(os, &mut attrs, AclType::Nfs4, &nfs4).unwrap();
            let kept: Vec<_> = attrs.names().collect();
            assert_eq!(
                kept,
                [
                    format!("{prefix}.acl_access"),
                    format!("{prefix}.acl_default"),
                    format!("{prefix}.acl_nfs4")
                ]
            );
            let back: Vec<AclEntry> = attrs.get(os.acl_nfs4).unwrap().unwrap();
            assert_eq!(back, nfs4);
            json.push(serde_json::to_string(&attrs).unwrap().replace(prefix, "PREFIX"));
        }
        assert_eq!(json[0], json[1]);
        // A generic attribute's object keys come out sorted.
        assert!(
            json[0].contains(r#""PREFIX.acl_nfs4":[{"id":1001,"perm":8,"tag":2,"type":512},"#),
            "{}",
            json[0]
        );
    }

    #[test]
    fn json_as_restic_writes_it() {
        let acl = vec![
            entry(USER_OBJ, UNDEFINED_ID, 6, 0),
            entry(USER, 1001, 0x18, ENTRY_TYPE_ALLOW),
        ];
        assert_eq!(
            serde_json::to_string(&acl).unwrap(),
            r#"[{"tag":1,"id":4294967295,"perm":6},{"tag":2,"id":1001,"perm":24,"type":256}]"#
        );
    }
}
