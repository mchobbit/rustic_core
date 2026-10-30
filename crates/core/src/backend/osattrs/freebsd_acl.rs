//! FreeBSD ACLs as `<sys/acl.h>` has them, and the part of FreeBSD's ACL
//! code (`sys/kern/subr_acl_nfs4.c`) that tells a trivial NFSv4 ACL, one that
//! says no more than the file's mode, from one worth keeping. Portable, so
//! that it is tested on any system; the system calls are in `freebsd.rs`.

#![cfg_attr(not(target_os = "freebsd"), allow(dead_code))]

use serde::{Deserialize, Serialize};

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
