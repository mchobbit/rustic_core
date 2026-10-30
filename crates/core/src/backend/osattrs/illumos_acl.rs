//! illumos ACLs, as ZFS keeps them: NFSv4-style ACEs (`ace_t` in
//! `<sys/acl.h>`), and the rule illumos uses to tell a trivial ACL, one the
//! mode says all of, from one worth keeping. Portable, so that it is tested
//! on any system; the library calls are in `illumos.rs`.

#![cfg_attr(not(target_os = "illumos"), allow(dead_code))]

use serde::{Deserialize, Serialize};

// a_type
const ACCESS_ALLOWED: u16 = 0x0000;
const ACCESS_DENIED: u16 = 0x0001;

// a_flags
const FILE_INHERIT: u16 = 0x0001;
const DIRECTORY_INHERIT: u16 = 0x0002;
const NO_PROPAGATE: u16 = 0x0004;
const INHERIT_ONLY: u16 = 0x0008;
const IDENTIFIER_GROUP: u16 = 0x0040;
const OWNER: u16 = 0x1000;
const GROUP: u16 = 0x2000;
const EVERYONE: u16 = 0x4000;
const TYPE_FLAGS: u16 = OWNER | GROUP | EVERYONE | IDENTIFIER_GROUP;
const INHERITANCE_FLAGS: u16 = FILE_INHERIT | DIRECTORY_INHERIT | NO_PROPAGATE | INHERIT_ONLY;

// a_access_mask
const WRITE_DATA: u32 = 0x0000_0002;
const WRITE_NAMED_ATTRS: u32 = 0x0000_0010;
const DELETE_CHILD: u32 = 0x0000_0040;
const READ_ATTRIBUTES: u32 = 0x0000_0080;
const WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const READ_ACL: u32 = 0x0002_0000;
const WRITE_ACL: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const OWNER_ONLY_ALLOWED: u32 = WRITE_OWNER | WRITE_ACL | WRITE_ATTRIBUTES | WRITE_NAMED_ATTRS;
const NEVER_DENIED_BY_MODE: u32 = READ_ACL | READ_ATTRIBUTES;

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero(v: &u16) -> bool {
    *v == 0
}

/// One ACE of an illumos ACL (`ace_t`), as BackOtter's restic keeps it: ids
/// are numeric, as the file's owner and group are.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct AceEntry {
    pub who: u32,
    pub mask: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub flags: u16,
    #[serde(rename = "type", default, skip_serializing_if = "is_zero")]
    pub ace_type: u16,
}

/// `ace_trivial_common()` from illumos' `acl_common.c`: whether an ACL says
/// no more than the file's mode, so that the mode alone restores it. It's
/// what `ls(1)` leaves the "+" off for.
pub(super) fn is_trivial(acl: &[AceEntry]) -> bool {
    for e in acl {
        let kind = e.flags & TYPE_FLAGS;
        if kind != OWNER && kind != GROUP | IDENTIFIER_GROUP && kind != EVERYONE {
            return false; // a named user or group
        }
        if e.flags & INHERITANCE_FLAGS != 0 {
            return false;
        }
        // Nobody is denied reading basic attributes or the ACL by a mode.
        if e.mask & NEVER_DENIED_BY_MODE != 0 && e.ace_type == ACCESS_DENIED {
            return false;
        }
        // A mode never grants delete, nor delete_child without write.
        if e.mask & DELETE != 0 || (e.mask & DELETE_CHILD != 0 && e.mask & WRITE_DATA == 0) {
            return false;
        }
        // Only owner@ is allowed to change the ACL, owner and attributes.
        if e.ace_type == ACCESS_ALLOWED && e.flags & OWNER == 0 && e.mask & OWNER_ONLY_ALLOWED != 0
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trivial_acls() {
        // What ls -V shows ZFS on illumos giving a new 0644 file.
        let (read, write) = (0x1, 0x2 | 0x4); // read_data; write_data, append_data
        let attrs = READ_ATTRIBUTES | 0x8 | READ_ACL | 0x0010_0000;
        let ace = |who, mask, flags, ace_type| AceEntry {
            who,
            mask,
            flags,
            ace_type,
        };
        let trivial = vec![
            ace(
                0xffff_ffff,
                read | write | attrs | WRITE_ATTRIBUTES | WRITE_NAMED_ATTRS | WRITE_ACL | WRITE_OWNER,
                OWNER,
                ACCESS_ALLOWED,
            ),
            ace(0xffff_ffff, read | attrs, GROUP | IDENTIFIER_GROUP, ACCESS_ALLOWED),
            ace(0xffff_ffff, read | attrs, EVERYONE, ACCESS_ALLOWED),
        ];
        assert!(is_trivial(&trivial), "ZFS's trivial ACL for 0644 not trivial");

        let mut named = vec![ace(60001, read, 0, ACCESS_ALLOWED)];
        named.extend(&trivial);
        assert!(!is_trivial(&named), "ACL with a named user is trivial");

        let mut deny = vec![ace(10, read, IDENTIFIER_GROUP, ACCESS_DENIED)];
        deny.extend(&trivial);
        assert!(!is_trivial(&deny), "ACL with a named group's deny entry is trivial");

        let mut inherit = trivial.clone();
        inherit[2].flags |= FILE_INHERIT;
        assert!(!is_trivial(&inherit), "ACL with an inheritable entry is trivial");

        let mut write_acl = trivial;
        write_acl[2].mask |= WRITE_ACL;
        assert!(!is_trivial(&write_acl), "everyone@ allowed write_acl is trivial");
    }
}
