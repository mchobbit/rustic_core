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
const READ_DATA: u32 = 0x0000_0001;
const WRITE_DATA: u32 = 0x0000_0002;
const APPEND_DATA: u32 = 0x0000_0004;
const READ_NAMED_ATTRS: u32 = 0x0000_0008;
const WRITE_NAMED_ATTRS: u32 = 0x0000_0010;
const EXECUTE: u32 = 0x0000_0020;
const DELETE_CHILD: u32 = 0x0000_0040;
const READ_ATTRIBUTES: u32 = 0x0000_0080;
const WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const READ_ACL: u32 = 0x0002_0000;
const WRITE_ACL: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const OWNER_ONLY_ALLOWED: u32 = WRITE_OWNER | WRITE_ACL | WRITE_ATTRIBUTES | WRITE_NAMED_ATTRS;
const NEVER_DENIED_BY_MODE: u32 = READ_ACL | READ_ATTRIBUTES;

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero(v: &u16) -> bool {
    *v == 0
}

/// One ACE of an illumos ACL (`ace_t`), as BackOtter's restic keeps it: ids
/// are numeric, as the file's owner and group are, but an ACE for a SID (an
/// ephemeral id, [`names_sid`]) has the SID too, which a restore maps to the
/// id it has there. Readers that don't know `sid` ignore it.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct AceEntry {
    pub who: u32,
    pub mask: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub flags: u16,
    #[serde(rename = "type", default, skip_serializing_if = "is_zero")]
    pub ace_type: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

/// `MAXUID`: the uids and gids above it are ephemeral, those idmap(8) hands
/// out for SIDs (Windows users and groups, as the SMB server and ZFS keep
/// them), and only for as long as it runs: after a reboot the same SID can
/// get another one.
pub(super) const MAX_UID: u32 = 2_147_483_647;

/// `UID_NOBODY` and `GID_NOBODY`, what an id idmap can't map becomes.
pub(super) const NOBODY: u32 = 60001;

/// Whether `e` is for a user or group (`ACE_IDENTIFIER_GROUP`) that is a
/// SID: not owner@, group@ or everyone@, and an ephemeral id.
pub(super) const fn names_sid(e: &AceEntry) -> bool {
    e.flags & (OWNER | GROUP | EVERYONE) == 0 && e.who > MAX_UID
}

/// Whether `e` is for a group, rather than a user.
pub(super) const fn is_group(e: &AceEntry) -> bool {
    e.flags & IDENTIFIER_GROUP != 0
}

/// Splits a SID, such as `S-1-5-21-1111-2222-3333-1001`, at its last dash
/// into what idmap calls its prefix and its RID. The prefix itself is `S-`
/// and a digit at least (`S-1`, the revision): `S-1` alone, or `S--1`, is
/// no SID, and libidmap isn't asked about the prefix `S` or `S-`.
pub(super) fn split_sid(sid: &str) -> Option<(&str, u32)> {
    let (prefix, rid) = sid.rsplit_once('-')?;
    let revision = prefix.strip_prefix("S-")?;
    if !revision.starts_with(|c: char| c.is_ascii_digit())
        || !rid.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    Some((prefix, rid.parse().ok()?))
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

/// `acl_trivial_create()` from illumos' `acl_common.c`: the trivial ACL of
/// a file (a directory, if `dir`) with the permission bits `mode`, which
/// says what the mode says and no more. It's what `acl_strip(3SEC)` and
/// `chmod A-` give a file, and ZFS a new one: owner@, group@ and everyone@
/// allowed what their bits say, before them owner@ allowed and then owner@
/// and group@ denied what a later class has and they don't. A restore
/// writes it over the ACL of a file whose node has none.
pub(super) fn trivial(mode: u32, dir: bool) -> Vec<AceEntry> {
    let read = READ_DATA;
    let write = WRITE_DATA | APPEND_DATA | if dir { DELETE_CHILD } else { 0 };
    let execute = EXECUTE;
    // The bits of one class (the owner's are shifted by 6, the group's by
    // 3) as a mask.
    let class = |shift: u32| {
        let bit = |b: u32, mask: u32| if mode >> shift & b == 0 { 0 } else { mask };
        bit(4, read) | bit(2, write) | bit(1, execute)
    };
    let (owner, group, everyone) = (class(6), class(3), class(0));
    // What the group has that everyone has not is no reason for an entry:
    // group@ comes before everyone@. What everyone has and the group hasn't
    // is denied the group, and allowed the owner first, where he has it.
    let allow0 = owner & !group & everyone;
    let deny1 = !owner & (group | everyone);
    let deny2 = !group & everyone;
    let basic = READ_ACL | READ_ATTRIBUTES | READ_NAMED_ATTRS | SYNCHRONIZE;
    let ace = |mask, flags, ace_type| AceEntry {
        who: u32::MAX,
        mask,
        flags,
        ace_type,
        sid: None,
    };
    let mut acl = Vec::with_capacity(6);
    if allow0 != 0 {
        acl.push(ace(allow0, OWNER, ACCESS_ALLOWED));
    }
    if deny1 != 0 {
        acl.push(ace(deny1, OWNER, ACCESS_DENIED));
    }
    if deny2 != 0 {
        acl.push(ace(deny2, GROUP | IDENTIFIER_GROUP, ACCESS_DENIED));
    }
    acl.push(ace(owner | basic | OWNER_ONLY_ALLOWED, OWNER, ACCESS_ALLOWED));
    acl.push(ace(group | basic, GROUP | IDENTIFIER_GROUP, ACCESS_ALLOWED));
    acl.push(ace(everyone | basic, EVERYONE, ACCESS_ALLOWED));
    acl
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ForkAudit1 G5-02: the trivial ACL of a mode, as illumos'
    /// `acl_trivial_create()` builds it (`ls -V` of new files on OmniOS).
    #[test]
    fn trivial_of_modes() {
        let ace = |mask, flags, ace_type| AceEntry {
            who: u32::MAX,
            mask,
            flags,
            ace_type,
            sid: None,
        };
        let group = GROUP | IDENTIFIER_GROUP;
        // rw-p--aARWcCos, r-----a-R-c--s, r-----a-R-c--s
        assert_eq!(
            trivial(0o644, false),
            [
                ace(0x001e_019f, OWNER, ACCESS_ALLOWED),
                ace(0x0012_0089, group, ACCESS_ALLOWED),
                ace(0x0012_0089, EVERYONE, ACCESS_ALLOWED),
            ]
        );
        assert_eq!(
            trivial(0o600, false),
            [
                ace(0x001e_019f, OWNER, ACCESS_ALLOWED),
                ace(0x0012_0088, group, ACCESS_ALLOWED),
                ace(0x0012_0088, EVERYONE, ACCESS_ALLOWED),
            ]
        );
        // A directory's write is add_file, add_subdirectory and delete_child.
        assert_eq!(
            trivial(0o755, true),
            [
                ace(0x001e_01ff, OWNER, ACCESS_ALLOWED),
                ace(0x0012_00a9, group, ACCESS_ALLOWED),
                ace(0x0012_00a9, EVERYONE, ACCESS_ALLOWED),
            ]
        );
        // The group has less than everyone: denied first. The owner has
        // what the group lacks: allowed before that.
        assert_eq!(
            trivial(0o604, false),
            [
                ace(READ_DATA, OWNER, ACCESS_ALLOWED),
                ace(READ_DATA, group, ACCESS_DENIED),
                ace(0x001e_019f, OWNER, ACCESS_ALLOWED),
                ace(0x0012_0088, group, ACCESS_ALLOWED),
                ace(0x0012_0089, EVERYONE, ACCESS_ALLOWED),
            ]
        );
        // The owner has less than the others: denied.
        assert_eq!(
            trivial(0o077, false),
            [
                ace(READ_DATA | WRITE_DATA | APPEND_DATA | EXECUTE, OWNER, ACCESS_DENIED),
                ace(0x001e_0198, OWNER, ACCESS_ALLOWED),
                ace(0x0012_00af, group, ACCESS_ALLOWED),
                ace(0x0012_00af, EVERYONE, ACCESS_ALLOWED),
            ]
        );
        assert_eq!(trivial(0o206, false).len(), 6);
        // The setuid, setgid and sticky bits and the file's type say nothing.
        assert_eq!(trivial(0o104_755, false), trivial(0o755, false));
        // Every one of them is trivial to `is_trivial`, so a file a restore
        // gave one has no `illumos.acl` in its next backup.
        for mode in 0..0o1000 {
            for dir in [false, true] {
                assert!(is_trivial(&trivial(mode, dir)), "{mode:o} {dir}");
            }
        }
    }

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
            sid: None,
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
        named.extend(trivial.iter().cloned());
        assert!(!is_trivial(&named), "ACL with a named user is trivial");

        let mut deny = vec![ace(10, read, IDENTIFIER_GROUP, ACCESS_DENIED)];
        deny.extend(trivial.iter().cloned());
        assert!(!is_trivial(&deny), "ACL with a named group's deny entry is trivial");

        let mut inherit = trivial.clone();
        inherit[2].flags |= FILE_INHERIT;
        assert!(!is_trivial(&inherit), "ACL with an inheritable entry is trivial");

        let mut write_acl = trivial;
        write_acl[2].mask |= WRITE_ACL;
        assert!(!is_trivial(&write_acl), "everyone@ allowed write_acl is trivial");
    }

    #[test]
    fn ace_sid_json() {
        // An entry as a reader without "sid" (rustic-bko before it) has it.
        #[derive(Deserialize)]
        struct OldAceEntry {
            who: u32,
            #[serde(default)]
            flags: u16,
        }

        // The ACL of a file with usersid: and groupsid: entries (ls -V), as
        // illumos.acl keeps it.
        let sid = |s: &str| Some(s.to_string());
        let entries = vec![
            AceEntry {
                who: 2_147_483_650,
                mask: 1,
                sid: sid("S-1-5-21-1111-2222-3333-1004"),
                ..AceEntry::default()
            },
            AceEntry {
                who: 2_147_483_651,
                mask: 2,
                flags: IDENTIFIER_GROUP,
                ace_type: ACCESS_DENIED,
                sid: sid("S-1-5-21-1111-2222-3333-1005"),
            },
            AceEntry {
                who: 0xffff_ffff,
                mask: 0x001e_019f,
                flags: OWNER,
                ..AceEntry::default()
            },
            AceEntry {
                who: 60001,
                mask: 1,
                ..AceEntry::default()
            },
        ];
        let want = concat!(
            r#"[{"who":2147483650,"mask":1,"sid":"S-1-5-21-1111-2222-3333-1004"},"#,
            r#"{"who":2147483651,"mask":2,"flags":64,"type":1,"sid":"S-1-5-21-1111-2222-3333-1005"},"#,
            r#"{"who":4294967295,"mask":1966495,"flags":4096},{"who":60001,"mask":1}]"#
        );
        let json = serde_json::to_string(&entries).unwrap();
        assert_eq!(json, want);
        assert_eq!(serde_json::from_str::<Vec<AceEntry>>(&json).unwrap(), entries);

        // A reader without "sid" gets the numbers.
        let old: Vec<OldAceEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(old.len(), 4);
        assert_eq!((old[1].who, old[1].flags), (2_147_483_651, IDENTIFIER_GROUP));

        // Which entries get a SID: ephemeral ids, not owner@, group@ or
        // everyone@ (whose who is -1).
        let named: Vec<_> = entries.iter().map(names_sid).collect();
        assert_eq!(named, [true, true, false, false]);
        assert!(is_group(&entries[1]) && !is_group(&entries[0]));
        let group = AceEntry {
            who: 0xffff_ffff,
            flags: GROUP | IDENTIFIER_GROUP,
            ..AceEntry::default()
        };
        assert!(!names_sid(&group), "group@ names a SID");
        let max = AceEntry {
            who: MAX_UID,
            ..AceEntry::default()
        };
        assert!(!names_sid(&max), "MAXUID names a SID");
    }

    #[test]
    fn split_sids() {
        assert_eq!(
            split_sid("S-1-5-21-1111-2222-3333-1001"),
            Some(("S-1-5-21-1111-2222-3333", 1001))
        );
        assert_eq!(split_sid("S-1-5-32-544"), Some(("S-1-5-32", 544)));
        for sid in [
            "",
            "S",
            "1001",
            "-1001",
            "S-1-5-21-",
            "S-1-5-21-x",
            "S-1-5-21-+5",
            "S-1-5-21-4294967296",
            "X-1-5-1",
            // ForkAudit1 G5-09: the prefix must be a SID's too, not `S` or
            // `S-` (these split as ("S", 1) and ("S-", 1)).
            "S-1",
            "S--1",
            "S-x-1",
            "-S-1-5",
        ] {
            assert_eq!(split_sid(sid), None, "malformed SID {sid:?} split");
        }
        assert_eq!(split_sid("S-1-5"), Some(("S-1", 5)));
    }

    /// `BackOtter` (`ForkAudit1` F2): `illumos.acl` from another machine, cut
    /// short or with any bit flipped: refused, or read, without a panic.
    #[test]
    fn acl_malformed() {
        use crate::backend::osattrs::malformed::every_json_mutation;

        let json = concat!(
            r#"[{"who":2147483650,"mask":1,"sid":"S-1-5-21-1111-2222-3333-1004"},"#,
            r#"{"who":2147483651,"mask":2,"flags":64,"type":1,"sid":"S-1-5-21-1111-2222-3333-1005"},"#,
            r#"{"who":4294967295,"mask":1966495,"flags":4096},{"who":60001,"mask":1}]"#
        );
        _ = every_json_mutation::<Vec<AceEntry>>("illumos.acl", json, |acl| {
            _ = is_trivial(acl);
            for e in acl {
                // What a restore would write over it is trivial, whatever
                // the entry's mask is taken for a mode.
                if !is_trivial(&trivial(e.mask, is_group(e))) {
                    return Err(format!("trivial({:#o}) isn't", e.mask));
                }
                _ = (names_sid(e), is_group(e), e.sid.as_deref().map(split_sid));
            }
            Ok(())
        });
    }

    /// `BackOtter` (`ForkAudit1` F2): SIDs cut short or with any bit flipped are
    /// refused, or split only into a prefix starting `S-` and a digit, and
    /// a RID of digits (`ForkAudit1` G5-09: `S-1` no longer splits as
    /// `("S", 1)`).
    #[test]
    fn sids_malformed() {
        use crate::backend::osattrs::malformed::{Found, every_mutation};

        let sid = "S-1-5-21-1111-2222-3333-1001";
        _ = every_mutation("SID", sid.as_bytes(), |input, _| {
            let Ok(s) = std::str::from_utf8(input) else {
                return Found::Refused;
            };
            match split_sid(s) {
                None => Found::Refused,
                Some((prefix, rid))
                    if prefix.strip_prefix("S-").is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()))
                        && s == format!("{prefix}-{}", &s[prefix.len() + 1..])
                        && s[prefix.len() + 1..].parse() == Ok(rid) =>
                {
                    Found::Decoded
                }
                Some(split) => Found::Wrong(format!("split as {split:?}")),
            }
        });
    }
}
