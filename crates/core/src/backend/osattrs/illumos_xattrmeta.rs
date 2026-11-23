//! What illumos keeps of each extended attribute besides its value: an
//! attribute is a file of its own (`runat(1)`, `fsattr(5)`), with an owner,
//! a group, a mode, times and an ACL, which `illumos.xattr_meta` holds by
//! the attribute's name. Without it a restored attribute belongs to whoever
//! ran the restore, with mode 0600 and the time of the restore. Portable, so
//! that it is tested on any system; the file access is in `illumos.rs`.

#![cfg_attr(not(target_os = "illumos"), allow(dead_code))]

use std::{collections::BTreeMap, io};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::illumos_acl::AceEntry;

/// The system attribute views in every attribute directory, which aren't
/// extended attributes of their own.
pub(super) const SYSTEM_VIEWS: [&str; 2] = ["SUNWattr_ro", "SUNWattr_rw"];

/// Why the extended attribute `name`, a snapshot's, isn't set or given its
/// metadata, or `None` for one that names an attribute file. An attribute's
/// name is a path relative to its file's attribute directory, where `..` is
/// the file itself (`fsattr(7)`): `..` would be the file truncated and
/// written, its owner and mode changed, and a name with a `/` can lead
/// out of the attribute directory to anywhere in the tree. So an empty name,
/// `.`, `..`, one with a `/` or a NUL and the system attribute views are
/// refused. An attribute on illumos can't be named so; a crafted snapshot,
/// or another system's (a Linux name can hold a `/`), can hold one.
pub(super) fn attr_name_refused(name: &str) -> Option<io::Error> {
    let why = if name.is_empty() || name == "." || name == ".." {
        "not an attribute file's name"
    } else if name.contains(['/', '\0']) {
        "a name with a '/' or a NUL"
    } else if SYSTEM_VIEWS.contains(&name) {
        "a system attribute view"
    } else {
        return None;
    };
    Some(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("not restored on illumos: {why}"),
    ))
}

/// The metadata of one attribute file. The times are in UTC, in the form of
/// a node's mtime; the ACL is there only when it says more than the mode
/// ([`is_trivial`](super::illumos_acl::is_trivial)), as `illumos.acl`.
///
/// An owner or group that is a SID (an ephemeral id, above
/// [`MAX_UID`](super::illumos_acl::MAX_UID)) has the SID too, as a file's
/// own has in `illumos.owner_sid` and `illumos.group_sid`: the number means
/// nothing after a reboot. Readers that don't know the two fields ignore
/// them, and get the numbers.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct XattrMeta {
    pub uid: u32,
    pub gid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_sid: Option<String>,
    /// The permission bits, `st_mode & 07777`.
    pub mode: u32,
    pub mtime: Timestamp,
    pub atime: Timestamp,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acl: Vec<AceEntry>,
}

/// The owner and group a restore that sets owners gives the attribute file
/// with the metadata `meta`: those of `meta`, but where the file's own were
/// the same at backup (`node`, its node's uid and gid), what the file has
/// at the destination (`now`). The restore gave the file those by name, or
/// as the ids its SIDs have here, so they can be other numbers than the
/// snapshot's, and the snapshot's can be someone else's here: an attribute
/// its file's owner owned is its file's owner's again, never a stranger's.
/// An attribute that was another user's or group's keeps its number: a node
/// has no name for it.
pub(super) fn restored_owner(
    meta: &XattrMeta,
    node: (Option<u32>, Option<u32>),
    now: (u32, u32),
) -> (u32, u32) {
    let id = |attr: u32, node: Option<u32>, now: u32| if node == Some(attr) { now } else { attr };
    (id(meta.uid, node.0, now.0), id(meta.gid, node.1, now.1))
}

/// Whether `now` and `want`, two values of `illumos.xattr_meta`, are the
/// same but for the attributes' owners and groups, which a restore that sets
/// no owners (`--no-ownership`, or not running as root) leaves as they are.
pub(super) fn same_but_owners(now: &Value, want: &Value) -> bool {
    let without_owners = |v: &Value| {
        let mut metas = BTreeMap::<String, XattrMeta>::deserialize(v).ok()?;
        for meta in metas.values_mut() {
            (meta.uid, meta.gid) = (0, 0);
            (meta.owner_sid, meta.group_sid) = (None, None);
        }
        Some(metas)
    };
    now == want
        || without_owners(now)
            .zip(without_owners(want))
            .is_some_and(|(now, want)| now == want)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(uid: u32, gid: u32) -> XattrMeta {
        XattrMeta {
            uid,
            gid,
            mode: 0o600,
            mtime: Timestamp::new(1_000_000_000, 0).unwrap(),
            atime: Timestamp::new(1_000_000_000, 0).unwrap(),
            ..XattrMeta::default()
        }
    }

    /// BackOtter: an attribute its file's owner (group) owned follows the
    /// file to the owner (group) it has at the destination; another's keeps
    /// its number (ForkAudit1 G5-01).
    #[test]
    fn restored_owners() {
        let node = (Some(1001), Some(10));
        // alice is 1500 here, and staff 20.
        let now = (1500, 20);
        assert_eq!(restored_owner(&meta(1001, 10), node, now), (1500, 20));
        // By number, or the same here: as in the snapshot.
        assert_eq!(restored_owner(&meta(1001, 10), node, (1001, 10)), (1001, 10));
        // Another user's attribute, the file's group's; and the reverse.
        assert_eq!(restored_owner(&meta(1002, 10), node, now), (1002, 20));
        assert_eq!(restored_owner(&meta(1001, 11), node, now), (1500, 11));
        // The file owner's number here as another user's attribute's: kept.
        assert_eq!(restored_owner(&meta(1500, 20), node, now), (1500, 20));
        // A node without an owner (not a Unix file's): the numbers.
        assert_eq!(restored_owner(&meta(1001, 10), (None, None), now), (1001, 10));
    }

    /// BackOtter: without ownership, two `illumos.xattr_meta` that differ
    /// only in the attributes' owners are the same to `--exact`; anything
    /// else still differs (ForkAudit1 G5-01).
    #[test]
    fn xattr_meta_same_but_owners() {
        let value = |metas: &[(&str, XattrMeta)]| {
            let metas: BTreeMap<_, _> = metas.iter().cloned().collect();
            serde_json::to_value(metas).unwrap()
        };
        let want = value(&[("a", meta(1001, 10)), ("b", meta(1002, 11))]);
        assert!(same_but_owners(&want, &want));
        assert!(same_but_owners(&value(&[("a", meta(0, 0)), ("b", meta(0, 3))]), &want));
        let mut mode = meta(0, 0);
        mode.mode = 0o644;
        assert!(!same_but_owners(&value(&[("a", mode), ("b", meta(0, 0))]), &want));
        assert!(!same_but_owners(&value(&[("a", meta(0, 0))]), &want));
        assert!(!same_but_owners(&value(&[("a", meta(0, 0)), ("c", meta(0, 0))]), &want));
        // An owner that is a SID is an owner (ForkAudit1 G5-03).
        let mut sid = meta(2_147_483_650, 10);
        sid.owner_sid = Some("S-1-5-21-1111-2222-3333-1001".to_string());
        let want_sid = value(&[("a", sid), ("b", meta(1002, 11))]);
        assert!(same_but_owners(&want, &want_sid));
        assert!(same_but_owners(&want_sid, &want));
        // What isn't an `illumos.xattr_meta` is the same only as itself.
        assert!(same_but_owners(&Value::from(1), &Value::from(1)));
        assert!(!same_but_owners(&Value::from(1), &Value::from(2)));
        assert!(!same_but_owners(&Value::from(1), &want));
    }

    #[test]
    fn attr_names_refused() {
        for name in [
            "",
            ".",
            "..",
            "../x",
            "a/b",
            "/etc/x",
            "a\0b",
            "SUNWattr_ro",
            "SUNWattr_rw",
        ] {
            let err = attr_name_refused(name).unwrap_or_else(|| panic!("{name:?} allowed"));
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{name:?}");
        }
        for name in [
            "a",
            "user.x",
            "...",
            "..x",
            ".hidden",
            "\u{fffd}",
            "SUNWattr_rw2",
        ] {
            assert!(attr_name_refused(name).is_none(), "{name:?} refused");
        }
    }

    #[test]
    fn xattr_meta_json() {
        let t = |sec, nsec| Timestamp::new(sec, nsec).unwrap();
        let metas = BTreeMap::from([
            (
                "note".to_string(),
                XattrMeta {
                    uid: 1500,
                    gid: 1501,
                    owner_sid: None,
                    group_sid: None,
                    mode: 0o640,
                    mtime: t(1_000_000_000, 123_456_789),
                    atime: t(1_000_000_000, 0),
                    acl: vec![
                        AceEntry {
                            who: 60001,
                            mask: 1,
                            ..AceEntry::default()
                        },
                        AceEntry {
                            who: 2_147_483_650,
                            mask: 2,
                            flags: 0x40,
                            ace_type: 1,
                            sid: Some("S-1-5-21-1111-2222-3333-513".to_string()),
                        },
                    ],
                },
            ),
            (
                "a name with spaces".to_string(),
                XattrMeta {
                    uid: 0,
                    gid: 0,
                    mode: 0o600,
                    mtime: t(1_000_000_000, 5),
                    atime: t(1_000_000_000, 5),
                    ..XattrMeta::default()
                },
            ),
            (
                "Grüße, ☃ und 日本語".to_string(),
                XattrMeta {
                    uid: 1,
                    gid: 2,
                    mode: 0o4755,
                    mtime: t(1_900_000_000, 0),
                    atime: t(1, 0),
                    ..XattrMeta::default()
                },
            ),
        ]);
        let json = serde_json::to_string(&metas).unwrap();
        let back: BTreeMap<String, XattrMeta> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, metas);

        // The form both tools write: the names as they are, times as a
        // node's mtime, no "acl" for a trivial one.
        let two: BTreeMap<_, _> = metas.iter().filter(|(name, _)| !name.starts_with('G')).collect();
        let want = concat!(
            r#"{"a name with spaces":{"uid":0,"gid":0,"mode":384,"#,
            r#""mtime":"2001-09-09T01:46:40.000000005Z","atime":"2001-09-09T01:46:40.000000005Z"},"#,
            r#""note":{"uid":1500,"gid":1501,"mode":416,"#,
            r#""mtime":"2001-09-09T01:46:40.123456789Z","atime":"2001-09-09T01:46:40Z","#,
            r#""acl":[{"who":60001,"mask":1},{"who":2147483650,"mask":2,"flags":64,"type":1,"sid":"S-1-5-21-1111-2222-3333-513"}]}}"#
        );
        assert_eq!(serde_json::to_string(&two).unwrap(), want);
        assert!(json.contains(r#""Grüße, ☃ und 日本語":{"#), "{json}");

        // Any offset is read.
        let meta: XattrMeta = serde_json::from_str(
            r#"{"uid":1,"gid":2,"mode":420,"mtime":"2001-09-09T03:46:40.5+02:00","atime":"2001-09-09T01:46:40Z"}"#,
        )
        .unwrap();
        assert_eq!(meta.mtime, t(1_000_000_000, 500_000_000));
        assert_eq!((&meta.owner_sid, &meta.group_sid), (&None, &None));
    }

    /// ForkAudit1 G5-03: an attribute file's owner and group that are SIDs
    /// are kept as SIDs too, after the numbers, and a reader that doesn't
    /// know the fields (rustic-bko before them, BackOtter's restic) reads
    /// the rest.
    #[test]
    fn xattr_meta_sid_owners_json() {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct OldXattrMeta {
            uid: u32,
            gid: u32,
            mode: u32,
            mtime: Timestamp,
            atime: Timestamp,
            #[serde(default)]
            acl: Vec<AceEntry>,
        }

        let t = Timestamp::new(1_000_000_000, 0).unwrap();
        let meta = XattrMeta {
            uid: 2_147_483_650,
            gid: 2_147_483_651,
            owner_sid: Some("S-1-5-21-1111-2222-3333-1001".to_string()),
            group_sid: Some("S-1-5-21-1111-2222-3333-513".to_string()),
            mode: 0o600,
            mtime: t,
            atime: t,
            acl: Vec::new(),
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert_eq!(
            json,
            concat!(
                r#"{"uid":2147483650,"gid":2147483651,"#,
                r#""owner_sid":"S-1-5-21-1111-2222-3333-1001","group_sid":"S-1-5-21-1111-2222-3333-513","#,
                r#""mode":384,"mtime":"2001-09-09T01:46:40Z","atime":"2001-09-09T01:46:40Z"}"#
            )
        );
        assert_eq!(serde_json::from_str::<XattrMeta>(&json).unwrap(), meta);
        let old: OldXattrMeta = serde_json::from_str(&json).unwrap();
        assert_eq!((old.uid, old.gid, old.mode), (2_147_483_650, 2_147_483_651, 0o600));
        // One alone.
        let group = XattrMeta {
            owner_sid: None,
            uid: 1500,
            ..meta
        };
        let json = serde_json::to_string(&group).unwrap();
        assert!(json.starts_with(r#"{"uid":1500,"gid":2147483651,"group_sid":"S-1-5-"#), "{json}");
        assert_eq!(serde_json::from_str::<XattrMeta>(&json).unwrap(), group);
    }

    /// `BackOtter` (`ForkAudit1` F2): `illumos.xattr_meta` from another machine,
    /// cut short or with any bit flipped: refused, or read into metadata
    /// whose names are refused or are plain names of attribute files, and
    /// whose ACL and times can be looked at, without a panic.
    #[test]
    fn xattr_meta_malformed() {
        use crate::backend::osattrs::malformed::every_json_mutation;

        let json = concat!(
            r#"{"a name with spaces":{"uid":0,"gid":0,"mode":384,"#,
            r#""mtime":"2001-09-09T01:46:40.000000005Z","atime":"2001-09-09T01:46:40.000000005Z"},"#,
            r#""note":{"uid":1500,"gid":1501,"mode":416,"#,
            r#""mtime":"2001-09-09T01:46:40.123456789Z","atime":"2001-09-09T01:46:40Z","#,
            r#""acl":[{"who":60001,"mask":1},{"who":2147483650,"mask":2,"flags":64,"type":1,"sid":"S-1-5-21-1111-2222-3333-513"}]},"#,
            r#""stream":{"uid":2147483650,"gid":2147483651,"owner_sid":"S-1-5-21-1111-2222-3333-1001","#,
            r#""group_sid":"S-1-5-21-1111-2222-3333-513","mode":384,"#,
            r#""mtime":"2001-09-09T01:46:40Z","atime":"2001-09-09T01:46:40Z"}}"#
        );
        let whole = serde_json::from_str::<Value>(json).unwrap();
        _ = every_json_mutation::<BTreeMap<String, XattrMeta>>("xattr_meta", json, |metas| {
            // `--exact`'s comparisons take any of them.
            let value = serde_json::to_value(metas).map_err(|err| err.to_string())?;
            if !same_but_owners(&value, &value) {
                return Err("not the same as itself".to_string());
            }
            _ = same_but_owners(&value, &whole);
            for (name, meta) in metas {
                let refused = attr_name_refused(name).is_some();
                let plain = !name.is_empty()
                    && name != "."
                    && name != ".."
                    && !name.contains(['/', '\0'])
                    && !SYSTEM_VIEWS.contains(&name.as_str());
                if refused == plain {
                    return Err(format!("{name:?}: refused {refused}"));
                }
                _ = super::super::illumos_acl::is_trivial(&meta.acl);
                for e in &meta.acl {
                    _ = e.sid.as_deref().map(super::super::illumos_acl::split_sid);
                }
                for sid in [&meta.owner_sid, &meta.group_sid].into_iter().flatten() {
                    _ = super::super::illumos_acl::split_sid(sid);
                }
                _ = restored_owner(meta, (Some(meta.uid), None), (1, 2));
                _ = super::super::unix_time(meta.mtime);
                _ = super::super::unix_time(meta.atime);
            }
            Ok(())
        });
        for name in [
            "",
            ".",
            "..",
            "a/b",
            "/",
            "../x",
            "a\0b",
            "SUNWattr_rw",
            "SUNWattr_ro",
        ] {
            assert!(attr_name_refused(name).is_some(), "{name:?} not refused");
        }
    }
}
