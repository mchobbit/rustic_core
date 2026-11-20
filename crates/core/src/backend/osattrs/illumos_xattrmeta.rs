//! What illumos keeps of each extended attribute besides its value: an
//! attribute is a file of its own (`runat(1)`, `fsattr(5)`), with an owner,
//! a group, a mode, times and an ACL, which `illumos.xattr_meta` holds by
//! the attribute's name. Without it a restored attribute belongs to whoever
//! ran the restore, with mode 0600 and the time of the restore. Portable, so
//! that it is tested on any system; the file access is in `illumos.rs`.

#![cfg_attr(not(target_os = "illumos"), allow(dead_code))]

use std::io;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

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
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(super) struct XattrMeta {
    pub uid: u32,
    pub gid: u32,
    /// The permission bits, `st_mode & 07777`.
    pub mode: u32,
    pub mtime: Timestamp,
    pub atime: Timestamp,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acl: Vec<AceEntry>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn attr_names_refused() {
        for name in ["", ".", "..", "../x", "a/b", "/etc/x", "a\0b", "SUNWattr_ro", "SUNWattr_rw"] {
            let err = attr_name_refused(name).unwrap_or_else(|| panic!("{name:?} allowed"));
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{name:?}");
        }
        for name in ["a", "user.x", "...", "..x", ".hidden", "\u{fffd}", "SUNWattr_rw2"] {
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
                    acl: Vec::new(),
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
                    acl: Vec::new(),
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
    }
}
