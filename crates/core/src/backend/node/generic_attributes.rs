//! restic's generic attributes: metadata that only some systems have, kept
//! under names that say which (`freebsd.file_flags`, `illumos.acl`, ...),
//! each a JSON value. BackOtter's rustic writes them in the same form as
//! BackOtter's restic, so that each restores what the other backed up.

use std::{cmp::Ordering, collections::BTreeMap};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// Linux's `chattr(1)` flags (`FS_IOC_GETFLAGS`), those a user can set.
pub const LINUX_INODE_FLAGS: &str = "linux.inode_flags";
/// FreeBSD's `chflags(1)` flags (`st_flags`).
pub const FREEBSD_FILE_FLAGS: &str = "freebsd.file_flags";
/// FreeBSD's extended attributes in the system namespace.
pub const FREEBSD_SYSTEM_EXTATTRS: &str = "freebsd.system_extattrs";
/// FreeBSD's POSIX.1e access ACL.
pub const FREEBSD_ACL_ACCESS: &str = "freebsd.acl_access";
/// FreeBSD's POSIX.1e default ACL, of a directory.
pub const FREEBSD_ACL_DEFAULT: &str = "freebsd.acl_default";
/// FreeBSD's NFSv4 ACL.
pub const FREEBSD_ACL_NFS4: &str = "freebsd.acl_nfs4";
/// illumos' ACL (ZFS's NFSv4-style ACEs).
pub const ILLUMOS_ACL: &str = "illumos.acl";
/// illumos' system attributes (`chmod(1)`'s `S+v...`), as a mask.
pub const ILLUMOS_SYSTEM_ATTRIBUTES: &str = "illumos.system_attributes";
/// OpenBSD's `chflags(1)` flags (`st_flags`).
pub const OPENBSD_FILE_FLAGS: &str = "openbsd.file_flags";

/// The generic attributes restic and BackOtter's restic know: an attribute
/// of another system is skipped quietly, an unknown one with a warning.
pub const KNOWN: &[&str] = &[
    "windows.creation_time",
    "windows.file_attributes",
    "windows.security_descriptor",
    LINUX_INODE_FLAGS,
    FREEBSD_FILE_FLAGS,
    FREEBSD_SYSTEM_EXTATTRS,
    FREEBSD_ACL_ACCESS,
    FREEBSD_ACL_DEFAULT,
    FREEBSD_ACL_NFS4,
    ILLUMOS_ACL,
    ILLUMOS_SYSTEM_ATTRIBUTES,
    OPENBSD_FILE_FLAGS,
];

/// A node's generic attributes, by name.
///
/// The values are [`serde_json::Value`]s rather than raw JSON, which serde
/// can't pass through a flattened struct such as [`super::Metadata`].
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(transparent)]
pub struct GenericAttributes(BTreeMap<String, serde_json::Value>);

impl GenericAttributes {
    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The names of the attributes.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }

    /// Decodes the attribute `name`, if there is one.
    pub fn get<T: DeserializeOwned>(&self, name: &str) -> Option<serde_json::Result<T>> {
        self.0
            .get(name)
            .map(|v| serde_json::from_value(v.clone()))
    }

    /// Stores `value` as the attribute `name`.
    ///
    /// # Errors
    ///
    /// * If `value` can't be encoded as JSON.
    pub fn set<T: Serialize>(&mut self, name: &str, value: &T) -> serde_json::Result<()> {
        _ = self.0.insert(name.to_string(), serde_json::to_value(value)?);
        Ok(())
    }

    /// The file flags in the attribute `name`, if there are any.
    #[must_use]
    pub fn file_flags(&self, name: &str) -> Option<u32> {
        match self.get(name)? {
            Ok(flags) => Some(flags),
            Err(err) => {
                log::warn!("ignoring generic attribute {name}: {err}");
                None
            }
        }
    }

    /// Stores file flags as the attribute `name`. A file without flags gets
    /// no attribute, so its node is the same as without flag support.
    pub fn set_file_flags(&mut self, name: &str, flags: u32) {
        if flags != 0 {
            _ = self.0.insert(name.to_string(), flags.into());
        }
    }
}

// Nodes are ordered (they derive `Ord`); JSON values aren't, so the
// attributes are ordered by their JSON text.
impl PartialOrd for GenericAttributes {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GenericAttributes {
    fn cmp(&self, other: &Self) -> Ordering {
        let text = |a: &Self| a.0.iter().map(|(k, v)| (k.clone(), v.to_string())).collect::<Vec<_>>();
        text(self).cmp(&text(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::node::Node;

    // A node as BackOtter's restic writes it (restic's JSON field names).
    const RESTIC_NODE: &str = r#"{"name":"f","type":"file","mode":420,
        "mtime":"2026-10-30T12:00:00Z","atime":"2026-10-30T12:00:00Z",
        "ctime":"2026-10-30T12:00:00Z","uid":0,"gid":0,"inode":5,"links":1,
        "generic_attributes":{"freebsd.file_flags":131072,
        "freebsd.acl_nfs4":[{"tag":1,"id":4294967295,"perm":1,"type":256}]},
        "content":[]}"#;

    #[test]
    fn restic_node_round_trips() {
        let node: Node = serde_json::from_str(RESTIC_NODE).unwrap();
        let attrs = &node.meta.generic_attributes;
        assert_eq!(attrs.file_flags(FREEBSD_FILE_FLAGS), Some(131_072));
        let acl: serde_json::Value = attrs.get(FREEBSD_ACL_NFS4).unwrap().unwrap();
        assert_eq!(acl[0]["id"], 4_294_967_295_u32);

        let again: Node = serde_json::from_str(&serde_json::to_string(&node).unwrap()).unwrap();
        assert_eq!(node, again);
    }

    #[test]
    fn no_flags_no_attribute() {
        let mut attrs = GenericAttributes::default();
        attrs.set_file_flags(LINUX_INODE_FLAGS, 0);
        assert!(attrs.is_empty());
        let node = Node::default();
        assert!(!serde_json::to_string(&node).unwrap().contains("generic_attributes"));
    }
}
