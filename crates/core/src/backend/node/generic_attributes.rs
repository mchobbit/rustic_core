//! restic's generic attributes: metadata that only some systems have, kept
//! under names that say which (`freebsd.file_flags`, `illumos.acl`, ...),
//! each a JSON value. BackOtter's rustic writes them in the same form as
//! BackOtter's restic, so that each restores what the other backed up.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    sync::Mutex,
};

use jiff::Timestamp;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// Linux's `chattr(1)` flags (`FS_IOC_GETFLAGS`), those a user can set.
pub const LINUX_INODE_FLAGS: &str = "linux.inode_flags";
/// Linux's project ID (`FS_IOC_FSGETXATTR`'s `fsx_projid`), for project
/// quotas: a number, when it isn't 0.
pub const LINUX_PROJECT_ID: &str = "linux.project_id";
/// A regular file with holes (`true`). The restore restores it sparse into a
/// new file; any other file, or one that exists already, it allocates in
/// full (see `write_sparse` in the restore).
pub const UNIX_SPARSE: &str = "unix.sparse";
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
/// NetBSD's `chflags(1)` flags (`st_flags`).
pub const NETBSD_FILE_FLAGS: &str = "netbsd.file_flags";
/// NetBSD's extended attributes in the system namespace.
pub const NETBSD_SYSTEM_EXTATTRS: &str = "netbsd.system_extattrs";
/// NetBSD's POSIX.1e access ACL.
pub const NETBSD_ACL_ACCESS: &str = "netbsd.acl_access";
/// NetBSD's POSIX.1e default ACL, of a directory.
pub const NETBSD_ACL_DEFAULT: &str = "netbsd.acl_default";
/// NetBSD's NFSv4 ACL.
pub const NETBSD_ACL_NFS4: &str = "netbsd.acl_nfs4";
/// DragonFly's `chflags(1)` flags (`st_flags`).
pub const DRAGONFLY_FILE_FLAGS: &str = "dragonfly.file_flags";
/// The DOS flags ZFS keeps on Linux (`ZFS_IOC_GETDOSFLAGS`), those
/// `linux.inode_flags` doesn't carry: a 64-bit mask, 0 included, when it
/// isn't archive alone.
pub const LINUX_ZFS_DOS_FLAGS: &str = "linux.zfs_dos_flags";
/// The FAT attributes of a file on Linux's vfat or msdos
/// (`FAT_IOCTL_GET_ATTRIBUTES`): read-only, hidden, system and archive, as a
/// number, 0 included, when they aren't what a new file (archive alone, its
/// read-only in its mode) or directory (none) has.
pub const LINUX_FAT_ATTRS: &str = "linux.fat_attrs";
/// A file's options on XFS (`FS_IOC_FSGETXATTR`) that `linux.inode_flags`
/// and `linux.project_id` don't carry: [`XfsOptions`], when it has any.
pub const LINUX_XFS_OPTIONS: &str = "linux.xfs_options";
/// A file's birth (creation) time, on FreeBSD and NetBSD (`st_birthtim`)
/// and illumos (ZFS's `crtime`): RFC 3339 in UTC with its nanoseconds, the
/// form of a node's mtime.
pub const UNIX_BIRTHTIME: &str = "unix.birthtime";
/// The SID an illumos file's owner is, when its uid is ephemeral (above
/// `MAXUID`): one idmap hands out for a SID, and only until a reboot.
pub const ILLUMOS_OWNER_SID: &str = "illumos.owner_sid";
/// The SID an illumos file's group is, as [`ILLUMOS_OWNER_SID`].
pub const ILLUMOS_GROUP_SID: &str = "illumos.group_sid";
/// The owner, group, mode, times and ACL of each of an illumos file's
/// extended attributes (named attribute files), by name.
pub const ILLUMOS_XATTR_META: &str = "illumos.xattr_meta";
/// An illumos file's ZFS project ID and whether it hands it down
/// (`zfs project -p ID -s`), when it has either.
pub const ILLUMOS_ZFS_PROJECT: &str = "illumos.zfs_project";
/// A FreeBSD file's ZFS project ID and whether it hands it down (`zfs
/// project -p ID -s`), when it has either, as [`ILLUMOS_ZFS_PROJECT`].
pub const FREEBSD_ZFS_PROJECT: &str = "freebsd.zfs_project";
/// The size in bytes of a regular file whose contents weren't backed up,
/// because illumos quarantined it (`av_quarantined`) and no one, root
/// included, could read it: its node has no contents and size 0.
pub const ILLUMOS_UNREAD_SIZE: &str = "illumos.unread_size";
/// Haiku's file attributes (BFS), with their type codes, other than those
/// of type `B_XATTR_TYPE`, which are the extended attributes: an object of
/// `{"NAME":{"type":TYPE_CODE,"value":"BASE64"}}`.
pub const HAIKU_ATTRIBUTES: &str = "haiku.attributes";

/// The generic attributes restic and BackOtter's restic know, and Haiku's
/// (restic doesn't run on Haiku): an attribute of another system is skipped
/// quietly, an unknown one with a warning.
pub const KNOWN: &[&str] = &[
    "windows.creation_time",
    "windows.file_attributes",
    "windows.security_descriptor",
    LINUX_INODE_FLAGS,
    LINUX_PROJECT_ID,
    UNIX_SPARSE,
    FREEBSD_FILE_FLAGS,
    FREEBSD_SYSTEM_EXTATTRS,
    FREEBSD_ACL_ACCESS,
    FREEBSD_ACL_DEFAULT,
    FREEBSD_ACL_NFS4,
    ILLUMOS_ACL,
    ILLUMOS_SYSTEM_ATTRIBUTES,
    OPENBSD_FILE_FLAGS,
    NETBSD_FILE_FLAGS,
    NETBSD_SYSTEM_EXTATTRS,
    NETBSD_ACL_ACCESS,
    NETBSD_ACL_DEFAULT,
    NETBSD_ACL_NFS4,
    DRAGONFLY_FILE_FLAGS,
    LINUX_ZFS_DOS_FLAGS,
    UNIX_BIRTHTIME,
    ILLUMOS_OWNER_SID,
    ILLUMOS_GROUP_SID,
    ILLUMOS_XATTR_META,
    ILLUMOS_ZFS_PROJECT,
    ILLUMOS_UNREAD_SIZE,
    HAIKU_ATTRIBUTES,
    FREEBSD_ZFS_PROJECT,
    LINUX_FAT_ATTRS,
    LINUX_XFS_OPTIONS,
];

/// The value of [`LINUX_XFS_OPTIONS`]: the kept `fsx_xflags` (extent size
/// hint `e`, its inheritance `E`, nodefrag `f`, filestream `S`, nosymlinks
/// `n`, copy-on-write extent size hint `C`), and the two hints' sizes in
/// bytes, left out when 0, as BackOtter's restic writes them:
/// `{"cowextsize":2097152,"extsize":1048576,"xflags":67584}`.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XfsOptions {
    /// The copy-on-write extent size hint, in bytes.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cowextsize: u32,
    /// The extent size hint, in bytes.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub extsize: u32,
    /// The kept `fsx_xflags`.
    pub xflags: u32,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if
const fn is_zero(n: &u32) -> bool {
    *n == 0
}

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

    /// The number (file flags, a project ID) in the attribute `name`, if
    /// there is one. One that isn't a number that fits is skipped, with a
    /// warning once per attribute name.
    #[must_use]
    pub fn number(&self, name: &str) -> Option<u32> {
        match self.get(name)? {
            Ok(n) => Some(n),
            Err(err) => {
                warn_malformed(name, &err);
                None
            }
        }
    }

    /// Stores a number (file flags, a project ID) as the attribute `name`. A
    /// file without flags gets no attribute, so its node is the same as
    /// without flag support.
    pub fn set_number(&mut self, name: &str, n: u32) {
        if n != 0 {
            _ = self.0.insert(name.to_string(), n.into());
        }
    }

    /// The 64-bit number (ZFS's DOS flags) in the attribute `name`, if there
    /// is one, as [`number`](Self::number) reads a 32-bit one.
    #[must_use]
    pub fn number_u64(&self, name: &str) -> Option<u64> {
        match self.get(name)? {
            Ok(n) => Some(n),
            Err(err) => {
                warn_malformed(name, &err);
                None
            }
        }
    }

    /// Stores a 64-bit number (ZFS's DOS flags, file flags) as the attribute
    /// `name`, 0 too: the caller decides when there is none.
    pub fn set_u64(&mut self, name: &str, n: u64) {
        _ = self.0.insert(name.to_string(), n.into());
    }

    /// The value of the attribute `name`, decoded as a `T` (an object, such
    /// as [`XfsOptions`]), if there is one. One that can't be is skipped,
    /// with a warning once per attribute name.
    #[must_use]
    pub fn decoded<T: DeserializeOwned>(&self, name: &str) -> Option<T> {
        match self.get(name)? {
            Ok(v) => Some(v),
            Err(err) => {
                warn_malformed(name, &err);
                None
            }
        }
    }

    /// Whether the attribute `name` (`unix.sparse`) is there and `true`. One
    /// that isn't a boolean counts as not there, with a warning once per
    /// attribute name.
    #[must_use]
    pub fn is_true(&self, name: &str) -> bool {
        match self.get(name) {
            None => false,
            Some(Ok(b)) => b,
            Some(Err(err)) => {
                warn_malformed(name, &err);
                false
            }
        }
    }

    /// Stores `true` as the attribute `name` (`unix.sparse`).
    pub fn set_true(&mut self, name: &str) {
        _ = self.0.insert(name.to_string(), true.into());
    }

    /// The time (a birth time) in the attribute `name`, if there is one: any
    /// RFC 3339 time, whatever its offset and number of fractional digits.
    /// One that isn't is skipped, with a warning once per attribute name.
    #[must_use]
    pub fn timestamp(&self, name: &str) -> Option<Timestamp> {
        match self.get(name)? {
            Ok(t) => Some(t),
            Err(err) => {
                warn_malformed(name, &err);
                None
            }
        }
    }

    /// Stores a time (a birth time) as the attribute `name`, as Go writes
    /// one: in UTC, with its nanoseconds and no trailing zeros
    /// (`"2001-09-09T01:46:40.5Z"`). Seconds 0 and -1, which file systems
    /// without birth times report (UFS1, NetBSD's first FFS), get no
    /// attribute, nor does a year before 0, which Go can't read.
    pub fn set_timestamp(&mut self, name: &str, t: Timestamp) {
        // 0000-01-01T00:00:00Z
        const YEAR_0: Timestamp = Timestamp::constant(-62_167_219_200, 0);
        // The second as C's tv_sec has it, rounded down.
        let sec = t.as_second() - i64::from(t.subsec_nanosecond() < 0);
        if matches!(sec, 0 | -1) || t < YEAR_0 {
            return;
        }
        _ = self.0.insert(name.to_string(), t.to_string().into());
    }
}

/// Warns that the generic attribute `name` can't be read, once per name, as
/// BackOtter's restic does: a snapshot could have it on every file.
fn warn_malformed(name: &str, err: &serde_json::Error) {
    static WARNED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
    let mut warned = WARNED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if warned.insert(name.to_string()) {
        log::warn!("ignoring generic attribute {name}: {err}");
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
        assert_eq!(attrs.number(FREEBSD_FILE_FLAGS), Some(131_072));
        let acl: serde_json::Value = attrs.get(FREEBSD_ACL_NFS4).unwrap().unwrap();
        assert_eq!(acl[0]["id"], 4_294_967_295_u32);

        let again: Node = serde_json::from_str(&serde_json::to_string(&node).unwrap()).unwrap();
        assert_eq!(node, again);
    }

    #[test]
    fn no_flags_no_attribute() {
        let mut attrs = GenericAttributes::default();
        attrs.set_number(LINUX_INODE_FLAGS, 0);
        attrs.set_number(LINUX_PROJECT_ID, 0);
        assert!(attrs.is_empty());
        assert!(!attrs.is_true(UNIX_SPARSE));
        let node = Node::default();
        assert!(!serde_json::to_string(&node).unwrap().contains("generic_attributes"));
    }

    // FreeBSD's flags of a file on ZFS with archive cleared: a 0 that is
    // there, as BackOtter's restic writes it, for the restore to set.
    #[test]
    fn freebsd_flags_0_json() {
        let mut node = Node::default();
        node.meta.generic_attributes.set_u64(FREEBSD_FILE_FLAGS, 0);
        let json = serde_json::to_string(&node).unwrap();
        assert!(json.contains(r#""freebsd.file_flags":0"#), "{json}");
        let again: Node = serde_json::from_str(&json).unwrap();
        assert_eq!(again.meta.generic_attributes.number(FREEBSD_FILE_FLAGS), Some(0));
    }

    // FAT attributes, 0 too, and XFS options in the form BackOtter's restic
    // writes them: keys in byte order, the sizes left out when 0.
    #[test]
    fn fat_attrs_and_xfs_options_json() {
        let mut node = Node::default();
        node.meta.generic_attributes.set_u64(LINUX_FAT_ATTRS, 0);
        let json = serde_json::to_string(&node).unwrap();
        assert!(json.contains(r#""generic_attributes":{"linux.fat_attrs":0}"#), "{json}");

        let mut attrs = GenericAttributes::default();
        attrs.set(LINUX_XFS_OPTIONS, &XfsOptions { xflags: 0x2000, ..XfsOptions::default() }).unwrap();
        assert_eq!(
            serde_json::to_string(&attrs).unwrap(),
            r#"{"linux.xfs_options":{"xflags":8192}}"#
        );
        let opts = XfsOptions { cowextsize: 2 << 20, extsize: 1 << 20, xflags: 0x10800 };
        attrs.set(LINUX_XFS_OPTIONS, &opts).unwrap();
        let json = serde_json::to_string(&attrs).unwrap();
        assert_eq!(
            json,
            r#"{"linux.xfs_options":{"cowextsize":2097152,"extsize":1048576,"xflags":67584}}"#
        );
        let again: GenericAttributes = serde_json::from_str(&json).unwrap();
        assert_eq!(again.decoded::<XfsOptions>(LINUX_XFS_OPTIONS), Some(opts));
        for bad in ["8192", r#"{"xflags":-1}"#, r#"{"extsize":"x"}"#] {
            let attrs: GenericAttributes =
                serde_json::from_str(&format!(r#"{{"linux.xfs_options":{bad}}}"#)).unwrap();
            assert_eq!(attrs.decoded::<XfsOptions>(LINUX_XFS_OPTIONS), None, "{bad}");
        }
    }

    #[test]
    fn malformed_values_are_skipped() {
        let attrs = |json: &str| -> GenericAttributes { serde_json::from_str(json).unwrap() };
        for bad in ["-1", "1.5", r#""x""#, "4294967296", "true"] {
            let a = attrs(&format!(r#"{{"linux.project_id":{bad},"unix.sparse":{bad}}}"#));
            assert_eq!(a.number(LINUX_PROJECT_ID), None, "{bad}");
            assert!(!a.is_true(UNIX_SPARSE) || bad == "true", "{bad}");
        }
        let a = attrs(r#"{"linux.project_id":0,"unix.sparse":false}"#);
        assert_eq!(a.number(LINUX_PROJECT_ID), Some(0));
        assert!(!a.is_true(UNIX_SPARSE));
    }

    // ZFS's DOS flags: a 64-bit number, 0 included.
    #[test]
    fn zfs_dos_flags_json() {
        let mut node = Node::default();
        node.meta.generic_attributes.set_u64(LINUX_ZFS_DOS_FLAGS, 0);
        let json = serde_json::to_string(&node).unwrap();
        assert!(json.contains(r#""generic_attributes":{"linux.zfs_dos_flags":0}"#), "{json}");
        let node: Node = serde_json::from_str(&json).unwrap();
        assert_eq!(node.meta.generic_attributes.number_u64(LINUX_ZFS_DOS_FLAGS), Some(0));

        let attrs: GenericAttributes =
            serde_json::from_str(r#"{"linux.zfs_dos_flags":52978421596160}"#).unwrap();
        assert_eq!(attrs.number_u64(LINUX_ZFS_DOS_FLAGS), Some(0x0000_302f_0000_0000));
        for bad in ["-1", "1.5", r#""x""#, "18446744073709551616", "true"] {
            let attrs: GenericAttributes =
                serde_json::from_str(&format!(r#"{{"linux.zfs_dos_flags":{bad}}}"#)).unwrap();
            assert_eq!(attrs.number_u64(LINUX_ZFS_DOS_FLAGS), None, "{bad}");
        }
    }

    // Birth times, in the form Go gives a node's mtime.
    #[test]
    fn birthtime_json() {
        for (sec, nsec, json) in [
            (1_000_000_000, 123_456_789, "2001-09-09T01:46:40.123456789Z"),
            (1_000_000_000, 0, "2001-09-09T01:46:40Z"),
            (1_000_000_000, 5, "2001-09-09T01:46:40.000000005Z"),
            (-1_000_000_000, 500_000_000, "1938-04-24T22:13:20.5Z"),
        ] {
            let mut node = Node::default();
            let t = Timestamp::new(sec, nsec).unwrap();
            node.meta.generic_attributes.set_timestamp(UNIX_BIRTHTIME, t);
            let text = serde_json::to_string(&node).unwrap();
            assert!(
                text.contains(&format!(r#""generic_attributes":{{"unix.birthtime":"{json}"}}"#)),
                "{text}"
            );
            let node: Node = serde_json::from_str(&text).unwrap();
            assert_eq!(node.meta.generic_attributes.timestamp(UNIX_BIRTHTIME), Some(t));
        }

        let attrs: GenericAttributes =
            serde_json::from_str(r#"{"unix.birthtime":"2001-09-09T03:46:40.5+02:00"}"#).unwrap();
        assert_eq!(
            attrs.timestamp(UNIX_BIRTHTIME),
            Some(Timestamp::new(1_000_000_000, 500_000_000).unwrap())
        );

        // tv_sec 0 and -1, whatever the nanoseconds, and a year Go can't read.
        let mut attrs = GenericAttributes::default();
        for (sec, nsec) in [(0, 0), (0, 999_999_999), (-1, 0), (0, -1), (-62_167_219_201, 0)] {
            attrs.set_timestamp(UNIX_BIRTHTIME, Timestamp::new(sec, nsec).unwrap());
        }
        assert!(attrs.is_empty());
        attrs.set_timestamp(UNIX_BIRTHTIME, Timestamp::new(-2, 999_999_999).unwrap());
        assert!(!attrs.is_empty(), "tv_sec -2 not written");

        for bad in ["1000000000", r#""x""#, r#""2001-09-09T01:46:40""#, "true"] {
            let attrs: GenericAttributes =
                serde_json::from_str(&format!(r#"{{"unix.birthtime":{bad}}}"#)).unwrap();
            assert_eq!(attrs.timestamp(UNIX_BIRTHTIME), None, "{bad}");
        }
    }

    // A file whose contents weren't backed up: its size a JSON number.
    #[test]
    fn unread_size_json() {
        let mut node = Node::default();
        node.meta.generic_attributes.set_u64(ILLUMOS_UNREAD_SIZE, 5_000_000_000);
        let json = serde_json::to_string(&node).unwrap();
        assert!(
            json.contains(r#""generic_attributes":{"illumos.unread_size":5000000000}"#),
            "{json}"
        );
        let node: Node = serde_json::from_str(&json).unwrap();
        assert_eq!(
            node.meta.generic_attributes.number_u64(ILLUMOS_UNREAD_SIZE),
            Some(5_000_000_000)
        );
    }

    // The JSON BackOtter's restic writes for a sparse file with a project ID.
    #[test]
    fn sparse_and_project_id_json() {
        let mut node = Node::default();
        let attrs = &mut node.meta.generic_attributes;
        attrs.set_true(UNIX_SPARSE);
        attrs.set_number(LINUX_PROJECT_ID, 4_000_000_000);
        let json = serde_json::to_string(&node).unwrap();
        assert!(
            json.contains(r#""generic_attributes":{"linux.project_id":4000000000,"unix.sparse":true}"#),
            "{json}"
        );

        let node: Node = serde_json::from_str(&json).unwrap();
        let attrs = &node.meta.generic_attributes;
        assert!(attrs.is_true(UNIX_SPARSE));
        assert_eq!(attrs.number(LINUX_PROJECT_ID), Some(4_000_000_000));

        let node: Node =
            serde_json::from_str(r#"{"name":"f","type":"file","generic_attributes":{"unix.sparse":false}}"#)
                .unwrap();
        assert!(!node.meta.generic_attributes.is_true(UNIX_SPARSE));
    }
}
