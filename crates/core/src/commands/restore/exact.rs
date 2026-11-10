//! BackOtter: `restore --exact` and `--clone-from`.
//!
//! `--exact` makes a destination that is already there (a btrfs snapshot of
//! a tree restored before, bko-holt's shared snapshots) exactly the node
//! tree, writing only what differs, so that what is the same stays shared:
//! no write reaches an entry that already matches, and none reaches the
//! other names of a hard-linked file.  `--clone-from` gives it files whose
//! contents were restored elsewhere on the same file system, cloned whole
//! instead of written.

use std::{
    collections::HashMap,
    ffi::OsStr,
    io,
    path::{Path, PathBuf},
};

use crate::{
    backend::{
        ignore::{Incomplete, mapper::LocalSourceSaveOptions},
        node::{
            ExtendedAttribute, Node,
            modification::{TimeOption, XattrOption},
        },
        osattrs,
    },
    blob::DataId,
};

/// Files already restored, by their contents (the blobs a snapshot lists
/// for them), which a restore may clone instead of writing.
#[derive(Debug, Default, Clone)]
pub struct CloneSources {
    by_content: HashMap<Vec<DataId>, PathBuf>,
}

impl CloneSources {
    /// No files.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `path` holds `content`, restored.  The first file given for some
    /// contents is the one cloned.
    pub fn insert(&mut self, content: Vec<DataId>, path: PathBuf) {
        _ = self.by_content.entry(content).or_insert(path);
    }

    /// A file that holds `content`, if any.
    #[must_use]
    pub fn get(&self, content: &[DataId]) -> Option<&Path> {
        self.by_content.get(content).map(PathBuf::as_path)
    }

    /// How many contents there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_content.len()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_content.is_empty()
    }
}

/// Whether `node`'s contents may be cloned into its file: not when the file
/// takes flags or options before its data (btrfs's no-copy-on-write, which
/// a clone refuses; XFS's extent size hint).
pub(super) fn clone_ok(node: &Node) -> bool {
    osattrs::takes_nothing_before_data(node)
}

/// Why [`clone_file`] didn't clone.
#[derive(Debug)]
pub(super) enum CloneFailed {
    /// Nothing was done: `dst` is as it was.
    Untouched(io::Error),
    /// `dst` was made or emptied first.
    Emptied(io::Error),
}

/// The file `dst` (made, or emptied) gets the whole contents of `src`,
/// sharing its extents, if the file system can.  `size` is what `src` must
/// hold; `dst` is touched only once `src` is open and that size.
pub(super) fn clone_file(src: &Path, dst: &Path, size: u64) -> Result<(), CloneFailed> {
    let s = std::fs::File::open(src).map_err(CloneFailed::Untouched)?;
    let len = s.metadata().map_err(CloneFailed::Untouched)?.len();
    if len != size {
        return Err(CloneFailed::Untouched(io::Error::other(format!("{} isn't {size} bytes", src.display()))));
    }
    let d = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(dst)
        .map_err(CloneFailed::Untouched)?;
    osattrs::clone_contents(&s, &d).map_err(CloneFailed::Emptied)
}

/// The existing file `path`, which has other names: its name gets a file of
/// its own, a clone of it where the file system can (nothing is written,
/// its extents stay shared), or nothing, the old one removed.  The other
/// names keep the old file.  True if it is a clone.
pub(super) fn break_link(path: &Path) -> io::Result<bool> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().unwrap_or_else(|| OsStr::new("file"));
    let mut tmp_name = std::ffi::OsString::from(".bko-exact-");
    tmp_name.push(name);
    let tmp = dir.join(tmp_name);
    let cloned = (|| {
        let size = std::fs::symlink_metadata(path)?.len();
        clone_file(path, &tmp, size).map_err(|e| match e {
            CloneFailed::Untouched(e) | CloneFailed::Emptied(e) => e,
        })?;
        std::fs::rename(&tmp, path)
    })();
    match cloned {
        Ok(()) => Ok(true),
        Err(_) => {
            _ = std::fs::remove_file(&tmp);
            std::fs::remove_file(path)?;
            Ok(false)
        }
    }
}

/// Whether the regular file at `path` has other names.
pub(super) fn has_other_names(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && m.nlink() > 1)
    }
    #[cfg(not(unix))]
    {
        _ = path;
        false
    }
}

/// What a backup would record for what is at `target` now, if it can all
/// be read.
fn node_now(target: &Path) -> Option<Node> {
    let m = std::fs::symlink_metadata(target).ok()?;
    let name = target.file_name().unwrap_or_else(|| OsStr::new(""));
    let incomplete = Incomplete::default();
    let opts = LocalSourceSaveOptions::default()
        .set_atime(TimeOption::Yes)
        .set_xattrs(XattrOption::Yes);
    let now = opts.map_path(target, name, &m, &incomplete, false).ok()?;
    (incomplete.get() == 0).then_some(now)
}

/// Whether what is at `target` is already `node`'s type: for a special
/// file, the same symlink target or device.
pub(super) fn same_type(target: &Path, node: &Node) -> bool {
    let Ok(m) = std::fs::symlink_metadata(target) else {
        return false;
    };
    let name = target.file_name().unwrap_or_else(|| OsStr::new(""));
    let opts = LocalSourceSaveOptions::default().set_xattrs(XattrOption::No);
    opts.map_path(target, name, &m, &Incomplete::default(), false)
        .is_ok_and(|now| now.node_type == node.node_type)
}

/// Whether `a` and `b` are the same file.
pub(super) fn same_file(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (std::fs::symlink_metadata(a), std::fs::symlink_metadata(b)) {
            (Ok(x), Ok(y)) => x.dev() == y.dev() && x.ino() == y.ino(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        _ = (a, b);
        false
    }
}

/// Whether what is at `target` already has `node`'s metadata: what a
/// backup would record for it now is `node`'s, but for what a restore can't
/// set or doesn't (the change time, the inode, the device, the link count,
/// the owner's names).  `numeric` says the owner is by ID; by name, the IDs
/// on this system may differ from the node's, and it never matches.
/// Anything that can't be read doesn't match.
pub(super) fn already_matches(target: &Path, node: &Node, numeric: bool, ownership: bool) -> bool {
    if ownership && !numeric {
        return false;
    }
    node_now(target).is_some_and(|now| same_metadata(&now, node, ownership))
}

/// The comparison [`already_matches`] makes.
fn same_metadata(now: &Node, node: &Node, ownership: bool) -> bool {
    let (a, b) = (&now.meta, &node.meta);
    let sorted = |x: &[ExtendedAttribute]| {
        let mut v: Vec<(String, Option<Vec<u8>>)> =
            x.iter().map(|e| (e.name.clone(), e.value.clone())).collect();
        v.sort();
        v
    };
    now.node_type == node.node_type
        && a.mode == b.mode
        && a.mtime == b.mtime
        && a.atime == b.atime
        && (!ownership || (a.uid == b.uid && a.gid == b.gid))
        && a.size == b.size
        && sorted(&a.extended_attributes) == sorted(&b.extended_attributes)
        && a.generic_attributes == b.generic_attributes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::node::{Metadata, NodeType};
    use jiff::Timestamp;

    fn node(mode: u32, xattrs: &[(&str, &[u8])]) -> Node {
        Node::new_node(
            OsStr::new("f"),
            NodeType::File,
            Metadata {
                mode: Some(mode),
                mtime: Some(Timestamp::from_second(1_700_000_000).unwrap()),
                atime: Some(Timestamp::from_second(1_700_000_100).unwrap()),
                uid: Some(0),
                gid: Some(0),
                size: 3,
                extended_attributes: xattrs
                    .iter()
                    .map(|(n, v)| ExtendedAttribute { name: (*n).to_string(), value: Some(v.to_vec()) })
                    .collect(),
                ..Metadata::default()
            },
        )
    }

    #[test]
    fn same_metadata_ignores_what_a_restore_cant_set() {
        let a = node(0o644, &[("security.selinux", b"x"), ("user.a", b"1")]);
        let mut b = node(0o644, &[("user.a", b"1"), ("security.selinux", b"x")]);
        b.meta.ctime = Some(Timestamp::from_second(1).unwrap());
        b.meta.inode = 7;
        b.meta.device_id = 9;
        b.meta.links = 2;
        b.meta.user = Some("root".into());
        assert!(same_metadata(&a, &b, true));
        b.meta.uid = Some(1);
        assert!(!same_metadata(&a, &b, true));
        assert!(same_metadata(&a, &b, false));
    }

    #[test]
    fn same_metadata_sees_every_difference() {
        let a = node(0o644, &[("user.a", b"1")]);
        assert!(!same_metadata(&a, &node(0o600, &[("user.a", b"1")]), true));
        assert!(!same_metadata(&a, &node(0o644, &[("user.a", b"2")]), true));
        assert!(!same_metadata(&a, &node(0o644, &[]), true));
        let mut b = node(0o644, &[("user.a", b"1")]);
        b.meta.atime = None;
        assert!(!same_metadata(&a, &b, true));
    }

    #[test]
    fn clone_sources_keep_the_first() {
        let mut c = CloneSources::new();
        let id = vec![DataId::default()];
        c.insert(id.clone(), "a".into());
        c.insert(id.clone(), "b".into());
        assert_eq!(c.get(&id), Some(Path::new("a")));
        assert_eq!(c.get(&[]), None);
        assert_eq!(c.len(), 1);
    }
}
