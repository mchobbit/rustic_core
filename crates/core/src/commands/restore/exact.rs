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

use jiff::Timestamp;

use crate::{
    backend::{
        ignore::{Incomplete, mapper::LocalSourceSaveOptions},
        node::{
            ExtendedAttribute, Node,
            generic_attributes::{UNIX_BIRTHTIME, UNIX_SPARSE},
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

/// The start of the names of the temporary files clones are made in, which
/// random digits end ([`clone_over`]): a name no entry has when it is
/// made, short enough for any directory, whatever the name of the file
/// cloned. As in BackOtter's restic (`.bko-exact-*`).
const CLONE_TEMP_PREFIX: &str = ".bko-exact-";

/// Whether this system can clone at all (Linux's `FICLONE`): elsewhere
/// nothing is made to try.
const CLONE_SUPPORTED: bool = cfg!(target_os = "linux");

/// Why [`clone_file`] or [`clone_over`] didn't clone. Either way the file
/// cloned onto is as it was, contents, inode and all.
#[derive(Debug)]
pub(super) enum CloneFailed {
    /// Nothing is left of the attempt.
    Failed(io::Error),
    /// The clone failed (`err`), and its temporary file `tmp` couldn't be
    /// removed (`remove`): it is left in the destination, under that name.
    TempLeft {
        err: io::Error,
        tmp: PathBuf,
        remove: io::Error,
    },
}

impl CloneFailed {
    /// BackOtter: this, with a temporary file left in `dst`'s directory
    /// named through `dst`: by the long path, past `PATH_MAX`, of a file
    /// cloned onto through a short path to it (`walkdir::short_path`).
    fn beside(self, dst: &Path) -> Self {
        match self {
            Self::TempLeft { err, tmp, remove } => {
                let name = tmp.file_name().map(ToOwned::to_owned);
                let tmp = name.map_or(tmp, |name| dst.with_file_name(name));
                Self::TempLeft { err, tmp, remove }
            }
            failed @ Self::Failed(_) => failed,
        }
    }
}

impl std::fmt::Display for CloneFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(err) => write!(f, "{err}"),
            Self::TempLeft { err, tmp, remove } => write!(
                f,
                "{err}, and its temporary file {} is left behind: {remove}",
                tmp.display()
            ),
        }
    }
}

impl From<CloneFailed> for io::Error {
    fn from(failed: CloneFailed) -> Self {
        match failed {
            CloneFailed::Failed(err) => err,
            left @ CloneFailed::TempLeft { .. } => Self::other(left.to_string()),
        }
    }
}

/// Opens the regular file at `path` for reading, following no symlink and
/// not waiting on a FIFO (`O_NONBLOCK`: BackOtter's rule S11), and checks
/// with `fstat` that it is one. It is only cloned from, never read.
/// BackOtter: `path` may be a short path to it past `PATH_MAX`; the error
/// names `shown`, the file's own path.
fn open_regular(path: &Path, shown: &Path) -> io::Result<(std::fs::File, std::fs::Metadata)> {
    let mut how = std::fs::OpenOptions::new();
    _ = how.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        _ = how.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let f = how.open(path)?;
    let m = f.metadata()?;
    if !m.is_file() {
        return Err(io::Error::other(format!("{} isn't a regular file", shown.display())));
    }
    Ok((f, m))
}

/// Makes a new, empty temporary file in `dir` for a clone: `O_EXCL`, so
/// that nothing there (a symlink, a file of the snapshot's, another
/// name of a file) is followed, emptied or taken over; another name is
/// tried while one is taken.
fn create_temp(dir: &Path) -> io::Result<(PathBuf, std::fs::File)> {
    use rand::{RngExt, rng};
    let mut tries = 0;
    loop {
        let tmp = dir.join(format!("{CLONE_TEMP_PREFIX}{}", rng().random::<u32>()));
        let mut how = std::fs::OpenOptions::new();
        _ = how.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            _ = how.custom_flags(libc::O_NOFOLLOW | libc::O_NOCTTY).mode(0o600);
        }
        match how.open(&tmp) {
            Ok(f) => return Ok((tmp, f)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists && tries < 100 => tries += 1,
            Err(err) => return Err(err),
        }
    }
}

/// Clones `src` into a new temporary file in `dst`'s directory
/// ([`create_temp`]) and renames it over `dst`, so that a clone that fails
/// leaves `dst` as it was. Whatever fails, the temporary file, which
/// nothing else made, is removed; one that can't be is
/// [`CloneFailed::TempLeft`], naming it. A `dst` with other names loses
/// that name only: they keep the old file. The clone's metadata is a new
/// file's, which the restore sets after.
fn clone_over(src: &std::fs::File, dst: &Path) -> Result<(), CloneFailed> {
    clone_over_with(src, dst, osattrs::clone_contents, |tmp| std::fs::remove_file(tmp))
}

/// [`clone_over`], cloning with `clone` and removing the temporary file
/// with `remove` (for tests).
fn clone_over_with(
    src: &std::fs::File,
    dst: &Path,
    clone: impl FnOnce(&std::fs::File, &std::fs::File) -> io::Result<()>,
    remove: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<(), CloneFailed> {
    let dir = dst
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let (tmp, t) = create_temp(dir).map_err(CloneFailed::Failed)?;
    let cloned = clone(src, &t).and_then(|()| {
        drop(t);
        std::fs::rename(&tmp, dst)
    });
    let Err(err) = cloned else {
        return Ok(());
    };
    match remove(&tmp) {
        Err(remove) if remove.kind() != io::ErrorKind::NotFound => {
            Err(CloneFailed::TempLeft { err, tmp, remove })
        }
        _ => Err(CloneFailed::Failed(err)),
    }
}

/// The file `dst` (a regular file, or none) gets the whole contents of
/// `src`, sharing its extents, if the file system can: the clone is made
/// in a new temporary file renamed over `dst` ([`clone_over`]), so that a
/// clone that fails leaves `dst` as it was, for the restore to write only
/// what differs; where the system can't clone at all, nothing is touched.
/// `size` is what `src`, a regular file opened without following a
/// symlink or waiting on a FIFO ([`open_regular`]), must hold; and it
/// mustn't be `dst` itself (by another name too).
pub(super) fn clone_file(src: &Path, dst: &Path, size: u64) -> Result<(), CloneFailed> {
    // BackOtter: past PATH_MAX, through short paths to them; the errors
    // name `src` and `dst`.
    let (src_sys, dst_sys) = (&*walkdir::short_path(src), &*walkdir::short_path(dst));
    // BackOtter: waits for the exit once XFS options are put back for it.
    let _making = super::making_entries();
    if !CLONE_SUPPORTED {
        return Err(CloneFailed::Failed(io::Error::new(
            io::ErrorKind::Unsupported,
            "reflinks not supported on this system",
        )));
    }
    let (s, m) = open_regular(src_sys, src).map_err(CloneFailed::Failed)?;
    if m.len() != size {
        return Err(CloneFailed::Failed(io::Error::other(format!(
            "{} isn't {size} bytes",
            src.display()
        ))));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if std::fs::symlink_metadata(dst_sys).is_ok_and(|d| d.dev() == m.dev() && d.ino() == m.ino()) {
            return Err(CloneFailed::Failed(io::Error::other(format!(
                "{} is {} itself",
                src.display(),
                dst.display()
            ))));
        }
    }
    clone_over(&s, dst_sys).map_err(|failed| failed.beside(dst))
}

/// The existing regular file `path`, which has other names, gets a file of
/// its own: a clone of it where the file system can ([`clone_over`]:
/// nothing is written, its extents stay shared), or nothing, the old one
/// removed, for the restore to write whole. The other names keep the old
/// file. True if it is a clone. A clone that failed and left its temporary
/// file is an error naming it, and `path` stays as it is.
pub(super) fn break_link(path: &Path) -> io::Result<bool> {
    break_link_with(path, clone_over)
}

/// [`break_link`], cloning with `clone_over` (for tests).
fn break_link_with(
    path: &Path,
    clone_over: impl FnOnce(&std::fs::File, &Path) -> Result<(), CloneFailed>,
) -> io::Result<bool> {
    // BackOtter: past PATH_MAX, through a short path to it; the messages,
    // and a temporary file left, name `path`.
    let sys = &*walkdir::short_path(path);
    // BackOtter: waits for the exit once XFS options are put back for it.
    let _making = super::making_entries();
    if CLONE_SUPPORTED {
        match open_regular(sys, path)
            .map_err(CloneFailed::Failed)
            .and_then(|(f, _)| clone_over(&f, sys).map_err(|failed| failed.beside(path)))
        {
            Ok(()) => return Ok(true),
            Err(left @ CloneFailed::TempLeft { .. }) => return Err(left.into()),
            Err(CloneFailed::Failed(err)) => {
                log::debug!("{} not cloned, to be removed: {err}", path.display());
            }
        }
    }
    std::fs::remove_file(sys)?;
    Ok(false)
}

/// Whether the regular file at `path` has other names.
pub(super) fn has_other_names(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // BackOtter: past PATH_MAX, through a short path to it.
        std::fs::symlink_metadata(walkdir::short_path(path))
            .is_ok_and(|m| m.is_file() && m.nlink() > 1)
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
    // BackOtter: past PATH_MAX, through a short path to it (map_path makes
    // its own for each call).
    let m = std::fs::symlink_metadata(walkdir::short_path(target)).ok()?;
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
    // BackOtter: past PATH_MAX, through a short path to it (map_path makes
    // its own for each call).
    let Ok(m) = std::fs::symlink_metadata(walkdir::short_path(target)) else {
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
        // BackOtter: past PATH_MAX, through short paths to them.
        match (
            std::fs::symlink_metadata(walkdir::short_path(a)),
            std::fs::symlink_metadata(walkdir::short_path(b)),
        ) {
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
/// backup would record for it now is `node`'s, as a restore sets it
/// ([`same_metadata`]), but for what a restore can't set or doesn't (the
/// change time, the inode, the device, the link count, the owner's names).
/// `numeric` says the owner is by ID; by name, the IDs on this system may
/// differ from the node's, and it never matches. `known_bko`: the snapshot
/// is BackOtter's. Anything that can't be read doesn't match.
pub(super) fn already_matches(
    target: &Path,
    node: &Node,
    numeric: bool,
    ownership: bool,
    known_bko: bool,
) -> bool {
    if ownership && !numeric {
        return false;
    }
    node_now(target).is_some_and(|now| same_metadata(&now, node, ownership, known_bko))
}

/// Whether what is at `target` has `node`'s metadata ([`already_matches`])
/// but for its atime ([`atime_alone_differs`]), which is then put back
/// alone ([`osattrs::set_atime`]), leaving the change time as it is: on
/// NetBSD, whose FFS moves no change time for an atime set with the mtime
/// omitted, and which has no `O_NOATIME`, so that on a mount that keeps
/// atimes (as installed) the restore's own reads move them (verifying a
/// file's contents, listing a directory). Not where it can't be set (a
/// restricting flag), nor elsewhere, where setting any time moves the
/// change time (and Linux reads with `O_NOATIME`): the restore then sets
/// the metadata whole.
pub(super) fn atime_put_back(
    target: &Path,
    node: &Node,
    numeric: bool,
    ownership: bool,
    known_bko: bool,
) -> bool {
    #[cfg(target_os = "netbsd")]
    {
        if ownership && !numeric {
            return false;
        }
        let Some(atime) =
            node_now(target).and_then(|now| atime_alone_differs(&now, node, ownership, known_bko))
        else {
            return false;
        };
        osattrs::set_atime(target, atime)
            .inspect_err(|err| log::debug!("{err}: its metadata set whole"))
            .is_ok()
    }
    #[cfg(not(target_os = "netbsd"))]
    {
        _ = (target, node, numeric, ownership, known_bko);
        false
    }
}

/// The atime a restore gives a file for `node` (its own, else its mtime),
/// if `now`, what a backup would record for the file, has another and
/// everything else of `node`'s, as [`same_metadata`] compares it: an atime
/// a read moved. None when it matches, when more differs, or when `node`
/// has no mtime (no times compared).
#[cfg_attr(not(any(test, target_os = "netbsd")), allow(dead_code))]
fn atime_alone_differs(
    now: &Node,
    node: &Node,
    ownership: bool,
    known_bko: bool,
) -> Option<Timestamp> {
    let mtime = node.meta.mtime?;
    let atime = node.meta.atime.unwrap_or(mtime);
    if now.meta.atime == Some(atime) {
        return None;
    }
    let mut put_back = now.clone();
    put_back.meta.atime = Some(atime);
    same_metadata(&put_back, node, ownership, known_bko).then_some(atime)
}

/// The comparison [`already_matches`] makes: the type (a symlink's target,
/// a device), mode, times (the mtime in place of a missing atime, as the
/// restore sets it; none when `node` has no mtime), the owner's IDs with
/// `ownership`, size, extended attributes in any order, and generic
/// attributes as [`same_generic_attributes`] compares them. As in
/// BackOtter's restic (`sameMetadata`).
fn same_metadata(now: &Node, node: &Node, ownership: bool, known_bko: bool) -> bool {
    let (a, b) = (&now.meta, &node.meta);
    let sorted = |x: &[ExtendedAttribute]| {
        let mut v: Vec<(String, Option<Vec<u8>>)> =
            x.iter().map(|e| (e.name.clone(), e.value.clone())).collect();
        v.sort();
        v
    };
    let times = b
        .mtime
        .is_none_or(|mtime| a.mtime == Some(mtime) && a.atime == Some(b.atime.unwrap_or(mtime)));
    now.node_type == node.node_type
        && a.mode == b.mode
        && times
        && (!ownership || (a.uid == b.uid && a.gid == b.gid))
        && a.size == b.size
        && sorted(&a.extended_attributes) == sorted(&b.extended_attributes)
        && same_generic_attributes(now, node, known_bko)
}

/// Whether `now`, what a backup would record for a file, holds `node`'s
/// generic attributes as a restore leaves them. Not those a restore doesn't
/// set: `unix.sparse` (the holes, which go with the contents, filled
/// apart), the birth time, compared as a restore can set it
/// ([`same_birth_time`]: on FreeBSD and NetBSD a backup records one for
/// every file, which a node from elsewhere hasn't got), nor, unless the
/// snapshot is BackOtter's (`known_bko`), one that `node` hasn't got: that
/// is unknown, and the restore leaves what the file has. As in BackOtter's
/// restic (`sameGenericAttributes`).
fn same_generic_attributes(now: &Node, node: &Node, known_bko: bool) -> bool {
    let (a, b) = (&now.meta.generic_attributes, &node.meta.generic_attributes);
    let skipped = |name: &str| name == UNIX_SPARSE || name == UNIX_BIRTHTIME;
    b.names().all(|name| skipped(name) || a.value(name).is_some())
        && a
            .names()
            .filter(|name| !skipped(name))
            .all(|name| b.value(name).map_or(!known_bko, |want| a.value(name) == Some(want)))
        && same_birth_time(now, node, BIRTH_TIME_LOWERED)
}

/// Whether a restore can only lower a file's birth time here: FreeBSD and
/// NetBSD set none, but lower it to any mtime set before it.
const BIRTH_TIME_LOWERED: bool = cfg!(any(target_os = "freebsd", target_os = "netbsd"));

/// Whether `now`, what a backup would record for a file, has the birth time
/// a restore of `node` would leave it with: any, where either has none (a
/// system or file system that keeps none, a node from one), since a restore
/// then sets none. Where it can only be lowered (`lowered`), and is lowered
/// to `node`'s mtime as well, a file whose birth time is `node`'s or
/// earlier, and no later than `node`'s mtime, keeps it: a restore would
/// leave it as it is. Elsewhere (illumos) it is `node`'s. As in BackOtter's
/// restic (`fs.SameBirthTime`).
fn same_birth_time(now: &Node, node: &Node, lowered: bool) -> bool {
    let birth = |n: &Node| n.meta.generic_attributes.timestamp(UNIX_BIRTHTIME);
    let (Some(have), Some(mut want)) = (birth(now), birth(node)) else {
        return true;
    };
    if !lowered {
        return have == want;
    }
    if let Some(mtime) = node.meta.mtime
        && mtime < want
    {
        want = mtime;
    }
    have <= want
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::node::{Metadata, NodeType};

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
        assert!(same_metadata(&a, &b, true, true));
        b.meta.uid = Some(1);
        assert!(!same_metadata(&a, &b, true, true));
        assert!(same_metadata(&a, &b, false, true));
    }

    #[test]
    fn same_metadata_sees_every_difference() {
        let a = node(0o644, &[("user.a", b"1")]);
        assert!(!same_metadata(&a, &node(0o600, &[("user.a", b"1")]), true, true));
        assert!(!same_metadata(&a, &node(0o644, &[("user.a", b"2")]), true, true));
        assert!(!same_metadata(&a, &node(0o644, &[]), true, true));
        let mut b = node(0o644, &[("user.a", b"1")]);
        b.meta.atime = Some(Timestamp::from_second(1_700_000_200).unwrap());
        assert!(!same_metadata(&a, &b, true, true));
        let mut b = node(0o644, &[("user.a", b"1")]);
        b.meta.mtime = Some(Timestamp::from_second(1_700_000_001).unwrap());
        assert!(!same_metadata(&a, &b, true, true));
    }

    /// D9: a node without an atime matches a file whose atime is its mtime,
    /// as the restore sets it; one without an mtime has no times compared.
    #[test]
    fn same_metadata_missing_atime_is_the_mtime() {
        let mut node_ = node(0o644, &[]);
        node_.meta.atime = None;
        let mut now = node(0o644, &[]);
        now.meta.atime = now.meta.mtime;
        assert!(same_metadata(&now, &node_, true, true));
        now.meta.atime = Some(Timestamp::from_second(1_700_000_100).unwrap());
        assert!(!same_metadata(&now, &node_, true, true));
        node_.meta.mtime = None;
        assert!(same_metadata(&now, &node_, true, true));
    }

    /// An atime a read moved (NetBSD) is put back alone: only where the
    /// rest matches, as the restore would set it.
    #[test]
    fn atime_alone_differs_when_the_rest_matches() {
        let ts = |s| Timestamp::from_second(s).unwrap();
        let node_ = node(0o644, &[("user.a", b"1")]);
        let mut now = node(0o644, &[("user.a", b"1")]);
        assert_eq!(atime_alone_differs(&now, &node_, true, true), None);
        now.meta.atime = Some(ts(1_800_000_000));
        assert_eq!(atime_alone_differs(&now, &node_, true, true), Some(ts(1_700_000_100)));
        // The mtime in place of a missing atime; no mtime, no times compared.
        let mut no_atime = node_.clone();
        no_atime.meta.atime = None;
        assert_eq!(atime_alone_differs(&now, &no_atime, true, true), Some(ts(1_700_000_000)));
        no_atime.meta.mtime = None;
        assert_eq!(atime_alone_differs(&now, &no_atime, true, true), None);
        // Anything else that differs: the metadata are set whole.
        let mut more = now.clone();
        more.meta.mtime = Some(ts(1_700_000_001));
        assert_eq!(atime_alone_differs(&more, &node_, true, true), None);
        let mut more = now.clone();
        more.meta.mode = Some(0o600);
        assert_eq!(atime_alone_differs(&more, &node_, true, true), None);
        let mut more = now.clone();
        more.meta.uid = Some(1);
        assert_eq!(atime_alone_differs(&more, &node_, true, true), None);
        assert_eq!(atime_alone_differs(&more, &node_, false, true), Some(ts(1_700_000_100)));
        let mut more = node(0o644, &[("user.a", b"2")]);
        more.meta.atime = now.meta.atime;
        assert_eq!(atime_alone_differs(&more, &node_, true, true), None);
    }

    /// D9: `unix.sparse` and the birth time aren't compared as other
    /// generic attributes; one the node hasn't got matches anything in a
    /// snapshot not BackOtter's, nothing in one of BackOtter's.
    #[test]
    fn same_generic_attributes_as_a_restore_leaves_them() {
        let node_ = node(0o644, &[]);
        let mut now = node(0o644, &[]);
        now.meta.generic_attributes.set_true(UNIX_SPARSE);
        assert!(same_metadata(&now, &node_, true, true));
        now.meta.generic_attributes.set_number("linux.inode_flags", 0x10);
        assert!(!same_metadata(&now, &node_, true, true));
        assert!(same_metadata(&now, &node_, true, false));
        let mut want = node_.clone();
        want.meta.generic_attributes.set_number("linux.inode_flags", 0x10);
        assert!(same_metadata(&now, &want, true, true));
        want.meta.generic_attributes.set_number("linux.inode_flags", 0x30);
        assert!(!same_metadata(&now, &want, true, false));
        // One the node has that the file hasn't never matches.
        let mut want = node_;
        want.meta.generic_attributes.set_number("linux.project_id", 3);
        assert!(!same_metadata(&now, &want, true, false));
    }

    /// D9: where a restore can only lower a birth time (FreeBSD, NetBSD),
    /// one at or before the node's, and no later than its mtime, matches;
    /// elsewhere only the node's; either missing one matches.
    #[test]
    fn same_birth_time_as_a_restore_sets_it() {
        let ts = |s| Timestamp::from_second(s).unwrap();
        let with_birth = |birth: Option<i64>| {
            let mut n = node(0o644, &[]);
            if let Some(b) = birth {
                n.meta.generic_attributes.set_timestamp(UNIX_BIRTHTIME, ts(b));
            }
            n
        };
        // mtime 1_700_000_000
        let node_ = with_birth(Some(1_600_000_000));
        assert!(same_birth_time(&with_birth(None), &node_, true));
        assert!(same_birth_time(&with_birth(Some(1_650_000_000)), &with_birth(None), true));
        assert!(same_birth_time(&with_birth(Some(1_600_000_000)), &node_, true));
        assert!(same_birth_time(&with_birth(Some(1_500_000_000)), &node_, true));
        assert!(!same_birth_time(&with_birth(Some(1_650_000_000)), &node_, true));
        assert!(!same_birth_time(&with_birth(Some(1_500_000_000)), &node_, false));
        assert!(same_birth_time(&with_birth(Some(1_600_000_000)), &node_, false));
        // A birth time after the mtime is lowered to the mtime.
        let later = with_birth(Some(1_800_000_000));
        assert!(same_birth_time(&with_birth(Some(1_700_000_000)), &later, true));
        assert!(!same_birth_time(&with_birth(Some(1_700_000_001)), &later, true));
    }

    /// D1, D5: the clone source is opened without following a symlink or
    /// waiting on a FIFO, and must be a regular file.
    #[test]
    #[cfg(unix)]
    fn clone_source_regular_only() {
        let dir = tempfile::tempdir().unwrap();
        let (f, l, p) = (dir.path().join("f"), dir.path().join("l"), dir.path().join("p"));
        std::fs::write(&f, b"x").unwrap();
        std::os::unix::fs::symlink(&f, &l).unwrap();
        nix::unistd::mkfifo(&p, nix::sys::stat::Mode::S_IRWXU).unwrap();
        assert!(open_regular(&f, &f).is_ok());
        assert!(open_regular(&l, &l).is_err());
        assert!(open_regular(&p, &p).is_err(), "a FIFO is no clone source");
        assert!(open_regular(dir.path(), dir.path()).is_err());
        // The error names the path it is given to name, not the one opened.
        let err = open_regular(dir.path(), Path::new("long/x")).unwrap_err();
        assert_eq!(err.to_string(), "long/x isn't a regular file");
        for src in [&l, &p] {
            assert!(clone_file(src, &dir.path().join("dst"), 1).is_err());
        }
        assert!(!dir.path().join("dst").exists());
    }

    /// The temporary files a clone is made in, left in `dir`.
    #[cfg(unix)]
    fn temps(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(CLONE_TEMP_PREFIX) && n != ".bko-exact-foo")
            .collect()
    }

    /// D1, D3, E2: a clone is made in a new temporary file, never in an
    /// entry there (a symlink to a file outside, a file of the snapshot's
    /// named `.bko-exact-NAME`), and renamed over the file only when it
    /// worked: a failed one leaves the file as it was and removes its
    /// temporary file, and one whose temporary file can't be removed says
    /// so, naming it.
    #[test]
    #[cfg(unix)]
    fn clone_over_a_new_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim");
        std::fs::write(&victim, b"outside").unwrap();
        let (foo, link) = (dir.path().join("foo"), dir.path().join(".bko-exact-foo"));
        std::fs::write(&foo, b"old contents").unwrap();
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let src = dir.path().join("src");
        std::fs::write(&src, b"new contents").unwrap();
        let s = std::fs::File::open(&src).unwrap();

        let failed = clone_over_with(&s, &foo, |_, _| Err(io::Error::other("no reflinks")), |t| {
            std::fs::remove_file(t)
        });
        assert!(matches!(failed, Err(CloneFailed::Failed(_))), "{failed:?}");
        assert_eq!(std::fs::read(&foo).unwrap(), b"old contents");
        assert!(temps(dir.path()).is_empty(), "{:?}", temps(dir.path()));

        let failed = clone_over_with(&s, &foo, |_, _| Err(io::Error::other("no reflinks")), |_| {
            Err(io::Error::from_raw_os_error(libc::EPERM))
        });
        let Err(CloneFailed::TempLeft { tmp, .. }) = &failed else { panic!("{failed:?}") };
        assert!(failed.as_ref().unwrap_err().to_string().contains(&*tmp.to_string_lossy()));
        assert_eq!(temps(dir.path()).len(), 1);
        std::fs::remove_file(tmp).unwrap();

        // What a clone gives, as a copy, renamed over the file.
        clone_over_with(
            &s,
            &foo,
            |mut src, mut dst| io::copy(&mut src, &mut dst).map(drop),
            |t| std::fs::remove_file(t),
        )
        .unwrap();
        assert_eq!(std::fs::read(&foo).unwrap(), b"new contents");
        assert_eq!(std::fs::read(&victim).unwrap(), b"outside");
        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(temps(dir.path()), Vec::<String>::new());

        // The system's own clone: one that fails (no reflinks here) leaves
        // the file as it was.
        std::fs::write(&foo, b"old contents").unwrap();
        match clone_file(&src, &foo, 12) {
            Ok(()) => assert_eq!(std::fs::read(&foo).unwrap(), b"new contents"),
            Err(_) => assert_eq!(std::fs::read(&foo).unwrap(), b"old contents"),
        }
        assert_eq!(std::fs::read(&victim).unwrap(), b"outside");
        assert_eq!(temps(dir.path()), Vec::<String>::new());
    }

    /// D1, E2: breaking a hard link never touches an entry named
    /// `.bko-exact-NAME` (a symlink to a file outside, followed by the old
    /// fixed temporary name), and leaves the file as it is, with an error
    /// naming the temporary file, when that couldn't be removed.
    #[test]
    #[cfg(unix)]
    fn break_link_leaves_other_entries() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim");
        std::fs::write(&victim, b"outside").unwrap();
        let (foo, other) = (dir.path().join("foo"), outside.path().join("other"));
        std::fs::write(&foo, b"shared").unwrap();
        std::fs::hard_link(&foo, &other).unwrap();
        let link = dir.path().join(".bko-exact-foo");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let entry = dir.path().join(".bko-exact-bar");
        std::fs::write(&entry, b"a snapshot entry").unwrap();

        if CLONE_SUPPORTED {
            let left = break_link_with(&foo, |_, _| {
                Err(CloneFailed::TempLeft {
                    err: io::Error::other("no reflinks"),
                    tmp: dir.path().join(".bko-exact-1"),
                    remove: io::Error::from_raw_os_error(libc::EPERM),
                })
            });
            assert!(left.unwrap_err().to_string().contains(".bko-exact-1"));
            assert!(has_other_names(&foo), "the file is left as it is");
        }

        let cloned = break_link(&foo).unwrap();
        if cloned {
            assert_eq!(std::fs::read(&foo).unwrap(), b"shared");
            assert!(!has_other_names(&foo));
        } else {
            assert!(!foo.exists());
        }
        assert_eq!(std::fs::read(&other).unwrap(), b"shared");
        assert_eq!(std::fs::read(&victim).unwrap(), b"outside");
        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(std::fs::read(&entry).unwrap(), b"a snapshot entry");
        assert!(temps(dir.path()).iter().all(|n| n == ".bko-exact-bar"));
    }

    /// A file is never cloned onto itself, or onto another of its names:
    /// opening the destination empties it, and with it the source, and a
    /// file system that clones then clones nothing and succeeds (btrfs,
    /// XFS), leaving an empty file.
    #[test]
    #[cfg(unix)]
    fn clone_file_never_onto_its_source() {
        let dir = tempfile::tempdir().unwrap();
        let (f, g) = (dir.path().join("f"), dir.path().join("g"));
        std::fs::write(&f, b"snapshot 12345").unwrap();
        std::fs::hard_link(&f, &g).unwrap();
        for dst in [&f, &g] {
            assert!(
                matches!(clone_file(&f, dst, 14), Err(CloneFailed::Failed(_))),
                "{} isn't untouched",
                dst.display()
            );
            assert_eq!(std::fs::read(&f).unwrap(), b"snapshot 12345", "{}", dst.display());
        }
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
