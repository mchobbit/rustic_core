//! illumos: the ACLs ZFS keeps (NFSv4-style ACEs), the system attributes
//! (immutable, appendonly, nounlink, nodump, hidden, readonly, ...), which
//! are kept and restored as file flags, and the creation time (`crtime`),
//! kept as the birth time. Without its ACL a file comes back with its mode
//! alone, which loses named users and groups and, worse, deny entries:
//! access the ACL denied can come back allowed. Also the SIDs of owners and
//! ACL entries that are SIDs (`illumos_idmap.rs`), the owner, mode, times
//! and ACL of each extended attribute (`illumos_xattrmeta.rs`), and ZFS
//! project IDs (`illumos_project.rs`).
//!
//! libc's `fgetattr(3C)` and `fsetattr(3C)` read and write the system
//! attributes through each file's `SUNWattr_rw` extended attribute, a packed
//! nvlist; this does the same, without libnvpair, writing an nvlist of just
//! the attributes it sets (`illumos_sysattr.rs`).

use std::{
    collections::BTreeMap,
    ffi::{CStr, CString, OsString},
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};

use jiff::Timestamp;
use log::{debug, warn};

use super::{
    RestoreErrors, SidUnmapped, Unsupported, XattrErrors, c_path, check,
    illumos_acl::{self, AceEntry, NOBODY},
    illumos_idmap,
    illumos_project::ZfsProject,
    illumos_sysattr::{self, View},
    illumos_xattrmeta::XattrMeta,
    path_error, set_flags_best_effort, unix_time,
};
use crate::backend::node::{
    ExtendedAttribute, Node, NodeType,
    generic_attributes::{
        ILLUMOS_ACL, ILLUMOS_GROUP_SID, ILLUMOS_OWNER_SID, ILLUMOS_SYSTEM_ATTRIBUTES,
        ILLUMOS_XATTR_META, ILLUMOS_ZFS_PROJECT, UNIX_BIRTHTIME,
    },
};

pub(super) const FILE_FLAGS: Option<&str> = Some(ILLUMOS_SYSTEM_ATTRIBUTES);
pub(super) const FLAGS_BEFORE_DATA: u32 = 0;
pub(super) const FLAGS_BEFORE_ENTRIES: u32 = 0;
pub(super) const FLAGS_XATTRS: &[&str] = &[];
// ZFS keeps its DOS flags in the system attributes here.
pub(super) const ZFS_DOS_FLAGS: Option<&str> = None;

const ACE_GETACL: libc::c_int = 4;
const ACE_SETACL: libc::c_int = 5;
const ACE_GETACLCNT: libc::c_int = 6;
const O_XATTR: libc::c_int = 0x4000;

/// `ace_t` from `<sys/acl.h>`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawAce {
    who: u32,
    mask: u32,
    flags: u16,
    ace_type: u16,
}

unsafe extern "C" {
    fn acl(
        path: *const libc::c_char,
        cmd: libc::c_int,
        nentries: libc::c_int,
        aclbufp: *mut libc::c_void,
    ) -> libc::c_int;
    fn facl(
        fd: libc::c_int,
        cmd: libc::c_int,
        nentries: libc::c_int,
        aclbufp: *mut libc::c_void,
    ) -> libc::c_int;
}

/// What an ACL is read from or written to: the file at a path, with
/// `acl(2)`, which follows symlinks (they have no ACL of their own anyway),
/// or an open file, with `facl(2)`, which errors name by its path.
#[derive(Clone, Copy)]
enum AclOf<'a> {
    Path(&'a Path),
    File(&'a File, &'a Path),
}

impl<'a> AclOf<'a> {
    fn call(
        self,
        cmd: libc::c_int,
        n: libc::c_int,
        buf: *mut libc::c_void,
    ) -> io::Result<libc::c_int> {
        match self {
            Self::Path(path) => {
                let p = c_path(path)?;
                // SAFETY: p is a C string; buf is what cmd takes.
                check(unsafe { acl(p.as_ptr(), cmd, n, buf) })
            }
            // SAFETY: f is open; buf is what cmd takes.
            Self::File(f, _) => check(unsafe { facl(f.as_raw_fd(), cmd, n, buf) }),
        }
    }

    /// The call, for errors.
    const fn op(self) -> &'static str {
        match self {
            Self::Path(_) => "acl",
            Self::File(..) => "facl",
        }
    }

    /// The file, for errors.
    const fn path(self) -> &'a Path {
        match self {
            Self::Path(path) | Self::File(_, path) => path,
        }
    }
}

/// The ACEs of `of`. The errors are the system's, for the callers to tell
/// a file system without ACLs from a failure.
fn get_ace(of: AclOf<'_>) -> io::Result<Vec<AceEntry>> {
    // ACE_GETACLCNT takes no buffer.
    let n = of.call(ACE_GETACLCNT, 0, ptr::null_mut())?;
    if n <= 0 {
        return Ok(Vec::new());
    }
    let mut raw = vec![RawAce::default(); usize::try_from(n).unwrap_or_default()];
    // raw holds n ace_t.
    let n = of.call(ACE_GETACL, n, raw.as_mut_ptr().cast())?;
    raw.truncate(usize::try_from(n).unwrap_or_default());
    Ok(raw
        .iter()
        .map(|r| AceEntry {
            who: r.who,
            mask: r.mask,
            flags: r.flags,
            ace_type: r.ace_type,
            sid: None,
        })
        .collect())
}

fn set_ace(of: AclOf<'_>, entries: &[AceEntry]) -> io::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let mut raw: Vec<_> = entries
        .iter()
        .map(|e| RawAce {
            who: e.who,
            mask: e.mask,
            flags: e.flags,
            ace_type: e.ace_type,
        })
        .collect();
    let n = libc::c_int::try_from(raw.len()).map_err(io::Error::other)?;
    // raw holds n ace_t.
    _ = of
        .call(ACE_SETACL, n, raw.as_mut_ptr().cast())
        .map_err(|err| path_error(&format!("{} ACE_SETACL", of.op()), of.path(), &err))?;
    Ok(())
}

/// Errors that mean the file system or the user can't have this kind of
/// metadata, rather than that reading it failed.
fn unsupported(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::ENOSYS | libc::ENOTSUP | libc::EINVAL | libc::EPERM | libc::EACCES)
    )
}

/// Opens the `SUNWattr_rw` view of the file at `path`, a regular file or
/// directory; other types of file have no system attributes worth keeping,
/// and opening a device or FIFO could have side effects. The errors are the
/// system's, for the callers to tell a file system without the view (UFS,
/// tmpfs) from a failure.
fn sysattr_view(path: &Path, typ: &NodeType, write: bool) -> io::Result<File> {
    if !matches!(typ, NodeType::File | NodeType::Dir) {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let how = O_XATTR | libc::O_CLOEXEC | if write { libc::O_RDWR } else { libc::O_RDONLY };
    // SAFETY: the name is a C string.
    let fd = check(unsafe { libc::openat(f.as_raw_fd(), c"SUNWattr_rw".as_ptr(), how) })?;
    // SAFETY: fd is a new file descriptor, owned by nothing else.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// The whole of the view `f`, in one read: illumos packs the view afresh
/// for each read, from its start whatever the offset, so a second read gave
/// its start again (BackOtter's restic read a SID owner's 728-byte view
/// that way). `fstat(2)` gives the view's size; the read may get more.
fn read_view(f: &File, path: &Path) -> io::Result<Vec<u8>> {
    let size = f
        .metadata()
        .map_err(|err| path_error("fstat SUNWattr_rw", path, &err))?
        .len();
    let mut view = vec![0; usize::try_from(size).unwrap_or_default() + 4096];
    let n = f
        .read_at(&mut view, 0)
        .map_err(|err| path_error("read SUNWattr_rw", path, &err))?;
    view.truncate(n);
    Ok(view)
}

fn parse_view<'a>(buf: &'a [u8], path: &Path) -> io::Result<View<'a>> {
    View::parse(buf).map_err(|err| path_error("read SUNWattr_rw", path, &err))
}

/// Opens the `SUNWattr_rw` view of a regular file or directory, for its
/// system attributes and creation time. `None` for other types of file, and
/// on a file system without them.
pub(super) fn open_for_attrs(
    path: &Path,
    typ: &NodeType,
    _m: &std::fs::Metadata,
) -> Option<File> {
    if !matches!(typ, NodeType::File | NodeType::Dir) {
        return None;
    }
    sysattr_view(path, typ, false)
        .map_err(|err| debug!("no system attributes for {}: {err}", path.display()))
        .ok()
}

pub(super) fn file_flags(
    path: &Path,
    _typ: &NodeType,
    _m: &std::fs::Metadata,
    f: Option<&File>,
) -> io::Result<Option<u32>> {
    let Some(f) = f else {
        return Ok(None);
    };
    // A mask of 0 too: a file whose archive and av_modified were cleared.
    Ok(parse_view(&read_view(f, path)?, path)?.kept_mask())
}

/// Records the SIDs of an owner and group that are SIDs, the creation time
/// and a mask of 0, from the system attribute view, and of a regular file or
/// directory its ACL and ZFS project.
pub(super) fn fill_attributes(path: &Path, node: &mut Node, f: Option<&File>) -> io::Result<()> {
    let mut sids = SidNamer::default();
    sids.owner(node);
    let view = f.map_or(Ok(()), |f| {
        let buf = read_view(f, path)?;
        let view = parse_view(&buf, path)?;
        if let Some(crtime) = view.crtime() {
            node.meta.generic_attributes.set_timestamp(UNIX_BIRTHTIME, crtime);
        }
        Ok(())
    });
    let acl = fill_acl(path, node, &mut sids);
    fill_zfs_project(path, node);
    sids.report(path);
    acl.and(view)
}

fn fill_acl(path: &Path, node: &mut Node, sids: &mut SidNamer) -> io::Result<()> {
    if node.is_symlink() {
        return Ok(());
    }
    let mut entries = match get_ace(AclOf::Path(path)) {
        Ok(entries) => entries,
        Err(err) if unsupported(&err) => {
            debug!("no ACL for {}: {err}", path.display());
            return Ok(());
        }
        Err(err) => return Err(path_error("acl ACE_GETACL", path, &err)),
    };
    if entries.is_empty() || illumos_acl::is_trivial(&entries) {
        return Ok(());
    }
    sids.aces(&mut entries);
    node.meta
        .generic_attributes
        .set(ILLUMOS_ACL, &entries)
        .map_err(io::Error::other)
}

/// Finds the SIDs of a node's ephemeral ids, keeping idmap's first failure
/// for [`SidNamer::report`].
#[derive(Default)]
struct SidNamer(Option<io::Error>);

impl SidNamer {
    /// The SID of the ephemeral uid `id` (gid, if `group`), or `None` when
    /// idmap has none: idmapd isn't running, say, though then `stat(2)`
    /// already gives nobody (60001) for every ephemeral id, which can't be
    /// helped.
    fn sid(&mut self, id: u32, group: bool) -> Option<String> {
        match illumos_idmap::sid_of_id(id, group) {
            Ok(sid) => Some(sid),
            Err(err) => {
                _ = self.0.get_or_insert(err);
                None
            }
        }
    }

    /// Records the SIDs of `node`'s owner and group, where they are SIDs.
    fn owner(&mut self, node: &mut Node) {
        for (id, group, attr) in [
            (node.meta.uid, false, ILLUMOS_OWNER_SID),
            (node.meta.gid, true, ILLUMOS_GROUP_SID),
        ] {
            if let Some(id) = id.filter(|&id| id > illumos_acl::MAX_UID)
                && let Some(sid) = self.sid(id, group)
            {
                _ = node.meta.generic_attributes.set(attr, &sid);
            }
        }
    }

    /// Gives each of `entries` for a SID ([`illumos_acl::names_sid`]) that
    /// SID.
    fn aces(&mut self, entries: &mut [AceEntry]) {
        for e in entries.iter_mut().filter(|e| illumos_acl::names_sid(e)) {
            e.sid = self.sid(e.who, illumos_acl::is_group(e));
        }
    }

    /// Warns about idmap's failure for the file at `path`, the first time
    /// in the backup: the number alone is kept, which a restore after a
    /// reboot may give to another SID, or nobody.
    fn report(self, path: &Path) {
        static LOST: AtomicBool = AtomicBool::new(false);
        let Some(err) = self.0 else {
            return;
        };
        if LOST.swap(true, Ordering::Relaxed) {
            debug!("SIDs of {} not kept: {err}", path.display());
        } else {
            warn!("{}: idmap offline: SID owners not kept: {err}", path.display());
        }
    }
}

/// The id `sid` has here (a gid, if `group`), or nobody (60001) when idmap
/// can't map it, keeping a warning about the first such SID of the
/// attribute `attr` in `unmapped`. Not the number the backup saw: that may
/// be another SID's by now.
fn map_sid(attr: &'static str, sid: &str, group: bool, unmapped: &mut Option<io::Error>) -> u32 {
    illumos_idmap::id_of_sid(sid, group).unwrap_or_else(|err| {
        _ = unmapped.get_or_insert_with(|| SidUnmapped::error(attr, sid, err));
        NOBODY
    })
}

/// Gives each of `entries` that has a SID the id the SID has here (see
/// [`map_sid`]), and returns a warning about the first SID idmap couldn't
/// map, if any.
fn aces_with_ids(attr: &'static str, entries: &mut [AceEntry]) -> Option<io::Error> {
    let mut unmapped = None;
    for e in entries.iter_mut() {
        if let Some(sid) = &e.sid {
            e.who = map_sid(attr, sid, illumos_acl::is_group(e), &mut unmapped);
        }
    }
    unmapped
}

/// `zfsxattr`, the struct ZFS's project ioctls take on illumos. illumos has
/// no `FS_IOC_FSGETXATTR`; ZFS takes ioctls numbered as Linux's, `'X'` 31
/// and 32, but with this 8-byte struct, as `truss(1)` shows `zfs project`
/// calling `_IORN('X', 31, 8)`. Of the flags, ZFS reports and sets only
/// inheritance: an immutable or nodump file has `xflags` 0, and keeps both
/// when they are set to 0 (checked on OmniOS r151058).
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct ZfsXattr {
    xflags: u32,
    projid: u32,
}

const ZFS_IOC_FSGETXATTR: u32 = 0x4008_581f; // _IORN('X', 31, 8)
const ZFS_IOC_FSSETXATTR: u32 = 0x8008_5820; // _IOWN('X', 32, 8)

fn zfs_xattr(f: &File, request: u32, zx: &mut ZfsXattr) -> io::Result<()> {
    // SAFETY: both ioctls take a ZfsXattr.
    check(unsafe { libc::ioctl(f.as_raw_fd(), request.cast_signed(), ptr::from_mut(zx)) })
        .map(drop)
}

/// Opens the regular file or directory at `path`, of type `typ`, for its
/// project ioctls, as `lsattr(1)` opens files, so as not to follow a
/// symlink, wait on a lock or take a terminal. `None` for other types of
/// file, and if it isn't of type `typ`, or not the inode `ino` (at backup:
/// the lstat's).
fn open_for_project(path: &Path, typ: &NodeType, ino: Option<u64>) -> io::Result<Option<File>> {
    if !matches!(typ, NodeType::File | NodeType::Dir) {
        return Ok(None);
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?;
    let m = f.metadata()?;
    let same_type = if matches!(typ, NodeType::Dir) { m.is_dir() } else { m.is_file() };
    if !same_type || ino.is_some_and(|ino| ino != m.ino()) {
        return Ok(None);
    }
    Ok(Some(f))
}

/// Records the ZFS project of a regular file or directory, when it has one:
/// an ID or inheritance.
fn fill_zfs_project(path: &Path, node: &mut Node) {
    let f = match open_for_project(path, &node.node_type, Some(node.meta.inode)) {
        Ok(Some(f)) => f,
        Ok(None) => return,
        Err(err) => {
            debug!("no ZFS project for {}: {err}", path.display());
            return;
        }
    };
    let mut zx = ZfsXattr::default();
    if let Err(err) = zfs_xattr(&f, ZFS_IOC_FSGETXATTR, &mut zx) {
        // Not ZFS (ENOTTY).
        debug!("no ZFS project for {}: {err}", path.display());
        return;
    }
    if let Some(p) = ZfsProject::of(zx.xflags, zx.projid) {
        _ = node.meta.generic_attributes.set(ILLUMOS_ZFS_PROJECT, &p);
    }
}

/// Gives the regular file or directory at `path` its ZFS project: its own
/// ID and inheritance, whatever it got from the directory it was created
/// in. It goes before the file flags, as Linux's project ID does, though ZFS
/// gives an immutable file one all the same. A file system other than ZFS
/// gives an [`Unsupported`] error.
fn restore_zfs_project(path: &Path, node: &Node) -> io::Result<()> {
    let Some(p) = node.meta.generic_attributes.get::<ZfsProject>(ILLUMOS_ZFS_PROJECT) else {
        return Ok(());
    };
    let p = p.map_err(io::Error::other)?;
    let Some(f) = open_for_project(path, &node.node_type, None)? else {
        return Ok(());
    };
    let error = |op, err| {
        if super::unsupported(&err) {
            Unsupported::error(ILLUMOS_ZFS_PROJECT, 0, err)
        } else {
            path_error(op, path, &err)
        }
    };
    let mut zx = ZfsXattr::default();
    zfs_xattr(&f, ZFS_IOC_FSGETXATTR, &mut zx).map_err(|err| error("ioctl get ZFS project", err))?;
    let mut want = ZfsXattr {
        xflags: p.xflags(zx.xflags),
        projid: p.id,
    };
    if want == zx {
        return Ok(());
    }
    zfs_xattr(&f, ZFS_IOC_FSSETXATTR, &mut want).map_err(|err| error("ioctl set ZFS project", err))
}

pub(super) fn prepare_file_for_flags(_path: &Path, _flags: u32) -> io::Result<()> {
    Ok(())
}

pub(super) fn prepare_dir_for_flags(_path: &Path, _flags: u32) -> io::Result<()> {
    Ok(())
}

/// Sets the system attributes the view has to those in `flags`, writing
/// their booleans alone: the whole view would set the creation time too,
/// which an immutable file refuses. Each write names every boolean, so as
/// not the owner, where one of them only root may set, the others are set
/// and cleared one at a time from what the file has
/// ([`set_flags_best_effort`]): `av_modified`, which the owner may set but
/// not clear, stays as it is meanwhile (naming it unchanged is allowed).
pub(super) fn restore_file_flags(
    path: &Path,
    typ: &NodeType,
    flags: u32,
    _xattrs: &[ExtendedAttribute],
) -> io::Result<()> {
    let f = sysattr_view(path, typ, true).map_err(|err| path_error("open SUNWattr_rw", path, &err))?;
    let buf = read_view(&f, path)?;
    let view = parse_view(&buf, path)?;
    set_flags_best_effort(
        ILLUMOS_SYSTEM_ATTRIBUTES,
        path,
        "write SUNWattr_rw",
        Some(view.mask()),
        flags,
        |mask| f.write_all_at(&view.mask_nvlist(mask), 0),
    )
}

pub(super) fn restore_zfs_dos_flags(_path: &Path, _typ: &NodeType, _flags: u64) -> io::Result<()> {
    Ok(())
}

/// Gives the file at `path` the owner and group its SIDs have here, after
/// the restore has given it its numbers, which may now be another SID's or
/// none (nobody). A SID idmap can't map gives nobody (60001), with a
/// [`SidUnmapped`] error: not the number, which may belong to another SID.
/// The owner and the group unmapped both give both errors
/// ([`RestoreErrors`]), a warning for each attribute.
pub(super) fn restore_owner(path: &Path, node: &Node) -> io::Result<()> {
    let id = |attr: &'static str, group, unmapped: &mut Option<io::Error>| {
        node.meta
            .generic_attributes
            .get::<String>(attr)
            .transpose()
            .map(|sid| sid.map(|sid| map_sid(attr, &sid, group, unmapped)))
            .map_err(io::Error::other)
    };
    let (mut owner_unmapped, mut group_unmapped) = (None, None);
    let uid = id(ILLUMOS_OWNER_SID, false, &mut owner_unmapped)?;
    let gid = id(ILLUMOS_GROUP_SID, true, &mut group_unmapped)?;
    if uid.is_none() && gid.is_none() {
        return Ok(());
    }
    let p = c_path(path)?;
    // SAFETY: p is a C string; an id of -1 is left as it is.
    _ = check(unsafe { libc::lchown(p.as_ptr(), uid.unwrap_or(u32::MAX), gid.unwrap_or(u32::MAX)) })
        .map_err(|err| path_error("lchown", path, &err))?;
    RestoreErrors::result(owner_unmapped.into_iter().chain(group_unmapped).collect())
}

/// Restores the metadata of the extended attributes, whose values are
/// restored by now, and the ZFS project.
pub(super) fn restore_attributes(path: &Path, node: &Node) -> io::Result<()> {
    let xattr_meta = restore_xattr_meta(path, node);
    restore_zfs_project(path, node).and(xattr_meta)
}

/// Restores the ACL, after the mode, since `chmod(2)` rewrites a ZFS ACL,
/// with the ids its SIDs have here. A SID idmap can't map gives nobody
/// (60001), with a [`SidUnmapped`] error.
pub(super) fn restore_acls(path: &Path, node: &Node) -> io::Result<()> {
    if node.is_symlink() {
        return Ok(());
    }
    let Some(entries) = node.meta.generic_attributes.get::<Vec<AceEntry>>(ILLUMOS_ACL) else {
        return Ok(());
    };
    let mut entries = entries.map_err(io::Error::other)?;
    let unmapped = aces_with_ids(ILLUMOS_ACL, &mut entries);
    set_ace(AclOf::Path(path), &entries)?;
    unmapped.map_or(Ok(()), Err)
}

/// A symlink's own permissions don't matter on illumos.
pub(super) fn restore_symlink_mode(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

/// Sets the birth time, ZFS's `crtime`, of a regular file or directory,
/// which can be any time: an nvlist of `crtime` alone, written to its
/// `SUNWattr_rw` view, sets it and leaves everything else. This goes before
/// the system attributes, since an immutable file refuses it. Symlinks have
/// no view of their own (it is their target's), the other types none, and
/// neither has UFS or tmpfs.
pub(super) fn restore_birthtime(path: &Path, node: &Node, birth: Timestamp) -> io::Result<()> {
    let f = match sysattr_view(path, &node.node_type, true) {
        Ok(f) => f,
        Err(err)
            if err.kind() == io::ErrorKind::Unsupported
                || matches!(
                    err.raw_os_error(),
                    Some(libc::ENOENT | libc::EINVAL | libc::ENOTSUP | libc::EOPNOTSUPP)
                ) =>
        {
            return Err(io::Error::new(io::ErrorKind::Unsupported, err));
        }
        Err(err) => return Err(path_error("open SUNWattr_rw", path, &err)),
    };
    f.write_all_at(&illumos_sysattr::crtime_nvlist(birth), 0)
        .map_err(|err| path_error("write SUNWattr_rw crtime", path, &err))
}

/// The system attribute views in every attribute directory, which aren't
/// extended attributes of their own.
const SYSTEM_VIEWS: [&str; 2] = ["SUNWattr_ro", "SUNWattr_rw"];

/// Opens the attribute directory of the file at `path`, a regular file or
/// directory. `None` for other types of file, which have none worth keeping
/// (and opening a device could have side effects), and on a file system
/// without them.
fn attr_dir(path: &Path) -> io::Result<Option<File>> {
    let m = std::fs::symlink_metadata(path)?;
    if !(m.is_file() || m.is_dir()) {
        return Ok(None);
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let how = O_XATTR | libc::O_RDONLY | libc::O_CLOEXEC;
    // SAFETY: "." is a C string.
    match check(unsafe { libc::openat(f.as_raw_fd(), c".".as_ptr(), how) }) {
        // SAFETY: fd is a new file descriptor, owned by nothing else.
        Ok(fd) => Ok(Some(unsafe { File::from_raw_fd(fd) })),
        Err(err) if matches!(err.raw_os_error(), Some(libc::EINVAL | libc::ENOTSUP)) => Ok(None),
        Err(err) => Err(err),
    }
}

/// The names in an attribute directory, without the system attribute views,
/// sorted, as BackOtter's restic stores them (not in directory order).
fn attr_names(dir: &File) -> io::Result<Vec<String>> {
    // fdopendir(3C) takes over the descriptor it's given: give it its own.
    // SAFETY: dir is an open descriptor.
    let fd = check(unsafe { libc::dup(dir.as_raw_fd()) })?;
    // SAFETY: fd is an open directory descriptor.
    let d = unsafe { libc::fdopendir(fd) };
    if d.is_null() {
        let err = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so fd is still ours.
        _ = unsafe { libc::close(fd) };
        return Err(err);
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: d is an open DIR.
        let e = unsafe { libc::readdir(d) };
        if e.is_null() {
            break;
        }
        // SAFETY: d_name is a C string, valid until the next readdir.
        let name = unsafe { CStr::from_ptr((*e).d_name.as_ptr()) }.to_string_lossy();
        if name != "." && name != ".." && !SYSTEM_VIEWS.contains(&&*name) {
            names.push(name.into_owned());
        }
    }
    // SAFETY: d is an open DIR, closed once.
    _ = unsafe { libc::closedir(d) };
    names.sort_unstable();
    Ok(names)
}

/// Opens the extended attribute `name` in `dir`, an attribute directory. A
/// new one is created with mode 0600, so that it is never readable by
/// others before its own mode is restored ([`restore_attributes`]).
fn open_attr(dir: &File, name: &str, how: libc::c_int) -> io::Result<File> {
    let n = CString::new(name)?;
    let mode: libc::c_uint = 0o600;
    // SAFETY: n is a C string.
    let fd = check(unsafe { libc::openat(dir.as_raw_fd(), n.as_ptr(), how | libc::O_CLOEXEC, mode) })?;
    // SAFETY: fd is a new file descriptor, owned by nothing else.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// The extended attributes of the file at `path`: on illumos, named
/// attribute files (`runat(1)`, `fsattr(5)`), which the xattr crate doesn't
/// support.
pub(super) fn xattrs(path: &Path) -> io::Result<Vec<ExtendedAttribute>> {
    let Some(dir) = attr_dir(path)? else {
        return Ok(Vec::new());
    };
    attr_names(&dir)?
        .into_iter()
        .map(|name| {
            let mut value = Vec::new();
            _ = open_attr(&dir, &name, libc::O_RDONLY)?.read_to_end(&mut value)?;
            Ok(ExtendedAttribute {
                name,
                value: Some(value),
            })
        })
        .collect()
}

/// Gives the file at `path` exactly the extended attributes `attrs`. One
/// that can't be set or removed doesn't keep the others from being set or
/// removed, as in BackOtter's restic: each failure is returned, by name.
pub(super) fn set_xattrs(path: &Path, attrs: &[ExtendedAttribute]) -> Result<(), XattrErrors> {
    let Some(dir) = attr_dir(path)? else {
        // Each one named, as those that can't be set are.
        let mut errors = XattrErrors::default();
        for attr in attrs {
            errors.push(
                attr.name.as_str(),
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "no extended attributes on this file system",
                ),
            );
        }
        return errors.into_result();
    };
    let mut errors = XattrErrors::default();
    match attr_names(&dir) {
        Ok(names) => {
            for name in names {
                if !attrs.iter().any(|a| a.name == name) {
                    let n = CString::new(name.as_str()).map_err(io::Error::from);
                    // SAFETY: n is a C string.
                    let removed = n.and_then(|n| {
                        check(unsafe { libc::unlinkat(dir.as_raw_fd(), n.as_ptr(), 0) })
                    });
                    if let Err(err) = removed {
                        errors.push(format!("removing {name}"), err);
                    }
                }
            }
        }
        Err(err) => errors.push("listing", err),
    }
    for a in attrs {
        let set = open_attr(&dir, &a.name, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC)
            .and_then(|mut f| f.write_all(a.value.as_deref().unwrap_or_default()));
        if let Err(err) = set {
            errors.push(a.name.as_str(), err);
        }
    }
    errors.into_result()
}

/// How errors name the extended attribute `name` of the file at `path`.
fn attr_path(path: &Path, name: &str) -> PathBuf {
    let mut p = OsString::from(path);
    p.push("/@");
    p.push(name);
    p.into()
}

/// Records the owner, group, mode, times and ACL of each extended attribute
/// of the file at `path`, a regular file or directory. An attribute that
/// can't be read is left out, as its value is; an ACL that can't be read
/// too.
pub(super) fn fill_xattr_meta(path: &Path, node: &mut Node) {
    let dir = match attr_dir(path) {
        Ok(Some(dir)) => dir,
        Ok(None) => return,
        Err(err) => {
            debug!("no extended attributes for {}: {err}", path.display());
            return;
        }
    };
    let names = match attr_names(&dir) {
        Ok(names) => names,
        Err(err) => {
            debug!("no extended attributes for {}: {err}", path.display());
            return;
        }
    };
    let mut sids = SidNamer::default();
    let metas: BTreeMap<_, _> = names
        .into_iter()
        .filter_map(|name| read_xattr_meta(&dir, path, &name, &mut sids).map(|meta| (name, meta)))
        .collect();
    if !metas.is_empty() {
        _ = node.meta.generic_attributes.set(ILLUMOS_XATTR_META, &metas);
    }
    sids.report(path);
}

/// The metadata of the attribute `name` in `dir`, the attribute directory
/// of `path`, if it can be read.
fn read_xattr_meta(dir: &File, path: &Path, name: &str, sids: &mut SidNamer) -> Option<XattrMeta> {
    let at = attr_path(path, name);
    let n = CString::new(name).ok()?;
    let mut st = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: n is a C string, st a stat buffer.
    let r = unsafe {
        libc::fstatat(dir.as_raw_fd(), n.as_ptr(), st.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW)
    };
    if let Err(err) = check(r) {
        debug!("fstatat {}: {err}", at.display());
        return None;
    }
    // SAFETY: fstatat filled it in.
    let st = unsafe { st.assume_init() };
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return None;
    }
    let time = |sec, nsec| Timestamp::new(sec, i32::try_from(nsec).ok()?).ok();
    let mut meta = XattrMeta {
        uid: st.st_uid,
        gid: st.st_gid,
        mode: st.st_mode & 0o7777,
        mtime: time(st.st_mtime, st.st_mtime_nsec)?,
        atime: time(st.st_atime, st.st_atime_nsec)?,
        acl: Vec::new(),
    };
    match open_attr(dir, name, libc::O_RDONLY | libc::O_NONBLOCK)
        .and_then(|f| get_ace(AclOf::File(&f, &at)))
    {
        Ok(mut entries) if !entries.is_empty() && !illumos_acl::is_trivial(&entries) => {
            sids.aces(&mut entries);
            meta.acl = entries;
        }
        Ok(_) => {}
        Err(err) => debug!("no ACL for {}: {err}", at.display()),
    }
    Some(meta)
}

/// Gives the extended attributes of the file at `path`, restored by now,
/// their metadata. One `node` has no value for (none was kept, or the
/// restore left it out) is left alone, as is a file system without them.
/// Each attribute's are tried even when another's failed; the error is the
/// first failure, or a [`SidUnmapped`] one about an ACL entry.
fn restore_xattr_meta(path: &Path, node: &Node) -> io::Result<()> {
    let Some(metas) = node
        .meta
        .generic_attributes
        .get::<BTreeMap<String, XattrMeta>>(ILLUMOS_XATTR_META)
    else {
        return Ok(());
    };
    let metas = metas.map_err(io::Error::other)?;
    let Some(dir) = attr_dir(path)? else {
        return Ok(());
    };
    let (mut failed, mut unmapped) = (None, None);
    for (name, meta) in &metas {
        if !node.meta.extended_attributes.iter().any(|a| a.name == *name) {
            continue;
        }
        if let Err(err) = restore_one_xattr_meta(&dir, path, name, meta, &mut unmapped) {
            _ = failed.get_or_insert(err);
        }
    }
    failed.or(unmapped).map_or(Ok(()), Err)
}

/// Gives the attribute `name` in `dir`, the attribute directory of `path`,
/// the metadata `meta`: owner, mode, ACL (after the mode, which rewrites
/// it), then the times, last, as for the file itself. Each is tried even
/// when one before it failed; the error is the first. A warning about a SID
/// in the ACL that idmap couldn't map goes to `unmapped`.
fn restore_one_xattr_meta(
    dir: &File,
    path: &Path,
    name: &str,
    meta: &XattrMeta,
    unmapped: &mut Option<io::Error>,
) -> io::Result<()> {
    let at = attr_path(path, name);
    let n = CString::new(name)?;
    let fd = dir.as_raw_fd();
    // SAFETY: n is a C string.
    let owner = match check(unsafe { libc::fchownat(fd, n.as_ptr(), meta.uid, meta.gid, 0) }) {
        Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
            debug!("{} not restored: {err}", at.display());
            return Ok(());
        }
        r => r.map(drop).map_err(|err| path_error("fchownat", &at, &err)),
    };
    // SAFETY: n is a C string.
    let mode = check(unsafe { libc::fchmodat(fd, n.as_ptr(), meta.mode & 0o7777, 0) })
        .map(drop)
        .map_err(|err| path_error("fchmodat", &at, &err));
    let acl = if meta.acl.is_empty() {
        Ok(())
    } else {
        let mut entries = meta.acl.clone();
        if let Some(err) = aces_with_ids(ILLUMOS_XATTR_META, &mut entries) {
            _ = unmapped.get_or_insert(err);
        }
        open_attr(dir, name, libc::O_RDONLY | libc::O_NONBLOCK)
            .map_err(|err| path_error("openat", &at, &err))
            .and_then(|f| set_ace(AclOf::File(&f, &at), &entries))
    };
    let timespec = |t| {
        let (sec, nsec) = unix_time(t);
        libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec.into(),
        }
    };
    let times = [timespec(meta.atime), timespec(meta.mtime)];
    // SAFETY: n is a C string, times two timespecs.
    let times = check(unsafe { libc::utimensat(fd, n.as_ptr(), times.as_ptr(), 0) })
        .map(drop)
        .map_err(|err| path_error("utimensat", &at, &err));
    owner.and(mode).and(acl).and(times)
}
