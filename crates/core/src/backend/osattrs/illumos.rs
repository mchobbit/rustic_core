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
    NATIVE_XATTR_MAX, RestoreErrors, SidUnmapped, Unsupported, XattrErrors, XattrsRead,
    acl_set_error, c_path, check,
    illumos_acl::{self, AceEntry, NOBODY},
    illumos_idmap,
    illumos_project::ZfsProject,
    illumos_sysattr::{self, View},
    illumos_xattrmeta::{SYSTEM_VIEWS, XattrMeta, attr_name_refused, restored_owner},
    is_root, path_error, permission_refused, set_flags_best_effort, unix_time, xattr_too_large,
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
    /// Opens the attribute directory of the file `name` (relative to `fd`)
    /// without opening the file itself: libc's own, which `getattrat(3C)`
    /// and `setattrat(3C)`, and so `ls -/` and `chmod S`, use (exported, but
    /// no public name). It follows a symlink.
    #[link_name = "__openattrdirat"]
    fn openattrdirat(fd: libc::c_int, name: *const libc::c_char) -> libc::c_int;
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
        .map_err(|err| {
            acl_set_error(
                path_error(&format!("{} ACE_SETACL", of.op()), of.path(), &err),
                &err,
            )
        })?;
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
///
/// A regular file illumos quarantined (`av_quarantined`) can't be opened,
/// by root either (`EACCES`), but its attribute directory can, without
/// opening the file, as `getattrat(3C)` and `ls -/ v` open it
/// (`__openattrdirat`): its view is opened through that.
fn sysattr_view(path: &Path, typ: &NodeType, write: bool) -> io::Result<File> {
    if !matches!(typ, NodeType::File | NodeType::Dir) {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }
    let rw = if write { libc::O_RDWR } else { libc::O_RDONLY };
    // The view in the file's attribute directory (O_XATTR), or in that
    // directory itself when the file can't be opened.
    let (base, how) = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => (f, O_XATTR | libc::O_CLOEXEC | rw),
        Err(err) if matches!(typ, NodeType::File) && err.raw_os_error() == Some(libc::EACCES) => {
            (attr_dir_unopened(path).map_err(|_| err)?, libc::O_CLOEXEC | rw)
        }
        Err(err) => return Err(err),
    };
    // SAFETY: the name is a C string.
    let fd = check(unsafe { libc::openat(base.as_raw_fd(), c"SUNWattr_rw".as_ptr(), how) })?;
    // SAFETY: fd is a new file descriptor, owned by nothing else.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// The attribute directory of the file at `path`, opened without opening
/// the file, for the system attribute view of one that can't be opened.
fn attr_dir_unopened(path: &Path) -> io::Result<File> {
    let p = c_path(path)?;
    // SAFETY: p is a C string.
    let fd = check(unsafe { openattrdirat(libc::AT_FDCWD, p.as_ptr()) })?;
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

/// No flags keep a restore from changing a file here that it clears
/// (illumos' immutable, appendonly and nounlink system attributes are left
/// as they are: see BACKOTTER.md).
pub(super) fn clear_restricting_flags(_path: &Path) -> io::Result<()> {
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
/// restored by now, and the ZFS project. `owners`: the restore sets owners
/// (not `--no-ownership`), so the attributes get theirs too.
pub(super) fn restore_attributes(path: &Path, node: &Node, owners: bool) -> io::Result<()> {
    let xattr_meta = restore_xattr_meta(path, node, owners);
    restore_zfs_project(path, node).and(xattr_meta)
}

/// Gives `of`, which has no ACL to restore, the trivial ACL of `mode` (a
/// directory's, if `dir`), unless the one it has is trivial already: what
/// `acl_strip(3SEC)` does. `chmod(2)` can't be left to do it: under ZFS's
/// `aclmode=passthrough` or `groupmask` it keeps the named and deny entries
/// of a file found at the destination, and those a new file inherited from
/// its directory, and under `restricted` it fails. Setting an ACL sets the
/// mode's permission bits to what it says, which are `mode`'s, and leaves
/// the setuid, setgid and sticky bits. A file system without NFSv4 ACLs
/// (UFS, tmpfs) is left alone.
fn strip_acl(of: AclOf<'_>, mode: u32, dir: bool) -> io::Result<()> {
    let entries = match get_ace(of) {
        Ok(entries) => entries,
        Err(err) if unsupported(&err) => {
            debug!("no ACL for {}: {err}", of.path().display());
            return Ok(());
        }
        Err(err) => {
            return Err(path_error(&format!("{} ACE_GETACL", of.op()), of.path(), &err));
        }
    };
    if entries.is_empty() || illumos_acl::is_trivial(&entries) {
        return Ok(());
    }
    set_ace(of, &illumos_acl::trivial(mode, dir))
}

/// Restores the ACL, after the mode, since `chmod(2)` rewrites a ZFS ACL,
/// with the ids its SIDs have here. A SID idmap can't map gives nobody
/// (60001), with a [`SidUnmapped`] error.
///
/// A node without an ACL had a trivial one in a snapshot of BackOtter's
/// (`known_bko`), which records every other: the file then gets the trivial
/// ACL of its mode, where it has another ([`strip_acl`]). In any other
/// snapshot the ACL is unknown, and the file keeps the one it has.
pub(super) fn restore_acls(path: &Path, node: &Node, known_bko: bool) -> io::Result<()> {
    if node.is_symlink() {
        return Ok(());
    }
    let Some(entries) = node.meta.generic_attributes.get::<Vec<AceEntry>>(ILLUMOS_ACL) else {
        if !known_bko {
            return Ok(());
        }
        // The node's mode, which the restore has just set; the file's own
        // where the node has none.
        let mode = match node.meta.mode {
            Some(mode) => mode,
            None => std::fs::symlink_metadata(path)
                .map_err(|err| path_error("lstat", path, &err))?
                .mode(),
        };
        return strip_acl(AclOf::Path(path), mode, node.is_dir());
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
/// UFS has none; tmpfs has one, but refuses a `crtime`.
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
    // BackOtter: tmpfs has the view, but refuses a crtime (EINVAL): it keeps
    // none it can be given, as UFS, which has no view; no error, nor a
    // warning, as in BackOtter's restic.
    match f.write_all_at(&illumos_sysattr::crtime_nvlist(birth), 0) {
        Err(err) if birthtime_unsupported(&err) => {
            Err(io::Error::new(io::ErrorKind::Unsupported, err))
        }
        result => result.map_err(|err| path_error("write SUNWattr_rw crtime", path, &err)),
    }
}

/// Whether `err`, from writing a `crtime` to a file's `SUNWattr_rw` view,
/// says its file system keeps none it can be given (tmpfs: `EINVAL`).
fn birthtime_unsupported(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EINVAL | libc::ENOTSUP | libc::EOPNOTSUPP | libc::ENOSYS)
    )
}

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

/// Sets errno, which `readdir(3C)` sets only on an error.
fn set_errno(errno: libc::c_int) {
    // SAFETY: ___errno gives this thread's errno.
    unsafe { *libc::___errno() = errno };
}

/// One step of a `readdir(3C)` loop: what `read` gives, `None` at the end of
/// the directory. `readdir` returns NULL at the end and on an error, and
/// only errno tells them apart, so it is cleared before the call: an error
/// partway is an error, not a short listing.
fn readdir_step<T>(read: impl FnOnce() -> Option<T>) -> io::Result<Option<T>> {
    set_errno(0);
    read().map_or_else(
        || match io::Error::last_os_error() {
            err if err.raw_os_error() == Some(0) => Ok(None),
            err => Err(err),
        },
        |entry| Ok(Some(entry)),
    )
}

/// The names in an attribute directory, without the system attribute views,
/// sorted, as BackOtter's restic stores them (not in directory order): as
/// their bytes, by which an attribute is opened and removed whatever they
/// are. A node holds a name as UTF-8 ([`node_name`]).
fn attr_names(dir: &File) -> io::Result<Vec<CString>> {
    // fdopendir(3C) takes over the descriptor it's given: give it its own.
    // SAFETY: dir is an open descriptor.
    let fd = check(unsafe { libc::dup(dir.as_raw_fd()) })?;
    // The duplicate shares dir's offset: back to the start, wherever an
    // earlier listing of dir left it (the end). Before fdopendir(3C), not
    // rewinddir(3C) after it, which on illumos looks at the new DIR's
    // still empty buffer for where it is, and may not seek at all.
    // SAFETY: fd is an open descriptor.
    _ = unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    // SAFETY: fd is an open directory descriptor.
    let d = unsafe { libc::fdopendir(fd) };
    if d.is_null() {
        let err = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so fd is still ours.
        _ = unsafe { libc::close(fd) };
        return Err(err);
    }
    let mut names = Vec::new();
    let result = loop {
        let step = readdir_step(|| {
            // SAFETY: d is an open DIR.
            let e = unsafe { libc::readdir(d) };
            (!e.is_null()).then_some(e)
        });
        let e = match step {
            Ok(Some(e)) => e,
            Ok(None) => break Ok(()),
            Err(err) => break Err(err),
        };
        // SAFETY: e is the entry readdir just gave, valid until the next
        // readdir. libc declares d_name with 3 bytes, so the name is read
        // through a pointer taken from e itself, never a reference to that
        // array, which a longer name would read past.
        let name_ptr = unsafe { &raw const (*e).d_name }.cast();
        // SAFETY: d_name is a C string the kernel NUL-terminated inside the
        // record, which is valid until the next readdir.
        let name = unsafe { CStr::from_ptr(name_ptr) };
        let bytes = name.to_bytes();
        if bytes != b"." && bytes != b".." && !SYSTEM_VIEWS.iter().any(|v| v.as_bytes() == bytes) {
            names.push(name.to_owned());
        }
    };
    // SAFETY: d is an open DIR, closed once.
    _ = unsafe { libc::closedir(d) };
    result?;
    names.sort_unstable();
    Ok(names)
}

/// The name a node holds for the attribute `name`: itself, with U+FFFD for
/// what isn't UTF-8, as on every other system and as BackOtter's restic's
/// JSON keeps it.
fn node_name(name: &CStr) -> String {
    name.to_string_lossy().into_owned()
}

/// Opens the extended attribute `name` in `dir`, an attribute directory. A
/// new one is created with mode 0600, so that it is never readable by
/// others before its own mode is restored ([`restore_attributes`]).
fn open_attr(dir: &File, name: &CStr, how: libc::c_int) -> io::Result<File> {
    let mode: libc::c_uint = 0o600;
    // SAFETY: name is a C string.
    let fd = check(unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), how | libc::O_CLOEXEC, mode) })?;
    // SAFETY: fd is a new file descriptor, owned by nothing else.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// The extended attributes of the file at `path`: on illumos, named
/// attribute files (`runat(1)`, `fsattr(5)`), which the xattr crate doesn't
/// support. One whose value can't be read is left out and named in
/// `unreadable`, and the others are kept, as BackOtter's restic does. One
/// whose name isn't UTF-8 is read by its bytes and kept under its name with
/// U+FFFD for what isn't ([`node_name`]).
///
/// # Errors
///
/// * If the attribute directory couldn't be opened or listed.
pub(super) fn xattrs_read(path: &Path) -> io::Result<XattrsRead> {
    let mut read = XattrsRead::default();
    let Some(dir) = attr_dir(path)? else {
        return Ok(read);
    };
    for name in attr_names(&dir)? {
        match attr_value(&dir, &name) {
            Ok(value) => read.attrs.push(ExtendedAttribute {
                name: node_name(&name),
                value: Some(value),
            }),
            Err(err) => read.unreadable.push((node_name(&name), err)),
        }
    }
    Ok(read)
}

/// The value of the extended attribute `name` in `dir`, an attribute
/// directory. An attribute is a file of any size: one over
/// [`NATIVE_XATTR_MAX`] is an error ([`xattr_too_large`]), by its size
/// before any of it is read, or once it has grown past that as it is read.
fn attr_value(dir: &File, name: &CStr) -> io::Result<Vec<u8>> {
    let f = open_attr(dir, name, libc::O_RDONLY)?;
    let size = f.metadata()?.len();
    if size > NATIVE_XATTR_MAX {
        return Err(xattr_too_large(size));
    }
    let mut value = Vec::new();
    _ = f.take(NATIVE_XATTR_MAX + 1).read_to_end(&mut value)?;
    let read = value.len() as u64;
    if read > NATIVE_XATTR_MAX {
        return Err(xattr_too_large(read));
    }
    Ok(value)
}

/// Whether the extended attribute `name` in `dir`, an attribute directory,
/// has the value `want`: false where it can't be read. Only one of the
/// same size is read.
fn attr_has_value(dir: &File, name: &CStr, want: &[u8]) -> bool {
    open_attr(dir, name, libc::O_RDONLY).is_ok_and(|mut f| {
        let mut value = Vec::with_capacity(want.len());
        f.metadata().is_ok_and(|m| m.len() == want.len() as u64)
            && f.read_to_end(&mut value).is_ok()
            && value == want
    })
}

/// Gives the file at `path` exactly the extended attributes `attrs`. One
/// that can't be set or removed doesn't keep the others from being set or
/// removed, as in BackOtter's restic: each failure is returned, by name.
/// One the file has already, with its node's value, is left as it is, as on
/// every other system and in BackOtter's restic; one that can't be read is
/// written. One whose name isn't an attribute file's, such as `..`, is
/// refused ([`attr_name_refused`]). One the file has that `attrs` hasn't is
/// removed by its name's bytes, so one whose name isn't UTF-8 goes too (a
/// node holds no such name).
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
    let present = match attr_names(&dir) {
        Ok(names) => {
            for name in &names {
                if !attrs.iter().any(|a| a.name.as_bytes() == name.to_bytes()) {
                    // SAFETY: name is a C string.
                    let removed = check(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) });
                    if let Err(err) = removed {
                        errors.push(format!("removing {}", node_name(name)), err);
                    }
                }
            }
            names
        }
        Err(err) => {
            errors.push("listing", err);
            Vec::new()
        }
    };
    for a in attrs {
        // Never a path out of the attribute directory.
        if let Some(err) = attr_name_refused(&a.name) {
            errors.push(a.name.as_str(), err);
            continue;
        }
        // No NUL in it: it wasn't refused.
        let name = match CString::new(a.name.as_str()) {
            Ok(name) => name,
            Err(err) => {
                errors.push(a.name.as_str(), err.into());
                continue;
            }
        };
        let value = a.value.as_deref().unwrap_or_default();
        if present.contains(&name) && attr_has_value(&dir, &name, value) {
            continue;
        }
        let set = open_attr(&dir, &name, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC)
            .and_then(|mut f| f.write_all(value));
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
        .iter()
        .filter_map(|name| {
            read_xattr_meta(&dir, path, name, &mut sids).map(|meta| (node_name(name), meta))
        })
        .collect();
    if !metas.is_empty() {
        _ = node.meta.generic_attributes.set(ILLUMOS_XATTR_META, &metas);
    }
    sids.report(path);
}

/// The metadata of the attribute `name` in `dir`, the attribute directory
/// of `path`, if it can be read.
fn read_xattr_meta(dir: &File, path: &Path, name: &CStr, sids: &mut SidNamer) -> Option<XattrMeta> {
    let at = attr_path(path, &node_name(name));
    let mut st = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: name is a C string, st a stat buffer.
    let r = unsafe {
        libc::fstatat(dir.as_raw_fd(), name.as_ptr(), st.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW)
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
    // An owner or group that is a SID, as the file's own
    // ([`SidNamer::owner`]).
    let mut sid = |id: u32, group| (id > illumos_acl::MAX_UID).then(|| sids.sid(id, group)).flatten();
    let (owner_sid, group_sid) = (sid(st.st_uid, false), sid(st.st_gid, true));
    let mut meta = XattrMeta {
        uid: st.st_uid,
        gid: st.st_gid,
        owner_sid,
        group_sid,
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
///
/// Its owner and group only with `owners`, as the file's own: not under
/// `--no-ownership`, and one that was its file's owner's or group's follows
/// the file to the owner or group the restore gave it, by name or as a
/// SID's id here ([`restored_owner`]). One that is a SID itself gets the id
/// the SID has here, or nobody (60001) and a [`SidUnmapped`] error when
/// idmap can't map it, as the file's own ([`restore_owner`]).
fn restore_xattr_meta(path: &Path, node: &Node, owners: bool) -> io::Result<()> {
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
    // The owner and group the restore gave the file itself.
    let file_now = if owners {
        let m = std::fs::symlink_metadata(path).map_err(|err| path_error("lstat", path, &err))?;
        Some((m.uid(), m.gid()))
    } else {
        None
    };
    let (mut failed, mut unmapped) = (None, None);
    for (name, meta) in &metas {
        if !node.meta.extended_attributes.iter().any(|a| a.name == *name) {
            continue;
        }
        let owner = file_now.map(|now| {
            let (mut uid, mut gid) = restored_owner(meta, (node.meta.uid, node.meta.gid), now);
            // An owner or group that is a SID: the id it has here, not the
            // backup's number ([`map_sid`]).
            if let Some(sid) = &meta.owner_sid {
                uid = map_sid(ILLUMOS_XATTR_META, sid, false, &mut unmapped);
            }
            if let Some(sid) = &meta.group_sid {
                gid = map_sid(ILLUMOS_XATTR_META, sid, true, &mut unmapped);
            }
            (uid, gid)
        });
        if let Err(err) = restore_one_xattr_meta(&dir, path, name, meta, owner, &mut unmapped) {
            _ = failed.get_or_insert(err);
        }
    }
    failed.or(unmapped).map_or(Ok(()), Err)
}

/// Gives the attribute `name` in `dir`, the attribute directory of `path`,
/// the metadata `meta`: the owner and group `owner`, if any (none: they are
/// left as they are), mode, ACL (after the mode, which rewrites it; without
/// one, the trivial ACL of the mode, where it has another: [`strip_acl`]),
/// then the times, last, as for the file itself. Each is tried even when one
/// before it failed; the error is the first. A warning about a SID in the
/// ACL that idmap couldn't map goes to `unmapped`. A change of owner refused
/// to a restore not running as root is no error, as for the file itself.
fn restore_one_xattr_meta(
    dir: &File,
    path: &Path,
    name: &str,
    meta: &XattrMeta,
    owner: Option<(u32, u32)>,
    unmapped: &mut Option<io::Error>,
) -> io::Result<()> {
    let at = attr_path(path, name);
    // Never a path out of the attribute directory.
    if let Some(err) = attr_name_refused(name) {
        return Err(path_error("extended attribute metadata", &at, &err));
    }
    let n = CString::new(name)?;
    let fd = dir.as_raw_fd();
    let gone = |err: &io::Error| {
        let gone = err.raw_os_error() == Some(libc::ENOENT);
        if gone {
            debug!("{} not restored: {err}", at.display());
        }
        gone
    };
    let owner = match owner.map(|(uid, gid)| {
        // SAFETY: n is a C string.
        check(unsafe { libc::fchownat(fd, n.as_ptr(), uid, gid, 0) })
    }) {
        None => Ok(()),
        Some(Err(err)) if gone(&err) => return Ok(()),
        Some(Err(err)) if !is_root() && permission_refused(&err) => {
            debug!("not running as root, owner of {} not set: {err}", at.display());
            Ok(())
        }
        Some(r) => r.map(drop).map_err(|err| path_error("fchownat", &at, &err)),
    };
    // SAFETY: n is a C string.
    let mode = match check(unsafe { libc::fchmodat(fd, n.as_ptr(), meta.mode & 0o7777, 0) }) {
        Err(err) if gone(&err) => return Ok(()),
        r => r.map(drop).map_err(|err| path_error("fchmodat", &at, &err)),
    };
    // No ACL kept: it was trivial ([`read_xattr_meta`]).
    let mut entries = meta.acl.clone();
    if let Some(err) = aces_with_ids(ILLUMOS_XATTR_META, &mut entries) {
        _ = unmapped.get_or_insert(err);
    }
    let acl = open_attr(dir, &n, libc::O_RDONLY | libc::O_NONBLOCK)
        .map_err(|err| path_error("openat", &at, &err))
        .and_then(|f| {
            let of = AclOf::File(&f, &at);
            if entries.is_empty() {
                strip_acl(of, meta.mode, false)
            } else {
                set_ace(of, &entries)
            }
        });
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

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use super::*;

    fn xattr(name: &str, value: &[u8]) -> ExtendedAttribute {
        ExtendedAttribute {
            name: name.to_string(),
            value: Some(value.to_vec()),
        }
    }

    /// The attribute `name` in the attribute directory `adir`, open.
    fn open_named(adir: &File, name: &str) -> File {
        open_attr(adir, &CString::new(name).unwrap(), libc::O_RDONLY).unwrap()
    }

    /// BackOtter: an extended attribute the file has already, with its
    /// node's value, isn't written again; the others are written, and those
    /// the node hasn't got removed. Nothing to check on a file system
    /// without them.
    #[test]
    fn set_xattrs_leaves_equal_ones() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"").unwrap();
        let first = [
            xattr("diff", b"old"),
            xattr("empty", b""),
            xattr("gone", b"g"),
            xattr("same", b"v"),
        ];
        if set_xattrs(&file, &first).is_err() {
            eprintln!("no extended attributes in {}", dir.path().display());
            return;
        }
        let adir = attr_dir(&file).unwrap().unwrap();
        let mtime = |name: &str| {
            open_named(&adir, name)
                .metadata()
                .unwrap()
                .modified()
                .unwrap()
        };
        let before = [mtime("diff"), mtime("empty"), mtime("same")];
        thread::sleep(Duration::from_millis(50));
        let want = [
            xattr("diff", b"new"),
            ExtendedAttribute {
                name: "empty".to_string(),
                value: None,
            },
            xattr("new", b"n"),
            xattr("same", b"v"),
        ];
        set_xattrs(&file, &want).unwrap();
        assert_ne!(mtime("diff"), before[0]);
        assert_eq!(mtime("empty"), before[1]);
        assert_eq!(mtime("same"), before[2]);
        assert_eq!(
            xattrs_read(&file).unwrap().attrs,
            [
                xattr("diff", b"new"),
                xattr("empty", b""),
                xattr("new", b"n"),
                xattr("same", b"v"),
            ]
        );
    }

    /// BackOtter: a snapshot's attribute named `..` (the file itself, in
    /// its attribute directory) or with a `/` is refused, and the others
    /// are still set: neither the file nor anything outside the attribute
    /// directory is written.
    #[test]
    fn set_xattrs_refuses_paths() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"data").unwrap();
        if set_xattrs(&file, &[xattr("probe", b"")]).is_err() {
            eprintln!("no extended attributes in {}", dir.path().display());
            return;
        }
        let attrs = [xattr("..", b"X"), xattr("../x", b"y"), xattr("ok", b"v")];
        let err = set_xattrs(&file, &attrs).unwrap_err();
        assert!(err.counts(true), "{err}");
        assert_eq!(
            err.to_string().matches("not restored on illumos").count(),
            2,
            "{err}"
        );
        assert_eq!(std::fs::read(&file).unwrap(), b"data");
        assert!(!dir.path().join("x").exists());
        assert_eq!(xattrs_read(&file).unwrap().attrs, [xattr("ok", b"v")]);
        let sub = dir.path().join("d");
        std::fs::create_dir(&sub).unwrap();
        assert!(set_xattrs(&sub, &[xattr("../x", b"y")]).is_err());
        assert!(!dir.path().join("x").exists());
    }

    /// ForkAudit1 G5-05 (RustAudit1 R4-04): a NULL from `readdir(3C)` with
    /// errno set is an error, not the end of the directory; a stale errno
    /// from before the call isn't one. Before, every NULL ended the listing,
    /// cut short without an error.
    #[test]
    fn readdir_step_tells_an_error_from_the_end() {
        assert_eq!(readdir_step(|| Some(7)).unwrap(), Some(7));
        set_errno(libc::EIO);
        assert_eq!(readdir_step(|| None::<()>).unwrap(), None);
        let err = readdir_step(|| {
            set_errno(libc::EIO);
            None::<()>
        })
        .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
        // An entry is an entry, whatever errno was left at.
        let got = readdir_step(|| {
            set_errno(libc::ENOENT);
            Some(1)
        });
        assert_eq!(got.unwrap(), Some(1));
    }

    /// ForkAudit1 G5-06 (RustAudit1 R4-05): an attribute whose name isn't
    /// UTF-8 is read by its bytes and kept under its name with U+FFFD, as
    /// on every other system, with its metadata, and a restore removes it
    /// by its bytes. Before, it was opened and removed by the U+FFFD name:
    /// "No such file or directory" at backup, and never removed.
    #[test]
    fn a_name_that_is_not_utf8() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"").unwrap();
        if set_xattrs(&file, &[xattr("plain", b"p")]).is_err() {
            eprintln!("no extended attributes in {}", dir.path().display());
            return;
        }
        let adir = attr_dir(&file).unwrap().unwrap();
        let raw = c"caf\xe9";
        let made = open_attr(&adir, raw, libc::O_WRONLY | libc::O_CREAT)
            .and_then(|mut f| f.write_all(b"latin-1"));
        if let Err(err) = made {
            eprintln!("no attribute names that aren't UTF-8 in {}: {err}", dir.path().display());
            return;
        }
        assert_eq!(attr_names(&adir).unwrap(), [raw.to_owned(), c"plain".to_owned()]);
        let read = xattrs_read(&file).unwrap();
        assert!(read.unreadable.is_empty(), "{:?}", read.unreadable);
        assert_eq!(read.attrs, [xattr("caf\u{fffd}", b"latin-1"), xattr("plain", b"p")]);
        let mut node = file_node(0o644, 0, 0);
        fill_xattr_meta(&file, &mut node);
        let metas = node
            .meta
            .generic_attributes
            .get::<BTreeMap<String, XattrMeta>>(ILLUMOS_XATTR_META)
            .unwrap()
            .unwrap();
        assert_eq!(metas.keys().collect::<Vec<_>>(), ["caf\u{fffd}", "plain"]);

        // A restore of that node: the file has the attribute under the name
        // the node holds, and no longer the one it can't hold.
        set_xattrs(&file, &read.attrs).unwrap();
        assert_eq!(attr_names(&adir).unwrap(), [c"caf\u{fffd}".to_owned(), c"plain".to_owned()]);
        assert_eq!(xattrs_read(&file).unwrap().attrs, read.attrs);

        // And one the node hasn't got at all is removed.
        drop(open_attr(&adir, raw, libc::O_WRONLY | libc::O_CREAT).unwrap());
        set_xattrs(&file, &[]).unwrap();
        assert_eq!(attr_names(&adir).unwrap(), Vec::<CString>::new());
    }

    /// ForkAudit1 G5-07 (RustAudit1 R4-06): an attribute over
    /// `NATIVE_XATTR_MAX` is left out by its size, unread, and named in
    /// `unreadable`; one of just that size and the file's others are kept.
    /// Before, any size was read whole into memory. The big ones are sparse.
    #[test]
    fn an_attribute_too_large_is_left_out() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"").unwrap();
        if set_xattrs(&file, &[xattr("small", b"s")]).is_err() {
            eprintln!("no extended attributes in {}", dir.path().display());
            return;
        }
        let adir = attr_dir(&file).unwrap().unwrap();
        for (name, size) in [(c"at-most", NATIVE_XATTR_MAX), (c"too-large", NATIVE_XATTR_MAX + 1)] {
            let f = open_attr(&adir, name, libc::O_WRONLY | libc::O_CREAT).unwrap();
            if let Err(err) = f.set_len(size) {
                eprintln!("no attribute of {size} bytes in {}: {err}", dir.path().display());
                return;
            }
        }
        let read = xattrs_read(&file).unwrap();
        let names: Vec<_> = read.attrs.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["at-most", "small"]);
        assert_eq!(read.attrs[0].value.as_ref().map(Vec::len), Some(16 << 20));
        assert_eq!(read.unreadable.len(), 1);
        let (name, err) = &read.unreadable[0];
        assert_eq!(name, "too-large");
        assert_eq!(err.kind(), io::ErrorKind::FileTooLarge);
        assert_eq!(err.to_string(), "too large to keep (16777217 bytes, over 16777216)");
    }

    /// The node of a file with the mode `mode`, owned by `uid`:`gid`.
    fn file_node(mode: u32, uid: u32, gid: u32) -> Node {
        let meta = crate::backend::node::Metadata {
            mode: Some(mode),
            uid: Some(uid),
            gid: Some(gid),
            ..Default::default()
        };
        Node::new_node(std::ffi::OsStr::new("f"), NodeType::File, meta)
    }

    /// The owner and group of the attribute `name` of `file`.
    fn attr_owner(file: &Path, name: &str) -> (u32, u32) {
        let adir = attr_dir(file).unwrap().unwrap();
        let m = open_named(&adir, name).metadata().unwrap();
        (m.uid(), m.gid())
    }

    /// ForkAudit1 G5-01: an attribute file gets an owner only when the
    /// restore sets owners, and one its file's owner owned follows the file
    /// to the owner it has here (restored by name); another's keeps its
    /// number. Before, each got the snapshot's numbers in every mode. As
    /// root, on a file system with extended attributes.
    #[test]
    fn xattr_meta_owners_as_the_restore_sets_owners() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"").unwrap();
        let attrs = [xattr("mine", b"m"), xattr("other", b"o")];
        if !is_root() || set_xattrs(&file, &attrs).is_err() {
            eprintln!("not root, or no extended attributes in {}", dir.path().display());
            return;
        }
        let t = Timestamp::new(1_000_000_000, 0).unwrap();
        let meta = |uid, gid| XattrMeta {
            uid,
            gid,
            mode: 0o640,
            mtime: t,
            atime: t,
            ..XattrMeta::default()
        };
        // At backup the file and "mine" were 1001:1001's, "other" 1002's.
        let mut node = file_node(0o644, 1001, 1001);
        node.meta.extended_attributes = attrs.to_vec();
        let metas = BTreeMap::from([
            ("mine".to_string(), meta(1001, 1001)),
            ("other".to_string(), meta(1002, 1001)),
        ]);
        node.meta.generic_attributes.set(ILLUMOS_XATTR_META, &metas).unwrap();
        let mode = |name: &str| {
            let adir = attr_dir(&file).unwrap().unwrap();
            open_named(&adir, name).metadata().unwrap().mode() & 0o7777
        };

        // --no-ownership: the attributes stay the restore's own (root's),
        // as the file does; the rest of their metadata is set.
        restore_xattr_meta(&file, &node, false).unwrap();
        assert_eq!(attr_owner(&file, "mine"), (0, 0));
        assert_eq!(attr_owner(&file, "other"), (0, 0));
        assert_eq!(mode("mine"), 0o640);

        // By name: the file's owner is 1500:1501 here. Hers follow it; the
        // other user's attribute keeps his number, with the file's group.
        std::os::unix::fs::chown(&file, Some(1500), Some(1501)).unwrap();
        restore_xattr_meta(&file, &node, true).unwrap();
        assert_eq!(attr_owner(&file, "mine"), (1500, 1501));
        assert_eq!(attr_owner(&file, "other"), (1002, 1501));

        // By number: as in the snapshot.
        std::os::unix::fs::chown(&file, Some(1001), Some(1001)).unwrap();
        restore_xattr_meta(&file, &node, true).unwrap();
        assert_eq!(attr_owner(&file, "mine"), (1001, 1001));
        assert_eq!(attr_owner(&file, "other"), (1002, 1001));
    }

    /// ForkAudit1 G5-03: an attribute file owned by a SID (an ephemeral id)
    /// is kept with the SID, and restored to the id the SID has here, not
    /// the backup's number; one idmap can't map goes to nobody, with a
    /// `SidUnmapped` error. As root, with idmap online.
    #[test]
    fn xattr_meta_sid_owners() {
        let (owner, group) = ("S-1-5-21-1111-2222-3333-1017", "S-1-5-21-1111-2222-3333-518");
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"").unwrap();
        let attrs = [xattr("stream", b"s")];
        let ids = illumos_idmap::id_of_sid(owner, false)
            .and_then(|uid| Ok((uid, illumos_idmap::id_of_sid(group, true)?)));
        let (Ok((uid, gid)), true, Ok(())) = (ids, is_root(), set_xattrs(&file, &attrs)) else {
            eprintln!("not root, idmap offline, or no extended attributes");
            return;
        };
        assert!(uid > illumos_acl::MAX_UID && gid > illumos_acl::MAX_UID);
        let adir = attr_dir(&file).unwrap().unwrap();
        let chown = |uid, gid| {
            // SAFETY: the name is a C string.
            _ = check(unsafe { libc::fchownat(adir.as_raw_fd(), c"stream".as_ptr(), uid, gid, 0) })
                .unwrap();
        };
        chown(uid, gid);

        // The backup keeps both SIDs beside the numbers.
        let mut node = file_node(0o644, 0, 0);
        node.meta.extended_attributes = attrs.to_vec();
        fill_xattr_meta(&file, &mut node);
        let mut metas = node
            .meta
            .generic_attributes
            .get::<BTreeMap<String, XattrMeta>>(ILLUMOS_XATTR_META)
            .unwrap()
            .unwrap();
        let meta = metas.get_mut("stream").unwrap();
        assert_eq!((meta.uid, meta.gid), (uid, gid));
        assert_eq!(meta.owner_sid.as_deref(), Some(owner));
        assert_eq!(meta.group_sid.as_deref(), Some(group));

        // After a reboot the numbers are someone else's: the SIDs decide.
        (meta.uid, meta.gid) = (uid + 1000, gid + 1000);
        node.meta.generic_attributes.set(ILLUMOS_XATTR_META, &metas).unwrap();
        chown(0, 0);
        restore_xattr_meta(&file, &node, true).unwrap();
        assert_eq!(attr_owner(&file, "stream"), (uid, gid));

        // Without ownership, nothing.
        chown(0, 0);
        restore_xattr_meta(&file, &node, false).unwrap();
        assert_eq!(attr_owner(&file, "stream"), (0, 0));

        // A SID idmap can't map: nobody, never the number, and a warning.
        metas.get_mut("stream").unwrap().owner_sid = Some("S-1-5-21-x".to_string());
        node.meta.generic_attributes.set(ILLUMOS_XATTR_META, &metas).unwrap();
        let err = restore_xattr_meta(&file, &node, true).unwrap_err();
        let unmapped = err.get_ref().and_then(|e| e.downcast_ref::<SidUnmapped>());
        assert!(unmapped.is_some(), "{err}");
        assert_eq!(attr_owner(&file, "stream"), (NOBODY, gid));
    }

    /// A named user's entry, as `chmod A+user:nobody:read_data:allow`.
    fn nobody_reads() -> AceEntry {
        AceEntry {
            who: NOBODY,
            mask: 1,
            ..AceEntry::default()
        }
    }

    /// ForkAudit1 G5-02: what ZFS gives a file as its ACL when its mode is
    /// set is `illumos_acl::trivial` of that mode (the ACL a restore writes
    /// in place of one the snapshot hasn't got). On ZFS, with the default
    /// `aclmode=discard`.
    #[test]
    fn trivial_acl_is_what_chmod_gives() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (file, sub) = (dir.path().join("f"), dir.path().join("d"));
        std::fs::write(&file, b"").unwrap();
        std::fs::create_dir(&sub).unwrap();
        if get_ace(AclOf::Path(&file)).is_err() {
            eprintln!("no NFSv4 ACLs in {}", dir.path().display());
            return;
        }
        for mode in [0o644, 0o600, 0o640, 0o755, 0o604, 0o046, 0o077, 0o206, 0o000, 0o777, 0o4755] {
            for (path, is_dir) in [(&file, false), (&sub, true)] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
                assert_eq!(
                    get_ace(AclOf::Path(path)).unwrap(),
                    illumos_acl::trivial(mode, is_dir),
                    "{mode:o} {}",
                    path.display()
                );
            }
        }
    }

    /// ForkAudit1 G5-02: a file whose node has no ACL, in a snapshot of
    /// BackOtter's, loses the named entry it has at the destination (added
    /// after the backup, or inherited): it gets the trivial ACL of its
    /// mode, and keeps its mode, the setuid bit too. In another snapshot it
    /// keeps what it has. Before, nothing took it off (`chmod(2)` only
    /// under `aclmode=discard`). On ZFS.
    #[test]
    fn restore_acls_strips_an_acl_the_node_has_not() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"secret").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o4750)).unwrap();
        let Ok(mut acl) = get_ace(AclOf::Path(&file)) else {
            eprintln!("no NFSv4 ACLs in {}", dir.path().display());
            return;
        };
        acl.insert(0, nobody_reads());
        set_ace(AclOf::Path(&file), &acl).unwrap();
        assert!(!illumos_acl::is_trivial(&get_ace(AclOf::Path(&file)).unwrap()));
        let node = file_node(0o104_750, 0, 0);

        // Not BackOtter's snapshot: unknown, left.
        restore_acls(&file, &node, false).unwrap();
        assert!(!illumos_acl::is_trivial(&get_ace(AclOf::Path(&file)).unwrap()));

        restore_acls(&file, &node, true).unwrap();
        assert_eq!(get_ace(AclOf::Path(&file)).unwrap(), illumos_acl::trivial(0o750, false));
        assert_eq!(std::fs::metadata(&file).unwrap().mode() & 0o7777, 0o4750);

        // A node without a mode: the file's own.
        set_ace(AclOf::Path(&file), &acl).unwrap();
        let mut no_mode = node;
        no_mode.meta.mode = None;
        restore_acls(&file, &no_mode, true).unwrap();
        assert!(illumos_acl::is_trivial(&get_ace(AclOf::Path(&file)).unwrap()));

        // A symlink has no ACL of its own: its target's is left.
        set_ace(AclOf::Path(&file), &acl).unwrap();
        let link = dir.path().join("l");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let link_node = Node::new_node(
            std::ffi::OsStr::new("l"),
            NodeType::Symlink {
                linktarget: "f".to_string(),
                linktarget_raw: None,
            },
            crate::backend::node::Metadata::default(),
        );
        restore_acls(&link, &link_node, true).unwrap();
        assert!(!illumos_acl::is_trivial(&get_ace(AclOf::Path(&file)).unwrap()));
    }

    /// ForkAudit1 G5-02: an attribute file whose metadata has no ACL loses
    /// the entry it has at the destination, as its file does. On ZFS.
    #[test]
    fn xattr_meta_strips_an_acl_it_has_not() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"").unwrap();
        let attrs = [xattr("note", b"n")];
        if get_ace(AclOf::Path(&file)).is_err() || set_xattrs(&file, &attrs).is_err() {
            eprintln!("no NFSv4 ACLs or extended attributes in {}", dir.path().display());
            return;
        }
        let adir = attr_dir(&file).unwrap().unwrap();
        let attr_file = open_named(&adir, "note");
        let at = attr_path(&file, "note");
        let mut acl = get_ace(AclOf::File(&attr_file, &at)).unwrap();
        acl.insert(0, nobody_reads());
        set_ace(AclOf::File(&attr_file, &at), &acl).unwrap();
        let t = Timestamp::new(1_000_000_000, 0).unwrap();
        let meta = XattrMeta {
            mode: 0o600,
            mtime: t,
            atime: t,
            ..XattrMeta::default()
        };
        let mut node = file_node(0o644, 0, 0);
        node.meta.extended_attributes = attrs.to_vec();
        let metas = BTreeMap::from([("note".to_string(), meta)]);
        node.meta.generic_attributes.set(ILLUMOS_XATTR_META, &metas).unwrap();
        restore_xattr_meta(&file, &node, false).unwrap();
        assert_eq!(get_ace(AclOf::File(&attr_file, &at)).unwrap(), illumos_acl::trivial(0o600, false));
        assert_eq!(attr_file.metadata().unwrap().mode() & 0o7777, 0o600);
    }
}
