//! BackOtter: the errors of saving and restoring this metadata, and how a
//! restore reports and counts them, as BackOtter's restic does: metadata the
//! file system doesn't support ([`Unsupported`]) and SIDs idmap couldn't map
//! ([`SidUnmapped`]), each warned about once; several errors of one step
//! ([`RestoreErrors`]) and of a file's extended attributes
//! ([`XattrErrors`]); what `--strict-exit` counts
//! ([`restore_error_counts`]); and a system call's error with its operation
//! and file ([`path_error`]), which keeps its errno ([`errno`]).

use std::{
    collections::BTreeMap,
    fmt, io,
    path::{Path, PathBuf},
    sync::Mutex,
};

use log::warn;

/// BackOtter: an error saying that the file system doesn't support a kind
/// of metadata (`attr`, and of file flags `bits`), rather than that setting
/// it failed. The restore warns about each kind once
/// ([`warn_restore`]).
#[derive(Debug)]
pub(crate) struct Unsupported {
    /// The generic attribute.
    pub(crate) attr: &'static str,
    /// The file flags refused, or XFS options' `fsx_xflags`, or 0.
    pub(crate) bits: u64,
    /// The system's error.
    pub(crate) source: io::Error,
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} not supported by the file system: {}",
            self.kind(),
            self.source
        )
    }
}

impl std::error::Error for Unsupported {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl Unsupported {
    /// An [`io::Error`] for this.
    #[cfg_attr(
        not(any(
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "illumos",
            target_os = "linux",
            target_os = "netbsd",
            target_os = "openbsd"
        )),
        allow(dead_code)
    )]
    pub(super) fn error(attr: &'static str, bits: u64, source: io::Error) -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, Self { attr, bits, source })
    }

    /// What isn't supported: `linux.inode_flags 0x10`, `linux.project_id`.
    pub(super) fn kind(&self) -> String {
        if self.bits == 0 {
            self.attr.to_string()
        } else {
            format!("{} {:#x}", self.attr, self.bits)
        }
    }
}

/// BackOtter: a SID on illumos that idmap couldn't map to an id here
/// (idmapd isn't running, say): the owner or group of a file
/// (`illumos.owner_sid`, `illumos.group_sid`), or the user or group of an
/// ACL entry (`illumos.acl`, `illumos.xattr_meta`), which got nobody (60001)
/// instead, not the number the backup saw: that may be another SID's by now.
/// The restore warns about each attribute once ([`warn_restore`]).
#[derive(Debug)]
pub(crate) struct SidUnmapped {
    /// The generic attribute.
    pub(crate) attr: &'static str,
    /// The SID.
    pub(crate) sid: String,
    /// idmap's error.
    pub(crate) source: io::Error,
}

impl fmt::Display for SidUnmapped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} not mapped by idmap, nobody (60001) used: {}",
            self.attr, self.sid, self.source
        )
    }
}

impl std::error::Error for SidUnmapped {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl SidUnmapped {
    /// An [`io::Error`] for this.
    #[cfg_attr(not(target_os = "illumos"), allow(dead_code))]
    pub(super) fn error(attr: &'static str, sid: &str, source: io::Error) -> io::Error {
        io::Error::other(Self {
            attr,
            sid: sid.to_string(),
            source,
        })
    }
}

/// BackOtter: more than one error from one step of restoring a file's
/// metadata, which [`warn_restore`] warns about each as if alone: the owner
/// and the group both SIDs that idmap couldn't map, a warning for each
/// attribute; a Linux file's flags and its btrfs compression property.
#[derive(Debug)]
pub(crate) struct RestoreErrors(pub(super) Vec<io::Error>);

impl RestoreErrors {
    /// `Ok` for no errors, the error itself for one, and one that holds them
    /// all for more.
    #[cfg_attr(
        not(any(
            target_os = "freebsd",
            target_os = "illumos",
            target_os = "linux",
            target_os = "netbsd"
        )),
        allow(dead_code)
    )]
    pub(super) fn result(mut errors: Vec<io::Error>) -> io::Result<()> {
        match errors.len() {
            0 => Ok(()),
            1 => Err(errors.remove(0)),
            _ => Err(io::Error::other(Self(errors))),
        }
    }
}

impl fmt::Display for RestoreErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, err) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{err}")?;
        }
        Ok(())
    }
}

impl std::error::Error for RestoreErrors {}

/// BackOtter: what a restore couldn't do to the extended attributes of a
/// file, each with its error: setting one (named), removing one, listing
/// them. One that can't be set doesn't keep the others from being set or
/// removed, as in BackOtter's restic, and one warning per file names them
/// all, as in `trusted.a: Operation not permitted (os error 1); removing
/// user.b: ...`.
#[derive(Debug, Default)]
pub(crate) struct XattrErrors(pub(super) Vec<(String, io::Error)>);

impl XattrErrors {
    /// Whether BackOtter's restic would count these failures as an error
    /// (exit 1): any that isn't extended attributes the file system doesn't
    /// support (`ErrorKind::Unsupported`, `ENOTSUP`, `EOPNOTSUPP`), nor,
    /// not running as `root`, a permission refused (`trusted.*` or
    /// `security.*` attributes, a file someone else owns), which restic's
    /// restore not running as root only warns about (S2). Setting, removing
    /// and listing alike.
    #[cfg_attr(any(windows, target_os = "openbsd"), allow(dead_code))]
    pub(crate) fn counts(&self, root: bool) -> bool {
        self.0
            .iter()
            .any(|(_, err)| !xattr_unsupported(err) && (root || !permission_refused(err)))
    }

    /// Adds the failure of `what`: an attribute's name, for setting it, or
    /// what else was done (`removing NAME`, `listing`).
    #[cfg_attr(
        any(windows, target_os = "openbsd", target_os = "haiku"),
        allow(dead_code)
    )]
    pub(crate) fn push(&mut self, what: impl Into<String>, err: io::Error) {
        self.0.push((what.into(), err));
    }

    /// `Ok` if nothing failed.
    ///
    /// # Errors
    ///
    /// * These failures, if there are any.
    #[cfg_attr(
        any(windows, target_os = "openbsd", target_os = "haiku"),
        allow(dead_code)
    )]
    pub(crate) fn into_result(self) -> Result<(), Self> {
        if self.0.is_empty() { Ok(()) } else { Err(self) }
    }
}

/// Whether `err` says the file system doesn't support extended attributes:
/// `ENOTSUP`/`EOPNOTSUPP`, or `ENOATTR` (`ENODATA` on Linux), which an
/// SMB/CIFS mount can give instead, as BackOtter's restic takes them all
/// (`handleXattrErr`, `xattrUnsupported`).
#[cfg_attr(any(windows, target_os = "openbsd"), allow(dead_code))]
pub(crate) fn xattr_unsupported(err: &io::Error) -> bool {
    if err.kind() == io::ErrorKind::Unsupported {
        return true;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let no_attr = Some(libc::ENODATA);
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    let no_attr = Some(libc::ENOATTR);
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )))]
    let no_attr: Option<i32> = None;
    #[cfg(unix)]
    {
        let errno = errno(err);
        matches!(errno, Some(e) if e == libc::ENOTSUP || e == libc::EOPNOTSUPP)
            || (no_attr.is_some() && errno == no_attr)
    }
    #[cfg(not(unix))]
    {
        _ = no_attr;
        false
    }
}

/// Whether `err` is a permission refused (`EPERM`, `EACCES`).
pub(super) fn permission_refused(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::PermissionDenied
}

/// BackOtter: whether this process runs as root, as restic asks
/// (`os.Geteuid() == 0`); always on Windows, where restic's `os.Geteuid()`
/// is -1 and its not-root rules don't apply.
pub(crate) fn is_root() -> bool {
    #[cfg(unix)]
    {
        nix::unistd::geteuid().is_root()
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// BackOtter: what a step of the restore makes of a permission refused
/// (`EPERM`, `EACCES`) when the restore doesn't run as root, for
/// [`restore_error_counts`], as BackOtter's restic does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotRoot {
    /// Only warned about, not counted: the steps restic's restore not
    /// running as root forgives it (S2): the owner, the permissions (a
    /// symlink's too), the times (the birth time too), ACLs and the
    /// attributes that go with extended attributes.
    Forgiven,
    /// Counted, as any other error: file flags, and what goes on with them
    /// or before entries and contents (ZFS's DOS flags, FAT's attributes,
    /// XFS's options).
    Counted,
}

/// BackOtter: whether `err`, a failure to restore metadata that the restore
/// warned about, is one BackOtter's restic counts as an error (exit 1): not
/// metadata the file system doesn't support ([`Unsupported`],
/// `ErrorKind::Unsupported`), a SID idmap couldn't map ([`SidUnmapped`]),
/// nor, in a step that forgives it (`not_root`: [`NotRoot::Forgiven`]) and
/// not running as root (`root`), a permission refused (`EPERM`, `EACCES`),
/// which restic's restore not running as root only warns about (S2). Each
/// of several ([`RestoreErrors`]) is judged alone.
pub(crate) fn restore_error_counts(err: &io::Error, not_root: NotRoot, root: bool) -> bool {
    let inner = err.get_ref();
    if let Some(errors) = inner.and_then(|e| e.downcast_ref::<RestoreErrors>()) {
        return errors
            .0
            .iter()
            .any(|err| restore_error_counts(err, not_root, root));
    }
    if inner.is_some_and(|e| e.is::<Unsupported>() || e.is::<SidUnmapped>()) {
        return false;
    }
    if err.kind() == io::ErrorKind::Unsupported {
        return false;
    }
    !(not_root == NotRoot::Forgiven && !root && permission_refused(err))
}

/// BackOtter: a copy of `err`, for each of several things it kept from being
/// done, such as each extended attribute of a file on a file system without
/// them, and for [`path_error`]: the same errno where it has one, a
/// [`PathError`] copied likewise, else the same kind and text.
#[cfg_attr(
    not(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "haiku",
        target_os = "illumos",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd"
    )),
    allow(dead_code)
)]
pub(crate) fn same_error(err: &io::Error) -> io::Error {
    if let Some(errno) = err.raw_os_error() {
        return io::Error::from_raw_os_error(errno);
    }
    err.get_ref()
        .and_then(|e| e.downcast_ref::<PathError>())
        .map_or_else(
            || io::Error::new(err.kind(), err.to_string()),
            |wrapped| {
                io::Error::new(
                    err.kind(),
                    PathError {
                        op: wrapped.op.clone(),
                        path: wrapped.path.clone(),
                        source: same_error(&wrapped.source),
                    },
                )
            },
        )
}

/// An error that isn't about one attribute: the file's extended attributes
/// can't be read or written at all.
impl From<io::Error> for XattrErrors {
    fn from(err: io::Error) -> Self {
        Self(vec![(String::new(), err)])
    }
}

impl fmt::Display for XattrErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (what, err)) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            if what.is_empty() {
                write!(f, "{err}")?;
            } else {
                write!(f, "{what}: {err}")?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for XattrErrors {}

/// The kinds of metadata the restore has warned about once (unsupported
/// metadata, unmapped SIDs), each with the first file and the number of
/// files.
static UNSUPPORTED: Mutex<BTreeMap<String, (PathBuf, u64)>> = Mutex::new(BTreeMap::new());

/// Warns about an error restoring the metadata of `path`: an [`Unsupported`]
/// or [`SidUnmapped`] one once per kind, with the first file, and
/// [`report_unsupported`] counts the files; any other each time; each of
/// [`RestoreErrors`] as if alone.
pub(crate) fn warn_restore(path: &Path, err: &io::Error) {
    let inner = err.get_ref();
    if let Some(errors) = inner.and_then(|e| e.downcast_ref::<RestoreErrors>()) {
        for err in &errors.0 {
            warn_restore(path, err);
        }
        return;
    }
    let (kind, msg) = if let Some(e) = inner.and_then(|e| e.downcast_ref::<Unsupported>()) {
        (
            format!("{} not supported by the file system", e.kind()),
            e.to_string(),
        )
    } else if let Some(e) = inner.and_then(|e| e.downcast_ref::<SidUnmapped>()) {
        (
            format!("{}: SIDs not mapped by idmap, nobody (60001) used", e.attr),
            e.to_string(),
        )
    } else {
        warn!("restore {}: {err}", path.display());
        return;
    };
    let mut seen = UNSUPPORTED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_, n) = seen.entry(kind).or_insert_with(|| (path.to_path_buf(), 0));
    *n += 1;
    let first = *n == 1;
    drop(seen);
    if first {
        warn!("restore {}: {msg}", path.display());
    }
}

/// Warns, once a restore is done, about the number of files with each kind
/// of metadata [`warn_restore`] saw more than once, and starts counting
/// again.
pub(crate) fn report_unsupported() {
    let seen = std::mem::take(
        &mut *UNSUPPORTED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    for (kind, (first, n)) in seen {
        if n > 1 {
            warn!("{kind}: {n} files, the first {}", first.display());
        }
    }
}

/// BackOtter: a system call's error with the operation and the file it
/// failed on, as [`path_error`] wraps it: it reads `OP PATH: ERROR`, and
/// keeps the error itself as its source, with its errno ([`errno`]).
#[derive(Debug)]
pub(crate) struct PathError {
    /// What was done: the system call, mostly.
    op: String,
    /// The file.
    path: PathBuf,
    /// The system's error.
    source: io::Error,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.op, self.path.display(), self.source)
    }
}

impl std::error::Error for PathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// An error that names the operation and the file: `err`'s kind, a
/// [`PathError`] of it inside.
#[cfg_attr(
    not(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "haiku",
        target_os = "illumos",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd"
    )),
    allow(dead_code)
)]
pub(super) fn path_error(op: &str, path: &Path, err: &io::Error) -> io::Error {
    io::Error::new(
        err.kind(),
        PathError {
            op: op.to_string(),
            path: path.to_path_buf(),
            source: same_error(err),
        },
    )
}

/// BackOtter: the errno of `err`, a system call's error as it came or as
/// [`path_error`] wrapped it since (a [`PathError`], looked through), for
/// the rules that go by it ([`unsupported`], [`xattr_unsupported`]): an
/// error doesn't change its class by being given a path.
pub(super) fn errno(err: &io::Error) -> Option<i32> {
    err.raw_os_error().or_else(|| {
        let wrapped = err.get_ref()?.downcast_ref::<PathError>()?;
        errno(&wrapped.source)
    })
}

/// BackOtter: `err`, an ACL that couldn't be set, as an
/// `ErrorKind::Unsupported` one, with the same text and `err` inside, where
/// it says the file system can't hold ACLs (`ENOTSUP`, `EOPNOTSUPP`, by
/// [`errno`]): unsupported metadata, which BackOtter's restic doesn't count
/// as an error (`restore_error_counts`).
#[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "illumos"))]
pub(super) fn acl_set_error(err: io::Error) -> io::Error {
    match errno(&err) {
        Some(e) if e == libc::ENOTSUP || e == libc::EOPNOTSUPP => {
            io::Error::new(io::ErrorKind::Unsupported, err)
        }
        _ => err,
    }
}

/// Errors that mean the file system doesn't have a kind of metadata (file
/// flags, a project ID), rather than that setting it failed.
#[cfg_attr(
    not(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd"
    )),
    allow(dead_code)
)]
pub(super) fn unsupported(err: &io::Error) -> bool {
    #[cfg(unix)]
    {
        errno(err).is_some_and(|code| {
            [libc::EINVAL, libc::ENOTSUP, libc::EOPNOTSUPP, libc::ENOTTY].contains(&code)
        })
    }
    #[cfg(not(unix))]
    {
        err.kind() == io::ErrorKind::Unsupported
    }
}
