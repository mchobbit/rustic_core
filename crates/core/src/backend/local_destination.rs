#[cfg(not(windows))]
use std::os::unix::fs::{PermissionsExt, symlink};

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    num::TryFromIntError,
    path::{Path, PathBuf},
};

use bytes::Bytes;
#[cfg(not(target_os = "dragonfly"))]
use filetime::{FileTime, set_symlink_file_times};
#[cfg(not(windows))]
use nix::errno::Errno;
#[cfg(not(windows))]
use nix::sys::stat::{Mode, SFlag, mknod};
#[cfg(not(windows))]
use nix::{
    fcntl::{AT_FDCWD, AtFlags},
    unistd::{Gid, Uid, fchownat},
};
use same_file::is_same_file;

#[cfg(not(windows))]
use crate::backend::ignore::mapper::nix_mapper::map_mode_from_go;
#[cfg(not(windows))]
use crate::backend::node::NodeType;
use crate::backend::osattrs;
use crate::{
    backend::node::{ExtendedAttribute, Metadata, Node},
    error::{ErrorKind, RusticError, RusticResult},
};

#[cfg(not(windows))]
mod helpers {
    // Helper function to cache mapping user name -> uid
    #![allow(clippy::needless_pass_by_value)]

    use cached::macros::cached;
    use log::warn;
    use nix::unistd::{Gid, Group, Uid, User};

    // BackOtter: a name that isn't found is cached too (`cache_none`), so
    // that it is looked up, and a failed lookup warned about, once per run:
    // cached 2 caches `None` no more, and without /etc/passwd every file
    // warned. The restore falls back to the saved id (set_user_group).
    #[cached(cache_none = true)]
    pub(super) fn uid_from_name(name: String) -> Option<Uid> {
        User::from_name(&name)
            .inspect_err(|err| {
                warn!("Cannot determine UID from name {name}: {err}. Using the saved UID.");
            })
            .unwrap_or_default()
            .map(|u| u.uid)
    }

    // Helper function to cache mapping group name -> gid
    #[cached(cache_none = true)]
    pub(super) fn gid_from_name(name: String) -> Option<Gid> {
        Group::from_name(&name)
            .inspect_err(|err| {
                warn!("Cannot determine GID from name {name}: {err}. Using the saved GID.");
            })
            .unwrap_or_default()
            .map(|g| g.gid)
    }
}

/// [`LocalDestinationErrorKind`] describes the errors that can be returned by an action on the filesystem in Backends
#[derive(thiserror::Error, Debug, displaydoc::Display)]
pub enum LocalDestinationErrorKind {
    /// directory creation failed: `{0:?}`
    DirectoryCreationFailed(std::io::Error),
    /// item path `{0:?}` contains invalid components or escapes destination
    ItemPathEscapesDestination(PathBuf),
    /// file `{0:?}` should have a parent
    FileDoesNotHaveParent(PathBuf),
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "haiku",
        all(target_os = "android", target_pointer_width = "32")
    ))]
    /// `DeviceID` could not be converted to other type `{target}` of device `{device}`: `{source}`
    DeviceIdConversionFailed {
        target: String,
        device: u64,
        source: TryFromIntError,
    },
    /// Length conversion failed for `{target}` of length `{length}`: `{source}`
    LengthConversionFailed {
        target: String,
        length: u64,
        source: TryFromIntError,
    },
    /// `{0}`
    #[error(transparent)]
    #[cfg(not(windows))]
    FromErrnoError(Errno),
    // BackOtter: each extended attribute that couldn't be set or removed,
    // with its error, in one (stock rustic stopped at the first).
    /// {0}
    #[cfg(not(any(windows, target_os = "openbsd")))]
    XattrsNotSet(osattrs::XattrErrors),
    /// removing directories failed: `{0:?}`
    // BackOtter: unused, as remove_dir and remove_file.
    #[allow(dead_code)]
    DirectoryRemovalFailed(std::io::Error),
    /// removing file failed: `{0:?}`
    #[allow(dead_code)]
    FileRemovalFailed(std::io::Error),
    /// setting time metadata failed: `{0:?}`
    SettingTimeMetadataFailed(std::io::Error),
    /// opening file failed: `{0:?}`
    OpeningFileFailed(std::io::Error),
    /// setting file length failed: `{0:?}`
    SettingFileLengthFailed(std::io::Error),
    /// can't jump to position in file: `{0:?}`
    CouldNotSeekToPositionInFile(std::io::Error),
    /// couldn't write to buffer: `{0:?}`
    CouldNotWriteToBuffer(std::io::Error),
    /// reading exact length of file contents failed: `{0:?}`
    ReadingExactLengthOfFileFailed(std::io::Error),
    /// setting file permissions failed: `{0:?}`
    #[cfg(not(windows))]
    SettingFilePermissionsFailed(std::io::Error),
    /// failed to symlink target `{linktarget:?}` from `{filename:?}` with `{source:?}`
    #[cfg(not(windows))]
    SymlinkingFailed {
        linktarget: PathBuf,
        filename: PathBuf,
        source: std::io::Error,
    },
    /// failed to create hardlink from `{source_path:?}` to `{filename:?}` with `{source:?}`
    HardLinkingFailed {
        source_path: PathBuf,
        filename: PathBuf,
        source: std::io::Error,
    },
}

pub(crate) type LocalDestinationResult<T> = Result<T, LocalDestinationErrorKind>;

#[derive(Clone, Debug)]
/// Local destination, used when restoring.
pub struct LocalDestination {
    /// The base path of the destination.
    path: PathBuf,
    /// Whether we expect a single file as destination.
    is_file: bool,
    /// BackOtter: files restored elsewhere, which `restore --exact` may
    /// clone (`--clone-from`)
    clone_sources: Option<std::sync::Arc<crate::commands::restore::CloneSources>>,
}

impl LocalDestination {
    /// BackOtter: the destination, with files restored elsewhere on its file
    /// system that `restore --exact` may clone instead of writing.
    #[must_use]
    pub fn with_clone_sources(mut self, sources: crate::commands::restore::CloneSources) -> Self {
        self.clone_sources = Some(std::sync::Arc::new(sources));
        self
    }

    /// BackOtter: a file restored elsewhere that holds `content`, if any.
    pub(crate) fn clone_source(&self, content: &[crate::blob::DataId]) -> Option<PathBuf> {
        self.clone_sources.as_ref()?.get(content).map(Path::to_path_buf)
    }

    /// Create a new [`LocalDestination`]
    ///
    /// # Arguments
    ///
    /// * `path` - The base path of the destination
    /// * `create` - If `create` is true, create the base path if it doesn't exist.
    /// * `expect_file` - Whether we expect a single file as destination.
    ///
    /// # Errors
    ///
    /// * If the directory could not be created.
    // TODO: We should use `impl Into<Path/PathBuf>` here. we even use it in the body!
    pub fn new(path: &str, create: bool, expect_file: bool) -> RusticResult<Self> {
        let is_dir = path.ends_with('/');
        let path: PathBuf = path.into();
        let is_file = path.is_file() || (!path.is_dir() && !is_dir && expect_file);

        // FIXME: Refactor logic to avoid duplication
        if create {
            if is_file {
                if let Some(path) = path.parent() {
                    fs::create_dir_all(path).map_err(|err| {
                        RusticError::with_source(
                            ErrorKind::InputOutput,
                            "The directory `{path}` could not be created.",
                            err,
                        )
                        .attach_context("path", path.display().to_string())
                    })?;
                }
            } else {
                fs::create_dir_all(&path).map_err(|err| {
                    RusticError::with_source(
                        ErrorKind::InputOutput,
                        "The directory `{path}` could not be created.",
                        err,
                    )
                    .attach_context("path", path.display().to_string())
                })?;
            }
        }

        // BackOtter: why paths past PATH_MAX can't be reached, if they can't.
        osattrs::warn_on_short_path_errors();
        Ok(Self { path, is_file, clone_sources: None })
    }

    /// Path to the given item (relative to the base path)
    ///
    /// # Arguments
    ///
    /// * `item` - The item to get the path for
    ///
    /// # Returns
    ///
    /// The path to the item.
    ///
    /// # Notes
    ///
    /// * If the destination is a file, this will return the base path.
    /// * If the destination is a directory, this will return the base path joined with the item.
    pub(crate) fn path(&self, item: impl AsRef<Path>) -> LocalDestinationResult<PathBuf> {
        let item = item.as_ref();
        if self.is_file {
            return Ok(self.path.clone());
        }

        let mut res = self.path.clone();
        for comp in item.components() {
            match comp {
                std::path::Component::Prefix(_)
                | std::path::Component::RootDir
                | std::path::Component::ParentDir => {
                    return Err(LocalDestinationErrorKind::ItemPathEscapesDestination(
                        item.to_path_buf(),
                    ));
                }
                std::path::Component::CurDir => {}
                std::path::Component::Normal(c) => {
                    res.push(c);
                }
            }
        }
        Ok(res)
    }

    /// BackOtter: [`Self::path`] as a system call takes it: past
    /// `PATH_MAX`, a short path to the same file ([`walkdir::short_path`]).
    /// For this destination's own system calls; the restore's decisions
    /// (what is where, in which order) go by [`Self::path`].
    ///
    /// Past `PATH_MAX`, the directories down to the deepest prefix cut must
    /// exist already: a short path leads through a link to that prefix,
    /// which dangles where it doesn't exist, so `create_dir_all` of it can't
    /// make them, and fails with "File exists" (`mkdir` of the link,
    /// `EEXIST`) instead. The restore makes each directory before what is
    /// below it, so it gets that error only below one it failed to make,
    /// in place of that one's own.
    ///
    /// # Errors
    ///
    /// * As [`Self::path`].
    pub(crate) fn sys_path(&self, item: impl AsRef<Path>) -> LocalDestinationResult<PathBuf> {
        let path = self.path(item)?;
        Ok(match walkdir::short_path(&path) {
            std::borrow::Cow::Borrowed(_) => path,
            std::borrow::Cow::Owned(short) => short,
        })
    }

    /// Remove the given directory (relative to the base path)
    ///
    /// # Arguments
    ///
    /// * `dirname` - The directory to remove
    ///
    /// # Errors
    ///
    /// * If the directory could not be removed.
    ///
    /// # Notes
    ///
    /// This will remove the directory recursively.
    // BackOtter: unused: the restore removes through its own remove_held,
    // remove_extra and remove_tree, past restricting flags and failures.
    #[allow(clippy::unused_self, dead_code)]
    pub(crate) fn remove_dir(&self, dirname: impl AsRef<Path>) -> LocalDestinationResult<()> {
        fs::remove_dir_all(dirname).map_err(LocalDestinationErrorKind::DirectoryRemovalFailed)
    }

    /// Remove the given file (relative to the base path)
    ///
    /// # Arguments
    ///
    /// * `filename` - The file to remove
    ///
    /// # Errors
    ///
    /// * If the file could not be removed.
    ///
    /// # Notes
    ///
    /// This will remove the file.
    ///
    /// * If the file is a symlink, the symlink will be removed, not the file it points to.
    /// * If the file is a directory or device, this will fail.
    // BackOtter: unused: the restore removes through its own remove_held,
    // remove_extra and remove_tree, past restricting flags and failures.
    #[allow(clippy::unused_self, dead_code)]
    pub(crate) fn remove_file(&self, filename: impl AsRef<Path>) -> LocalDestinationResult<()> {
        fs::remove_file(filename).map_err(LocalDestinationErrorKind::FileRemovalFailed)
    }

    /// Create the given directory (relative to the base path)
    ///
    /// # Arguments
    ///
    /// * `item` - The directory to create
    ///
    /// # Errors
    ///
    /// * If the directory could not be created.
    ///
    /// # Notes
    ///
    /// This will create the directory structure recursively.
    ///
    /// BackOtter: past `PATH_MAX`, only below the deepest prefix a short
    /// path cuts, which must exist ([`Self::sys_path`]).
    pub(crate) fn create_dir(&self, item: impl AsRef<Path>) -> LocalDestinationResult<()> {
        // BackOtter: waits for the exit once XFS options are put back for it.
        let _making = crate::commands::restore::making_entries();
        let dirname = self.sys_path(item)?;
        fs::create_dir_all(dirname).map_err(LocalDestinationErrorKind::DirectoryCreationFailed)?;
        Ok(())
    }

    /// Set changed and modified times for `item` (relative to the base path) utilizing the file metadata
    ///
    /// # Arguments
    ///
    /// * `item` - The item to set the times for
    /// * `meta` - The metadata to get the times from
    ///
    /// # Errors
    ///
    /// * If the times could not be set
    pub(crate) fn set_times(
        &self,
        item: impl AsRef<Path>,
        meta: &Metadata,
    ) -> LocalDestinationResult<()> {
        let filename = self.sys_path(item)?;
        if let Some(mtime) = meta.mtime {
            let atime = meta.atime.unwrap_or(mtime);
            // BackOtter: on DragonFly filetime takes microseconds alone.
            #[cfg(target_os = "dragonfly")]
            let set = osattrs::set_times(&filename, atime, mtime);
            #[cfg(not(target_os = "dragonfly"))]
            let set = set_symlink_file_times(
                filename,
                FileTime::from_system_time(atime.into()),
                FileTime::from_system_time(mtime.into()),
            );
            set.map_err(LocalDestinationErrorKind::SettingTimeMetadataFailed)?;
        }

        Ok(())
    }

    #[cfg(windows)]
    // TODO: Windows support
    /// Set user/group for `item` (relative to the base path) utilizing the file metadata
    ///
    /// # Arguments
    ///
    /// * `item` - The item to set the user/group for
    /// * `meta` - The metadata to get the user/group from
    ///
    /// # Errors
    ///
    /// * If the user/group could not be set.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    pub(crate) fn set_user_group(
        &self,
        _item: impl AsRef<Path>,
        _meta: &Metadata,
    ) -> LocalDestinationResult<()> {
        // https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights
        // https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/struct.SECURITY_ATTRIBUTES.html
        // https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Storage/FileSystem/struct.CREATEFILE2_EXTENDED_PARAMETERS.html#structfield.lpSecurityAttributes
        Ok(())
    }

    #[cfg(not(windows))]
    /// Set user/group for `item` (relative to the base path) utilizing the file metadata
    ///
    /// # Arguments
    ///
    /// * `item` - The item to set the user/group for
    /// * `meta` - The metadata to get the user/group from
    ///
    /// # Errors
    ///
    /// * If the user/group could not be set.
    #[allow(clippy::similar_names)]
    pub(crate) fn set_user_group(
        &self,
        item: impl AsRef<Path>,
        meta: &Metadata,
    ) -> LocalDestinationResult<()> {
        let filename = self.sys_path(item)?;

        let user = meta.user.clone().and_then(helpers::uid_from_name);
        // use uid from user if valid, else from saved uid (if saved)
        let uid = user.or_else(|| meta.uid.map(Uid::from_raw));

        let group = meta.group.clone().and_then(helpers::gid_from_name);
        // use gid from group if valid, else from saved gid (if saved)
        let gid = group.or_else(|| meta.gid.map(Gid::from_raw));

        fchownat(AT_FDCWD, &filename, uid, gid, AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(LocalDestinationErrorKind::FromErrnoError)?;
        Ok(())
    }

    #[cfg(windows)]
    // TODO: Windows support
    /// Set uid/gid for `item` (relative to the base path) utilizing the file metadata
    ///
    /// # Arguments
    ///
    /// * `item` - The item to set the uid/gid for
    /// * `meta` - The metadata to get the uid/gid from
    ///
    /// # Errors
    ///
    /// * If the uid/gid could not be set.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    pub(crate) fn set_uid_gid(
        &self,
        _item: impl AsRef<Path>,
        _meta: &Metadata,
    ) -> LocalDestinationResult<()> {
        Ok(())
    }

    #[cfg(not(windows))]
    /// Set uid/gid for `item` (relative to the base path) utilizing the file metadata
    ///
    /// # Arguments
    ///
    /// * `item` - The item to set the uid/gid for
    /// * `meta` - The metadata to get the uid/gid from
    ///
    /// # Errors
    ///
    /// * If the uid/gid could not be set.
    #[allow(clippy::similar_names)]
    pub(crate) fn set_uid_gid(
        &self,
        item: impl AsRef<Path>,
        meta: &Metadata,
    ) -> LocalDestinationResult<()> {
        let filename = self.sys_path(item)?;

        let uid = meta.uid.map(Uid::from_raw);
        let gid = meta.gid.map(Gid::from_raw);

        fchownat(AT_FDCWD, &filename, uid, gid, AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(LocalDestinationErrorKind::FromErrnoError)?;
        Ok(())
    }

    // BackOtter's.
    /// Whether `err`, from [`Self::set_uid_gid`] or
    /// [`Self::set_user_group`], is one a restore says nothing about: a
    /// change of owner refused (`EPERM`, `EACCES`) to a restore not running
    /// as root. Like restic (and `cp -a`, `rsync -a`), which reports such
    /// errors only when it runs as root: a user can't give files away, so
    /// the root-owned directories above the restored path, say, keep their
    /// owners quietly.
    #[cfg(not(windows))]
    pub(crate) fn chown_refused_not_root(err: &LocalDestinationErrorKind) -> bool {
        matches!(
            err,
            LocalDestinationErrorKind::FromErrnoError(Errno::EPERM | Errno::EACCES)
        ) && !nix::unistd::geteuid().is_root()
    }

    /// Windows sets no owners.
    #[cfg(windows)]
    pub(crate) fn chown_refused_not_root(_err: &LocalDestinationErrorKind) -> bool {
        false
    }

    // BackOtter's.
    /// Whether `err`, a failure to set an owner, extended attributes, the
    /// permissions or the times that the restore warned about, is one
    /// BackOtter's restic counts as an error (exit 1): not, not running as
    /// `root`, a permission refused (a change of owner, `trusted.*` or
    /// `security.*` attributes, a file someone else owns), nor extended
    /// attributes or times the file system doesn't support
    /// ([`osattrs::XattrErrors::counts`], `osattrs::restore_error_counts`).
    pub(crate) fn error_counts(err: &LocalDestinationErrorKind, root: bool) -> bool {
        match err {
            #[cfg(not(windows))]
            LocalDestinationErrorKind::FromErrnoError(Errno::EPERM | Errno::EACCES) => root,
            #[cfg(not(any(windows, target_os = "openbsd")))]
            LocalDestinationErrorKind::XattrsNotSet(errors) => errors.counts(root),
            LocalDestinationErrorKind::SettingTimeMetadataFailed(err) => {
                osattrs::restore_error_counts(err, true, root)
            }
            #[cfg(not(windows))]
            LocalDestinationErrorKind::SettingFilePermissionsFailed(err) => {
                osattrs::restore_error_counts(err, true, root)
            }
            _ => true,
        }
    }

    #[cfg(windows)]
    // TODO: Windows support
    /// Set permissions for `item` (relative to the base path) from `node`
    ///
    /// # Arguments
    ///
    /// * `item` - The item to set the permissions for
    /// * `node` - The node to get the permissions from
    ///
    /// # Errors
    ///
    /// * If the permissions could not be set.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    pub(crate) fn set_permission(
        &self,
        _item: impl AsRef<Path>,
        _node: &Node,
        _zero_if_missing: bool,
    ) -> LocalDestinationResult<()> {
        Ok(())
    }

    #[cfg(not(windows))]
    /// Set permissions for `item` (relative to the base path) from `node`
    ///
    /// # Arguments
    ///
    /// * `item` - The item to set the permissions for
    /// * `node` - The node to get the permissions from
    /// * `zero_if_missing` - BackOtter: whether a node without a mode had
    ///   mode 0
    ///
    /// # Errors
    ///
    /// * If the permissions could not be set.
    #[allow(clippy::similar_names)]
    pub(crate) fn set_permission(
        &self,
        item: impl AsRef<Path>,
        node: &Node,
        zero_if_missing: bool,
    ) -> LocalDestinationResult<()> {
        if node.is_symlink() {
            return Ok(());
        }

        let filename = self.sys_path(item)?;

        // BackOtter: restic leaves a mode of 0 out ("omitempty"), and a
        // regular file's Go mode is its permissions alone: a file without a
        // mode, where the restore knows that means 0 (the restore's
        // `mode_zero_if_missing`), gets 0000 (/etc/shadow, say), rather than
        // keep the 0644 it was created with. Without a mode otherwise
        // (stdin, Windows, stock rustic) it keeps that, as in stock rustic.
        if let Some(mode) = node.meta.mode.or_else(|| zero_if_missing.then_some(0)) {
            let mode = map_mode_from_go(mode);
            fs::set_permissions(filename, fs::Permissions::from_mode(mode))
                .map_err(LocalDestinationErrorKind::SettingFilePermissionsFailed)?;
        }
        Ok(())
    }

    #[cfg(any(windows, target_os = "openbsd"))]
    // TODO: Windows support
    // TODO: openbsd support
    /// Set extended attributes for `item` (relative to the base path)
    ///
    /// # Arguments
    ///
    /// * `item` - The item to set the extended attributes for
    /// * `extended_attributes` - The extended attributes to set
    ///
    /// # Errors
    ///
    /// * If the extended attributes could not be set.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    pub(crate) fn set_extended_attributes(
        &self,
        _item: impl AsRef<Path>,
        _extended_attributes: &[ExtendedAttribute],
        _stock_names: bool,
    ) -> LocalDestinationResult<()> {
        Ok(())
    }

    #[cfg(any(windows, target_os = "openbsd", target_os = "illumos", target_os = "haiku"))]
    /// BackOtter: [`Self::set_extended_attributes`]; the SELinux label is
    /// Linux's only.
    pub(crate) fn set_extended_attributes_all(
        &self,
        item: impl AsRef<Path>,
        extended_attributes: &[ExtendedAttribute],
        stock_names: bool,
        _remove_label: bool,
    ) -> LocalDestinationResult<()> {
        self.set_extended_attributes(item, extended_attributes, stock_names)
    }

    #[cfg(any(target_os = "illumos", target_os = "haiku"))]
    /// BackOtter: set extended attributes for `item` (relative to the base
    /// path): on illumos, named attribute files, and on Haiku, attributes of
    /// type `B_XATTR_TYPE` (osattrs), which the xattr crate doesn't support.
    ///
    /// # Errors
    ///
    /// * Each extended attribute that couldn't be set or removed.
    pub(crate) fn set_extended_attributes(
        &self,
        item: impl AsRef<Path>,
        extended_attributes: &[ExtendedAttribute],
        _stock_names: bool,
    ) -> LocalDestinationResult<()> {
        osattrs::set_native_xattrs(&self.sys_path(item)?, extended_attributes)
            .map_err(LocalDestinationErrorKind::XattrsNotSet)
    }

    #[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos", target_os = "haiku")))]
    /// Set extended attributes for `item` (relative to the base path)
    ///
    /// # Arguments
    ///
    /// * `item` - The item to set the extended attributes for
    /// * `extended_attributes` - The extended attributes to set
    /// * `stock_names` - BackOtter: whether names may be stock rustic's,
    ///   with their namespace (`user.NAME`) on FreeBSD and NetBSD: in a
    ///   snapshot not BackOtter's ([`xattr_restore_names`])
    ///
    /// # Errors
    ///
    /// * BackOtter: each extended attribute that couldn't be set or removed,
    ///   and a failure to list them, all in one; one that can't be set
    ///   doesn't keep the others from being set or removed, as in
    ///   BackOtter's restic (stock rustic stopped at the first).
    ///
    /// # Returns
    ///
    /// Ok if the extended attributes were set.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn set_extended_attributes(
        &self,
        item: impl AsRef<Path>,
        extended_attributes: &[ExtendedAttribute],
        stock_names: bool,
    ) -> LocalDestinationResult<()> {
        self.set_extended_attributes_all(item, extended_attributes, stock_names, false)
    }

    #[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos", target_os = "haiku")))]
    /// BackOtter: [`Self::set_extended_attributes`]; with `remove_label`
    /// (`restore --exact`), an SELinux label the node doesn't have goes too.
    pub(crate) fn set_extended_attributes_all(
        &self,
        item: impl AsRef<Path>,
        extended_attributes: &[ExtendedAttribute],
        stock_names: bool,
        remove_label: bool,
    ) -> LocalDestinationResult<()> {
        let filename = self.sys_path(item)?;
        // BackOtter: nothing to do where the xattr crate has no support,
        // rather than an error for each file.
        if !xattr::SUPPORTED_PLATFORM {
            return Ok(());
        }
        let bsd_stock = stock_names && cfg!(any(target_os = "freebsd", target_os = "netbsd"));
        set_xattrs_all(&SystemXattrs, &filename, extended_attributes, bsd_stock, remove_label)
            .map_err(LocalDestinationErrorKind::XattrsNotSet)
    }

    /// Set length of `item` (relative to the base path)
    ///
    /// # Arguments
    ///
    /// * `item` - The item to set the length for
    /// * `size` - The size to set the length to
    /// * `sparse` - BackOtter: whether the file is restored sparse
    ///
    /// # Errors
    ///
    /// * If the file does not have a parent.
    /// * If the directory could not be created.
    /// * If the file could not be opened.
    /// * If the length of the file could not be set.
    ///
    /// # Notes
    ///
    /// If the file exists, truncate it to the given length. (TODO: check if this is correct)
    /// If it doesn't exist, create a new (empty) one with given length.
    ///
    /// BackOtter: a file restored sparse is emptied first, so that no hole
    /// it gets keeps old contents (it should be new, but may not be: a race);
    /// any other is allocated in full, where the system can. Past
    /// `PATH_MAX`, its parent is made only below the deepest prefix a short
    /// path cuts, as by [`Self::create_dir`].
    ///
    /// # Returns
    ///
    /// BackOtter: the file, open for writing, which the restore writes its
    /// contents through ([`Self::write_at`], [`Self::write_sparse_at`]), so
    /// that it isn't opened again for each blob.
    pub(crate) fn set_length(
        &self,
        item: impl AsRef<Path>,
        size: u64,
        sparse: bool,
    ) -> LocalDestinationResult<File> {
        // BackOtter: waits for the exit once XFS options are put back for it.
        let _making = crate::commands::restore::making_entries();
        let filename = self.sys_path(item)?;
        let dir = filename
            .parent()
            .ok_or_else(|| LocalDestinationErrorKind::FileDoesNotHaveParent(filename.clone()))?;
        fs::create_dir_all(dir).map_err(LocalDestinationErrorKind::DirectoryCreationFailed)?;

        let file = OpenOptions::new()
            .create(true)
            .truncate(sparse)
            .write(true)
            .open(filename)
            .map_err(LocalDestinationErrorKind::OpeningFileFailed)?;
        file.set_len(size)
            .map_err(LocalDestinationErrorKind::SettingFileLengthFailed)?;
        if !sparse {
            osattrs::preallocate(&file, size);
        }
        Ok(file)
    }

    /// BackOtter: opens `item` (relative to the base path), a file the
    /// restore sized already ([`Self::set_length`]) and closed while it had
    /// writes to come, for writing again: neither emptied nor resized. It is
    /// created if it doesn't exist, as stock rustic's writes did.
    ///
    /// # Errors
    ///
    /// * If the file could not be opened.
    pub(crate) fn open_for_write(&self, item: impl AsRef<Path>) -> LocalDestinationResult<File> {
        // BackOtter: waits for the exit once XFS options are put back for it.
        let _making = crate::commands::restore::making_entries();
        let filename = self.sys_path(item)?;
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(filename)
            .map_err(LocalDestinationErrorKind::OpeningFileFailed)
    }

    #[cfg(windows)]
    // TODO: Windows support
    /// Create a special file (relative to the base path)
    ///
    /// # Arguments
    ///
    /// * `item` - The item to create
    /// * `node` - The node to get the type from
    ///
    /// # Errors
    ///
    /// * If the special file could not be created.
    ///
    /// # Returns
    ///
    /// Ok if the special file was created.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    pub(crate) fn create_special(
        &self,
        _item: impl AsRef<Path>,
        _node: &Node,
    ) -> LocalDestinationResult<()> {
        Ok(())
    }

    #[cfg(not(windows))]
    /// Create a special file (relative to the base path)
    ///
    /// # Arguments
    ///
    /// * `item` - The item to create
    /// * `node` - The node to get the type from
    ///
    /// # Errors
    ///
    /// * If the symlink could not be created.
    /// * If the device could not be converted to the correct type.
    /// * If the device could not be created.
    pub(crate) fn create_special(
        &self,
        item: impl AsRef<Path>,
        node: &Node,
    ) -> LocalDestinationResult<()> {
        // BackOtter: waits for the exit once XFS options are put back for it.
        let _making = crate::commands::restore::making_entries();
        let filename = self.sys_path(item)?;

        match &node.node_type {
            NodeType::Symlink { .. } => {
                let linktarget = node.node_type.to_link();
                symlink(linktarget, &filename).map_err(|err| {
                    LocalDestinationErrorKind::SymlinkingFailed {
                        linktarget: linktarget.to_path_buf(),
                        filename,
                        source: err,
                    }
                })?;
            }
            NodeType::Dev { device } => {
                #[cfg(not(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "openbsd",
                    target_os = "dragonfly",
                    target_os = "haiku",
                    all(target_os = "android", target_pointer_width = "32")
                )))]
                let device = *device;
                // BackOtter: Haiku's dev_t is an i32 too.
                #[cfg(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "openbsd",
                    target_os = "haiku"
                ))]
                let device = i32::try_from(*device).map_err(|err| {
                    LocalDestinationErrorKind::DeviceIdConversionFailed {
                        target: "i32".to_string(),
                        device: *device,
                        source: err,
                    }
                })?;
                // BackOtter: DragonFly's dev_t is a u32 too.
                #[cfg(any(
                    target_os = "dragonfly",
                    all(target_os = "android", target_pointer_width = "32")
                ))]
                let device = u32::try_from(*device).map_err(|err| {
                    LocalDestinationErrorKind::DeviceIdConversionFailed {
                        target: "u32".to_string(),
                        device: *device,
                        source: err,
                    }
                })?;
                mknod(&filename, SFlag::S_IFBLK, Mode::empty(), device)
                    .map_err(LocalDestinationErrorKind::FromErrnoError)?;
            }
            NodeType::Chardev { device } => {
                #[cfg(not(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "openbsd",
                    target_os = "dragonfly",
                    target_os = "haiku",
                    all(target_os = "android", target_pointer_width = "32")
                )))]
                let device = *device;
                // BackOtter: Haiku's dev_t is an i32 too.
                #[cfg(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "openbsd",
                    target_os = "haiku"
                ))]
                let device = i32::try_from(*device).map_err(|err| {
                    LocalDestinationErrorKind::DeviceIdConversionFailed {
                        target: "i32".to_string(),
                        device: *device,
                        source: err,
                    }
                })?;
                // BackOtter: DragonFly's dev_t is a u32 too.
                #[cfg(any(
                    target_os = "dragonfly",
                    all(target_os = "android", target_pointer_width = "32")
                ))]
                let device = u32::try_from(*device).map_err(|err| {
                    LocalDestinationErrorKind::DeviceIdConversionFailed {
                        target: "u32".to_string(),
                        device: *device,
                        source: err,
                    }
                })?;
                mknod(&filename, SFlag::S_IFCHR, Mode::empty(), device)
                    .map_err(LocalDestinationErrorKind::FromErrnoError)?;
            }
            NodeType::Fifo => {
                mknod(&filename, SFlag::S_IFIFO, Mode::empty(), 0)
                    .map_err(LocalDestinationErrorKind::FromErrnoError)?;
            }
            NodeType::Socket => {
                mknod(&filename, SFlag::S_IFSOCK, Mode::empty(), 0)
                    .map_err(LocalDestinationErrorKind::FromErrnoError)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Read the given item (relative to the base path)
    ///
    /// # Arguments
    ///
    /// * `item` - The item to read
    /// * `offset` - The offset to read from
    /// * `length` - The length to read
    ///
    /// # Errors
    ///
    /// * If the file could not be opened.
    /// * If the file could not be sought to the given position.
    /// * If the length of the file could not be converted to u32.
    /// * If the length of the file could not be read.
    pub(crate) fn read_at(
        &self,
        item: impl AsRef<Path>,
        offset: u64,
        length: u64,
    ) -> LocalDestinationResult<Bytes> {
        let filename = self.sys_path(item)?;
        // BackOtter: reading leaves the file's atime alone (open_reading).
        let mut file =
            open_reading(&filename).map_err(LocalDestinationErrorKind::OpeningFileFailed)?;
        _ = file
            .seek(SeekFrom::Start(offset))
            .map_err(LocalDestinationErrorKind::CouldNotSeekToPositionInFile)?;
        let mut vec = vec![
            0;
            length.try_into().map_err(|err| {
                LocalDestinationErrorKind::LengthConversionFailed {
                    target: "u8".to_string(),
                    length,
                    source: err,
                }
            })?
        ];
        file.read_exact(&mut vec)
            .map_err(LocalDestinationErrorKind::ReadingExactLengthOfFileFailed)?;
        Ok(vec.into())
    }

    /// Check if a matching file exists.
    ///
    /// # Arguments
    ///
    /// * `item` - The item to check
    /// * `size` - The size to check
    ///
    /// # Returns
    ///
    /// If a file exists and size matches, this returns a `File` open for reading.
    /// In all other cases, returns `None`
    pub fn get_matching_file(&self, item: impl AsRef<Path>, size: u64) -> Option<File> {
        let filename = self.sys_path(item).ok()?;
        fs::symlink_metadata(&filename).map_or_else(
            |_| None,
            |meta| {
                if meta.is_file() && meta.len() == size {
                    open_to_verify(&filename, size)
                } else {
                    None
                }
            },
        )
    }

    /// Write `data` to the given file at `offset`
    ///
    /// # Arguments
    ///
    /// * `file` - The file to write to, open for writing
    /// * `offset` - The offset to write at
    /// * `data` - The data to write
    ///
    /// # Errors
    ///
    /// * If the bytes could not be written to the file.
    ///
    /// # Notes
    ///
    /// BackOtter: the restore keeps a file open while it has blobs to come
    /// (`commands::restore::files_writer`), which its threads write at once:
    /// a positioned write, which leaves the handle's position alone. Stock
    /// rustic opened the file by its path for each blob, sought and wrote.
    pub(crate) fn write_at(file: &File, offset: u64, data: &[u8]) -> LocalDestinationResult<()> {
        // BackOtter: waits for the exit once XFS options are put back for it.
        let _making = crate::commands::restore::making_entries();
        write_all_at(file, data, offset).map_err(LocalDestinationErrorKind::CouldNotWriteToBuffer)
    }

    /// BackOtter: write `data` to `file`, a file restored sparse, at
    /// `offset`, leaving holes: of each block of the file system
    /// ([`osattrs::hole_block_size`]) that `data` reaches into, the part
    /// inside `data` isn't written if it is all zeros ([`sparse_writes`]).
    /// The file must be new, sized without being allocated: what isn't
    /// written reads as zeros. Positioned writes, as in [`Self::write_at`].
    ///
    /// # Errors
    ///
    /// * If the bytes could not be written to the file.
    pub(crate) fn write_sparse_at(
        file: &File,
        offset: u64,
        data: &[u8],
    ) -> LocalDestinationResult<()> {
        // BackOtter: waits for the exit once XFS options are put back for it.
        let _making = crate::commands::restore::making_entries();
        for range in sparse_writes(offset, data, osattrs::hole_block_size(file)) {
            let at = offset + range.start as u64;
            write_all_at(file, &data[range], at)
                .map_err(LocalDestinationErrorKind::CouldNotWriteToBuffer)?;
        }
        Ok(())
    }

    /// Create a hardlink `item` pointing to `source_item`, both relative to the base path.
    ///
    /// An entry that already exists at `item` is replaced, unless it already is that hardlink.
    ///
    /// # Arguments
    ///
    /// * `source_item` - The already-restored file to link to
    /// * `item` - The path to create as a hardlink
    ///
    /// # Errors
    ///
    /// * If the new hardlink does not have a parent directory.
    /// * If the directory could not be created.
    /// * If a file already at `item` could not be removed.
    /// * If the hardlink could not be created.
    ///
    /// # Notes
    ///
    /// BackOtter: as in BackOtter's restic, what is at `item` already
    /// (another file, a symlink) is replaced, as the link can't be made over
    /// it (`EEXIST`); the same link, left by an earlier restore, is left as
    /// it is (upstream's #634), which also keeps the file when a symlinked
    /// directory makes both names one. A directory there is an error. Past
    /// `PATH_MAX`, its parent is made only below the deepest prefix a short
    /// path cuts, as by [`Self::create_dir`].
    pub(crate) fn hard_link(
        &self,
        source_item: impl AsRef<Path>,
        item: impl AsRef<Path>,
    ) -> LocalDestinationResult<()> {
        // BackOtter: waits for the exit once XFS options are put back for it.
        let _making = crate::commands::restore::making_entries();
        let source_path = self.sys_path(source_item)?;
        let filename = self.sys_path(item)?;
        let dir = filename
            .parent()
            .ok_or_else(|| LocalDestinationErrorKind::FileDoesNotHaveParent(filename.clone()))?;
        fs::create_dir_all(dir).map_err(LocalDestinationErrorKind::DirectoryCreationFailed)?;
        link_over_existing(&source_path, &filename).map_err(|err| {
            LocalDestinationErrorKind::HardLinkingFailed {
                source_path,
                filename,
                source: err,
            }
        })?;
        Ok(())
    }
}

// BackOtter: the extended attribute sync, the sparse and positioned
// writes, the opens for reading and their tests are in a file of the
// fork's own (local_destination/bko.rs).
mod bko;
pub(crate) use bko::is_zero;
#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos", target_os = "haiku")))]
use bko::{SystemXattrs, set_xattrs_all};
use bko::{open_reading, open_to_verify, sparse_writes, write_all_at};

/// Hardlink `filename` to `source`, replacing a different entry that sits at `filename`.
///
/// # Arguments
///
/// * `source` - The file to link to
/// * `filename` - The path of the hardlink
///
/// # Errors
///
/// * If `filename` could not be inspected, removed or linked.
fn link_over_existing(source: &Path, filename: &Path) -> std::io::Result<()> {
    match fs::hard_link(source, filename) {
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let is_symlink = fs::symlink_metadata(filename)?.is_symlink();
            if !is_symlink && is_same_file(source, filename)? {
                return Ok(());
            }
            fs::remove_file(filename)?;
            fs::hard_link(source, filename)
        }
        linked => linked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn hard_link_leaves_a_directory_in_place() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let dest = LocalDestination::new(temp.path().to_str().unwrap(), false, false)?;
        fs::write(temp.path().join("canonical"), "restored")?;
        fs::create_dir(temp.path().join("link"))?;

        assert!(dest.hard_link("canonical", "link").is_err());

        assert!(temp.path().join("link").is_dir());
        Ok(())
    }

    #[test]
    #[cfg(not(windows))]
    fn hard_link_replaces_a_symlink_to_the_canonical_file() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempdir()?;
        let dest = LocalDestination::new(temp.path().to_str().unwrap(), false, false)?;
        fs::write(temp.path().join("canonical"), "restored")?;
        symlink("canonical", temp.path().join("link"))?;

        dest.hard_link("canonical", "link")?;

        assert!(!fs::symlink_metadata(temp.path().join("link"))?.is_symlink());
        Ok(())
    }

    #[test]
    #[cfg(not(windows))]
    fn hard_link_keeps_the_file_when_a_symlinked_directory_makes_both_paths_one()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let dest = LocalDestination::new(temp.path().to_str().unwrap(), false, false)?;
        fs::create_dir(temp.path().join("real"))?;
        symlink("real", temp.path().join("alias"))?;
        fs::write(temp.path().join("real/canonical"), "restored")?;

        dest.hard_link("real/canonical", "alias/canonical")?;

        assert_eq!(
            fs::read_to_string(temp.path().join("real/canonical"))?,
            "restored"
        );
        Ok(())
    }

    #[test]
    fn test_path_sanitization() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let dest = LocalDestination::new(temp.path().to_str().unwrap(), false, false)?;

        // Valid relative paths
        assert_eq!(dest.path("foo/bar")?, temp.path().join("foo/bar"));
        assert_eq!(dest.path("./foo")?, temp.path().join("foo"));
        assert_eq!(dest.path("")?, temp.path());

        // Path traversal attempts
        assert!(dest.path("../escaped").is_err());
        assert!(dest.path("../../etc/passwd").is_err());
        assert!(dest.path("a/../../b").is_err());
        assert!(dest.path("/absolute/path").is_err());

        Ok(())
    }

    #[test]
    fn test_operations_reject_traversal() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let dest = LocalDestination::new(temp.path().to_str().unwrap(), false, false)?;

        assert!(dest.create_dir("../escaped_dir").is_err());
        assert!(dest.set_length("../escaped_file", 4, false).is_err());
        assert!(dest.open_for_write("../escaped_file").is_err());
        assert!(dest.read_at("../escaped_file", 0, 4).is_err());
        assert!(dest.get_matching_file("../escaped_file", 4).is_none());

        Ok(())
    }
}
