#[cfg(not(windows))]
use std::os::unix::fs::{PermissionsExt, symlink};

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
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
    DirectoryRemovalFailed(std::io::Error),
    /// removing file failed: `{0:?}`
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
    #[allow(clippy::unused_self)]
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
    #[allow(clippy::unused_self)]
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
    pub(crate) fn create_dir(&self, item: impl AsRef<Path>) -> LocalDestinationResult<()> {
        let dirname = self.path(item)?;
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
        let filename = self.path(item)?;
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
        let filename = self.path(item)?;

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
        let filename = self.path(item)?;

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

        let filename = self.path(item)?;

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
        osattrs::set_native_xattrs(&self.path(item)?, extended_attributes)
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
        let filename = self.path(item)?;
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
    /// any other is allocated in full, where the system can.
    pub(crate) fn set_length(
        &self,
        item: impl AsRef<Path>,
        size: u64,
        sparse: bool,
    ) -> LocalDestinationResult<()> {
        let filename = self.path(item)?;
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
        Ok(())
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
        let filename = self.path(item)?;

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
                    target_os = "openbsd",
                    target_os = "dragonfly",
                    target_os = "haiku",
                    all(target_os = "android", target_pointer_width = "32")
                )))]
                let device = *device;
                // BackOtter: Haiku's dev_t is an i32 too.
                #[cfg(any(target_os = "macos", target_os = "openbsd", target_os = "haiku"))]
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
                    target_os = "openbsd",
                    target_os = "dragonfly",
                    target_os = "haiku",
                    all(target_os = "android", target_pointer_width = "32")
                )))]
                let device = *device;
                // BackOtter: Haiku's dev_t is an i32 too.
                #[cfg(any(target_os = "macos", target_os = "openbsd", target_os = "haiku"))]
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
        let filename = self.path(item)?;
        let mut file =
            File::open(filename).map_err(LocalDestinationErrorKind::OpeningFileFailed)?;
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
        let filename = self.path(item).ok()?;
        fs::symlink_metadata(&filename).map_or_else(
            |_| None,
            |meta| {
                if meta.is_file() && meta.len() == size {
                    File::open(&filename).ok()
                } else {
                    None
                }
            },
        )
    }

    /// Write `data` to given item (relative to the base path) at `offset`
    ///
    /// # Arguments
    ///
    /// * `item` - The item to write to
    /// * `offset` - The offset to write at
    /// * `data` - The data to write
    ///
    /// # Errors
    ///
    /// * If the file could not be opened.
    /// * If the file could not be sought to the given position.
    /// * If the bytes could not be written to the file.
    ///
    /// # Notes
    ///
    /// This will create the file if it doesn't exist.
    pub(crate) fn write_at(
        &self,
        item: impl AsRef<Path>,
        offset: u64,
        data: &[u8],
    ) -> LocalDestinationResult<()> {
        let filename = self.path(item)?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(filename)
            .map_err(LocalDestinationErrorKind::OpeningFileFailed)?;
        _ = file
            .seek(SeekFrom::Start(offset))
            .map_err(LocalDestinationErrorKind::CouldNotSeekToPositionInFile)?;
        file.write_all(data)
            .map_err(LocalDestinationErrorKind::CouldNotWriteToBuffer)?;
        Ok(())
    }

    /// BackOtter: write `data` to the given item (relative to the base
    /// path), a file restored sparse, at `offset`, leaving holes: of each
    /// block of the file system ([`osattrs::hole_block_size`]) that `data`
    /// reaches into, the part inside `data` isn't written if it is all
    /// zeros ([`sparse_writes`]). The file must be new, sized without being
    /// allocated: what isn't written reads as zeros.
    ///
    /// # Errors
    ///
    /// * If the file could not be opened.
    /// * If the file could not be sought to the given position.
    /// * If the bytes could not be written to the file.
    pub(crate) fn write_sparse_at(
        &self,
        item: impl AsRef<Path>,
        offset: u64,
        data: &[u8],
    ) -> LocalDestinationResult<()> {
        let filename = self.path(item)?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(filename)
            .map_err(LocalDestinationErrorKind::OpeningFileFailed)?;
        for range in sparse_writes(offset, data, osattrs::hole_block_size(&file)) {
            _ = file
                .seek(SeekFrom::Start(offset + range.start as u64))
                .map_err(LocalDestinationErrorKind::CouldNotSeekToPositionInFile)?;
            file.write_all(&data[range])
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
    /// directory makes both names one. A directory there is an error.
    pub(crate) fn hard_link(
        &self,
        source_item: impl AsRef<Path>,
        item: impl AsRef<Path>,
    ) -> LocalDestinationResult<()> {
        let source_path = self.path(source_item)?;
        let filename = self.path(item)?;
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

/// BackOtter: the calls [`set_xattrs_with`] makes to read and change a
/// file's extended attributes, by the names the xattr crate takes: the
/// system's ([`SystemXattrs`]), or a test's.
#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos", target_os = "haiku")))]
trait XattrCalls {
    fn list(&self, path: &Path) -> std::io::Result<Vec<std::ffi::OsString>>;
    fn get(&self, path: &Path, name: &std::ffi::OsStr) -> std::io::Result<Option<Vec<u8>>>;
    fn set(&self, path: &Path, name: &str, value: &[u8]) -> std::io::Result<()>;
    fn remove(&self, path: &Path, name: &std::ffi::OsStr) -> std::io::Result<()>;
    /// Says that bcachefs refused to change the casefolding (`name`) of
    /// `path`, a directory with entries ([`osattrs::casefold_not_empty`]).
    fn warn_casefold(&self, name: &str, path: &Path);
}

/// BackOtter: the system's extended attribute calls, through osattrs and
/// the xattr crate.
#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos", target_os = "haiku")))]
struct SystemXattrs;

#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos", target_os = "haiku")))]
impl XattrCalls for SystemXattrs {
    fn list(&self, path: &Path) -> std::io::Result<Vec<std::ffi::OsString>> {
        osattrs::xattr_list(path)
    }
    fn get(&self, path: &Path, name: &std::ffi::OsStr) -> std::io::Result<Option<Vec<u8>>> {
        osattrs::xattr_get(path, name)
    }
    fn set(&self, path: &Path, name: &str, value: &[u8]) -> std::io::Result<()> {
        xattr::set(path, name, value)
    }
    fn remove(&self, path: &Path, name: &std::ffi::OsStr) -> std::io::Result<()> {
        xattr::remove(path, name)
    }
    fn warn_casefold(&self, name: &str, path: &Path) {
        warn_casefold_not_empty(name, path);
    }
}

/// BackOtter: for the extended attribute a node names `name`, the name the
/// sync of a file's attributes matches it by (a node's name for one the
/// system lists, [`osattrs::xattr_node_name`]), or `None` for one the system
/// doesn't list, and the name the xattr crate sets it by.
///
/// With `bsd_stock` (FreeBSD or NetBSD, a snapshot not BackOtter's), a name
/// that begins with `user.` or `system.` is stock rustic's, which kept the
/// namespace (BackOtter's, as restic's, is the bare name of one in the user
/// namespace): it is set by that name, under its namespace, and a `user.`
/// one matches the bare name the system lists; `system.` ones are not
/// listed (nor removed). Otherwise the node's name, set as
/// [`osattrs::xattr_os_name`] says.
#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos", target_os = "haiku")))]
fn xattr_restore_names(name: &str, bsd_stock: bool) -> (Option<String>, String) {
    if bsd_stock {
        if let Some(bare) = name.strip_prefix("user.") {
            return (Some(bare.to_string()), name.to_string());
        }
        if name.starts_with("system.") {
            return (None, name.to_string());
        }
    }
    (Some(name.to_string()), osattrs::xattr_os_name(name))
}

/// BackOtter: gives `filename` exactly the extended attributes
/// `extended_attributes`, with `calls` ([`LocalDestination::set_extended_attributes`]);
/// `bsd_stock` as [`xattr_restore_names`] takes it.
///
/// # Errors
///
/// * Each extended attribute that couldn't be set or removed, and a failure
///   to list them, all in one.
#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos", target_os = "haiku")))]
fn set_xattrs_with(
    calls: &impl XattrCalls,
    filename: &Path,
    extended_attributes: &[ExtendedAttribute],
    bsd_stock: bool,
) -> Result<(), osattrs::XattrErrors> {
    set_xattrs_all(calls, filename, extended_attributes, bsd_stock, false)
}

/// BackOtter: [`set_xattrs_with`]; with `remove_label`, an SELinux label
/// that isn't among `extended_attributes` is removed too (`restore --exact`).
#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos", target_os = "haiku")))]
fn set_xattrs_all(
    calls: &impl XattrCalls,
    filename: &Path,
    extended_attributes: &[ExtendedAttribute],
    bsd_stock: bool,
    remove_label: bool,
) -> Result<(), osattrs::XattrErrors> {
    let names: Vec<_> = extended_attributes
        .iter()
        .map(|ExtendedAttribute { name, .. }| xattr_restore_names(name, bsd_stock))
        .collect();
    let mut done = vec![false; extended_attributes.len()];
    let mut errors = osattrs::XattrErrors::default();

    // BackOtter: osattrs::xattr_list, as the xattr crate's list misnames
    // one on FreeBSD; and a file that can't have any (a FIFO on ZFS)
    // needs none. Where they can't be listed for another reason, they
    // are still set, as in restic.
    let curr_names = match calls.list(filename) {
        Ok(names) => names,
        Err(err)
            if err.kind() == std::io::ErrorKind::Unsupported
                && extended_attributes.is_empty() =>
        {
            return Ok(());
        }
        // BackOtter: a file system without them; the warning names
        // each attribute, as it does those that can't be set.
        Err(err) if err.kind() == std::io::ErrorKind::Unsupported => {
            for ExtendedAttribute { name, .. } in extended_attributes {
                errors.push(name.as_str(), osattrs::same_error(&err));
            }
            return Err(errors);
        }
        Err(err) => {
            errors.push("listing", err);
            Vec::new()
        }
    };
    for curr_name in curr_names {
        // BackOtter: restic's names; FreeBSD's system namespace is
        // restored from a generic attribute (osattrs), and left alone.
        let Some(curr_node_name) = osattrs::xattr_node_name(&curr_name) else {
            continue;
        };
        match names
            .iter()
            .position(|(matched, _)| matched.as_ref() == Some(&curr_node_name))
        {
            // BackOtter: one with the right value already is left; one
            // that can't be read is set below, as are the others.
            Some(index) => {
                let value = &extended_attributes[index].value;
                if calls.get(filename, &curr_name).is_ok_and(|curr| value == &curr) {
                    done[index] = true;
                }
            }
            // BackOtter: nor the SELinux label (osattrs::xattr_never_removed).
            None if !remove_label && osattrs::xattr_never_removed(&curr_node_name) => {}
            None => {
                if let Err(err) = calls.remove(filename, &curr_name) {
                    // BackOtter: bcachefs refusing to clear casefolding
                    // on a directory with entries is a warning.
                    if osattrs::casefold_not_empty(&curr_node_name, &err) {
                        calls.warn_casefold(&curr_node_name, filename);
                    } else {
                        errors.push(format!("removing {curr_node_name}"), err);
                    }
                }
            }
        }
    }

    for (index, ExtendedAttribute { name, value }) in extended_attributes.iter().enumerate() {
        if !done[index] {
            let (matched, os_name) = &names[index];
            // BackOtter: not one that isn't kept (bcachefs_effective.*,
            // which stock restic keeps), whose setting does nothing; a
            // stock name of the system namespace is set.
            if matched.is_some() && osattrs::xattr_node_name(os_name.as_ref()).is_none() {
                continue;
            }
            if let Err(err) = calls.set(filename, os_name, value.as_deref().unwrap_or_default()) {
                // BackOtter: bcachefs refusing casefolding on a
                // directory with entries is a warning, as for F.
                if osattrs::casefold_not_empty(name, &err) {
                    calls.warn_casefold(name, filename);
                } else {
                    errors.push(name.as_str(), err);
                }
            }
        }
    }

    errors.into_result()
}

/// BackOtter: the warning for bcachefs refusing to change the casefolding
/// (`name`, `bcachefs.casefold`) of `path`, a directory with entries
/// ([`osattrs::casefold_not_empty`]), as BackOtter's restic gives it.
#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos", target_os = "haiku")))]
fn warn_casefold_not_empty(name: &str, path: &Path) {
    log::warn!(
        "casefolding ({name}) not restored on {}: directory not empty",
        path.display()
    );
}

/// BackOtter: the ranges of `data`, written at `offset` of a file restored
/// sparse, that are written, as BackOtter's restic writes them: of each
/// block of `block` bytes, aligned to the file's offsets, that `data`
/// reaches into, the part inside `data`, unless it is all zeros. Nothing
/// outside `data` is written: the file is new and sized without being
/// allocated, so what no blob writes reads as zeros, and a block is
/// allocated only if some blob puts a byte other than zero in it. Adjacent
/// parts are one range.
fn sparse_writes(offset: u64, data: &[u8], block: u64) -> Vec<std::ops::Range<usize>> {
    let block = block.max(1);
    let mut writes: Vec<std::ops::Range<usize>> = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        // The end of the block data[pos] is in, or of data.
        let rest = block - (offset + pos as u64) % block;
        let next = usize::try_from(rest).map_or(data.len(), |n| n.min(data.len() - pos) + pos);
        if !is_zero(&data[pos..next]) {
            match writes.last_mut() {
                Some(last) if last.end == pos => last.end = next,
                _ => writes.push(pos..next),
            }
        }
        pos = next;
    }
    writes
}

/// Whether `data` is all zeros: by pieces the compiler vectorizes, which
/// a check byte by byte with an early stop isn't.
pub(crate) fn is_zero(data: &[u8]) -> bool {
    data.chunks(1024)
        .all(|piece| piece.iter().fold(0, |acc, &b| acc | b) == 0)
}

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
mod sparse_tests {
    use proptest::prelude::*;

    use super::*;

    /// The writes are in order, apart, and inside `data`; applied to zeros
    /// they give `data`; they start and end at `data`'s ends or at block
    /// boundaries; and of the blocks `data` reaches into, they touch those
    /// whose part in `data` has a byte other than zero, and no other.
    fn check(offset: u64, data: &[u8], block: u64) -> Vec<std::ops::Range<usize>> {
        let writes = sparse_writes(offset, data, block);
        let mut out = vec![0; data.len()];
        let mut end = None;
        for range in &writes {
            assert!(end.is_none_or(|end| range.start > end), "{writes:?}");
            assert!(range.start < range.end && range.end <= data.len(), "{writes:?}");
            for at in [range.start, range.end] {
                assert!(
                    at == 0 || at == data.len() || (offset + at as u64).is_multiple_of(block),
                    "{writes:?}"
                );
            }
            out[range.clone()].copy_from_slice(&data[range.clone()]);
            end = Some(range.end);
        }
        assert_eq!(out, data);
        let mut pos = 0;
        while pos < data.len() {
            let next = usize::try_from(block - (offset + pos as u64) % block)
                .unwrap()
                .min(data.len() - pos)
                + pos;
            let touched = writes.iter().any(|w| w.start < next && pos < w.end);
            let nonzero = data[pos..next].iter().any(|&b| b != 0);
            assert_eq!(touched, nonzero, "block part {pos}..{next}: {writes:?}");
            pos = next;
        }
        writes
    }

    #[test]
    fn sparse_writes_cases() {
        const B: u64 = 4096;
        const K: usize = 4096;
        let zeros = vec![0_u8; 4 * K];
        // All zeros, aligned or not, longer or shorter than a block:
        // nothing written.
        assert!(check(0, &zeros, B).is_empty());
        assert!(check(8192, &zeros, B).is_empty());
        assert!(check(100, &zeros, B).is_empty());
        assert!(check(0, &zeros[..4095], B).is_empty());
        assert!(check(1, &zeros[..4096], B).is_empty());
        assert!(check(0, &[], B).is_empty());
        // Data in the second block: that block.
        let mut data = zeros.clone();
        data[5000] = 1;
        assert_eq!(check(0, &data, B), vec![K..2 * K]);
        // And at the end of the last.
        data[4 * K - 1] = 1;
        assert_eq!(check(0, &data, B), vec![K..2 * K, 3 * K..4 * K]);
        // Unaligned: a partial block at either end is written only if it
        // has data, and only its part in the blob.
        let mut data = zeros.clone();
        data[0] = 1;
        assert_eq!(check(100, &data, B), vec![0..3996]);
        let mut data = zeros.clone();
        data[4 * K - 1] = 1;
        assert_eq!(check(100, &data, B), vec![3996 + 3 * K..4 * K]);
        let mut data = zeros.clone();
        data[4000] = 1;
        assert_eq!(check(100, &data, B), vec![3996..3996 + K]);
        // A blob inside one block, with data: all of it.
        assert_eq!(check(10, &[0, 0, 5, 0], B), vec![0..4]);
        // Data blocks side by side: one write.
        assert_eq!(check(7, &[1; 10000], B), vec![0..10000]);
        let mut data = zeros;
        data[K - 1] = 1;
        data[K] = 1;
        assert_eq!(check(0, &data, B), vec![0..2 * K]);
        // Larger blocks (ZFS's records).
        assert!(check(0, &vec![0; 300 << 10], 128 << 10).is_empty());
        let mut data = vec![0; 300 << 10];
        data[260 << 10] = 1;
        assert_eq!(check(0, &data, 128 << 10), vec![256 << 10..300 << 10]);
    }

    proptest! {
        #[test]
        fn sparse_writes_give_the_data(
            offset in 0_u64..20_000,
            runs in prop::collection::vec((0_u8..3, 1_usize..12_000), 0..12),
            block in prop::sample::select(vec![1_u64, 512, 4096, 16384]),
        ) {
            // Runs of zeros, of data, and of zeros with a byte of data here
            // and there.
            let mut data = Vec::new();
            for (i, (kind, len)) in runs.into_iter().enumerate() {
                let byte = u8::try_from(i % 255 + 1).unwrap();
                data.extend((0..len).map(|j| match kind {
                    0 => 0,
                    1 => byte,
                    _ => u8::from(j % 5000 == 4999) * byte,
                }));
            }
            _ = check(offset, &data, block);
            _ = check(offset + (1 << 32) + 1, &data, block);
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn xattr(name: &str, value: &[u8]) -> ExtendedAttribute {
        ExtendedAttribute {
            name: name.to_string(),
            value: Some(value.to_vec()),
        }
    }

    /// BackOtter: a change of owner refused to a restore not running as root
    /// is quiet (as in restic); any other failure, and every failure as
    /// root, isn't.
    #[test]
    fn chown_refused_quiet_only_not_root() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("f"), b"").unwrap();
        let dest = LocalDestination::new(dir.path().to_str().unwrap(), false, false).unwrap();
        let meta = Metadata {
            uid: Some(0),
            gid: Some(0),
            ..Default::default()
        };
        let res = dest.set_uid_gid("f", &meta);
        let eperm = LocalDestinationErrorKind::FromErrnoError(Errno::EPERM);
        let eio = LocalDestinationErrorKind::FromErrnoError(Errno::EIO);
        assert!(!LocalDestination::chown_refused_not_root(&eio));
        if nix::unistd::geteuid().is_root() {
            res.unwrap();
            assert!(!LocalDestination::chown_refused_not_root(&eperm));
        } else {
            let err = res.unwrap_err();
            assert!(LocalDestination::chown_refused_not_root(&err), "{err}");
            assert!(LocalDestination::chown_refused_not_root(&eperm));
        }
    }

    /// BackOtter: an extended attribute that can't be set, first in the node,
    /// doesn't keep the others from being set, or those the node hasn't from
    /// being removed; the error names each one that failed.
    #[test]
    fn xattr_not_settable_first() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        fs::write(&file, b"").unwrap();
        // A file system without user extended attributes can't show it.
        if xattr::set(&file, "user.old", b"x").is_err() {
            eprintln!("no user extended attributes in {}", dir.path().display());
            return;
        }
        let dest = LocalDestination::new(dir.path().to_str().unwrap(), false, false).unwrap();
        // Linux has no namespace "bogus": EOPNOTSUPP, for root too. Not as
        // root, trusted.* gives EPERM.
        let mut attrs = vec![xattr("bogus.a", b"1"), xattr("user.b", b"2")];
        if !nix::unistd::geteuid().is_root() {
            attrs.insert(0, xattr("trusted.t", b"0"));
        }
        attrs.push(xattr("bogus.c", b"3"));
        let err = dest.set_extended_attributes("f", &attrs, false).unwrap_err().to_string();
        assert_eq!(xattr::get(&file, "user.b").unwrap(), Some(b"2".to_vec()));
        assert_eq!(xattr::get(&file, "user.old").unwrap(), None);
        assert!(err.contains("bogus.a: "), "{err}");
        assert!(err.ends_with(&format!("; bogus.c: {}", std::io::Error::from_raw_os_error(95))));
        assert!(!err.contains("user."), "{err}");
        if !nix::unistd::geteuid().is_root() {
            assert!(err.starts_with("trusted.t: Operation not permitted"), "{err}");
        }

        // Again, over its own result: only the attributes that can't be set.
        let err = dest.set_extended_attributes("f", &attrs, false).unwrap_err().to_string();
        assert!(!err.contains("user."), "{err}");
        assert_eq!(xattr::get(&file, "user.b").unwrap(), Some(b"2".to_vec()));

        // A node without any removes them all.
        dest.set_extended_attributes("f", &[], false).unwrap();
        assert_eq!(xattr::list(&file).unwrap().count(), 0);
    }

    /// BackOtter: extended attribute calls on one file, kept in a map: those
    /// in `not_empty` are refused, set or removed, with `ENOTEMPTY`, as
    /// bcachefs refuses `bcachefs.casefold` on a directory with entries.
    #[derive(Default)]
    struct FakeXattrs {
        attrs: std::cell::RefCell<std::collections::BTreeMap<String, Vec<u8>>>,
        not_empty: Vec<&'static str>,
        warned: std::cell::RefCell<Vec<String>>,
        /// The error those in `not_empty` are refused with, if not
        /// `ENOTEMPTY`.
        errno: Option<i32>,
    }

    impl FakeXattrs {
        fn with(attrs: &[(&str, &[u8])], not_empty: &[&'static str]) -> Self {
            Self {
                attrs: std::cell::RefCell::new(
                    attrs
                        .iter()
                        .map(|(n, v)| ((*n).to_string(), v.to_vec()))
                        .collect(),
                ),
                not_empty: not_empty.to_vec(),
                warned: std::cell::RefCell::default(),
                errno: None,
            }
        }

        fn refuse(&self, name: &str) -> std::io::Result<()> {
            if self.not_empty.contains(&name) {
                return Err(std::io::Error::from_raw_os_error(
                    self.errno.unwrap_or(libc::ENOTEMPTY),
                ));
            }
            Ok(())
        }

        fn names(&self) -> Vec<String> {
            self.attrs.borrow().keys().cloned().collect()
        }
    }

    impl XattrCalls for FakeXattrs {
        fn list(&self, _path: &Path) -> std::io::Result<Vec<std::ffi::OsString>> {
            Ok(self.attrs.borrow().keys().map(Into::into).collect())
        }
        fn get(&self, _path: &Path, name: &std::ffi::OsStr) -> std::io::Result<Option<Vec<u8>>> {
            Ok(self.attrs.borrow().get(&*name.to_string_lossy()).cloned())
        }
        fn set(&self, _path: &Path, name: &str, value: &[u8]) -> std::io::Result<()> {
            self.refuse(name)?;
            _ = self
                .attrs
                .borrow_mut()
                .insert(name.to_string(), value.to_vec());
            Ok(())
        }
        fn remove(&self, _path: &Path, name: &std::ffi::OsStr) -> std::io::Result<()> {
            let name = name.to_string_lossy();
            self.refuse(&name)?;
            _ = self.attrs.borrow_mut().remove(&*name);
            Ok(())
        }
        fn warn_casefold(&self, name: &str, path: &Path) {
            self.warned
                .borrow_mut()
                .push(format!("{name} {}", path.display()));
        }
    }

    /// BackOtter: bcachefs refusing to set `bcachefs.casefold` on a directory
    /// with entries (`ENOTEMPTY`) is a warning, not an error, and the
    /// directory's other attributes are still set and removed; `ENOTEMPTY`
    /// for any other attribute stays an error.
    #[test]
    fn casefold_not_empty_set_is_warning() {
        let dir = Path::new("/r/d");
        let calls = FakeXattrs::with(
            &[("user.old", b"x"), ("user.same", b"s")],
            &["bcachefs.casefold"],
        );
        let attrs = [
            xattr("bcachefs.casefold", b"1"),
            xattr("user.new", b"n"),
            xattr("user.same", b"s"),
        ];
        set_xattrs_with(&calls, dir, &attrs, false).unwrap();
        assert_eq!(calls.names(), ["user.new", "user.same"]);
        assert_eq!(*calls.warned.borrow(), ["bcachefs.casefold /r/d"]);

        let calls = FakeXattrs::with(&[], &["user.notempty"]);
        let attrs = [xattr("user.notempty", b"1"), xattr("user.b", b"2")];
        let err = set_xattrs_with(&calls, dir, &attrs, false).unwrap_err().to_string();
        assert!(err.starts_with("user.notempty: "), "{err}");
        assert_eq!(calls.names(), ["user.b"]);
        assert!(calls.warned.borrow().is_empty());
    }

    /// BackOtter: an extended attribute the file system doesn't support
    /// (`EOPNOTSUPP`) isn't counted as an error under `--strict-exit`, as
    /// root or not; one that couldn't be set for another reason (`EIO`) is.
    #[test]
    fn xattrs_not_set_count_unless_unsupported() {
        let file = Path::new("/r/f");
        for (errno, counts) in [(libc::EOPNOTSUPP, false), (libc::EIO, true)] {
            let mut calls = FakeXattrs::with(&[], &["user.a"]);
            calls.errno = Some(errno);
            let errors =
                set_xattrs_with(&calls, file, &[xattr("user.a", b"1")], false).unwrap_err();
            let err = LocalDestinationErrorKind::XattrsNotSet(errors);
            assert_eq!(LocalDestination::error_counts(&err, true), counts, "{errno}");
            assert_eq!(LocalDestination::error_counts(&err, false), counts, "{errno}");
        }
        // A change of owner refused counts as root only.
        let err = LocalDestinationErrorKind::FromErrnoError(Errno::EPERM);
        assert!(LocalDestination::error_counts(&err, true));
        assert!(!LocalDestination::error_counts(&err, false));
    }

    /// BackOtter: the same for removing `bcachefs.casefold` from a
    /// directory whose node hasn't got it.
    #[test]
    fn casefold_not_empty_remove_is_warning() {
        let dir = Path::new("/r/d");
        let calls = FakeXattrs::with(
            &[("bcachefs.casefold", b"1"), ("user.old", b"x")],
            &["bcachefs.casefold"],
        );
        set_xattrs_with(&calls, dir, &[xattr("user.new", b"n")], false).unwrap();
        assert_eq!(calls.names(), ["bcachefs.casefold", "user.new"]);
        assert_eq!(*calls.warned.borrow(), ["bcachefs.casefold /r/d"]);

        let calls = FakeXattrs::with(
            &[("user.notempty", b"1"), ("user.old", b"x")],
            &["user.notempty"],
        );
        let err = set_xattrs_with(&calls, dir, &[xattr("user.new", b"n")], false)
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("removing user.notempty: "), "{err}");
        assert_eq!(calls.names(), ["user.new", "user.notempty"]);
        assert!(calls.warned.borrow().is_empty());
    }

    /// BackOtter: stock rustic's names on FreeBSD and NetBSD (`user.NAME`,
    /// `system.NAME`) are restored under their namespace in a snapshot not
    /// BackOtter's, and a `user.` one matches the bare name listed; in
    /// BackOtter's snapshots (and elsewhere) a node's name is the name.
    #[test]
    fn xattr_stock_bsd_names() {
        let own = |name: &str| (Some(name.to_string()), osattrs::xattr_os_name(name));
        assert_eq!(
            xattr_restore_names("user.comment", true),
            (Some("comment".to_string()), "user.comment".to_string())
        );
        assert_eq!(
            xattr_restore_names("system.mac", true),
            (None, "system.mac".to_string())
        );
        assert_eq!(xattr_restore_names("comment", true), own("comment"));
        assert_eq!(xattr_restore_names("user.comment", false), own("user.comment"));
        assert_eq!(xattr_restore_names("system.mac", false), own("system.mac"));
    }

    /// BackOtter: a stock name of the user namespace that the file has with
    /// the right value is left, one of the system namespace is set (never
    /// listed, nor removed), with `bsd_stock`.
    #[test]
    fn xattr_stock_bsd_names_synced() {
        let dir = Path::new("/r/f");
        // On FreeBSD and NetBSD the system lists user.comment as "comment";
        // here the fake lists its keys, so they are the node's names.
        let calls = FakeXattrs::with(&[("comment", b"c")], &[]);
        let attrs = [xattr("user.comment", b"c"), xattr("system.mac", b"m")];
        // The fake's set takes the name as given: one already right isn't set.
        set_xattrs_with(&calls, dir, &attrs, true).unwrap();
        assert_eq!(calls.names(), ["comment", "system.mac"]);
    }

    /// BackOtter: a node without an SELinux label leaves the file's alone,
    /// which SELinux never lets anyone remove, and removes the others.
    /// Setting security.selinux takes root (and SELinux's leave, where it
    /// runs): the test does nothing where it can't.
    #[test]
    fn selinux_label_never_removed() {
        assert!(osattrs::xattr_never_removed("security.selinux"));
        assert!(!osattrs::xattr_never_removed("security.capability"));
        assert!(!osattrs::xattr_never_removed("user.selinux"));
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        fs::write(&file, b"").unwrap();
        let label = b"system_u:object_r:etc_t:s0\0";
        if xattr::set(&file, "user.old", b"x").is_err()
            || xattr::set(&file, "security.selinux", label).is_err()
        {
            eprintln!("can't set security.selinux in {}", dir.path().display());
            return;
        }
        let dest = LocalDestination::new(dir.path().to_str().unwrap(), false, false).unwrap();
        dest.set_extended_attributes("f", &[], false).unwrap();
        let names: Vec<_> = xattr::list(&file).unwrap().collect();
        assert_eq!(names, ["security.selinux"]);
    }

    /// BackOtter: a file restored sparse, blob by blob, has the blobs'
    /// contents, and blocks only for those with a byte other than zero
    /// (and maybe one for the file system's own records of its extents).
    #[test]
    fn write_sparse_leaves_zero_blocks_unwritten() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let dest = LocalDestination::new(dir.path().to_str().unwrap(), false, false).unwrap();
        // Blobs of odd sizes: data, zeros, data at a block's end, zeros, a
        // single byte, zeros, a byte at a blob's start and end, zeros to
        // the end.
        let mut blobs: Vec<Vec<u8>> = vec![vec![7; 10_000], vec![0; 3 << 20]];
        let mut b = vec![0; 1 << 20];
        b[(1 << 20) - 1] = 1;
        blobs.push(b);
        blobs.push(vec![0; (5 << 20) + 123]);
        blobs.push(vec![1]);
        blobs.push(vec![0; 100_000]);
        let mut b = vec![0; 50_000];
        b[0] = 2;
        b[49_999] = 3;
        blobs.push(b);
        blobs.push(vec![0; 2 << 20]);
        let size: usize = blobs.iter().map(Vec::len).sum();
        dest.set_length("f", size as u64, true).unwrap();
        let block = osattrs::hole_block_size(&File::open(dir.path().join("f")).unwrap());
        // In reverse, as the restore writes blobs in any order.
        let mut offsets = Vec::new();
        let mut off = 0;
        for blob in &blobs {
            offsets.push(off);
            off += blob.len() as u64;
        }
        for (blob, off) in blobs.iter().zip(&offsets).rev() {
            dest.write_sparse_at("f", *off, blob).unwrap();
        }
        let want: Vec<u8> = blobs.concat();
        assert_eq!(fs::read(dir.path().join("f")).unwrap(), want);
        let m = fs::metadata(dir.path().join("f")).unwrap();
        let data_blocks = want
            .chunks(usize::try_from(block).unwrap())
            .filter(|c| c.iter().any(|&b| b != 0))
            .count() as u64;
        let max = (data_blocks + 1) * block;
        eprintln!(
            "block {block}: {} bytes allocated, {} of data blocks, at most {max}",
            m.blocks() * 512,
            data_blocks * block
        );
        assert!(m.blocks() * 512 <= max, "{} > {max}", m.blocks() * 512);
    }
}

#[cfg(test)]
mod path_tests {
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
        assert!(dest.write_at("../escaped_file", 0, b"data").is_err());
        assert!(dest.read_at("../escaped_file", 0, 4).is_err());
        assert!(dest.get_matching_file("../escaped_file", 4).is_none());

        Ok(())
    }
}
