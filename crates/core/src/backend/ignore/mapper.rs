#[cfg(not(windows))]
pub mod nix_mapper;

use std::{ffi::OsStr, path::Path};

use derive_setters::Setters;
use ignore::DirEntry;
use jiff::Timestamp;
use log::warn;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::{IgnoreErrorKind, IgnoreResult, Incomplete, OpenFile};
#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos", target_os = "haiku")))]
use crate::backend::node::ExtendedAttribute;
use crate::backend::{
    ReadSourceEntry,
    osattrs,
    node::{
        Metadata, Node, NodeType,
        generic_attributes::GenericAttributes,
        modification::{DevIdOption, TimeOption, XattrOption},
    },
};

#[cfg(not(windows))]
use std::os::unix::fs::{FileTypeExt, MetadataExt};

#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockdevOption {
    #[default]
    Special,
    File,
}

#[serde_as]
#[cfg_attr(feature = "clap", derive(clap::Parser))]
#[cfg_attr(feature = "merge", derive(conflate::Merge))]
#[derive(serde::Deserialize, serde::Serialize, Default, Clone, Copy, Debug, Setters)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
#[setters(into)]
#[non_exhaustive]
/// [`LocalSourceSaveOptions`] describes how entries from a local source will be saved in the repository.
pub struct LocalSourceSaveOptions {
    // BackOtter: the mtime by default, as in stock rustic (and stock restic
    // without --with-atime); BackOtter asks for the real one (yes).
    /// Set access time [default: mtime]
    #[cfg_attr(feature = "clap", clap(long))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::option::overwrite_none))]
    pub set_atime: Option<TimeOption>,

    /// Set changed time [default: yes]
    #[cfg_attr(feature = "clap", clap(long))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::option::overwrite_none))]
    pub set_ctime: Option<TimeOption>,

    /// Set device ID [default: hardlink]
    #[cfg_attr(feature = "clap", clap(long))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::option::overwrite_none))]
    pub set_devid: Option<DevIdOption>,

    /// How block devices should be stored [default: special]
    #[cfg_attr(feature = "clap", clap(long))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::option::overwrite_none))]
    pub set_blockdev: Option<BlockdevOption>,

    /// Set extended attributes [default: yes]
    #[cfg_attr(feature = "clap", clap(long))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::option::overwrite_none))]
    pub set_xattrs: Option<XattrOption>,
}

impl LocalSourceSaveOptions {
    /// Maps a [`DirEntry`] to a [`ReadSourceEntry`].
    ///
    /// # Arguments
    ///
    /// * `entry` - The [`DirEntry`] to map.
    /// * `options` - options for saving entries
    ///
    /// # Errors
    ///
    /// * If metadata could not be read.
    /// * If the xattr of the entry could not be read.
    pub fn map_entry(self, entry: DirEntry) -> IgnoreResult<ReadSourceEntry<OpenFile>> {
        self.map_entry_counted(entry, &Incomplete::default())
    }

    /// BackOtter: [`Self::map_entry`], counting in `incomplete` an entry
    /// whose metadata couldn't all be read (each warned about), as
    /// BackOtter's restic counts them toward its exit status 3.
    ///
    /// # Errors
    ///
    /// * If metadata could not be read.
    /// * If a symlink's target could not be read.
    pub(crate) fn map_entry_counted(
        self,
        entry: DirEntry,
        incomplete: &Incomplete,
    ) -> IgnoreResult<ReadSourceEntry<OpenFile>> {
        let name = entry.file_name();
        let m = entry
            .metadata()
            .map_err(|err| IgnoreErrorKind::AcquiringMetadataFailed {
                name: name.to_string_lossy().to_string(),
                source: err,
            })?;
        let node = self.map_path(entry.path(), name, &m, incomplete, false)?;
        let path = entry.into_path();
        // BackOtter: a file with holes is read by its data extents.
        let open = Some(OpenFile::new(path.clone(), osattrs::is_sparse(&node)));
        Ok(ReadSourceEntry { path, node, open })
    }

    /// BackOtter: the [`Node`] of the entry at `path`, named `name`, whose
    /// `lstat` is `m`: what a backup stores for it, for an entry the walk
    /// gives ([`Self::map_entry`]) and for a directory above the backed-up
    /// paths (`LocalSource`'s `dir_node`), as restic stores both.
    ///
    /// Each part of the metadata it couldn't read and left out (file flags,
    /// attributes, extended attributes, each one that couldn't be read) is
    /// warned about and counted in `incomplete`; but not, for a directory
    /// `above` the backed-up paths, extended attributes it may not list, as
    /// restic ignores that error there.
    ///
    /// # Errors
    ///
    /// * If a symlink's target could not be read.
    pub(crate) fn map_path(
        self,
        path: &Path,
        name: &OsStr,
        m: &std::fs::Metadata,
        incomplete: &Incomplete,
        above: bool,
    ) -> IgnoreResult<Node> {
        let mtime = m.modified().ok().and_then(|t| Timestamp::try_from(t).ok());
        let atime = || m.accessed().ok().and_then(|t| Timestamp::try_from(t).ok());
        let atime = self
            .set_atime
            .unwrap_or(TimeOption::Mtime)
            .map_or_else(atime, mtime);
        let ctime = || Self::ctime(m);
        let ctime = self
            .set_ctime
            .unwrap_or(TimeOption::Yes)
            .map_or_else(ctime, mtime);

        let (uid, user, gid, group) = Self::user_group(m);
        let size = if m.is_dir() { 0 } else { m.len() };
        let device_id = self
            .set_devid
            .unwrap_or_default()
            .map_or_else(|| Self::device_id(m), Self::hardlink(m));
        let xattr = || match Self::xattrs(path) {
            Err(err) => {
                warn!("ignoring error obtaining xargs: {err}");
                if !(above && xattr_list_refused(&err)) {
                    incomplete.add();
                }
                Vec::new()
            }
            Ok(read) => {
                for (name, err) in &read.unreadable {
                    warn!(
                        "ignoring extended attribute {name} of {}: {err}",
                        path.display()
                    );
                    incomplete.add();
                }
                read.attrs
            }
        };
        let (mode, inode, links) = Self::nix_infos(m);

        let meta = Metadata {
            mode,
            mtime,
            atime,
            ctime,
            uid,
            gid,
            user,
            group,
            inode,
            device_id,
            size,
            links,
            extended_attributes: Vec::new(),
            generic_attributes: GenericAttributes::default(),
        };

        let mut node = self.to_node(path, name, m, meta)?;
        // BackOtter: a size only for a file, and no link count for a FIFO or
        // a socket, as restic stores them.
        if !node.is_file() {
            node.meta.size = 0;
        }
        if matches!(node.node_type, NodeType::Fifo | NodeType::Socket) {
            node.meta.links = 0;
            // BackOtter: and so no device ID by default (only for hard
            // links, which are never restored for these), whatever its
            // link count, as BackOtter's restic stores them.
            node.meta.device_id = self
                .set_devid
                .unwrap_or_default()
                .map_or_else(|| Self::device_id(m), false);
        }
        // BackOtter: the extended attributes' values after osattrs, which on
        // illumos reads their metadata first: reading a value moves its atime.
        let set_xattrs = self.set_xattrs.unwrap_or_default();
        if osattrs::fill(path, &mut node, m, set_xattrs == XattrOption::Yes) {
            incomplete.add();
        }
        // BackOtter: a file illumos quarantined (av_quarantined) can't be
        // read, by root either, nor its extended attributes: its node is
        // kept without them or its contents, with a warning, as in
        // BackOtter's restic (the archiver reads no contents for it).
        if osattrs::is_quarantined(&node) && osattrs::open_refused(path) {
            osattrs::keep_unread(path, &mut node);
        } else {
            node.meta.extended_attributes = set_xattrs.map_or_else(xattr);
        }
        Ok(node)
    }

    fn to_node(
        self,
        path: &Path,
        name: &OsStr,
        m: &std::fs::Metadata,
        meta: Metadata,
    ) -> IgnoreResult<Node> {
        let node = if m.is_dir() {
            Node::new_node(name, NodeType::Dir, meta)
        } else if m.is_symlink() {
            let target = std::fs::read_link(path).map_err(|err| IgnoreErrorKind::ErrorLink {
                path: path.to_path_buf(),
                source: err,
            })?;
            let node_type = NodeType::from_link(&target);
            Node::new_node(name, node_type, meta)
        } else {
            self.to_node_other(name, m, meta)
        };
        Ok(node)
    }
}

/// BackOtter: whether `err` is extended attributes the backup was refused
/// permission to list or read, which restic ignores for the directories
/// above the backed-up paths (`ignoreXattrListError`).
fn xattr_list_refused(err: &IgnoreErrorKind) -> bool {
    #[cfg(all(not(windows), not(target_os = "openbsd")))]
    if let IgnoreErrorKind::ErrorXattr { source, .. } = err {
        return source.kind() == std::io::ErrorKind::PermissionDenied;
    }
    _ = err;
    false
}

#[cfg(not(windows))]
impl LocalSourceSaveOptions {
    fn ctime(m: &std::fs::Metadata) -> Option<Timestamp> {
        #[allow(clippy::cast_possible_truncation)]
        Timestamp::new(m.ctime(), m.ctime_nsec() as i32).ok()
    }

    fn device_id(m: &std::fs::Metadata) -> u64 {
        m.dev()
    }

    fn hardlink(m: &std::fs::Metadata) -> bool {
        m.nlink() > 1 && !m.is_dir()
    }

    fn user_group(
        m: &std::fs::Metadata,
    ) -> (Option<u32>, Option<String>, Option<u32>, Option<String>) {
        let uid = m.uid();
        let gid = m.gid();
        let user = nix_mapper::get_user_by_uid(uid);
        let group = nix_mapper::get_group_by_gid(gid);
        (Some(uid), user, Some(gid), group)
    }

    fn nix_infos(m: &std::fs::Metadata) -> (Option<u32>, u64, u64) {
        let mode = nix_mapper::map_mode_to_go(m.mode());
        let inode = m.ino();
        let links = if m.is_dir() { 0 } else { m.nlink() };
        (Some(mode), inode, links)
    }

    /// BackOtter: list [`ExtendedAttribute`] for a [`Node`] located at
    /// `path`: on illumos, named attribute files, and on Haiku, attributes
    /// of type `B_XATTR_TYPE` (osattrs), which the xattr crate doesn't
    /// support.
    ///
    /// # Errors
    ///
    /// * If they couldn't be listed or read
    #[cfg(any(target_os = "illumos", target_os = "haiku"))]
    fn xattrs(path: &Path) -> IgnoreResult<osattrs::XattrsRead> {
        osattrs::native_xattrs(path).map_err(|err| IgnoreErrorKind::ErrorXattr {
            path: path.to_path_buf(),
            source: err,
        })
    }

    /// List [`ExtendedAttribute`] for a [`Node`] located at `path`
    ///
    /// # Argument
    ///
    /// * `path` to the [`Node`] for which to list attributes
    ///
    /// # Errors
    ///
    /// * If Xattr couldn't be listed or couldn't be read
    #[cfg(not(any(target_os = "openbsd", target_os = "illumos", target_os = "haiku")))]
    fn xattrs(path: &Path) -> IgnoreResult<osattrs::XattrsRead> {
        // BackOtter: no warning for each file where the xattr crate has no
        // support.
        if !xattr::SUPPORTED_PLATFORM {
            return Ok(osattrs::XattrsRead::default());
        }
        Self::xattrs_with(
            path,
            || osattrs::xattr_list(path),
            |name| osattrs::xattr_get(path, name),
        )
    }

    /// BackOtter: the extended attributes of `path`, listed by `list` and
    /// each read by `get`: [`Self::xattrs`], apart from where they come from.
    ///
    /// One that can't be read is left out and named in the result's
    /// `unreadable`, with its error, and the others are kept, as BackOtter's
    /// restic does (stock rustic dropped them all).
    ///
    /// # Errors
    ///
    /// * If they couldn't be listed
    #[cfg(not(any(target_os = "openbsd", target_os = "illumos", target_os = "haiku")))]
    fn xattrs_with(
        path: &Path,
        list: impl FnOnce() -> std::io::Result<Vec<std::ffi::OsString>>,
        mut get: impl FnMut(&OsStr) -> std::io::Result<Option<Vec<u8>>>,
    ) -> IgnoreResult<osattrs::XattrsRead> {
        // BackOtter: osattrs::xattr_list, as the xattr crate's list misnames
        // one on FreeBSD; none where there can be none (a FIFO on ZFS), as
        // restic does; restic's names (osattrs::xattr_node_name); and in the
        // byte order of those names, as BackOtter's restic stores them, not
        // in the order the file system lists them.
        // BackOtter: a list or a value the file system says it doesn't
        // support (osattrs::xattr_unsupported, ENOATTR included, which an
        // SMB/CIFS mount gives) is none: no attributes, or one kept without
        // a value, as BackOtter's restic takes them (handleXattrErr).
        let names = match list() {
            Err(err) if osattrs::xattr_unsupported(&err) => Vec::new(),
            names => names.map_err(|err| IgnoreErrorKind::ErrorXattr {
                path: path.to_path_buf(),
                source: err,
            })?,
        };
        let mut names: Vec<_> = names
            .into_iter()
            .filter_map(|name| Some((osattrs::xattr_node_name(&name)?, name)))
            .collect();
        names.sort_unstable();
        let mut read = osattrs::XattrsRead::default();
        for (node_name, name) in names {
            match get(&name) {
                Ok(value) => read.attrs.push(ExtendedAttribute {
                    name: node_name,
                    value,
                }),
                Err(err) if osattrs::xattr_unsupported(&err) => {
                    read.attrs.push(ExtendedAttribute {
                        name: node_name,
                        value: None,
                    });
                }
                Err(err) => read.unreadable.push((node_name, err)),
            }
        }
        Ok(read)
    }

    #[cfg(target_os = "openbsd")]
    fn xattrs(_path: &Path) -> IgnoreResult<osattrs::XattrsRead> {
        Ok(osattrs::XattrsRead::default())
    }

    fn to_node_other(self, name: &OsStr, m: &std::fs::Metadata, meta: Metadata) -> Node {
        let filetype = m.file_type();
        if filetype.is_block_device() {
            if matches!(self.set_blockdev.unwrap_or_default(), BlockdevOption::File) {
                Node::new_node(name, NodeType::File, meta)
            } else {
                let node_type = NodeType::Dev { device: m.rdev() };
                Node::new_node(name, node_type, meta)
            }
        } else if filetype.is_char_device() {
            let node_type = NodeType::Chardev { device: m.rdev() };
            Node::new_node(name, node_type, meta)
        } else if filetype.is_fifo() {
            Node::new_node(name, NodeType::Fifo, meta)
        } else if filetype.is_socket() {
            Node::new_node(name, NodeType::Socket, meta)
        } else {
            Node::new_node(name, NodeType::File, meta)
        }
    }
}

#[cfg(windows)]
impl LocalSourceSaveOptions {
    fn ctime(m: &std::fs::Metadata) -> Option<Timestamp> {
        m.created().ok().and_then(|t| Timestamp::try_from(t).ok())
    }
    fn device_id(_m: &std::fs::Metadata) -> u64 {
        0
    }
    fn hardlink(_m: &std::fs::Metadata) -> bool {
        false
    }
    fn user_group(
        _m: &std::fs::Metadata,
    ) -> (Option<u32>, Option<String>, Option<u32>, Option<String>) {
        (None, None, None, None)
    }

    fn nix_infos(_m: &std::fs::Metadata) -> (Option<u32>, u64, u64) {
        (None, 0, 0)
    }

    fn xattrs(_path: &Path) -> IgnoreResult<osattrs::XattrsRead> {
        Ok(osattrs::XattrsRead::default())
    }

    fn to_node_other(self, name: &OsStr, _m: &std::fs::Metadata, meta: Metadata) -> Node {
        Node::new_node(name, NodeType::File, meta)
    }
}

#[cfg(all(test, not(any(windows, target_os = "openbsd", target_os = "illumos"))))]
mod tests {
    use super::*;

    /// BackOtter: as stock rustic, a backup stores the mtime as the atime
    /// by default; `--set-atime yes` (BackOtter's) the real one.
    #[test]
    fn atime_is_mtime_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        std::fs::write(&path, b"hello").unwrap();
        let old = filetime::FileTime::from_unix_time(1_577_836_800, 0);
        filetime::set_file_atime(&path, old).unwrap();
        let m = std::fs::symlink_metadata(&path).unwrap();
        let name = OsStr::new("file");
        let node = LocalSourceSaveOptions::default()
            .map_path(&path, name, &m, &Incomplete::default(), false)
            .unwrap();
        assert_eq!(node.meta.atime, node.meta.mtime);
        let real = LocalSourceSaveOptions::default().set_atime(TimeOption::Yes);
        let node = real
            .map_path(&path, name, &m, &Incomplete::default(), false)
            .unwrap();
        assert_eq!(node.meta.atime.map(Timestamp::as_second), Some(old.unix_seconds()));
    }

    /// BackOtter: extended attributes are stored in the byte order of their
    /// names, whatever order the file system lists them in, as BackOtter's
    /// restic stores them.
    #[test]
    fn xattrs_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        std::fs::write(&path, b"hello world").unwrap();
        for name in ["user.zeta", "user.alpha", "user.mid", "user.Beta"] {
            if xattr::set(&path, name, name.as_bytes()).is_err() {
                // A file system without user extended attributes.
                return;
            }
        }
        let names: Vec<_> = LocalSourceSaveOptions::xattrs(&path)
            .unwrap()
            .attrs
            .into_iter()
            .map(|attr| attr.name)
            .collect();
        let want = ["user.Beta", "user.alpha", "user.mid", "user.zeta"];
        let want: Vec<_> = want
            .iter()
            .filter_map(|name| osattrs::xattr_node_name(name.as_ref()))
            .collect();
        assert_eq!(names, want);
    }

    /// BackOtter: one extended attribute that can't be read is left out
    /// alone, named with its error, and the others are kept in order, as
    /// BackOtter's restic does; one the list can't give fails them all.
    #[cfg(not(target_os = "haiku"))]
    #[test]
    fn xattrs_with_skips_only_unreadable() {
        use std::{ffi::OsString, io};

        let path = Path::new("/nowhere");
        let list = || {
            Ok(["user.c", "user.a", "user.b"]
                .into_iter()
                .map(OsString::from)
                .collect())
        };
        let get = |name: &OsStr| {
            if name == "user.b" {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                Ok(Some(name.as_encoded_bytes().to_vec()))
            }
        };
        let read = LocalSourceSaveOptions::xattrs_with(path, list, get).unwrap();
        let kept: Vec<_> = read.attrs.iter().map(|attr| attr.name.as_str()).collect();
        let want: Vec<_> = ["user.a", "user.c"]
            .iter()
            .filter_map(|name| osattrs::xattr_node_name(name.as_ref()))
            .collect();
        assert_eq!(kept, want);
        for attr in &read.attrs {
            assert_eq!(
                attr.value.as_deref(),
                Some(format!("user.{}", attr.name.trim_start_matches("user.")).as_bytes())
            );
        }
        assert_eq!(read.unreadable.len(), 1);
        let (name, err) = &read.unreadable[0];
        assert_eq!(Some(name.clone()), osattrs::xattr_node_name("user.b".as_ref()));
        assert_eq!(err.raw_os_error(), Some(libc::EIO));

        let refused = || Err(io::Error::from_raw_os_error(libc::EACCES));
        let err = LocalSourceSaveOptions::xattrs_with(path, refused, get).unwrap_err();
        assert!(matches!(err, IgnoreErrorKind::ErrorXattr { .. }));

        // What the file system says it doesn't support is no error, as
        // restic: a list is none, and a value kept as none.
        let unsupported = || Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
        let read = LocalSourceSaveOptions::xattrs_with(path, unsupported, get).unwrap();
        assert!(read.attrs.is_empty() && read.unreadable.is_empty());
        #[cfg(target_os = "linux")]
        {
            let no_data = || Err(io::Error::from_raw_os_error(libc::ENODATA));
            let read = LocalSourceSaveOptions::xattrs_with(path, no_data, get).unwrap();
            assert!(read.attrs.is_empty() && read.unreadable.is_empty());
        }
        let get_unsupported = |name: &OsStr| {
            if name == "user.b" {
                Err(io::Error::from_raw_os_error(libc::ENOTSUP))
            } else {
                Ok(Some(name.as_encoded_bytes().to_vec()))
            }
        };
        let read = LocalSourceSaveOptions::xattrs_with(path, list, get_unsupported).unwrap();
        assert!(read.unreadable.is_empty());
        assert_eq!(read.attrs.len(), 3);
        assert!(read.attrs[1].value.is_none());
    }
}
