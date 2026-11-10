pub mod mapper;
pub use mapper::LocalSourceSaveOptions;

use std::{
    ffi::OsString,
    fs::File,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use bytesize::ByteSize;
use derive_setters::Setters;
use ignore::{Walk, WalkBuilder};
#[cfg(unix)]
use log::debug;
use log::warn;
use serde_with::{DisplayFromStr, serde_as};

#[cfg(not(windows))]
use std::num::TryFromIntError;

use crate::{
    Excludes,
    backend::{ReadSource, ReadSourceEntry, ReadSourceOpen, node::Node, osattrs},
    error::{ErrorKind, RusticError, RusticResult},
};

/// [`IgnoreErrorKind`] describes the errors that can be returned by a Ignore action in Backends
#[derive(thiserror::Error, Debug, displaydoc::Display)]
pub enum IgnoreErrorKind {
    #[cfg(all(not(windows), not(target_os = "openbsd")))]
    /// Error getting xattrs for `{path:?}`: `{source:?}`
    ErrorXattr {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Error reading link target for `{path:?}`: `{source:?}`
    ErrorLink {
        path: PathBuf,
        source: std::io::Error,
    },
    #[cfg(not(windows))]
    /// Error converting ctime `{ctime}` and `ctime_nsec` `{ctime_nsec}` to Utc Timestamp: `{source:?}`
    CtimeConversionToTimestampFailed {
        ctime: i64,
        ctime_nsec: i64,
        source: TryFromIntError,
    },
    /// Error acquiring metadata for `{name}`: `{source:?}`
    AcquiringMetadataFailed { name: String, source: ignore::Error },
    /// time error
    JiffError(#[from] jiff::Error),
}

pub(crate) type IgnoreResult<T> = Result<T, IgnoreErrorKind>;

/// BackOtter: how many entries a [`LocalSource`] gave without some of their
/// metadata because it couldn't be read (each warned about), shared by the
/// source and its walkers ([`ReadSource::incomplete`]).
#[derive(Debug, Default, Clone)]
pub(crate) struct Incomplete(Arc<AtomicU64>);

impl Incomplete {
    /// Counts one more.
    pub(crate) fn add(&self) {
        _ = self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// The count.
    pub(crate) fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A [`LocalSource`] is a source from local paths which is used to be read from (i.e. to backup it).
#[derive(Debug)]
pub struct LocalSource {
    /// The walk builder.
    builder: WalkBuilder,
    /// The save options to use.
    save_opts: LocalSourceSaveOptions,
    /// BackOtter: entries given without some of their metadata.
    incomplete: Incomplete,
}

#[serde_as]
#[cfg_attr(feature = "clap", derive(clap::Parser))]
#[cfg_attr(feature = "merge", derive(conflate::Merge))]
#[derive(serde::Deserialize, serde::Serialize, Default, Clone, Debug, Setters)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
#[setters(into)]
#[non_exhaustive]
/// [`LocalSourceFilterOptions`] allow to filter a local source by various criteria.
pub struct LocalSourceFilterOptions {
    /// Ignore files based on .gitignore files
    #[cfg_attr(feature = "clap", clap(long))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::bool::overwrite_false))]
    pub git_ignore: bool,

    /// Do not require a git repository to apply git-ignore rule
    #[cfg_attr(feature = "clap", clap(long))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::bool::overwrite_false))]
    pub no_require_git: bool,

    /// Treat the provided filename like a .gitignore file (can be specified multiple times)
    #[cfg_attr(
        feature = "clap",
        clap(long = "custom-ignorefile", value_name = "FILE")
    )]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::vec::overwrite_empty))]
    pub custom_ignorefiles: Vec<String>,

    /// Exclude contents of directories containing this filename (can be specified multiple times)
    #[cfg_attr(feature = "clap", clap(long, value_name = "FILE"))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::vec::overwrite_empty))]
    pub exclude_if_present: Vec<String>,

    /// Exclude files/directories having the given extended attribute set (can be specified multiple times)
    #[cfg_attr(feature = "clap", clap(long, value_name = "XATTR"))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::vec::overwrite_empty))]
    pub exclude_if_xattr: Vec<String>,

    /// Exclude other file systems, don't cross filesystem boundaries and subvolumes
    #[cfg_attr(feature = "clap", clap(long, short = 'x'))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::bool::overwrite_false))]
    pub one_file_system: bool,

    /// Maximum size of files to be backed up. Larger files will be excluded.
    #[cfg_attr(feature = "clap", clap(long, value_name = "SIZE"))]
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::option::overwrite_none))]
    pub exclude_larger_than: Option<ByteSize>,
}

impl LocalSource {
    /// Create a local source from [`LocalSourceSaveOptions`], [`LocalSourceFilterOptions`] and backup path(s).
    ///
    /// # Arguments
    ///
    /// * `save_opts` - The [`LocalSourceSaveOptions`] to use.
    /// * `filter_opts` - The [`LocalSourceFilterOptions`] to use.
    /// * `backup_paths` - The backup path(s) to use.
    ///
    /// # Returns
    ///
    /// The created local source.
    ///
    /// # Errors
    ///
    /// * If the a glob pattern could not be added to the override builder.
    /// * If a glob file could not be read.
    #[allow(clippy::too_many_lines)]
    pub fn new(
        save_opts: LocalSourceSaveOptions,
        excludes: &Excludes,
        filter_opts: &LocalSourceFilterOptions,
        backup_paths: &[impl AsRef<Path>],
    ) -> RusticResult<Self> {
        let mut walk_builder = WalkBuilder::new(&backup_paths[0]);

        for path in &backup_paths[1..] {
            _ = walk_builder.add(path);
        }

        let overrides = excludes.as_override()?;

        for file in &filter_opts.custom_ignorefiles {
            _ = walk_builder.add_custom_ignore_filename(file);
        }

        _ = walk_builder
            .follow_links(false)
            .hidden(false)
            .ignore(false)
            .git_ignore(filter_opts.git_ignore)
            .git_exclude(filter_opts.git_ignore)
            .require_git(!filter_opts.no_require_git)
            .sort_by_file_path(Path::cmp)
            .same_file_system(filter_opts.one_file_system)
            .max_filesize(filter_opts.exclude_larger_than.map(|s| s.as_u64()))
            .overrides(overrides);

        let exclude_if_present = filter_opts.exclude_if_present.clone();
        let exclude_if_xattr: Vec<OsString> = filter_opts
            .exclude_if_xattr
            .iter()
            .map(OsString::from)
            .collect();

        if !exclude_if_xattr.is_empty() {
            #[cfg(any(windows, target_os = "openbsd"))]
            warn!("exclude-if-xattr is not supported on this platform");
            #[cfg(not(any(windows, target_os = "openbsd")))]
            if !xattr::SUPPORTED_PLATFORM {
                warn!("exclude-if-xattr is not supported on this platform");
            }
        }

        let needs_entry_filter = !exclude_if_present.is_empty() || !exclude_if_xattr.is_empty();

        if needs_entry_filter {
            _ = walk_builder.filter_entry(move |entry| {
                // exclude-if-present: skip directories containing a marker file
                if !exclude_if_present.is_empty()
                    && let Some(tpe) = entry.file_type()
                    && tpe.is_dir()
                    && exclude_if_present
                        .iter()
                        .any(|file| entry.path().join(file).exists())
                {
                    return false;
                }

                // exclude-if-xattr: skip entries that have a matching xattr
                #[cfg(not(any(windows, target_os = "openbsd")))]
                if xattr::SUPPORTED_PLATFORM && !exclude_if_xattr.is_empty() {
                    match xattr::list(entry.path()) {
                        Ok(mut attrs) => {
                            if attrs.any(|attr| exclude_if_xattr.contains(&attr)) {
                                return false;
                            }
                        }
                        Err(err) => {
                            warn!(
                                "Error reading xattrs for {}, not excluding: {err}",
                                entry.path().display()
                            );
                        }
                    }
                }

                true
            });
        }

        let builder = walk_builder;

        Ok(Self {
            builder,
            save_opts,
            incomplete: Incomplete::default(),
        })
    }
}

#[derive(Debug)]
/// Describes an open file from the local backend.
pub struct OpenFile {
    /// The path of the file.
    path: PathBuf,
    /// BackOtter: whether it has holes (`unix.sparse`), and is read by its
    /// data extents (`osattrs::backup_reader`).
    sparse: bool,
}

impl OpenFile {
    /// BackOtter: the file at `path`, which `sparse` says has holes.
    pub(crate) const fn new(path: PathBuf, sparse: bool) -> Self {
        Self { path, sparse }
    }
}

impl ReadSourceOpen for OpenFile {
    // BackOtter: a file with holes is read by its data extents, and its
    // holes given as zeros without being read: the same bytes as the file.
    type Reader = Box<dyn std::io::Read + Send>;

    /// Open the file from the local backend.
    ///
    /// # Returns
    ///
    /// The read handle to the file from the local backend.
    ///
    /// # Errors
    ///
    /// * If the file could not be opened.
    fn open(self) -> RusticResult<Self::Reader> {
        let path = self.path;
        let f = open_noatime(&path).map_err(|err| {
            RusticError::with_source(
                ErrorKind::InputOutput,
                "Failed to open file at `{path}`. Please make sure the file exists and is accessible.",
                err,
            )
            .attach_context("path", path.display().to_string())
        })?;
        Ok(osattrs::backup_reader(f, self.sparse))
    }
}

/// BackOtter: opens the file at `path` for reading. On Linux without
/// updating its access time (`O_NOATIME`), which a backup keeps, as
/// BackOtter's restic does; that takes owning the file (or `CAP_FOWNER`),
/// and without it the file is opened as usual.
fn open_noatime(path: &Path) -> std::io::Result<File> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::unix::fs::OpenOptionsExt;

        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOATIME)
            .open(path)
        {
            Err(err) if err.raw_os_error() == Some(libc::EPERM) => {}
            result => return result,
        }
    }
    File::open(path)
}

impl ReadSource for LocalSource {
    type Open = OpenFile;
    type Iter = LocalSourceWalker;

    /// Get the size of the local source.
    ///
    /// # Returns
    ///
    /// The size of the local source or `None` if the size could not be determined.
    ///
    /// # Errors
    ///
    /// * If the size could not be determined.
    fn size(&self) -> RusticResult<Option<u64>> {
        let mut size = 0;
        for entry in self.builder.build() {
            if let Err(err) = entry.and_then(|e| e.metadata()).map(|m| {
                size += if m.is_dir() { 0 } else { m.len() };
            }) {
                warn!("ignoring error {err}");
            }
        }
        Ok(Some(size))
    }

    /// Iterate over the entries of the local source.
    ///
    /// # Returns
    ///
    /// An iterator over the entries of the local source.
    fn entries(&self) -> Self::Iter {
        LocalSourceWalker {
            walker: self.builder.build(),
            save_opts: self.save_opts,
            incomplete: self.incomplete.clone(),
        }
    }

    /// BackOtter: the node of a directory above the backed-up paths, from
    /// its own `lstat`, as an entry's node is made, as restic stores it; for
    /// a symlink (a relative path's "home" -> "usr/home"), that of the
    /// directory it leads to, as restic follows it there. A path that can't
    /// be read, or isn't a directory, gets none (a node of rustic's own
    /// making), with a warning.
    fn dir_node(&self, path: &Path) -> Option<Node> {
        let name = path.file_name()?;
        // BackOtter: each "saved without its metadata" counts, as restic
        // fails such a snapshot.
        let (read_path, m) = std::fs::symlink_metadata(path)
            .and_then(|m| {
                if m.file_type().is_symlink() {
                    let target = std::fs::canonicalize(path)?;
                    let m = std::fs::symlink_metadata(&target)?;
                    Ok((target, m))
                } else {
                    Ok((path.to_path_buf(), m))
                }
            })
            .inspect_err(|err| {
                warn!("{}: {err}, saved without its metadata", path.display());
                self.incomplete.add();
            })
            .ok()?;
        if !m.is_dir() {
            warn!(
                "{} is not a directory, saved without its metadata",
                path.display()
            );
            self.incomplete.add();
            return None;
        }
        self.save_opts
            .map_path(&read_path, name, &m, &self.incomplete, true)
            .inspect_err(|err| {
                warn!("{}: {err}, saved without its metadata", path.display());
                self.incomplete.add();
            })
            .ok()
    }

    /// BackOtter: entries given without some of their metadata (flags,
    /// attributes, extended attributes; a directory above the backed-up
    /// paths saved without its own), each warned about.
    fn incomplete(&self) -> u64 {
        self.incomplete.get()
    }
}

/// BackOtter: what a file of type `tpe` is, where a backup skips it: a
/// socket; or a file of none of the types a node has, an illumos door (a
/// running program's door server, made again when it starts:
/// /etc/sysevent, /var/run), whose restored copy would have nobody behind
/// it, and which can't be read (`ENOSYS`), as BackOtter's restic skips
/// them. Stock rustic took a door for a regular file and warned about its
/// directory.
#[cfg(unix)]
fn skipped_type(tpe: std::fs::FileType) -> Option<&'static str> {
    use std::os::unix::fs::FileTypeExt;
    if tpe.is_socket() {
        Some("a socket")
    } else if tpe.is_file()
        || tpe.is_dir()
        || tpe.is_symlink()
        || tpe.is_block_device()
        || tpe.is_char_device()
        || tpe.is_fifo()
    {
        None
    } else {
        Some("a door")
    }
}

// Walk doesn't implement Debug
#[allow(missing_debug_implementations)]
pub struct LocalSourceWalker {
    /// The walk iterator.
    walker: Walk,
    /// The save options to use.
    save_opts: LocalSourceSaveOptions,
    /// BackOtter: entries given without some of their metadata, shared with
    /// the [`LocalSource`].
    incomplete: Incomplete,
}

impl Iterator for LocalSourceWalker {
    type Item = RusticResult<ReadSourceEntry<OpenFile>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            #[cfg(unix)]
            let mut next = self.walker.next();
            #[cfg(not(unix))]
            let next = self.walker.next();
            // BackOtter: sockets are skipped, as restic skips them: a socket
            // is only the name a running program listens on, made again when
            // it starts, and a restored one has nobody listening. So are
            // illumos' doors (skipped_type).
            #[cfg(unix)]
            while let Some(Ok(entry)) = &next
                && let Some(what) = entry.file_type().and_then(skipped_type)
            {
                debug!("{} is {what}, ignoring", entry.path().display());
                next = self.walker.next();
            }
            let next = match next {
                // ignore root dir, i.e. an entry with depth 0 of type dir
                // BackOtter: ... unless it has a name. A directory backed up
                // keeps its own metadata, as restic keeps it, for a restore
                // of "SNAP:path" to give the destination; "/" has no node in
                // a snapshot, in restic either.
                Some(Ok(entry))
                    if entry.depth() == 0
                        && entry.file_type().unwrap().is_dir()
                        && entry.path().file_name().is_none() =>
                {
                    self.walker.next()
                }
                item => item,
            }?;
            // BackOtter: an entry below a backed-up path that was deleted
            // after its directory was listed is warned about as before, but
            // is not an error the source returns (which counts toward exit
            // status 3), as BackOtter's restic ignores it.
            let mut vanished = false;
            let item = next
                .map_err(|err| {
                    vanished = is_vanished(&err, err.depth());
                    RusticError::with_source(
                        ErrorKind::Internal,
                        "Failed to get next entry from walk iterator.",
                        err,
                    )
                    .ask_report()
                })
                .and_then(|entry| {
                    let depth = entry.depth();
                    self.save_opts
                        .map_entry_counted(entry, &self.incomplete)
                        .map_err(|err| {
                            if let IgnoreErrorKind::AcquiringMetadataFailed { source, .. } = &err {
                                vanished = is_vanished(source, Some(depth));
                            }
                            RusticError::with_source(
                                ErrorKind::Internal,
                                "Failed to map Directory entry to ReadSourceEntry.",
                                err,
                            )
                            .ask_report()
                        })
                });
            match item {
                Err(err) if vanished => warn!("ignoring error: {}", err.display_log()),
                item => return Some(item),
            }
        }
    }
}

/// BackOtter: whether `err`, for an entry at `depth` of the walk, is one
/// below a backed-up path (depth above 0) that no longer exists.
fn is_vanished(err: &ignore::Error, depth: Option<usize>) -> bool {
    depth.is_some_and(|depth| depth > 0)
        && err
            .io_error()
            .is_some_and(|err| err.kind() == std::io::ErrorKind::NotFound)
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::net::UnixListener;

    use super::*;
    use crate::backend::ReadSource;

    #[test]
    fn skipped_types() {
        // BackOtter: sockets, and doors (illumos): types no node has.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("f"), b"x").unwrap();
        let _listener = UnixListener::bind(dir.path().join("s")).unwrap();
        let tpe = |name: &str| {
            std::fs::symlink_metadata(dir.path().join(name))
                .unwrap()
                .file_type()
        };
        assert_eq!(skipped_type(tpe("f")), None);
        assert_eq!(skipped_type(tpe(".")), None);
        assert_eq!(skipped_type(tpe("s")), Some("a socket"));
    }

    #[test]
    fn sockets_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a-file"), b"data").unwrap();
        let _socket = UnixListener::bind(dir.path().join("b-socket")).unwrap();
        nix::unistd::mkfifo(&dir.path().join("c-fifo"), nix::sys::stat::Mode::S_IRWXU).unwrap();

        let source = LocalSource::new(
            LocalSourceSaveOptions::default(),
            &Excludes::default(),
            &LocalSourceFilterOptions::default(),
            &[dir.path()],
        )
        .unwrap();
        let mut names: Vec<_> = source
            .entries()
            .map(|entry| entry.unwrap().node.name().into_owned())
            .collect();
        names.sort();
        let dir_name = dir.path().file_name().unwrap().to_owned();
        assert_eq!(names, [dir_name, "a-file".into(), "c-fifo".into()]);

        // A socket given as the path to back up is skipped too.
        let source = LocalSource::new(
            LocalSourceSaveOptions::default(),
            &Excludes::default(),
            &LocalSourceFilterOptions::default(),
            &[dir.path().join("b-socket")],
        )
        .unwrap();
        assert_eq!(source.entries().count(), 0);
    }

    #[test]
    fn device_id_only_for_hard_links() {
        // BackOtter: by default (--set-devid hardlink) a device ID only for
        // a hard-linked file, not a directory, a file with one link, or a
        // FIFO, hard-linked or not (its link count isn't stored), as
        // BackOtter's restic stores them (device-id-for-hardlinks).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file"), b"data").unwrap();
        std::fs::write(dir.path().join("linked"), b"data").unwrap();
        std::fs::hard_link(dir.path().join("linked"), dir.path().join("linked2")).unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        nix::unistd::mkfifo(&dir.path().join("fifo"), nix::sys::stat::Mode::S_IRWXU).unwrap();
        std::fs::hard_link(dir.path().join("fifo"), dir.path().join("fifo2")).unwrap();

        let source = LocalSource::new(
            LocalSourceSaveOptions::default(),
            &Excludes::default(),
            &LocalSourceFilterOptions::default(),
            &[dir.path()],
        )
        .unwrap();
        let mut ids: Vec<_> = source
            .entries()
            .map(|entry| {
                let node = entry.unwrap().node;
                (node.name().into_owned(), node.meta.device_id != 0)
            })
            .collect();
        ids.sort();
        let dir_name = dir.path().file_name().unwrap().to_owned();
        let want = [
            (dir_name, false),
            ("fifo".into(), false),
            ("fifo2".into(), false),
            ("file".into(), false),
            ("linked".into(), true),
            ("linked2".into(), true),
            ("sub".into(), false),
        ];
        assert_eq!(ids, want);
    }

    #[test]
    fn dir_node_is_the_directory_s_own() {
        use std::os::unix::fs::PermissionsExt;
        // BackOtter: a directory above the backed-up path gets the node an
        // entry of the walk would get, as restic stores it.
        let dir = tempfile::tempdir().unwrap();
        let anc = dir.path().join("anc");
        std::fs::create_dir_all(anc.join("data")).unwrap();
        std::fs::set_permissions(&anc, std::fs::Permissions::from_mode(0o751)).unwrap();
        std::fs::write(dir.path().join("a-file"), b"data").unwrap();

        let source = LocalSource::new(
            LocalSourceSaveOptions::default(),
            &Excludes::default(),
            &LocalSourceFilterOptions::default(),
            &[anc.join("data")],
        )
        .unwrap();
        let node = source.dir_node(&anc).unwrap();
        assert!(node.is_dir());
        assert_eq!(node.name(), std::ffi::OsStr::new("anc"));
        let walked = LocalSource::new(
            LocalSourceSaveOptions::default(),
            &Excludes::default(),
            &LocalSourceFilterOptions::default(),
            &[&anc],
        )
        .unwrap()
        .entries()
        .next()
        .unwrap()
        .unwrap()
        .node;
        // (the walk may list it before, which can move its atime)
        let mut walked = walked;
        walked.meta.atime = node.meta.atime;
        assert_eq!(node, walked);
        assert_eq!(node.meta.mode, Some(0o20_000_000_751));
        assert!(node.meta.uid.is_some() && node.meta.mtime.is_some());

        // Not a directory, or missing: none.
        assert!(source.dir_node(&dir.path().join("a-file")).is_none());
        assert!(source.dir_node(&dir.path().join("missing")).is_none());
    }
}
