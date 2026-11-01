//! Haiku: the attributes BFS keeps with each file, directory and symlink
//! (`fs_attr(3)`), name, type code and data, which the xattr crate doesn't
//! support. Those of type `B_XATTR_TYPE` are the extended attributes, as
//! Haiku's own xattr functions see them; the rest are kept as the generic
//! attribute `haiku.attributes` (`haiku_attrs.rs`, which also has what to do
//! with them). Haiku has no file flags or ACLs.

use std::{
    collections::BTreeMap,
    ffi::CStr,
    fs::{File, OpenOptions},
    io,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
};

use jiff::Timestamp;
use log::{debug, warn};

use super::{
    XattrErrors, check,
    haiku_attrs::{self, Attr, AttrFile, Attrs, Stat},
    path_error,
};
use crate::backend::node::{
    ExtendedAttribute, Node, NodeType, generic_attributes::HAIKU_ATTRIBUTES,
};

pub(super) const FILE_FLAGS: Option<&str> = None;
pub(super) const FLAGS_BEFORE_DATA: u32 = 0;
pub(super) const FLAGS_BEFORE_ENTRIES: u32 = 0;
pub(super) const FLAGS_XATTRS: &[&str] = &[];
pub(super) const ZFS_DOS_FLAGS: Option<&str> = None;

/// Errors that mean the file system has no attributes.
fn unsupported(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EOPNOTSUPP | libc::ENOTSUP | libc::B_UNSUPPORTED | libc::ENOSYS)
    )
}

/// Errors that mean the attribute is gone, removed since the listing.
fn gone(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::ENOENT | libc::ENOATTR))
}

/// The result of an `fs_attr(3)` call on one attribute, `None` if it's
/// gone.
fn unless_gone<T: Copy + Default + PartialOrd>(r: T) -> io::Result<Option<T>> {
    match check(r) {
        Ok(r) => Ok(Some(r)),
        Err(err) if gone(&err) => Ok(None),
        Err(err) => Err(err),
    }
}

/// A file, directory or symlink itself, open for its attributes.
#[derive(Debug)]
struct Attributes(File);

/// Opens the file at `path` itself, a symlink too (`O_NOTRAVERSE`), for
/// its attributes. `None` for a type of file other than a regular file,
/// directory or symlink: opening a device or FIFO could have side effects.
fn open(path: &Path) -> io::Result<Option<Attributes>> {
    let t = std::fs::symlink_metadata(path)
        .map_err(|err| path_error("lstat", path, &err))?
        .file_type();
    if !(t.is_file() || t.is_dir() || t.is_symlink()) {
        return Ok(None);
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOTRAVERSE | libc::O_NONBLOCK)
        .open(path)
        .map(|f| Some(Attributes(f)))
        .map_err(|err| path_error("open", path, &err))
}

/// Sets errno, which `fs_read_attr_dir(3)` sets only on an error.
fn set_errno(errno: libc::c_int) {
    // SAFETY: _errnop gives this thread's errno.
    unsafe { *libc::_errnop() = errno };
}

impl AttrFile for Attributes {
    fn names(&self) -> io::Result<Option<Vec<Vec<u8>>>> {
        // SAFETY: the file is open; the attribute directory gets a
        // descriptor of its own.
        let dir = unsafe { libc::fs_fopen_attr_dir(self.0.as_raw_fd()) };
        if dir.is_null() {
            let err = io::Error::last_os_error();
            return if unsupported(&err) {
                Ok(None)
            } else {
                Err(err)
            };
        }
        let mut names = Vec::new();
        let result = loop {
            // The end of the directory and an error are both NULL; only an
            // error sets errno.
            set_errno(0);
            // SAFETY: dir is an open attribute directory.
            let e = unsafe { libc::fs_read_attr_dir(dir) };
            if e.is_null() {
                let err = io::Error::last_os_error();
                break if err.raw_os_error() == Some(0) {
                    Ok(())
                } else {
                    Err(err)
                };
            }
            // SAFETY: d_name is a C string, valid until the next
            // fs_read_attr_dir.
            names.push(
                unsafe { CStr::from_ptr((*e).d_name.as_ptr()) }
                    .to_bytes()
                    .to_vec(),
            );
        };
        // SAFETY: dir is an open attribute directory, closed once.
        _ = unsafe { libc::fs_close_attr_dir(dir) };
        result.map(|()| Some(names))
    }

    fn stat(&self, name: &CStr) -> io::Result<Option<Stat>> {
        let mut info = libc::attr_info { type_: 0, size: 0 };
        // SAFETY: name is a C string, info an attr_info.
        let r = unsafe { libc::fs_stat_attr(self.0.as_raw_fd(), name.as_ptr(), &raw mut info) };
        if unless_gone(r)?.is_none() {
            return Ok(None);
        }
        Ok(Some(Stat {
            type_code: info.type_,
            size: u64::try_from(info.size).map_err(io::Error::other)?,
        }))
    }

    fn read(&self, name: &CStr, type_code: u32, buf: &mut [u8]) -> io::Result<Option<usize>> {
        // SAFETY: name is a C string, buf holds buf.len() bytes.
        let n = unless_gone(unsafe {
            libc::fs_read_attr(
                self.0.as_raw_fd(),
                name.as_ptr(),
                type_code,
                0,
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        })?;
        Ok(n.map(|n| usize::try_from(n).unwrap_or_default()))
    }

    fn write(&self, name: &CStr, type_code: u32, value: &[u8]) -> io::Result<usize> {
        // SAFETY: name is a C string, value holds value.len() bytes.
        let n = check(unsafe {
            libc::fs_write_attr(
                self.0.as_raw_fd(),
                name.as_ptr(),
                type_code,
                0,
                value.as_ptr().cast(),
                value.len(),
            )
        })?;
        Ok(usize::try_from(n).unwrap_or_default())
    }

    fn remove(&self, name: &CStr) -> io::Result<()> {
        // SAFETY: name is a C string.
        unless_gone(unsafe { libc::fs_remove_attr(self.0.as_raw_fd(), name.as_ptr()) }).map(drop)
    }
}

/// The attributes of the file at `path` that are extended attributes
/// (`xattrs`) or those that aren't, by name, or `None` for a type of file
/// that isn't kept with attributes, or on a file system without them. One
/// whose name isn't UTF-8 is left out with a warning.
fn kept(path: &Path, xattrs: bool) -> io::Result<Option<BTreeMap<String, Attr>>> {
    let read = match open(path)? {
        Some(f) => haiku_attrs::read_kind(&f, xattrs)
            .map_err(|err| path_error("attributes of", path, &err))?,
        None => None,
    };
    let Some((kept, bad_names)) = read else {
        debug!("no attributes for {}", path.display());
        return Ok(None);
    };
    for name in bad_names {
        warn!(
            "ignoring attribute {} of {}: its name isn't UTF-8",
            String::from_utf8_lossy(&name),
            path.display()
        );
    }
    Ok(Some(kept))
}

/// The extended attributes of the file at `path`: its attributes of type
/// `B_XATTR_TYPE`.
pub(super) fn xattrs(path: &Path) -> io::Result<Vec<ExtendedAttribute>> {
    Ok(kept(path, true)?
        .unwrap_or_default()
        .into_iter()
        .map(|(name, attr)| ExtendedAttribute {
            name,
            value: Some(attr.value),
        })
        .collect())
}

/// Gives the file at `path` exactly the extended attributes `attrs`, as
/// attributes of type `B_XATTR_TYPE`, and leaves its other attributes alone.
pub(super) fn set_xattrs(path: &Path, attrs: &[ExtendedAttribute]) -> Result<(), XattrErrors> {
    Ok(apply(path, &haiku_attrs::from_xattrs(attrs), true)?)
}

/// Gives the file at `path` exactly the attributes `want` of one kind,
/// extended attributes (`xattrs`) or the rest, each with its type.
fn apply(path: &Path, want: &BTreeMap<String, Attr>, xattrs: bool) -> io::Result<()> {
    match open(path)? {
        Some(f) => haiku_attrs::apply(&f, want, xattrs),
        None if want.is_empty() => Ok(()),
        None => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no attributes are kept for this type of file",
        )),
    }
    .map_err(|err| path_error("attributes of", path, &err))
}

/// The attributes are read by path in `fill_attributes`: no file opened for
/// them here.
pub(super) fn open_for_attrs(_path: &Path, _typ: &NodeType, _m: &std::fs::Metadata) -> Option<File> {
    None
}

pub(super) fn file_flags(
    _path: &Path,
    _typ: &NodeType,
    _m: &std::fs::Metadata,
    _f: Option<&File>,
) -> io::Result<Option<u32>> {
    Ok(None)
}

/// Keeps the attributes other than the extended attributes, with their
/// types, as `haiku.attributes`: an empty object for a file that has none,
/// so that a restore removes any it has then, as from a snapshot that
/// doesn't know (one made on another system) it doesn't.
pub(super) fn fill_attributes(path: &Path, node: &mut Node, _f: Option<&File>) -> io::Result<()> {
    let Some(attrs) = kept(path, false)? else {
        return Ok(());
    };
    node.meta
        .generic_attributes
        .set(HAIKU_ATTRIBUTES, &Attrs(attrs))
        .map_err(io::Error::other)
}

pub(super) fn prepare_file_for_flags(_path: &Path, _flags: u32) -> io::Result<()> {
    Ok(())
}

pub(super) fn prepare_dir_for_flags(_path: &Path, _flags: u32) -> io::Result<()> {
    Ok(())
}

pub(super) fn restore_file_flags(
    _path: &Path,
    _typ: &NodeType,
    _flags: u32,
    _xattrs: &[ExtendedAttribute],
) -> io::Result<()> {
    Ok(())
}

/// Gives the file exactly the attributes in `haiku.attributes`, besides its
/// extended attributes, as the extended attributes are restored: one it
/// has that the snapshot doesn't is removed. A node without
/// `haiku.attributes` (from another system, or a file system without
/// attributes) leaves the file's as they are, as FreeBSD's system extended
/// attributes are.
pub(super) fn restore_attributes(path: &Path, node: &Node) -> io::Result<()> {
    let Some(attrs) = node.meta.generic_attributes.get::<Attrs>(HAIKU_ATTRIBUTES) else {
        return Ok(());
    };
    let (want, rejected) = haiku_attrs::typed(attrs.map_err(io::Error::other)?);
    apply(path, &want, false)?;
    if rejected.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{}: skipped {} in haiku.attributes: of type B_XATTR_TYPE, they belong with the extended attributes",
                path.display(),
                rejected.join(", ")
            ),
        ))
    }
}

pub(super) fn restore_zfs_dos_flags(_path: &Path, _typ: &NodeType, _flags: u64) -> io::Result<()> {
    Ok(())
}

/// No flags here keep a restore from changing a file.
pub(super) fn clear_restricting_flags(_path: &Path) -> io::Result<()> {
    Ok(())
}

pub(super) fn restore_owner(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

pub(super) fn restore_acls(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

/// A symlink's own permissions don't matter on Haiku.
pub(super) fn restore_symlink_mode(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

/// Haiku's creation time (`st_crtim`) isn't kept.
pub(super) fn restore_birthtime(_path: &Path, _node: &Node, _birth: Timestamp) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "birth times aren't restored on Haiku"))
}

/// Extended attributes have no metadata of their own here.
pub(super) fn fill_xattr_meta(_path: &Path, _node: &mut Node) {}

/// On the system's own file system (BFS): run on Haiku.
#[cfg(test)]
mod tests {
    use std::{
        ffi::CString,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
    };

    use super::*;

    const MIMS: u32 = u32::from_be_bytes(*b"MIMS");
    const RAWT: u32 = u32::from_be_bytes(*b"RAWT");

    fn attr(type_code: u32, value: &[u8]) -> Attr {
        Attr {
            type_code,
            value: value.to_vec(),
        }
    }

    fn typed(attrs: &[(&str, Attr)]) -> BTreeMap<String, Attr> {
        attrs
            .iter()
            .map(|(name, a)| ((*name).to_string(), a.clone()))
            .collect()
    }

    /// A new directory of its own for a test.
    fn scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rustic-haiku-{test}-{}", std::process::id()));
        _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    fn node_with(attrs: &BTreeMap<String, Attr>) -> Node {
        let mut node = Node::default();
        node.meta
            .generic_attributes
            .set(HAIKU_ATTRIBUTES, &Attrs(attrs.clone()))
            .unwrap();
        node
    }

    /// Restores `want` onto `path`, and backs it up again.
    fn round_trip(path: &Path, want: &BTreeMap<String, Attr>) {
        restore_attributes(path, &node_with(want)).unwrap();
        let mut node = Node::default();
        fill_attributes(path, &mut node, None).unwrap();
        let got: Attrs = node
            .meta
            .generic_attributes
            .get(HAIKU_ATTRIBUTES)
            .unwrap()
            .unwrap();
        assert_eq!(&got.0, want, "{}", path.display());
    }

    #[test]
    fn files_dirs_and_symlinks_keep_their_own() {
        let dir = scratch("kinds");
        let file = dir.join("file");
        let sub = dir.join("dir");
        let link = dir.join("link");
        std::fs::write(&file, b"x").unwrap();
        std::fs::create_dir(&sub).unwrap();
        symlink("file", &link).unwrap();

        let want = typed(&[("BEOS:TYPE", attr(MIMS, b"text/plain\0"))]);
        round_trip(&file, &want);
        round_trip(&sub, &typed(&[("dir attr", attr(RAWT, b"d"))]));
        round_trip(&link, &typed(&[("link attr", attr(RAWT, b"l"))]));
        // The symlink's own, not its target's.
        round_trip(&file, &want);

        // Extended attributes are a kind apart.
        set_xattrs(
            &file,
            &[ExtendedAttribute {
                name: "user.comment".to_string(),
                value: Some(b"hi".to_vec()),
            }],
        )
        .unwrap();
        round_trip(&file, &want);
        let x = xattrs(&file).unwrap();
        assert_eq!(x.len(), 1);
        assert_eq!(x[0].value.as_deref(), Some(&b"hi"[..]));
        set_xattrs(&file, &[]).unwrap();
        assert!(xattrs(&file).unwrap().is_empty());
        round_trip(&file, &want);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn empty_large_and_changed_attributes() {
        let dir = scratch("values");
        let file = dir.join("file");
        std::fs::write(&file, b"x").unwrap();
        let big = vec![b'b'; 20_000];

        round_trip(&file, &typed(&[("a", attr(RAWT, b""))]));
        round_trip(&file, &typed(&[("a", attr(MIMS, b"some data"))]));
        round_trip(&file, &typed(&[("a", attr(RAWT, b""))]));
        round_trip(&file, &typed(&[("a", attr(RAWT, &big))]));
        round_trip(&file, &typed(&[("a", attr(MIMS, b""))]));
        round_trip(&file, &typed(&[("a", attr(MIMS, b"x"))]));
        // Type alone.
        round_trip(&file, &typed(&[("a", attr(RAWT, b"x"))]));

        set_xattrs(
            &file,
            &[ExtendedAttribute {
                name: "user.empty".to_string(),
                value: None,
            }],
        )
        .unwrap();
        let x = xattrs(&file).unwrap();
        assert_eq!(x.len(), 1);
        assert_eq!(x[0].value.as_deref(), Some(&b""[..]));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn in_place_restores() {
        let dir = scratch("in-place");
        let file = dir.join("file");
        std::fs::write(&file, b"x").unwrap();
        let both = typed(&[("a", attr(RAWT, b"1")), ("b", attr(RAWT, b"2"))]);
        round_trip(&file, &both);

        // A node from another system leaves them alone.
        restore_attributes(&file, &Node::default()).unwrap();
        round_trip(&file, &both);
        // A Haiku node without them removes them.
        round_trip(&file, &BTreeMap::new());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn read_only_files_and_fifos() {
        let dir = scratch("special");
        let file = dir.join("file");
        std::fs::write(&file, b"x").unwrap();
        let want = typed(&[("a", attr(RAWT, b"1"))]);
        round_trip(&file, &want);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o444)).unwrap();
        // Readable: backed up all the same.
        let mut node = Node::default();
        fill_attributes(&file, &mut node, None).unwrap();
        assert!(
            node.meta
                .generic_attributes
                .get::<Attrs>(HAIKU_ATTRIBUTES)
                .is_some()
        );
        // BFS wants write access to write one, which root doesn't need:
        // the restore sets them before the mode.
        // SAFETY: geteuid has no preconditions.
        let root = unsafe { libc::geteuid() } == 0;
        let result = restore_attributes(&file, &node_with(&typed(&[("a", attr(RAWT, b"2"))])));
        assert_eq!(result.is_ok(), root, "{result:?}");

        let fifo = dir.join("fifo");
        let c_fifo = CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: c_fifo is a C string.
        assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o644) }, 0);
        let mut node = Node::default();
        fill_attributes(&fifo, &mut node, None).unwrap();
        assert!(node.meta.generic_attributes.is_empty());
        assert!(xattrs(&fifo).unwrap().is_empty());
        restore_attributes(&fifo, &node_with(&BTreeMap::new())).unwrap();
        assert!(restore_attributes(&fifo, &node_with(&want)).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn xatr_entries_in_haiku_attributes_are_skipped() {
        let dir = scratch("xatr");
        let file = dir.join("file");
        std::fs::write(&file, b"x").unwrap();
        let mut want = typed(&[("a", attr(RAWT, b"1"))]);
        _ = want.insert("user.x".to_string(), attr(haiku_attrs::XATTR_TYPE, b"x"));
        let err = restore_attributes(&file, &node_with(&want)).unwrap_err();
        assert!(err.to_string().contains("skipped user.x"), "{err}");
        assert!(xattrs(&file).unwrap().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
