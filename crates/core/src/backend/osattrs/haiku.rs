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
use log::debug;

use super::{
    XattrErrors, XattrsRead, check,
    haiku_attrs::{self, Attr, AttrFile, Attrs, Kept, Stat, Unreadable},
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
            // SAFETY: e is the entry fs_read_attr_dir just gave, valid until
            // the next. Haiku's record is only as long as its name (d_name[1]
            // in its header, 1024 bytes in libc's), so the name is read
            // through a pointer taken from e itself, never a reference to
            // libc's array, which could reach past the record.
            let name_ptr = unsafe { &raw const (*e).d_name }.cast();
            // SAFETY: d_name is a C string NUL-terminated inside the record,
            // which is valid until the next fs_read_attr_dir.
            names.push(unsafe { CStr::from_ptr(name_ptr) }.to_bytes().to_vec());
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
/// (`xattrs`) or those that aren't, by name, and those of that kind left
/// out, each with why ([`haiku_attrs::read_kind`]: one that can't be read,
/// is too large, or whose name isn't UTF-8 doesn't lose the file its
/// others); or `None` for a type of file that isn't kept with attributes,
/// or on a file system without them.
///
/// # Errors
///
/// * If the file couldn't be opened or its attributes listed.
fn kept(path: &Path, xattrs: bool) -> io::Result<Option<Kept>> {
    let read = match open(path)? {
        Some(f) => haiku_attrs::read_kind(&f, xattrs)
            .map_err(|err| path_error("attributes of", path, &err))?,
        None => None,
    };
    if read.is_none() {
        debug!("no attributes for {}", path.display());
    }
    Ok(read)
}

/// How a warning names the attribute `name`.
fn shown(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

/// The extended attributes of the file at `path`: its attributes of type
/// `B_XATTR_TYPE`. One left out is named in `unreadable`, for the backup to
/// warn about and count each, as on every other system.
///
/// # Errors
///
/// * If the file couldn't be opened or its attributes listed.
pub(super) fn xattrs_read(path: &Path) -> io::Result<XattrsRead> {
    let (attrs, unreadable) = kept(path, true)?.unwrap_or_default();
    Ok(XattrsRead {
        attrs: attrs
            .into_iter()
            .map(|(name, attr)| ExtendedAttribute {
                name,
                value: Some(attr.value),
            })
            .collect(),
        unreadable: unreadable
            .into_iter()
            .map(|(name, err)| (shown(&name), err))
            .collect(),
    })
}

/// The error for the attributes `unreadable` that a backup left out of
/// `haiku.attributes`, which names each with why; none, no error.
fn left_out(unreadable: &Unreadable) -> io::Result<()> {
    if unreadable.is_empty() {
        return Ok(());
    }
    let each: Vec<_> = unreadable
        .iter()
        .map(|(name, err)| format!("{}: {err}", shown(name)))
        .collect();
    Err(io::Error::other(format!("{}; its others are kept", each.join("; "))))
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
///
/// # Errors
///
/// * If the file couldn't be opened or its attributes listed: none are
///   kept, and no `haiku.attributes`.
/// * If one or more couldn't be read, are too large or have names that
///   aren't UTF-8: the error names each, and `haiku.attributes` has the
///   others. The backup warns with it and counts the file as incomplete.
pub(super) fn fill_attributes(path: &Path, node: &mut Node, _f: Option<&File>) -> io::Result<()> {
    let Some((attrs, unreadable)) = kept(path, false)? else {
        return Ok(());
    };
    node.meta
        .generic_attributes
        .set(HAIKU_ATTRIBUTES, &Attrs(attrs))
        .map_err(io::Error::other)?;
    left_out(&unreadable)
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
        let x = xattrs_read(&file).unwrap().attrs;
        assert_eq!(x.len(), 1);
        assert_eq!(x[0].value.as_deref(), Some(&b"hi"[..]));
        set_xattrs(&file, &[]).unwrap();
        assert!(xattrs_read(&file).unwrap().attrs.is_empty());
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
        let x = xattrs_read(&file).unwrap().attrs;
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
        assert!(xattrs_read(&fifo).unwrap().attrs.is_empty());
        restore_attributes(&fifo, &node_with(&BTreeMap::new())).unwrap();
        assert!(restore_attributes(&fifo, &node_with(&want)).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// ForkAudit1 G5-04: the attributes a backup leaves out of
    /// `haiku.attributes` are one error that names each, after the others
    /// are kept.
    #[test]
    fn left_out_names_each() {
        assert!(left_out(&Vec::new()).is_ok());
        let unreadable = vec![
            (b"big".to_vec(), io::Error::other("no")),
            (b"bad\xff".to_vec(), io::Error::other("its name isn't UTF-8")),
        ];
        assert_eq!(
            left_out(&unreadable).unwrap_err().to_string(),
            "big: no; bad\u{fffd}: its name isn't UTF-8; its others are kept"
        );
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
        assert!(xattrs_read(&file).unwrap().attrs.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
