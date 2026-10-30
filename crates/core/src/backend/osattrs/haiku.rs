//! Haiku: the attributes BFS keeps with each file, directory and symlink
//! (`fs_attr(3)`), name, type code and data, which the xattr crate doesn't
//! support. Those of type `B_XATTR_TYPE` are the extended attributes, as
//! Haiku's own xattr functions see them; the rest are kept as the generic
//! attribute `haiku.attributes` (`haiku_attrs.rs`). Haiku has no file
//! flags or ACLs.

use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    io,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
};

use log::{debug, warn};

use super::{
    check,
    haiku_attrs::{self, Attr, Attrs, Listed},
    path_error,
};
use crate::backend::node::{
    ExtendedAttribute, Node, NodeType, generic_attributes::HAIKU_ATTRIBUTES,
};

pub(super) const FILE_FLAGS: Option<&str> = None;
pub(super) const FLAGS_BEFORE_DATA: u32 = 0;

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

/// Opens the file at `path` itself, a symlink too (`O_NOTRAVERSE`), for
/// its attributes. `None` for a type of file other than a regular file,
/// directory or symlink: opening a device or FIFO could have side effects.
fn open_node(path: &Path) -> io::Result<Option<File>> {
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
        .map(Some)
        .map_err(|err| path_error("open", path, &err))
}

/// The names of the attributes of the open file `f`, or `None` on a file
/// system without attributes.
fn names(f: &File) -> io::Result<Option<Vec<Vec<u8>>>> {
    // SAFETY: f is an open file descriptor; the attribute directory gets one
    // of its own.
    let dir = unsafe { libc::fs_fopen_attr_dir(f.as_raw_fd()) };
    if dir.is_null() {
        let err = io::Error::last_os_error();
        return if unsupported(&err) {
            Ok(None)
        } else {
            Err(err)
        };
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: dir is an open attribute directory.
        let e = unsafe { libc::fs_read_attr_dir(dir) };
        if e.is_null() {
            break;
        }
        // SAFETY: d_name is a C string, valid until the next fs_read_attr_dir.
        names.push(
            unsafe { CStr::from_ptr((*e).d_name.as_ptr()) }
                .to_bytes()
                .to_vec(),
        );
    }
    // SAFETY: dir is an open attribute directory, closed once.
    _ = unsafe { libc::fs_close_attr_dir(dir) };
    Ok(Some(names))
}

/// The type and data of the attribute `name` of the open file `f`, or
/// `None` if it's gone.
fn read_attr(f: &File, name: &CStr) -> io::Result<Option<Attr>> {
    let mut info = libc::attr_info { type_: 0, size: 0 };
    // SAFETY: name is a C string, info an attr_info.
    if let Err(err) =
        check(unsafe { libc::fs_stat_attr(f.as_raw_fd(), name.as_ptr(), &raw mut info) })
    {
        return if gone(&err) { Ok(None) } else { Err(err) };
    }
    let size = usize::try_from(info.size).map_err(io::Error::other)?;
    let mut value = vec![0_u8; size];
    if size > 0 {
        // SAFETY: value holds size bytes.
        let n = unsafe {
            libc::fs_read_attr(
                f.as_raw_fd(),
                name.as_ptr(),
                info.type_,
                0,
                value.as_mut_ptr().cast(),
                size,
            )
        };
        match check(n) {
            Ok(n) => value.truncate(usize::try_from(n).unwrap_or_default()),
            Err(err) if gone(&err) => return Ok(None),
            Err(err) => return Err(err),
        }
    }
    Ok(Some(Attr {
        type_code: info.type_,
        value,
    }))
}

/// All the attributes of the file at `path`, or `None` for a type of file
/// that isn't kept with attributes, or on a file system without them.
fn read_all(path: &Path) -> io::Result<Option<(File, Listed)>> {
    let Some(f) = open_node(path)? else {
        return Ok(None);
    };
    let Some(names) = names(&f).map_err(|err| path_error("fs_fopen_attr_dir", path, &err))? else {
        return Ok(None);
    };
    let mut listed = Listed::new();
    for name in names {
        let c_name = CString::new(name.clone())?;
        let attr = read_attr(&f, &c_name).map_err(|err| {
            path_error(
                &format!("read attribute {}", c_name.to_string_lossy()),
                path,
                &err,
            )
        })?;
        if let Some(attr) = attr {
            _ = listed.insert(name, attr);
        }
    }
    Ok(Some((f, listed)))
}

/// The attributes of the file at `path` that are extended attributes
/// (`xattrs`) or those that aren't, by name. One whose name isn't UTF-8 is
/// left out with a warning.
fn kept(path: &Path, xattrs: bool) -> io::Result<BTreeMap<String, Attr>> {
    let Some((_, listed)) = read_all(path)? else {
        debug!("no attributes for {}", path.display());
        return Ok(BTreeMap::new());
    };
    let (kept, bad_names) = haiku_attrs::partition(listed, xattrs);
    for name in bad_names {
        warn!(
            "ignoring attribute {} of {}: its name isn't UTF-8",
            String::from_utf8_lossy(&name),
            path.display()
        );
    }
    Ok(kept)
}

/// The extended attributes of the file at `path`: its attributes of type
/// `B_XATTR_TYPE`.
pub(super) fn xattrs(path: &Path) -> io::Result<Vec<ExtendedAttribute>> {
    Ok(kept(path, true)?
        .into_iter()
        .map(|(name, attr)| ExtendedAttribute {
            name,
            value: Some(attr.value),
        })
        .collect())
}

/// Gives the file at `path` exactly the extended attributes `attrs`, as
/// attributes of type `B_XATTR_TYPE`, and leaves its other attributes alone.
pub(super) fn set_xattrs(path: &Path, attrs: &[ExtendedAttribute]) -> io::Result<()> {
    apply(path, &haiku_attrs::from_xattrs(attrs), true)
}

/// Gives the file at `path` exactly the attributes `want` of one kind,
/// extended attributes (`xattrs`) or the rest, each with its type. Goes on
/// after an error, and returns the first.
fn apply(path: &Path, want: &BTreeMap<String, Attr>, xattrs: bool) -> io::Result<()> {
    let Some((f, current)) = read_all(path)? else {
        if want.is_empty() {
            return Ok(());
        }
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "{}: no attributes on this file or file system",
                path.display()
            ),
        ));
    };
    let fd = f.as_raw_fd();
    let remove = |name: &CStr| {
        // SAFETY: name is a C string.
        match check(unsafe { libc::fs_remove_attr(fd, name.as_ptr()) }) {
            Err(err) if !gone(&err) => Err(path_error(
                &format!("remove attribute {}", name.to_string_lossy()),
                path,
                &err,
            )),
            _ => Ok(()),
        }
    };
    let plan = haiku_attrs::plan(&current, want, xattrs);
    let mut first_err = None;
    for name in plan.remove {
        if let Err(err) = CString::new(name)
            .map_err(io::Error::from)
            .and_then(|n| remove(&n))
        {
            _ = first_err.get_or_insert(err);
        }
    }
    for (name, attr, replace) in plan.write {
        let write = || {
            let n = CString::new(name)?;
            // Remove one of another type first: BFS may keep its old type.
            if replace {
                remove(&n)?;
            }
            write_attr(&f, &n, attr)
                .map_err(|err| path_error(&format!("write attribute {name}"), path, &err))
        };
        if let Err(err) = write() {
            _ = first_err.get_or_insert(err);
        }
    }
    first_err.map_or(Ok(()), Err)
}

/// Writes the attribute `name` of the open file `f`, replacing its data.
fn write_attr(f: &File, name: &CStr, attr: &Attr) -> io::Result<()> {
    let len = attr.value.len();
    // SAFETY: name is a C string, value holds len bytes.
    let n = check(unsafe {
        libc::fs_write_attr(
            f.as_raw_fd(),
            name.as_ptr(),
            attr.type_code,
            0,
            attr.value.as_ptr().cast(),
            len,
        )
    })?;
    if usize::try_from(n).ok() != Some(len) {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("wrote {n} of {len} bytes"),
        ));
    }
    // An empty attribute is created when it's opened for writing; make sure
    // of it, rather than lose it without a word.
    if len == 0 && read_attr(f, name)?.is_none_or(|got| got.type_code != attr.type_code) {
        return Err(io::Error::other("empty attribute not created"));
    }
    Ok(())
}

pub(super) fn file_flags(_path: &Path, _typ: &NodeType, _m: &std::fs::Metadata) -> io::Result<u32> {
    Ok(0)
}

/// Keeps the attributes other than the extended attributes, with their
/// types, as `haiku.attributes`.
pub(super) fn fill_attributes(path: &Path, node: &mut Node) -> io::Result<()> {
    let attrs = kept(path, false)?;
    if attrs.is_empty() {
        return Ok(());
    }
    node.meta
        .generic_attributes
        .set(HAIKU_ATTRIBUTES, &Attrs(attrs))
        .map_err(io::Error::other)
}

pub(super) fn prepare_file_for_flags(_path: &Path, _flags: u32) -> io::Result<()> {
    Ok(())
}

pub(super) fn restore_file_flags(_path: &Path, _typ: &NodeType, _flags: u32) -> io::Result<()> {
    Ok(())
}

/// Gives the file exactly the attributes in `haiku.attributes`, besides its
/// extended attributes, as the extended attributes are restored: one it
/// has that the snapshot doesn't is removed.
pub(super) fn restore_attributes(path: &Path, node: &Node) -> io::Result<()> {
    let want = match node.meta.generic_attributes.get::<Attrs>(HAIKU_ATTRIBUTES) {
        Some(attrs) => attrs.map_err(io::Error::other)?.0,
        None => BTreeMap::new(),
    };
    apply(path, &want, false)
}

pub(super) fn restore_acls(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}

/// A symlink's own permissions don't matter on Haiku.
pub(super) fn restore_symlink_mode(_path: &Path, _node: &Node) -> io::Result<()> {
    Ok(())
}
