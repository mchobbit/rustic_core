//! Haiku's file attributes, as BFS keeps them (`fs_attr(3)`,
//! `listattr(1)`): each has a name, a type code and data, and files,
//! directories and symlinks can all have them. Those of type
//! `B_XATTR_TYPE` (`'XATR'`) are what Haiku's own xattr functions
//! (`getxattr(3)` and the rest, in libgnu) read and write, under the same
//! names: they are kept as extended attributes. The rest are kept as the
//! generic attribute `haiku.attributes`, with their type codes.
//!
//! Portable, so that it is tested on any system: the system calls are
//! behind [`AttrFile`], which `haiku.rs` implements with `fs_attr(3)`, and
//! the tests with a fake that behaves as BFS does.

#![cfg_attr(not(target_os = "haiku"), allow(dead_code))]

use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    io,
};

use serde_derive::{Deserialize, Serialize};
use serde_with::{DefaultOnNull, base64::Base64, serde_as};

use crate::backend::node::ExtendedAttribute;

/// `B_XATTR_TYPE` from `<TypeConstants.h>`, the type of the attributes that
/// Haiku's xattr functions write.
pub(super) const XATTR_TYPE: u32 = u32::from_be_bytes(*b"XATR");

/// The size of a value too large for BFS to keep in the inode (its
/// `small_data`): more than the largest BFS inode, 8 KiB.
const SPILL_SIZE: usize = 16 * 1024;

/// How often an attribute that grows while it's read is read.
const READ_TRIES: usize = 3;

/// An attribute's type code (`attr_info.type`, a four-character code such
/// as `'MIMS'` read as a big-endian `u32`) and data.
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(super) struct Attr {
    #[serde(rename = "type")]
    pub(super) type_code: u32,
    #[serde_as(as = "DefaultOnNull<Base64>")]
    #[serde(default)]
    pub(super) value: Vec<u8>,
}

impl Attr {
    /// The type and size `fs_stat_attr(3)` gives for this attribute.
    fn stat(&self) -> Stat {
        Stat {
            type_code: self.type_code,
            size: u64::try_from(self.value.len()).unwrap_or(u64::MAX),
        }
    }
}

/// A file's attributes other than the extended attributes, by name: the
/// generic attribute `haiku.attributes`, as in
/// `{"BEOS:TYPE":{"type":1296649555,"value":"dGV4dC9wbGFpbgA="}}`.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(transparent)]
pub(super) struct Attrs(pub(super) BTreeMap<String, Attr>);

/// An attribute's type code and size (`attr_info`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Stat {
    pub(super) type_code: u32,
    pub(super) size: u64,
}

/// The type and size of each attribute a file has, by its name's bytes.
pub(super) type Stats = BTreeMap<Vec<u8>, Stat>;

/// The attributes of one open file: `fs_attr(3)` on Haiku. An attribute
/// removed meanwhile is `None`.
pub(super) trait AttrFile {
    /// The names of the file's attributes, or `None` on a file system
    /// without attributes.
    fn names(&self) -> io::Result<Option<Vec<Vec<u8>>>>;
    /// The type and size of the attribute `name`.
    fn stat(&self, name: &CStr) -> io::Result<Option<Stat>>;
    /// Reads the attribute `name` from its start into `buf`: how many bytes
    /// it read.
    fn read(&self, name: &CStr, type_code: u32, buf: &mut [u8]) -> io::Result<Option<usize>>;
    /// Writes `value` as the attribute `name` of type `type_code`, from its
    /// start, truncating it first (`fs_write_attr(3)` at 0): how many bytes
    /// it wrote.
    fn write(&self, name: &CStr, type_code: u32, value: &[u8]) -> io::Result<usize>;
    /// Removes the attribute `name`; one that's gone is no error.
    fn remove(&self, name: &CStr) -> io::Result<()>;
}

/// `err`, saying what was done to which attribute.
fn named(op: &str, name: &[u8], err: &io::Error) -> io::Error {
    io::Error::new(
        err.kind(),
        format!("{op} attribute {}: {err}", String::from_utf8_lossy(name)),
    )
}

/// The type and size of each of the file's attributes, without their data,
/// or `None` on a file system without attributes.
pub(super) fn stats(file: &impl AttrFile) -> io::Result<Option<Stats>> {
    let Some(names) = file.names()? else {
        return Ok(None);
    };
    let mut stats = Stats::new();
    for name in names {
        let c_name = CString::new(name.clone())?;
        if let Some(stat) = file
            .stat(&c_name)
            .map_err(|err| named("stat", &name, &err))?
        {
            _ = stats.insert(name, stat);
        }
    }
    Ok(Some(stats))
}

/// The attribute `name`, which `fs_stat_attr(3)` said is `stat`. One that
/// grew since is read again: a single read of its old size would give only
/// the start of it.
fn read_attr(file: &impl AttrFile, name: &CStr, mut stat: Stat) -> io::Result<Option<Attr>> {
    for _ in 0..READ_TRIES {
        let size = usize::try_from(stat.size).map_err(io::Error::other)?;
        // A byte more, to see whether there is more.
        let mut value = vec![0_u8; size + 1];
        let Some(n) = file.read(name, stat.type_code, &mut value)? else {
            return Ok(None);
        };
        if n <= size {
            value.truncate(n);
            return Ok(Some(Attr {
                type_code: stat.type_code,
                value,
            }));
        }
        let Some(again) = file.stat(name)? else {
            return Ok(None);
        };
        stat = again;
    }
    Err(io::Error::other("it keeps growing as it's read"))
}

/// A file's attributes of one kind, by name, and the names of those left
/// out because they aren't UTF-8, which a node can't hold.
pub(super) type Kept = (BTreeMap<String, Attr>, Vec<Vec<u8>>);

/// The file's attributes that are extended attributes (`xattrs`) or those
/// that aren't, or `None` on a file system without attributes. Only the
/// data of that kind is read.
pub(super) fn read_kind(file: &impl AttrFile, xattrs: bool) -> io::Result<Option<Kept>> {
    let Some(stats) = stats(file)? else {
        return Ok(None);
    };
    let mut kept = BTreeMap::new();
    let mut bad_names = Vec::new();
    for (name, stat) in stats {
        if (stat.type_code == XATTR_TYPE) != xattrs {
            continue;
        }
        let name = match String::from_utf8(name) {
            Ok(name) => name,
            Err(err) => {
                bad_names.push(err.into_bytes());
                continue;
            }
        };
        let c_name = CString::new(name.clone())?;
        if let Some(attr) =
            read_attr(file, &c_name, stat).map_err(|err| named("read", name.as_bytes(), &err))?
        {
            _ = kept.insert(name, attr);
        }
    }
    Ok(Some((kept, bad_names)))
}

/// Extended attributes as the attributes they are on Haiku.
pub(super) fn from_xattrs(attrs: &[ExtendedAttribute]) -> BTreeMap<String, Attr> {
    attrs
        .iter()
        .map(|a| {
            let attr = Attr {
                type_code: XATTR_TYPE,
                value: a.value.clone().unwrap_or_default(),
            };
            (a.name.clone(), attr)
        })
        .collect()
}

/// The attributes of `haiku.attributes` to restore, and the names of those
/// of type `B_XATTR_TYPE`, left out: those belong with the extended
/// attributes, whose restore would remove each such one again.
pub(super) fn typed(attrs: Attrs) -> (BTreeMap<String, Attr>, Vec<String>) {
    let mut rejected = Vec::new();
    let mut want = attrs.0;
    want.retain(|name, attr| {
        let ok = attr.type_code != XATTR_TYPE;
        if !ok {
            rejected.push(name.clone());
        }
        ok
    });
    (want, rejected)
}

/// What to change for a file's attributes of one kind (extended attributes
/// or not) to be exactly `want`.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Plan<'a> {
    /// Attributes of this kind that `want` doesn't have. One whose name
    /// isn't UTF-8 isn't among them: no snapshot can have it.
    pub(super) remove: Vec<Vec<u8>>,
    /// Attributes to write: the file has none of that name, or one of
    /// another type or size.
    pub(super) write: Vec<(&'a str, &'a Attr)>,
    /// Attributes the file has with the type and size wanted, to write if
    /// their data differs.
    pub(super) compare: Vec<(&'a str, &'a Attr)>,
}

/// The changes that give a file whose attributes are `current` exactly the
/// attributes `want` of one kind, extended attributes (`xattrs`) or the
/// rest, and leave those of the other kind alone.
pub(super) fn plan<'a>(
    current: &Stats,
    want: &'a BTreeMap<String, Attr>,
    xattrs: bool,
) -> Plan<'a> {
    let remove = current
        .iter()
        .filter(|(name, stat)| {
            (stat.type_code == XATTR_TYPE) == xattrs
                && std::str::from_utf8(name).is_ok_and(|name| !want.contains_key(name))
        })
        .map(|(name, _)| name.clone())
        .collect();
    let (compare, write) = want
        .iter()
        .map(|(name, attr)| (name.as_str(), attr))
        .partition(|(name, attr)| current.get(name.as_bytes()) == Some(&attr.stat()));
    Plan {
        remove,
        write,
        compare,
    }
}

/// Gives the file exactly the attributes `want` of one kind, extended
/// attributes (`xattrs`) or the rest, each with its type, and leaves the
/// others alone. One that is already as wanted isn't written. Goes on after
/// an error, and returns the first.
pub(super) fn apply(
    file: &impl AttrFile,
    want: &BTreeMap<String, Attr>,
    xattrs: bool,
) -> io::Result<()> {
    let Some(current) = stats(file)? else {
        return if want.is_empty() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the file system has no attributes",
            ))
        };
    };
    let plan = plan(&current, want, xattrs);
    let mut first_err = None;
    let mut note = |result: io::Result<()>| {
        if let Err(err) = result {
            _ = first_err.get_or_insert(err);
        }
    };
    for name in &plan.remove {
        note(
            CString::new(name.clone())
                .map_err(io::Error::from)
                .and_then(|n| file.remove(&n))
                .map_err(|err| named("remove", name, &err)),
        );
    }
    for (name, attr) in plan.compare {
        let set = || {
            let n = CString::new(name)?;
            match read_attr(file, &n, attr.stat())? {
                Some(have) if have == *attr => Ok(()),
                _ => write_attr(file, &n, attr),
            }
        };
        note(set().map_err(|err| named("write", name.as_bytes(), &err)));
    }
    for (name, attr) in plan.write {
        note(
            CString::new(name)
                .map_err(io::Error::from)
                .and_then(|n| write_attr(file, &n, attr))
                .map_err(|err| named("write", name.as_bytes(), &err)),
        );
    }
    first_err.map_or(Ok(()), Err)
}

/// Writes all of `value` as the attribute `name`, from its start.
fn write_all(file: &impl AttrFile, name: &CStr, type_code: u32, value: &[u8]) -> io::Result<()> {
    let n = file.write(name, type_code, value)?;
    if n == value.len() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("wrote {n} of {} bytes", value.len()),
        ))
    }
}

/// Whether the attribute `name` is `attr`, as far as its type and size say:
/// it was written from its start, so its size says whether more is left.
fn written(file: &impl AttrFile, name: &CStr, attr: &Attr) -> io::Result<bool> {
    Ok(file.stat(name)? == Some(attr.stat()))
}

/// Gives the file the attribute `name` as `attr`, type and data, in place
/// of any it has of that name: a failed write leaves the old one.
///
/// A write of no data creates no attribute on BFS (the kernel doesn't call
/// the file system's write for 0 bytes, and BFS creates an attribute only
/// as it writes), and the truncation that comes with each write leaves the
/// data of an attribute BFS keeps in the inode as it was. So an empty
/// attribute BFS didn't make is first written too large for the inode,
/// which puts it in an attribute inode of its own, and then written empty,
/// which truncates that.
fn write_attr(file: &impl AttrFile, name: &CStr, attr: &Attr) -> io::Result<()> {
    write_all(file, name, attr.type_code, &attr.value)?;
    if written(file, name, attr)? {
        return Ok(());
    }
    if attr.value.is_empty() {
        write_all(file, name, attr.type_code, &vec![0; SPILL_SIZE])?;
        write_all(file, name, attr.type_code, &[])?;
        if written(file, name, attr)? {
            return Ok(());
        }
        // Not the zeros, at least.
        file.remove(name)?;
        return Err(io::Error::other(
            "the file system doesn't create an empty attribute",
        ));
    }
    // A file system that kept the old type, or more of the old data.
    file.remove(name)?;
    write_all(file, name, attr.type_code, &attr.value)?;
    if written(file, name, attr)? {
        Ok(())
    } else {
        Err(io::Error::other("it isn't as written"))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;

    const MIMS: u32 = u32::from_be_bytes(*b"MIMS");
    const RAWT: u32 = u32::from_be_bytes(*b"RAWT");

    fn attr(type_code: u32, value: &[u8]) -> Attr {
        Attr {
            type_code,
            value: value.to_vec(),
        }
    }

    fn stat(type_code: u32, size: u64) -> Stat {
        Stat { type_code, size }
    }

    fn want(attrs: &[(&str, Attr)]) -> BTreeMap<String, Attr> {
        attrs
            .iter()
            .map(|(name, a)| ((*name).to_string(), a.clone()))
            .collect()
    }

    /// An attribute of the fake BFS: in the inode (`small_data`) or in an
    /// attribute inode of its own.
    #[derive(Clone, Debug)]
    struct FakeAttr {
        attr: Attr,
        own_inode: bool,
    }

    /// The most the fake BFS keeps in the inode.
    const SMALL_DATA: usize = 1000;

    /// A file on BFS, as `fs_attr(3)` sees it (Haiku's `vfs.cpp` and
    /// `fd.cpp`, BFS's `Attribute.cpp` and `Inode.cpp`).
    #[derive(Default)]
    struct FakeBfs {
        attrs: RefCell<BTreeMap<Vec<u8>, FakeAttr>>,
        /// How many reads and writes of data, and removals.
        reads: Cell<usize>,
        writes: Cell<usize>,
        removes: Cell<usize>,
        /// Writes of data fail, as on a full disk.
        full: Cell<bool>,
        /// Data another program gives the attribute just before the next
        /// read, after its stat.
        grow: RefCell<Option<Vec<u8>>>,
    }

    impl FakeBfs {
        fn with(attrs: &[(&[u8], Attr)]) -> Self {
            let bfs = Self::default();
            for (name, a) in attrs {
                _ = bfs.attrs.borrow_mut().insert(
                    name.to_vec(),
                    FakeAttr {
                        attr: a.clone(),
                        own_inode: a.value.len() > SMALL_DATA,
                    },
                );
            }
            bfs
        }

        fn get(&self, name: &[u8]) -> Option<FakeAttr> {
            self.attrs.borrow().get(name).cloned()
        }

        /// Moves the attribute `name` to an attribute inode of its own, as
        /// an empty one is on BFS.
        fn own_inode(&self, name: &[u8]) {
            self.attrs.borrow_mut().get_mut(name).unwrap().own_inode = true;
        }
    }

    impl AttrFile for FakeBfs {
        fn names(&self) -> io::Result<Option<Vec<Vec<u8>>>> {
            Ok(Some(self.attrs.borrow().keys().cloned().collect()))
        }

        fn stat(&self, name: &CStr) -> io::Result<Option<Stat>> {
            Ok(self.get(name.to_bytes()).map(|a| a.attr.stat()))
        }

        fn read(&self, name: &CStr, _type_code: u32, buf: &mut [u8]) -> io::Result<Option<usize>> {
            self.reads.set(self.reads.get() + 1);
            let mut attrs = self.attrs.borrow_mut();
            let Some(a) = attrs.get_mut(name.to_bytes()) else {
                return Ok(None);
            };
            if let Some(value) = self.grow.borrow_mut().take() {
                a.attr.value = value;
            }
            let n = a.attr.value.len().min(buf.len());
            buf[..n].copy_from_slice(&a.attr.value[..n]);
            Ok(Some(n))
        }

        fn write(&self, name: &CStr, type_code: u32, value: &[u8]) -> io::Result<usize> {
            self.writes.set(self.writes.get() + 1);
            let mut attrs = self.attrs.borrow_mut();
            let name = name.to_bytes();
            // Attribute::Create with O_TRUNC truncates an attribute inode,
            // and leaves small data as it is.
            if let Some(a) = attrs.get_mut(name)
                && a.own_inode
            {
                a.attr.value.clear();
            }
            // common_user_io: nothing more for 0 bytes.
            if value.is_empty() {
                return Ok(0);
            }
            if self.full.get() {
                return Err(io::Error::from(io::ErrorKind::StorageFull));
            }
            // Inode::WriteAttribute: in the inode if it fits, else in an
            // attribute inode; of the new type either way.
            _ = attrs.insert(
                name.to_vec(),
                FakeAttr {
                    attr: attr(type_code, value),
                    own_inode: value.len() > SMALL_DATA,
                },
            );
            Ok(value.len())
        }

        fn remove(&self, name: &CStr) -> io::Result<()> {
            self.removes.set(self.removes.get() + 1);
            _ = self.attrs.borrow_mut().remove(name.to_bytes());
            Ok(())
        }
    }

    /// A file system that creates no empty attribute at all.
    struct NoEmpty(FakeBfs);

    impl AttrFile for NoEmpty {
        fn names(&self) -> io::Result<Option<Vec<Vec<u8>>>> {
            self.0.names()
        }
        fn stat(&self, name: &CStr) -> io::Result<Option<Stat>> {
            self.0.stat(name)
        }
        fn read(&self, name: &CStr, type_code: u32, buf: &mut [u8]) -> io::Result<Option<usize>> {
            self.0.read(name, type_code, buf)
        }
        fn write(&self, name: &CStr, type_code: u32, value: &[u8]) -> io::Result<usize> {
            if value.is_empty() {
                return Ok(0);
            }
            _ = self.0.attrs.borrow_mut().insert(
                name.to_bytes().to_vec(),
                FakeAttr {
                    attr: attr(type_code, value),
                    own_inode: false,
                },
            );
            Ok(value.len())
        }
        fn remove(&self, name: &CStr) -> io::Result<()> {
            self.0.remove(name)
        }
    }

    #[test]
    fn type_codes_are_haikus() {
        assert_eq!(XATTR_TYPE, 0x5841_5452);
        assert_eq!(MIMS, 1_296_649_555);
    }

    #[test]
    fn attrs_json() {
        let mut attrs = Attrs::default();
        _ = attrs
            .0
            .insert("BEOS:TYPE".to_string(), attr(MIMS, b"text/plain\0"));
        _ = attrs.0.insert("empty".to_string(), attr(RAWT, b""));
        let json = serde_json::to_string(&attrs).unwrap();
        assert_eq!(
            json,
            r#"{"BEOS:TYPE":{"type":1296649555,"value":"dGV4dC9wbGFpbgA="},"empty":{"type":1380013908,"value":""}}"#
        );
        let back: Attrs = serde_json::from_str(&json).unwrap();
        assert_eq!(back, attrs);

        // A null or missing value is empty, as Go writes a nil []byte.
        let back: Attrs =
            serde_json::from_str(r#"{"a":{"type":1,"value":null},"b":{"type":4294967295}}"#)
                .unwrap();
        assert_eq!(back.0["a"], attr(1, b""));
        assert_eq!(back.0["b"], attr(u32::MAX, b""));
        assert!(serde_json::from_str::<Attrs>(r#"{"a":{"value":""}}"#).is_err());
    }

    #[test]
    fn attrs_in_a_node() {
        use crate::backend::node::{Node, generic_attributes::HAIKU_ATTRIBUTES};
        let mut node = Node::default();
        let mut attrs = Attrs::default();
        _ = attrs
            .0
            .insert("BEOS:TYPE".to_string(), attr(MIMS, b"text/plain\0"));
        node.meta
            .generic_attributes
            .set(HAIKU_ATTRIBUTES, &attrs)
            .unwrap();
        let json = serde_json::to_string(&node).unwrap();
        assert!(
            json.contains(r#""generic_attributes":{"haiku.attributes":{"BEOS:TYPE":{"type":1296649555,"value":"dGV4dC9wbGFpbgA="}}}"#),
            "{json}"
        );
        let back: Node = serde_json::from_str(&json).unwrap();
        let got: Attrs = back
            .meta
            .generic_attributes
            .get(HAIKU_ATTRIBUTES)
            .unwrap()
            .unwrap();
        assert_eq!(got, attrs);

        // A Haiku file without typed attributes says so, unlike a node from
        // another system.
        let mut node = Node::default();
        node.meta
            .generic_attributes
            .set(HAIKU_ATTRIBUTES, &Attrs::default())
            .unwrap();
        let json = serde_json::to_string(&node).unwrap();
        assert!(
            json.contains(r#""generic_attributes":{"haiku.attributes":{}}"#),
            "{json}"
        );
    }

    #[test]
    fn read_kind_reads_only_its_kind() {
        let bfs = FakeBfs::with(&[
            (b"BEOS:TYPE", attr(MIMS, b"text/plain\0")),
            (b"empty", attr(RAWT, b"")),
            (b"user.comment", attr(XATTR_TYPE, b"hi")),
            (b"bad\xff", attr(MIMS, b"x")),
            (b"bad\xfe", attr(XATTR_TYPE, b"x")),
        ]);

        let (typed, bad) = read_kind(&bfs, false).unwrap().unwrap();
        assert_eq!(
            typed,
            want(&[
                ("BEOS:TYPE", attr(MIMS, b"text/plain\0")),
                ("empty", attr(RAWT, b"")),
            ])
        );
        assert_eq!(bad, [b"bad\xff".to_vec()]);
        assert_eq!(bfs.reads.get(), 2);

        let (xattrs, bad) = read_kind(&bfs, true).unwrap().unwrap();
        assert_eq!(xattrs, want(&[("user.comment", attr(XATTR_TYPE, b"hi"))]));
        assert_eq!(bad, [b"bad\xfe".to_vec()]);
        assert_eq!(bfs.reads.get(), 3);
    }

    #[test]
    fn read_an_attribute_that_grows() {
        let bfs = FakeBfs::with(&[(b"a", attr(RAWT, b"short"))]);
        *bfs.grow.borrow_mut() = Some(b"longer now".to_vec());
        let (got, _) = read_kind(&bfs, false).unwrap().unwrap();
        assert_eq!(got["a"], attr(RAWT, b"longer now"));
        assert_eq!(bfs.reads.get(), 2);

        // One that shrinks is read once.
        *bfs.grow.borrow_mut() = Some(b"s".to_vec());
        let (got, _) = read_kind(&bfs, false).unwrap().unwrap();
        assert_eq!(got["a"], attr(RAWT, b"s"));
        assert_eq!(bfs.reads.get(), 3);
    }

    #[test]
    fn xattrs_are_xatr_attributes() {
        let attrs = [
            ExtendedAttribute {
                name: "user.a".to_string(),
                value: Some(b"1".to_vec()),
            },
            ExtendedAttribute {
                name: "user.b".to_string(),
                value: None,
            },
        ];
        let want = from_xattrs(&attrs);
        assert_eq!(want["user.a"], attr(XATTR_TYPE, b"1"));
        assert_eq!(want["user.b"], attr(XATTR_TYPE, b""));
    }

    #[test]
    fn typed_attributes_of_type_xatr_are_left_out() {
        let attrs = Attrs(want(&[
            ("BEOS:TYPE", attr(MIMS, b"text/plain\0")),
            ("user.sneaky", attr(XATTR_TYPE, b"x")),
        ]));
        let (want, rejected) = typed(attrs);
        assert_eq!(want.keys().collect::<Vec<_>>(), ["BEOS:TYPE"]);
        assert_eq!(rejected, ["user.sneaky"]);
    }

    #[test]
    fn plan_changes_one_kind_only() {
        let mut current = Stats::new();
        _ = current.insert(b"same".to_vec(), stat(MIMS, 1));
        _ = current.insert(b"other data".to_vec(), stat(MIMS, 1));
        _ = current.insert(b"other size".to_vec(), stat(MIMS, 1));
        _ = current.insert(b"other type".to_vec(), stat(MIMS, 1));
        _ = current.insert(b"extra".to_vec(), stat(MIMS, 1));
        _ = current.insert(b"extra\xff".to_vec(), stat(MIMS, 1));
        _ = current.insert(b"user.xattr".to_vec(), stat(XATTR_TYPE, 1));

        let w = want(&[
            ("same", attr(MIMS, b"x")),
            ("other data", attr(MIMS, b"y")),
            ("other size", attr(MIMS, b"xy")),
            ("other type", attr(1, b"x")),
            ("new", attr(MIMS, b"")),
        ]);
        let p = plan(&current, &w, false);
        // A name that isn't UTF-8 can't be in a snapshot: it stays.
        assert_eq!(p.remove, [b"extra".to_vec()]);
        assert_eq!(
            p.write,
            [
                ("new", &w["new"]),
                ("other size", &w["other size"]),
                ("other type", &w["other type"]),
            ]
        );
        assert_eq!(
            p.compare,
            [("other data", &w["other data"]), ("same", &w["same"])]
        );

        // The extended attributes alone: the rest stay as they are.
        let w = from_xattrs(&[]);
        let p = plan(&current, &w, true);
        assert_eq!(p.remove, [b"user.xattr".to_vec()]);
        assert!(p.write.is_empty() && p.compare.is_empty());

        // A name the file has as the other kind is written over.
        let w = want(&[("same", attr(XATTR_TYPE, b"x"))]);
        let p = plan(&current, &w, true);
        assert_eq!(p.remove, [b"user.xattr".to_vec()]);
        assert_eq!(p.write, [("same", &w["same"])]);
    }

    #[test]
    fn apply_gives_exactly_the_attributes_of_one_kind() {
        let bfs = FakeBfs::with(&[
            (b"same", attr(MIMS, b"x")),
            (b"other data", attr(MIMS, b"x")),
            (b"other type", attr(MIMS, b"x")),
            (b"extra", attr(MIMS, b"x")),
            (b"extra\xff", attr(MIMS, b"x")),
            (b"user.xattr", attr(XATTR_TYPE, b"x")),
        ]);
        let w = want(&[
            ("same", attr(MIMS, b"x")),
            ("other data", attr(MIMS, b"y")),
            ("other type", attr(RAWT, b"x")),
            ("new", attr(RAWT, b"new")),
        ]);
        apply(&bfs, &w, false).unwrap();
        // Only the two of the type and size wanted are read; one of another
        // type is written over, not removed first.
        assert_eq!(bfs.reads.get(), 2);
        assert_eq!(bfs.removes.get(), 1);
        let (got, bad) = read_kind(&bfs, false).unwrap().unwrap();
        assert_eq!(got, w);
        assert_eq!(bad, [b"extra\xff".to_vec()]);
        assert_eq!(bfs.get(b"user.xattr").unwrap().attr, attr(XATTR_TYPE, b"x"));

        // Again: nothing to write.
        bfs.reads.set(0);
        bfs.writes.set(0);
        apply(&bfs, &w, false).unwrap();
        assert_eq!((bfs.reads.get(), bfs.writes.get()), (4, 0));
    }

    #[test]
    fn a_failed_write_leaves_the_old_attribute() {
        let bfs = FakeBfs::with(&[(b"a", attr(MIMS, b"old"))]);
        bfs.full.set(true);
        let err = apply(&bfs, &want(&[("a", attr(RAWT, b"new"))]), false).unwrap_err();
        assert!(err.to_string().starts_with("write attribute a: "), "{err}");
        assert_eq!(bfs.get(b"a").unwrap().attr, attr(MIMS, b"old"));
    }

    #[test]
    fn empty_attributes_are_created() {
        let big = vec![7_u8; SMALL_DATA + 1];
        let bfs = FakeBfs::with(&[
            (b"small", attr(MIMS, b"old data")),
            (b"big", attr(MIMS, &big)),
            (b"empty", attr(MIMS, b"")),
        ]);
        bfs.own_inode(b"empty");
        let typed = want(&[
            ("new", attr(RAWT, b"")),
            ("small", attr(RAWT, b"")),
            ("big", attr(RAWT, b"")),
            ("empty", attr(RAWT, b"")),
        ]);
        let xattrs = want(&[("user.empty", attr(XATTR_TYPE, b""))]);
        apply(&bfs, &typed, false).unwrap();
        apply(&bfs, &xattrs, true).unwrap();
        for name in ["new", "small", "big", "empty", "user.empty"] {
            let got = bfs.get(name.as_bytes()).unwrap();
            assert!(
                got.attr.value.is_empty() && got.own_inode,
                "{name}: {got:?}"
            );
        }
        assert_eq!(bfs.get(b"new").unwrap().attr.type_code, RAWT);
        assert_eq!(bfs.get(b"user.empty").unwrap().attr.type_code, XATTR_TYPE);
        assert_eq!(bfs.removes.get(), 0);
        let (got, _) = read_kind(&bfs, false).unwrap().unwrap();
        assert_eq!(got, typed);
    }

    #[test]
    fn large_attributes_round_trip() {
        let big = vec![1_u8; 3 * SMALL_DATA];
        let bfs = FakeBfs::with(&[(b"a", attr(MIMS, b"small"))]);
        apply(&bfs, &want(&[("a", attr(RAWT, &big))]), false).unwrap();
        assert!(bfs.get(b"a").unwrap().own_inode);
        let (got, _) = read_kind(&bfs, false).unwrap().unwrap();
        assert_eq!(got["a"], attr(RAWT, &big));
        // And back into the inode.
        apply(&bfs, &want(&[("a", attr(MIMS, b"small"))]), false).unwrap();
        assert_eq!(bfs.get(b"a").unwrap().attr, attr(MIMS, b"small"));
    }

    #[test]
    fn an_empty_attribute_that_cant_be_made_is_an_error() {
        let fs = NoEmpty(FakeBfs::default());
        let err = apply(&fs, &want(&[("e", attr(RAWT, b""))]), false).unwrap_err();
        assert_eq!(
            err.to_string(),
            "write attribute e: the file system doesn't create an empty attribute"
        );
        // No zeros left behind.
        assert!(fs.0.get(b"e").is_none());
    }
}
