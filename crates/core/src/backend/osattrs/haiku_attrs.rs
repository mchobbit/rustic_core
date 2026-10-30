//! Haiku's file attributes, as BFS keeps them (`fs_attr(3)`,
//! `listattr(1)`): each has a name, a type code and data, and files,
//! directories and symlinks can all have them. Those of type
//! `B_XATTR_TYPE` (`'XATR'`) are what Haiku's own xattr functions
//! (`getxattr(3)` and the rest, in libgnu) read and write, under the same
//! names: they are kept as extended attributes. The rest are kept as the
//! generic attribute `haiku.attributes`, with their type codes. Portable, so
//! that it is tested on any system; the file access is in `haiku.rs`.

#![cfg_attr(not(target_os = "haiku"), allow(dead_code))]

use std::collections::BTreeMap;

use serde_derive::{Deserialize, Serialize};
use serde_with::{DefaultOnNull, base64::Base64, serde_as};

use crate::backend::node::ExtendedAttribute;

/// `B_XATTR_TYPE` from `<TypeConstants.h>`, the type of the attributes that
/// Haiku's xattr functions write.
pub(super) const XATTR_TYPE: u32 = u32::from_be_bytes(*b"XATR");

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

/// A file's attributes other than the extended attributes, by name: the
/// generic attribute `haiku.attributes`, as in
/// `{"BEOS:TYPE":{"type":1296649555,"value":"dGV4dC9wbGFpbgA="}}`.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(transparent)]
pub(super) struct Attrs(pub(super) BTreeMap<String, Attr>);

/// The attributes a file has, as listed, by their names' bytes.
pub(super) type Listed = BTreeMap<Vec<u8>, Attr>;

/// Those of the `listed` attributes that are extended attributes (`xattrs`)
/// or those that aren't (`!xattrs`), by name, and the names of those left
/// out because they aren't UTF-8, which a node can't hold.
pub(super) fn partition(listed: Listed, xattrs: bool) -> (BTreeMap<String, Attr>, Vec<Vec<u8>>) {
    let mut kept = BTreeMap::new();
    let mut bad_names = Vec::new();
    for (name, attr) in listed {
        if (attr.type_code == XATTR_TYPE) != xattrs {
            continue;
        }
        match String::from_utf8(name) {
            Ok(name) => _ = kept.insert(name, attr),
            Err(err) => bad_names.push(err.into_bytes()),
        }
    }
    (kept, bad_names)
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

/// What to change for a file's attributes of one kind (extended attributes
/// or not) to be exactly `want`.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Plan<'a> {
    /// Attributes of this kind that `want` doesn't have.
    pub(super) remove: Vec<Vec<u8>>,
    /// Attributes to write, and whether the file has one of that name
    /// already, of another type or with other data, to remove first.
    pub(super) write: Vec<(&'a str, &'a Attr, bool)>,
}

/// The changes that give a file whose attributes are `current` exactly the
/// attributes `want` of one kind, extended attributes (`xattrs`) or the
/// rest, and leave those of the other kind alone. One that is already as
/// wanted is left as it is.
pub(super) fn plan<'a>(
    current: &Listed,
    want: &'a BTreeMap<String, Attr>,
    xattrs: bool,
) -> Plan<'a> {
    let remove = current
        .iter()
        .filter(|(name, attr)| {
            (attr.type_code == XATTR_TYPE) == xattrs
                && std::str::from_utf8(name).map_or(true, |name| !want.contains_key(name))
        })
        .map(|(name, _)| name.clone())
        .collect();
    let write = want
        .iter()
        .filter_map(|(name, attr)| match current.get(name.as_bytes()) {
            Some(have) if have == attr => None,
            have => Some((name.as_str(), attr, have.is_some())),
        })
        .collect();
    Plan { remove, write }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIMS: u32 = u32::from_be_bytes(*b"MIMS");

    fn attr(type_code: u32, value: &[u8]) -> Attr {
        Attr {
            type_code,
            value: value.to_vec(),
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
        _ = attrs.0.insert("empty".to_string(), attr(0x5241_5754, b""));
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
    }

    #[test]
    fn partition_by_type() {
        let mut listed = Listed::new();
        _ = listed.insert(b"BEOS:TYPE".to_vec(), attr(MIMS, b"text/plain\0"));
        _ = listed.insert(b"user.comment".to_vec(), attr(XATTR_TYPE, b"hi"));
        _ = listed.insert(b"bad\xff".to_vec(), attr(MIMS, b"x"));
        _ = listed.insert(b"bad\xfe".to_vec(), attr(XATTR_TYPE, b"x"));

        let (typed, bad) = partition(listed.clone(), false);
        assert_eq!(typed.keys().collect::<Vec<_>>(), ["BEOS:TYPE"]);
        assert_eq!(typed["BEOS:TYPE"], attr(MIMS, b"text/plain\0"));
        assert_eq!(bad, [b"bad\xff".to_vec()]);

        let (xattrs, bad) = partition(listed, true);
        assert_eq!(xattrs.keys().collect::<Vec<_>>(), ["user.comment"]);
        assert_eq!(bad, [b"bad\xfe".to_vec()]);
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
    fn plan_changes_one_kind_only() {
        let mut current = Listed::new();
        _ = current.insert(b"same".to_vec(), attr(MIMS, b"x"));
        _ = current.insert(b"other data".to_vec(), attr(MIMS, b"x"));
        _ = current.insert(b"other type".to_vec(), attr(MIMS, b"x"));
        _ = current.insert(b"extra".to_vec(), attr(MIMS, b"x"));
        _ = current.insert(b"extra\xff".to_vec(), attr(MIMS, b"x"));
        _ = current.insert(b"user.xattr".to_vec(), attr(XATTR_TYPE, b"x"));

        let mut want = BTreeMap::new();
        _ = want.insert("same".to_string(), attr(MIMS, b"x"));
        _ = want.insert("other data".to_string(), attr(MIMS, b"y"));
        _ = want.insert("other type".to_string(), attr(1, b"x"));
        _ = want.insert("new".to_string(), attr(MIMS, b""));

        let p = plan(&current, &want, false);
        assert_eq!(p.remove, [b"extra".to_vec(), b"extra\xff".to_vec()]);
        assert_eq!(
            p.write,
            [
                ("new", &want["new"], false),
                ("other data", &want["other data"], true),
                ("other type", &want["other type"], true),
            ]
        );

        // The extended attributes alone: the rest stay as they are.
        let want = from_xattrs(&[]);
        let p = plan(&current, &want, true);
        assert_eq!(p.remove, [b"user.xattr".to_vec()]);
        assert!(p.write.is_empty());

        // A name the file has as the other kind is written over.
        let mut want = BTreeMap::new();
        _ = want.insert("same".to_string(), attr(XATTR_TYPE, b"x"));
        let p = plan(&current, &want, true);
        assert_eq!(p.remove, [b"user.xattr".to_vec()]);
        assert_eq!(p.write, [("same", &want["same"], true)]);
    }
}
