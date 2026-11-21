//! The names of FreeBSD's and NetBSD's extended attributes, as
//! `extattr_list_link(2)` lists them: bytes, which needn't be UTF-8. Each is
//! read and set by those bytes; the name a node keeps is made valid UTF-8
//! only there, as the name of a Linux extended attribute is
//! (`xattr_node_name`) and as restic-bko's JSON makes it. Portable,
//! so that it is tested on any system; the system calls are in
//! `freebsd_netbsd.rs`.

#![cfg_attr(
    not(any(target_os = "freebsd", target_os = "netbsd")),
    allow(dead_code)
)]

use std::{
    ffi::OsString,
    os::unix::ffi::{OsStrExt, OsStringExt},
};

/// The names in `list`, an `extattr_list_link(2)` list: each name follows a
/// byte holding its length. A name the list cuts short ends it.
pub(super) fn list_names(list: &[u8]) -> Vec<Vec<u8>> {
    let mut names = Vec::new();
    let mut rest = list;
    while let Some((&n, tail)) = rest.split_first() {
        let Some(name) = tail.get(..usize::from(n)) else {
            break;
        };
        names.push(name.to_vec());
        rest = &tail[usize::from(n)..];
    }
    names
}

/// The name the xattr crate gives the user extended attribute `name`:
/// `user.` and its bytes.
pub(super) fn user_name(name: &[u8]) -> OsString {
    let mut full = b"user.".to_vec();
    full.extend_from_slice(name);
    OsString::from_vec(full)
}

/// The name a node keeps for the extended attribute `name`, valid UTF-8, as
/// a Linux one's (`OsStr::to_string_lossy`).
pub(super) fn node_name(name: &[u8]) -> String {
    std::ffi::OsStr::from_bytes(name)
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_names_keeps_bytes() {
        let list = b"\x01\xff\x03abc\x00\x02\xc3\xa9";
        assert_eq!(
            list_names(list),
            [
                b"\xff".to_vec(),
                b"abc".to_vec(),
                Vec::new(),
                "é".as_bytes().to_vec()
            ]
        );
        // A name cut short ends the list.
        assert_eq!(list_names(b"\x01a\x05ab"), [b"a".to_vec()]);
        assert!(list_names(b"").is_empty());
    }

    #[test]
    fn non_utf8_name_read_by_bytes_kept_lossy() {
        let raw = b"\xffx";
        // Read and set by its own bytes, under `user.`.
        assert_eq!(user_name(raw).as_bytes(), b"user.\xffx");
        // Kept as a Linux one is, and as restic's JSON keeps it.
        assert_eq!(node_name(raw), "\u{fffd}x");
        assert_eq!(
            node_name(raw),
            std::ffi::OsStr::from_bytes(raw).to_string_lossy()
        );
        assert_eq!(node_name(b"plain"), "plain");
    }
}
