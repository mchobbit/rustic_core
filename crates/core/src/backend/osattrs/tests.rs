//! BackOtter: the tests of `osattrs.rs`, `osattrs/errors.rs` and
//! `osattrs/xattr.rs`.

use super::*;

// BackOtter (ForkAudit1 G3-10): an error given its operation and path
// reads as before, and keeps its errno, so that the rules that go by
// the errno class it as they did before it was wrapped.
#[test]
#[cfg(unix)]
fn path_error_keeps_the_errno() {
    let raw = io::Error::from_raw_os_error(libc::ENOTSUP);
    let err = path_error("setxattr", Path::new("/a/b"), &raw);
    assert_eq!(err.to_string(), format!("setxattr /a/b: {raw}"));
    assert_eq!(err.kind(), raw.kind());
    assert_eq!(err.raw_os_error(), None);
    assert_eq!(errno(&err), Some(libc::ENOTSUP));
    let source = std::error::Error::source(&err).and_then(|e| e.downcast_ref::<io::Error>());
    assert_eq!(source.and_then(io::Error::raw_os_error), Some(libc::ENOTSUP));
    assert!(unsupported(&err) && xattr_unsupported(&err));
    // Wrapped again, and copied.
    let twice = path_error("restore", Path::new("c"), &err);
    assert_eq!(twice.to_string(), format!("restore c: setxattr /a/b: {raw}"));
    assert_eq!(errno(&twice), Some(libc::ENOTSUP));
    assert!(unsupported(&twice) && xattr_unsupported(&twice));
    assert_eq!(same_error(&err).to_string(), err.to_string());

    // An error that isn't the system's has none, wrapped or not.
    let other = io::Error::other("no such thing");
    assert_eq!(errno(&other), None);
    let wrapped = path_error("open", Path::new("d"), &other);
    assert_eq!(wrapped.to_string(), "open d: no such thing");
    assert_eq!(errno(&wrapped), None);
    assert!(!unsupported(&wrapped));
    // Nor does every errno say "unsupported".
    let eperm = path_error("chflags", Path::new("e"), &io::Error::from_raw_os_error(libc::EPERM));
    assert!(!unsupported(&eperm) && !xattr_unsupported(&eperm));
    assert!(permission_refused(&eperm));
    #[cfg(any(target_os = "linux", target_os = "android"))]
    assert!(xattr_unsupported(&path_error(
        "getxattr",
        Path::new("f"),
        &io::Error::from_raw_os_error(libc::ENODATA)
    )));
}

// An ACL the file system can't hold is unsupported metadata, with the
// text and the errno it had.
#[test]
#[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "illumos"))]
fn acl_set_error_by_the_wrapped_errno() {
    let wrapped = |errno| path_error("acl", Path::new("f"), &io::Error::from_raw_os_error(errno));
    for errno in [libc::ENOTSUP, libc::EOPNOTSUPP] {
        let text = wrapped(errno).to_string();
        let err = acl_set_error(wrapped(errno));
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert_eq!(err.to_string(), text);
        assert!(!restore_error_counts(&err, NotRoot::Forgiven, true));
    }
    let err = acl_set_error(wrapped(libc::EPERM));
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(restore_error_counts(&err, NotRoot::Forgiven, true));
}

// BackOtter (ForkAudit1 G3-07): FICLONE as <linux/fs.h> gives it where
// an ioctl's direction is asm-generic's. Its low 32 bits: musl's ioctl
// takes an int and glibc's an unsigned long.
#[test]
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn ficlone_is_the_headers() {
    assert_eq!(i128::from(FICLONE) & 0xffff_ffff, 0x4004_9409);
}

/// BackOtter: what `--strict-exit` counts of the failures a restore
/// warns about, as BackOtter's restic does: not unsupported metadata nor
/// unmapped SIDs, nor a permission refused to a restore not running as
/// root in the steps restic forgives that; anything else.
#[test]
#[cfg(unix)]
fn restore_errors_counted_as_restic() {
    let eperm = || io::Error::from_raw_os_error(libc::EPERM);
    let eio = || io::Error::from_raw_os_error(libc::EIO);
    let unsupported = || Unsupported::error("linux.inode_flags", 0x10, eperm());
    assert!(!restore_error_counts(&unsupported(), NotRoot::Counted, true));
    let kind = io::Error::new(io::ErrorKind::Unsupported, "no ACLs here");
    assert!(!restore_error_counts(&kind, NotRoot::Counted, true));
    let sid = SidUnmapped::error("illumos.owner_sid", "S-1-5-21-1", eio());
    assert!(!restore_error_counts(&sid, NotRoot::Counted, true));
    let several = |errors| io::Error::other(RestoreErrors(errors));
    let mixed = several(vec![unsupported(), eio()]);
    assert!(restore_error_counts(&mixed, NotRoot::Counted, true));
    let all_unsupported = several(vec![unsupported(), unsupported()]);
    assert!(!restore_error_counts(&all_unsupported, NotRoot::Counted, true));
    assert!(!restore_error_counts(&eperm(), NotRoot::Forgiven, false));
    assert!(restore_error_counts(&eperm(), NotRoot::Forgiven, true));
    assert!(restore_error_counts(&eperm(), NotRoot::Counted, false));
    assert!(restore_error_counts(&eio(), NotRoot::Forgiven, false));
    assert!(restore_error_counts(&eio(), NotRoot::Counted, true));
}

/// BackOtter: extended attributes the file system doesn't support
/// (`ENOATTR` included) don't count, nor, not running as root, a permission refused (listing
/// included); anything else does.
#[test]
#[cfg(unix)]
fn xattr_errors_counted_as_restic() {
    let errors = |errno: i32, what: &str| {
        let mut errors = XattrErrors::default();
        errors.push(what, io::Error::from_raw_os_error(errno));
        errors
    };
    for root in [true, false] {
        assert!(!errors(libc::ENOTSUP, "user.a").counts(root));
        assert!(!errors(libc::EOPNOTSUPP, "user.a").counts(root));
        assert!(errors(libc::EIO, "user.a").counts(root));
        // An SMB/CIFS mount's ENOATTR (ENODATA on Linux), as restic.
        #[cfg(target_os = "linux")]
        assert!(!errors(libc::ENODATA, "user.a").counts(root));
        #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd"))]
        assert!(!errors(libc::ENOATTR, "user.a").counts(root));
    }
    assert!(!errors(libc::EPERM, "trusted.a").counts(false));
    assert!(errors(libc::EPERM, "trusted.a").counts(true));
    assert!(!errors(libc::EACCES, "listing").counts(false));
    assert!(errors(libc::EACCES, "listing").counts(true));
}

/// BackOtter: a node without file flags says its file had none only in
/// a snapshot of BackOtter's; then, or where it has some, the restore
/// clears what would refuse it and sets the node's.
#[test]
fn flags_known_from_node_or_bko() {
    let node = Node::default();
    assert_eq!(node_flags(&node, false), None);
    assert!(!node_sets_flags(&node, false));
    assert_eq!(node_flags(&node, true), Some(0));
    assert!(node_sets_flags(&node, true));
    if let Some(name) = os::FILE_FLAGS {
        let mut flagged = Node::default();
        flagged.meta.generic_attributes.set_u64(name, 0x10);
        assert_eq!(node_flags(&flagged, false), Some(0x10));
        assert!(node_sets_flags(&flagged, false));
        assert_eq!(node_flags(&flagged, true), Some(0x10));
    }
}

/// BackOtter: the size scan is skipped only for real atimes where
/// listing moves them.
#[test]
fn scan_skipped_only_for_real_atimes() {
    assert!(scan_moves_saved_atimes(true, false));
    assert!(!scan_moves_saved_atimes(true, true));
    assert!(!scan_moves_saved_atimes(false, false));
    assert!(!scan_moves_saved_atimes(false, true));
}

#[cfg(not(any(windows, target_os = "openbsd", target_os = "illumos", target_os = "haiku")))]
#[test]
fn casefold_not_empty_is_bcachefs_casefold_refused() {
    let not_empty = io::Error::from(io::ErrorKind::DirectoryNotEmpty);
    assert!(casefold_not_empty("bcachefs.casefold", &not_empty));
    assert!(!casefold_not_empty("bcachefs.compression", &not_empty));
    assert!(!casefold_not_empty("user.casefold", &not_empty));
    assert!(!casefold_not_empty(
        "bcachefs.casefold",
        &io::Error::from(io::ErrorKind::PermissionDenied)
    ));
    #[cfg(target_os = "linux")]
    assert!(casefold_not_empty(
        "bcachefs.casefold",
        &io::Error::from_raw_os_error(libc::ENOTEMPTY)
    ));
}

// A file illumos quarantined, as the backup builds its node from the
// lstat and the system attributes: no contents, size 0, its size in
// illumos.unread_size, its other metadata kept.
#[test]
fn quarantined_node_without_contents() {
    use crate::backend::node::Metadata;

    let mut meta = Metadata {
        mode: Some(0o644),
        uid: Some(0),
        inode: 7,
        links: 1,
        size: 12,
        extended_attributes: vec![ExtendedAttribute {
            name: "note".to_string(),
            value: Some(b"x".to_vec()),
        }],
        ..Metadata::default()
    };
    let quarantined = illumos_sysattr::AV_QUARANTINED | illumos_sysattr::AUTOMATIC;
    meta.generic_attributes
        .set_u64(ILLUMOS_SYSTEM_ATTRIBUTES, quarantined.into());
    let mut node = Node::new_node(std::ffi::OsStr::new("q"), NodeType::File, meta);
    assert!(is_quarantined(&node));
    assert_eq!(unread_size(&node), None);

    keep_unread(Path::new("/q"), &mut node);
    assert_eq!(node.content, Some(Vec::new()));
    assert_eq!(node.meta.size, 0);
    assert_eq!(node.meta.extended_attributes, []);
    assert_eq!(unread_size(&node), Some(12));
    assert_eq!(node.meta.mode, Some(0o644));
    assert_eq!(node.meta.inode, 7);
    assert_eq!(file_flags_mask(&node), Some(u64::from(quarantined)));
    let json = serde_json::to_string(&node).unwrap();
    assert!(json.contains(r#""content":[]"#), "{json}");
    assert!(json.contains(r#""illumos.unread_size":12"#), "{json}");
    assert!(!json.contains(r#""size""#), "{json}");

    // Other files, and a directory with the attribute, aren't.
    let mut other = Node::default();
    other.meta.generic_attributes.set_u64(ILLUMOS_SYSTEM_ATTRIBUTES, 1 << 5);
    assert!(!is_quarantined(&other));
    let mut dir = Node::new_node(std::ffi::OsStr::new("d"), NodeType::Dir, Metadata::default());
    dir.meta.generic_attributes.set_u64(ILLUMOS_SYSTEM_ATTRIBUTES, quarantined.into());
    assert!(!is_quarantined(&dir));
    assert!(!open_refused(Path::new("/nonexistent/bko")));
}

fn file_flags_mask(node: &Node) -> Option<u64> {
    node.meta.generic_attributes.number_u64(ILLUMOS_SYSTEM_ATTRIBUTES)
}

#[test]
fn xattr_errors_name_each() {
    let mut errors = XattrErrors::default();
    assert!(XattrErrors::default().into_result().is_ok());
    errors.push("trusted.a", io::Error::from(io::ErrorKind::PermissionDenied));
    errors.push("removing user.b", io::Error::other("busy"));
    let msg = errors.into_result().unwrap_err().to_string();
    assert_eq!(msg, "trusted.a: permission denied; removing user.b: busy");
    let all = XattrErrors::from(io::Error::other("no extended attributes"));
    assert_eq!(all.to_string(), "no extended attributes");
}

#[test]
fn birthtime_first_only_when_earlier() {
    let t = |sec, nsec| Timestamp::new(sec, nsec).unwrap();
    let mut node = Node::default();
    node.meta.mtime = Some(t(1_200_000_000, 222_222_222));
    // Earlier: set first (two utimensat calls), else not (one).
    for (birth, first) in [
        (t(1_000_000_000, 111_111_111), true),
        (t(1_200_000_000, 222_222_221), true),
        (t(1_200_000_000, 222_222_222), false),
        (t(1_300_000_000, 0), false),
    ] {
        assert_eq!(birthtime_first(&node, birth), first.then_some(birth), "{birth}");
    }
    // Without an mtime, which the restore then doesn't set.
    node.meta.mtime = None;
    assert_eq!(birthtime_first(&node, t(1_000_000_000, 0)), None);
}

#[test]
fn restore_birthtime_without_attribute() {
    // No attribute: nothing to do, and no system call either.
    restore_birthtime(Path::new("/nonexistent"), &Node::default()).unwrap();
}

#[test]
fn unix_time_rounds_down() {
    let t = |sec, nsec| Timestamp::new(sec, nsec).unwrap();
    assert_eq!(unix_time(t(1_000_000_000, 123_456_789)), (1_000_000_000, 123_456_789));
    assert_eq!(unix_time(t(0, 0)), (0, 0));
    assert_eq!(unix_time(t(0, -1)), (-1, 999_999_999));
    assert_eq!(unix_time(t(-2, 500_000_000)), (-2, 500_000_000));
}

#[cfg(unix)]
#[test]
fn set_flags_best_effort_sets_what_it_can() {
    let path = Path::new("f");
    // A file system that refuses bit 0x4, as ZFS refuses some FreeBSD
    // flags, and bit 0x8 to all but root.
    let current = std::cell::Cell::new(0);
    let mut set = |f: u32| {
        if f & 0x4 != 0 {
            return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
        }
        if f & 0x8 != 0 {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        current.set(f);
        Ok(())
    };
    set_flags_best_effort("x.flags", path, "set", None, 0x3, &mut set).unwrap();

    // Unsupported: a warning once.
    let err = set_flags_best_effort("x.flags", path, "set", None, 0x15, &mut set).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    let unsupported = err.get_ref().unwrap().downcast_ref::<Unsupported>().unwrap();
    assert_eq!((unsupported.attr, unsupported.bits), ("x.flags", 0x4));
    assert_eq!(current.get(), 0x11);

    // Unsupported and not permitted: an error.
    let err = set_flags_best_effort("x.flags", path, "set", None, 0x1d, &mut set).unwrap_err();
    assert!(err.get_ref().unwrap().downcast_ref::<Unsupported>().is_none());
    assert!(err.to_string().contains("0xc of 0x1d"), "{err}");
    assert_eq!(current.get(), 0x11);
}

#[cfg(unix)]
#[test]
fn set_flags_best_effort_64_bits() {
    let path = Path::new("f");
    // ZFS's DOS flags: sparse not supported, read-only not permitted.
    let (readonly, hidden, sparse) = (0x1_0000_0000_u64, 0x2_0000_0000, 0x2000_0000_0000);
    let current = std::cell::Cell::new(0);
    let mut set = |f: u64| {
        if f & sparse != 0 {
            return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
        }
        if f & readonly != 0 {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        current.set(f);
        Ok(())
    };
    let err = set_flags_best_effort("x.flags", path, "set", None, hidden | sparse, &mut set)
        .unwrap_err();
    let unsupported = err.get_ref().unwrap().downcast_ref::<Unsupported>().unwrap();
    assert_eq!(unsupported.bits, sparse);
    assert_eq!(unsupported.kind(), "x.flags 0x200000000000");
    assert_eq!(current.get(), hidden);

    let all = readonly | hidden | sparse;
    let err = set_flags_best_effort("x.flags", path, "set", None, all, &mut set).unwrap_err();
    assert!(err.get_ref().unwrap().downcast_ref::<Unsupported>().is_none());
    assert!(
        err.to_string().contains("0x200100000000 of 0x200300000000"),
        "{err}"
    );
    assert_eq!(current.get(), hidden);
}

#[cfg(unix)]
#[test]
fn set_flags_best_effort_from_current() {
    // illumos as the owner: every write names every flag; immutable
    // (0x20) only root may set, av_modified (0x200) the owner may set
    // but not clear. A new file has archive (0x8) and av_modified.
    let path = Path::new("f");
    let (archive, immutable, av_modified) = (0x8_u32, 0x20, 0x200);
    let current = std::cell::Cell::new(archive | av_modified);
    let mut set = |f: u32| {
        let was = current.get();
        if f & immutable != 0 && was & immutable == 0
            || f & av_modified == 0 && was & av_modified != 0
        {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        current.set(f);
        Ok(())
    };
    // hidden (0x1) and archive set beside immutable, which isn't.
    let want = 0x1 | archive | immutable | av_modified;
    let err = set_flags_best_effort("x.flags", path, "set", Some(current.get()), want, &mut set)
        .unwrap_err();
    assert!(err.to_string().contains("file flags 0x20 of 0x229 not set:"), "{err}");
    assert_eq!(current.get(), 0x1 | archive | av_modified);

    // archive cleared beside av_modified, which can't be.
    current.set(archive | av_modified);
    let err = set_flags_best_effort("x.flags", path, "set", Some(current.get()), 0, &mut set)
        .unwrap_err();
    assert!(err.to_string().contains("file flags 0x200 not cleared:"), "{err}");
    assert_eq!(current.get(), av_modified);

    // Both at once.
    current.set(archive | av_modified);
    let err =
        set_flags_best_effort("x.flags", path, "set", Some(current.get()), immutable, &mut set)
            .unwrap_err();
    assert!(
        err.to_string().contains("file flags 0x20 of 0x20 not set, 0x200 not cleared:"),
        "{err}"
    );
    assert_eq!(current.get(), av_modified);

    // Nothing to change: whatever set says, the file has the flags.
    set_flags_best_effort("x.flags", path, "set", Some(av_modified), av_modified, |_| {
        Err(io::Error::from_raw_os_error(libc::EPERM))
    })
    .unwrap();
}

#[cfg(unix)]
#[test]
fn set_flags_best_effort_0_fails_with_set() {
    // Nothing to try one at a time: the error is set's.
    let path = Path::new("f");
    let err = set_flags_best_effort("x.flags", path, "set", None, 0_u64, |_| {
        Err(io::Error::from_raw_os_error(libc::EACCES))
    })
    .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(err.get_ref().unwrap().downcast_ref::<Unsupported>().is_none());
    let err = set_flags_best_effort("x.flags", path, "set", None, 0_u32, |_| {
        Err(io::Error::from_raw_os_error(libc::ENOTTY))
    })
    .unwrap_err();
    let unsupported = err.get_ref().unwrap().downcast_ref::<Unsupported>().unwrap();
    assert_eq!(unsupported.kind(), "x.flags");
}

/// BackOtter (ForkAudit1 F2): what the restore asks of a node with every
/// generic attribute, cut short or with any bit flipped, answered
/// without a panic.
#[test]
fn node_readers_malformed() {
    use malformed::{EVERY_ATTRIBUTE_NODE, every_json_mutation};

    _ = every_json_mutation::<Node>("node readers", EVERY_ATTRIBUTE_NODE, |node| {
        _ = (
            is_sparse(node),
            file_flags(node),
            zfs_dos_flags(node),
            fat_attrs(node),
        );
        _ = (xfs_options(node), is_quarantined(node), unread_size(node));
        _ = (
            takes_nothing_before_data(node),
            node_flags(node, true),
            node_flags(node, false),
        );
        _ = (node_sets_flags(node, true), flags_xattrs(node));
        if let Some(t) = node.meta.generic_attributes.timestamp(UNIX_BIRTHTIME) {
            _ = (birthtime_first(node, t), unix_time(t));
        }
        warn_unknown(node);
        Ok(())
    });
}

/// BackOtter (ForkAudit1 F2): the same nodes restored onto a file of
/// their own type: each step succeeds or fails, and none panics.
#[cfg(target_os = "linux")]
#[cfg_attr(miri, ignore = "system calls")]
#[test]
fn node_restore_malformed() {
    use malformed::{EVERY_ATTRIBUTE_NODE, every_json_mutation};

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("f");
    let sub = dir.path().join("d");
    _ = every_json_mutation::<Node>("node restore", EVERY_ATTRIBUTE_NODE, |node| {
        let path = if node.is_dir() {
            _ = std::fs::create_dir(&sub);
            &sub
        } else {
            _ = std::fs::write(&file, b"x");
            &file
        };
        let typ = &node.node_type;
        _ = prepare_file(path, node);
        if let Some(f) = file_flags(node) {
            _ = restore_file_flags(path, typ, f, &flags_xattrs(node));
        }
        if let Some(f) = zfs_dos_flags(node) {
            _ = restore_zfs_dos_flags(path, typ, f);
        }
        if let Some(a) = fat_attrs(node) {
            _ = restore_fat_attrs(path, typ, a);
        }
        if let Some(o) = xfs_options(node) {
            _ = restore_xfs_options(path, typ, &o);
        }
        _ = restore_attributes(path, node, true, true);
        _ = restore_acls(path, node, true);
        _ = restore_birthtime(path, node);
        clear_restricting_flags(path);
        Ok(())
    });
}
