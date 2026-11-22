//! BackOtter: what [`LocalDestination`](super::LocalDestination) restores
//! with that is the fork's own, kept out of upstream's file: the sync of a
//! file's extended attributes with a node's ([`set_xattrs_all`], through
//! [`XattrCalls`], the system's or a test's), the writes of a file restored
//! sparse ([`sparse_writes`]) and the positioned writes ([`write_all_at`]),
//! and the opens that read a destination file's contents without following
//! a symlink or moving its atime ([`open_reading`], [`open_to_verify`]).

use std::{
    fs::{File, OpenOptions},
    path::Path,
};

#[cfg(not(any(
    windows,
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "haiku"
)))]
use crate::backend::{node::ExtendedAttribute, osattrs};

/// BackOtter: the calls [`set_xattrs_with`] makes to read and change a
/// file's extended attributes, by the names the xattr crate takes: the
/// system's ([`SystemXattrs`]), or a test's.
#[cfg(not(any(
    windows,
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "haiku"
)))]
pub(super) trait XattrCalls {
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
#[cfg(not(any(
    windows,
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "haiku"
)))]
pub(super) struct SystemXattrs;

#[cfg(not(any(
    windows,
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "haiku"
)))]
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
#[cfg(not(any(
    windows,
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "haiku"
)))]
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
/// `extended_attributes`, with `calls` ([`LocalDestination::set_extended_attributes`](super::LocalDestination::set_extended_attributes));
/// `bsd_stock` as [`xattr_restore_names`] takes it.
///
/// # Errors
///
/// * Each extended attribute that couldn't be set or removed, and a failure
///   to list them, all in one.
#[cfg(not(any(
    windows,
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "haiku"
)))]
#[cfg_attr(not(test), allow(dead_code))]
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
#[cfg(not(any(
    windows,
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "haiku"
)))]
pub(super) fn set_xattrs_all(
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
            if err.kind() == std::io::ErrorKind::Unsupported && extended_attributes.is_empty() =>
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
            // that can't be read is set below, as are the others. By its
            // bytes: a node's attribute without a value (JSON null, which a
            // backup saves for one whose value the file system wouldn't
            // give) is set as an empty one, so the empty value the file
            // then has is the right one, as in BackOtter's restic
            // (bytes.Equal). 0.14.0+backotter.1 took the two for unequal
            // and set it again on every restore (ForkAudit1 G7-04).
            Some(index) => {
                let value = extended_attributes[index]
                    .value
                    .as_deref()
                    .unwrap_or_default();
                if calls
                    .get(filename, &curr_name)
                    .is_ok_and(|curr| curr.is_some_and(|curr| curr == value))
                {
                    done[index] = true;
                }
            }
            // BackOtter: nor the SELinux label (osattrs::xattr_never_removed).
            None if !remove_label && osattrs::xattr_never_removed(&curr_node_name) => {}
            None => {
                if let Err(err) = calls.remove(filename, &curr_name) {
                    // BackOtter: bcachefs refusing to clear casefolding
                    // on a directory with entries is a warning. An SELinux
                    // label an active SELinux keeps is one error for the
                    // whole restore (osattrs::label_refused).
                    if osattrs::casefold_not_empty(&curr_node_name, &err) {
                        calls.warn_casefold(&curr_node_name, filename);
                    } else if !(remove_label
                        && osattrs::label_refused(&curr_node_name, filename, &err))
                    {
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
#[cfg(not(any(
    windows,
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "haiku"
)))]
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
pub(super) fn sparse_writes(offset: u64, data: &[u8], block: u64) -> Vec<std::ops::Range<usize>> {
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

/// BackOtter: writes all of `data` at `offset` of `file`, without moving
/// its position, which threads writing other parts of the file through the
/// same handle share.
#[cfg(not(windows))]
pub(super) fn write_all_at(file: &File, data: &[u8], offset: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(file, data, offset)
}

/// BackOtter: writes all of `data` at `offset` of `file`, without the
/// handle's position mattering, which threads writing other parts of the
/// file through the same handle share (`seek_write` moves it, but no write
/// here goes by it). As std's `write_all_at` on Unix: again after a short
/// write or an interrupt, an error for a write of nothing.
#[cfg(windows)]
pub(super) fn write_all_at(file: &File, mut data: &[u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;

    while !data.is_empty() {
        match file.seek_write(data, offset) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                data = &data[n..];
                offset += n as u64;
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// BackOtter: opens the regular file `filename`, of `size` bytes, to read
/// its contents for a restore that verifies them: following no symlink
/// (checked with `fstat`, which must find a regular file of that size), and,
/// on Linux, with `O_NOATIME` where the restore may set it (the file's
/// owner, or root), so that reading it leaves its atime alone; otherwise an
/// `--exact` restore would find every file it verified with an atime moved
/// (`relatime` moves one no later than the mtime), and set its metadata,
/// and with it its change time, again on every run. As in BackOtter's
/// restic (`verifyFile`, `fs.SetNoatime`).
pub(super) fn open_to_verify(filename: &Path, size: u64) -> Option<File> {
    let f = open_reading(filename).ok()?;
    let m = f.metadata().ok()?;
    (m.is_file() && m.len() == size).then_some(f)
}

/// BackOtter: opens the regular file `filename` in the destination for
/// reading its contents ([`open_to_verify`]; a blob a restore takes from a
/// file there), by BackOtter's rule for such opens (S11, as
/// `commands::restore::exact`'s `open_regular`): following no symlink
/// (`O_NOFOLLOW`), not waiting for the writer of a FIFO that has taken the
/// file's place since the restore looked (`O_NONBLOCK`, which does nothing
/// to the reads of a regular file), taking no terminal (`O_NOCTTY`), and
/// checking with `fstat` that it is a regular file. On Linux with
/// `O_NOATIME` where the restore may set it, so that reading leaves its
/// atime alone. 0.14.0+backotter.1 opened with `O_NOFOLLOW` alone, and a
/// restore waited on such a FIFO for good (ForkAudit1 G7-05).
///
/// # Errors
///
/// * If it couldn't be opened, or isn't a regular file.
pub(super) fn open_reading(filename: &Path) -> std::io::Result<File> {
    let mut how = OpenOptions::new();
    _ = how.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        _ = how.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let f = how.open(filename)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        if let Ok(flags) = fcntl(&f, FcntlArg::F_GETFL) {
            _ = fcntl(
                &f,
                FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NOATIME),
            );
        }
    }
    Ok(f)
}

/// Whether `data` is all zeros: by pieces the compiler vectorizes, which
/// a check byte by byte with an early stop isn't.
pub(crate) fn is_zero(data: &[u8]) -> bool {
    data.chunks(1024)
        .all(|piece| piece.iter().fold(0, |acc, &b| acc | b) == 0)
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
            assert!(
                range.start < range.end && range.end <= data.len(),
                "{writes:?}"
            );
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
        let none: Vec<std::ops::Range<usize>> = Vec::new();
        // All zeros, aligned or not, longer or shorter than a block:
        // nothing written.
        assert_eq!(check(0, &zeros, B), none);
        assert_eq!(check(8192, &zeros, B), none);
        assert_eq!(check(100, &zeros, B), none);
        assert_eq!(check(0, &zeros[..4095], B), none);
        assert_eq!(check(1, &zeros[..4096], B), none);
        assert_eq!(check(0, &[], B), none);
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
        assert_eq!(check(0, &vec![0; 300 << 10], 128 << 10), none);
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

/// BackOtter: the tests of the extended attribute sync with a fake system
/// ([`set_xattrs_with`]), on every system that has it, so that FreeBSD's
/// and NetBSD's stock names (`bsd_stock`) are tested where they apply.
#[cfg(all(
    test,
    not(any(
        windows,
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "haiku"
    ))
))]
mod xattr_tests {
    use nix::errno::Errno;

    use super::super::{LocalDestination, LocalDestinationErrorKind};
    use super::*;

    pub(super) fn xattr(name: &str, value: &[u8]) -> ExtendedAttribute {
        ExtendedAttribute {
            name: name.to_string(),
            value: Some(value.to_vec()),
        }
    }

    /// BackOtter: extended attribute calls on one file, kept in a map: those
    /// in `not_empty` are refused, set or removed, with `ENOTEMPTY`, as
    /// bcachefs refuses `bcachefs.casefold` on a directory with entries.
    /// Names are the system's, as the xattr crate takes them
    /// ([`osattrs::xattr_os_name`]).
    #[derive(Default)]
    pub(super) struct FakeXattrs {
        attrs: std::cell::RefCell<std::collections::BTreeMap<String, Vec<u8>>>,
        not_empty: Vec<String>,
        pub(super) warned: std::cell::RefCell<Vec<String>>,
        /// The error those in `not_empty` are refused with, if not
        /// `ENOTEMPTY`.
        pub(super) errno: Option<i32>,
        /// The names `set` was called with, in order.
        pub(super) sets: std::cell::RefCell<Vec<String>>,
    }

    impl FakeXattrs {
        pub(super) fn with(attrs: &[(&str, &[u8])], not_empty: &[&str]) -> Self {
            Self {
                attrs: std::cell::RefCell::new(
                    attrs
                        .iter()
                        .map(|(n, v)| ((*n).to_string(), v.to_vec()))
                        .collect(),
                ),
                not_empty: not_empty.iter().map(|n| (*n).to_string()).collect(),
                warned: std::cell::RefCell::default(),
                errno: None,
                sets: std::cell::RefCell::default(),
            }
        }

        fn refuse(&self, name: &str) -> std::io::Result<()> {
            if self.not_empty.iter().any(|n| n == name) {
                return Err(std::io::Error::from_raw_os_error(
                    self.errno.unwrap_or(libc::ENOTEMPTY),
                ));
            }
            Ok(())
        }

        pub(super) fn names(&self) -> Vec<String> {
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
            self.sets.borrow_mut().push(name.to_string());
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

    /// BackOtter: an extended attribute the file system doesn't support
    /// (`EOPNOTSUPP`) isn't counted as an error under `--strict-exit`, as
    /// root or not; one that couldn't be set for another reason (`EIO`) is.
    #[test]
    fn xattrs_not_set_count_unless_unsupported() {
        let file = Path::new("/r/f");
        let os_name = osattrs::xattr_os_name("user.a");
        for (errno, counts) in [(libc::EOPNOTSUPP, false), (libc::EIO, true)] {
            let mut calls = FakeXattrs::with(&[], &[&os_name]);
            calls.errno = Some(errno);
            let errors =
                set_xattrs_with(&calls, file, &[xattr("user.a", b"1")], false).unwrap_err();
            let err = LocalDestinationErrorKind::XattrsNotSet(errors);
            assert_eq!(
                LocalDestination::error_counts(&err, true),
                counts,
                "{errno}"
            );
            assert_eq!(
                LocalDestination::error_counts(&err, false),
                counts,
                "{errno}"
            );
        }
        // A change of owner refused counts as root only.
        let err = LocalDestinationErrorKind::FromErrnoError(Errno::EPERM);
        assert!(LocalDestination::error_counts(&err, true));
        assert!(!LocalDestination::error_counts(&err, false));
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
        assert_eq!(
            xattr_restore_names("user.comment", false),
            own("user.comment")
        );
        assert_eq!(xattr_restore_names("system.mac", false), own("system.mac"));
    }

    /// BackOtter: a stock name of the user namespace that the file has with
    /// the right value is left, one of the system namespace is set (never
    /// listed, nor removed), with `bsd_stock`.
    #[test]
    fn xattr_stock_bsd_names_synced() {
        let dir = Path::new("/r/f");
        // The file has user.comment (the system's name: "user.comment" on
        // FreeBSD and NetBSD, whose node name is "comment"; "comment"
        // elsewhere).
        let comment = osattrs::xattr_os_name("comment");
        let calls = FakeXattrs::with(&[(&comment, b"c")], &[]);
        let attrs = [xattr("user.comment", b"c"), xattr("system.mac", b"m")];
        // The fake's set takes the name as given: one already right isn't set.
        set_xattrs_with(&calls, dir, &attrs, true).unwrap();
        let mut want = vec![comment, "system.mac".to_string()];
        want.sort();
        assert_eq!(calls.names(), want);
        assert_eq!(*calls.sets.borrow(), ["system.mac"]);
    }

    /// BackOtter (ForkAudit1 G7-04): a node's attribute without a value
    /// is set as an empty one, once: over the empty value the file then
    /// has it isn't set again (0.14.0+backotter.1 set it on every restore,
    /// moving the file's change time); over another value it is.
    #[test]
    fn xattr_without_value_is_the_empty_one() {
        let file = Path::new("/r/f");
        let os_name = osattrs::xattr_os_name("user.a");
        let attrs = [ExtendedAttribute {
            name: "user.a".to_string(),
            value: None,
        }];
        let calls = FakeXattrs::with(&[], &[]);
        set_xattrs_with(&calls, file, &attrs, false).unwrap();
        assert_eq!(
            calls.sets.borrow().as_slice(),
            std::slice::from_ref(&os_name)
        );
        // Again, over its own result: no call.
        set_xattrs_with(&calls, file, &attrs, false).unwrap();
        assert_eq!(
            calls.sets.borrow().as_slice(),
            std::slice::from_ref(&os_name)
        );
        // An empty value in the node over the empty one, too.
        set_xattrs_with(&calls, file, &[xattr("user.a", b"")], false).unwrap();
        assert_eq!(
            calls.sets.borrow().as_slice(),
            std::slice::from_ref(&os_name)
        );
        // Over another value it is set, to the empty one.
        let calls = FakeXattrs::with(&[(&os_name, b"x")], &[]);
        set_xattrs_with(&calls, file, &attrs, false).unwrap();
        assert_eq!(
            calls.sets.borrow().as_slice(),
            std::slice::from_ref(&os_name)
        );
        assert_eq!(calls.get(file, os_name.as_ref()).unwrap(), Some(Vec::new()));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use filetime::FileTime;
    use nix::errno::Errno;

    use super::super::{LocalDestination, LocalDestinationErrorKind};
    use super::xattr_tests::{FakeXattrs, xattr};
    use super::*;
    use crate::backend::node::Metadata;

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
        let err = dest
            .set_extended_attributes("f", &attrs, false)
            .unwrap_err()
            .to_string();
        assert_eq!(xattr::get(&file, "user.b").unwrap(), Some(b"2".to_vec()));
        assert_eq!(xattr::get(&file, "user.old").unwrap(), None);
        assert!(err.contains("bogus.a: "), "{err}");
        assert!(err.ends_with(&format!(
            "; bogus.c: {}",
            std::io::Error::from_raw_os_error(95)
        )));
        assert!(!err.contains("user."), "{err}");
        if !nix::unistd::geteuid().is_root() {
            assert!(
                err.starts_with("trusted.t: Operation not permitted"),
                "{err}"
            );
        }

        // Again, over its own result: only the attributes that can't be set.
        let err = dest
            .set_extended_attributes("f", &attrs, false)
            .unwrap_err()
            .to_string();
        assert!(!err.contains("user."), "{err}");
        assert_eq!(xattr::get(&file, "user.b").unwrap(), Some(b"2".to_vec()));

        // A node without any removes them all.
        dest.set_extended_attributes("f", &[], false).unwrap();
        assert_eq!(xattr::list(&file).unwrap().count(), 0);
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
        let err = set_xattrs_with(&calls, dir, &attrs, false)
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("user.notempty: "), "{err}");
        assert_eq!(calls.names(), ["user.b"]);
        assert!(calls.warned.borrow().is_empty());
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

    /// BackOtter: a file read to verify its contents keeps its atime (Linux's
    /// `O_NOATIME`, which its owner may ask for), however `relatime` would
    /// move it; a symlink to a file isn't followed.
    #[test]
    fn verify_read_keeps_atime() {
        use std::io::Read;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        fs::write(&file, b"contents").unwrap();
        let old = FileTime::from_unix_time(1_000_000_000, 0);
        filetime::set_file_atime(&file, old).unwrap();
        let mut f = open_to_verify(&file, 8).unwrap();
        let mut buf = Vec::new();
        _ = f.read_to_end(&mut buf).unwrap();
        drop(f);
        let atime = FileTime::from_last_access_time(&fs::metadata(&file).unwrap());
        assert_eq!(atime, old);
        symlink(&file, dir.path().join("l")).unwrap();
        assert!(open_to_verify(&dir.path().join("l"), 8).is_none());
        assert!(open_to_verify(&file, 9).is_none());
    }

    /// BackOtter (ForkAudit1 G7-05): a FIFO where the restore looks for a
    /// file's contents (it took the file's place since the plan) is an
    /// error at once, "not a regular file", and no match to verify;
    /// 0.14.0+backotter.1 waited for a writer to open it.
    #[test]
    fn reading_a_fifo_fails_at_once() {
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("p");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        let dest = LocalDestination::new(dir.path().to_str().unwrap(), false, false).unwrap();
        // In a thread, so that a wait fails the test instead of hanging it.
        let (tx, rx) = mpsc::channel();
        let (d, f) = (dest.clone(), fifo.clone());
        let reader = std::thread::spawn(move || {
            let read = d
                .read_at("p", 0, 4)
                .map(|_| ())
                .map_err(|err| err.to_string());
            let verified = open_to_verify(&f, 0).is_some();
            tx.send((read, verified)).unwrap();
        });
        let Ok((read, verified)) = rx.recv_timeout(Duration::from_secs(20)) else {
            // Lets the reader go: its open waits for a writer.
            for _ in 0..2 {
                drop(OpenOptions::new().write(true).open(&fifo));
                std::thread::sleep(Duration::from_millis(200));
            }
            panic!("reading a FIFO waited for a writer");
        };
        reader.join().unwrap();
        let err = read.unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
        assert!(!verified);
        // The match by size is by lstat first: none either.
        assert!(dest.get_matching_file("p", 0).is_none());
    }

    /// BackOtter: under `--exact`, an SELinux label an active SELinux refuses
    /// to remove (`EACCES`, as for every file of such a snapshot) is no
    /// error of the file's, but one for the whole restore, with a count
    /// (`osattrs::report_labels_kept`); any other refusal (`EPERM`) is the
    /// file's.
    #[test]
    fn selinux_label_refusals_folded() {
        _ = osattrs::report_labels_kept();
        for _ in 0..3 {
            let mut calls = FakeXattrs::with(&[("security.selinux", b"l")], &["security.selinux"]);
            calls.errno = Some(libc::EACCES);
            set_xattrs_all(&calls, Path::new("/r/f"), &[], false, true).unwrap();
        }
        assert!(osattrs::report_labels_kept());
        assert!(!osattrs::report_labels_kept());
        let mut calls = FakeXattrs::with(&[("security.selinux", b"l")], &["security.selinux"]);
        calls.errno = Some(libc::EPERM);
        let err = set_xattrs_all(&calls, Path::new("/r/f"), &[], false, true)
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("removing security.selinux: "), "{err}");
        assert!(!osattrs::report_labels_kept());
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
        let file = dest.set_length("f", size as u64, true).unwrap();
        let block = osattrs::hole_block_size(&file);
        // In reverse, as the restore writes blobs in any order.
        let mut offsets = Vec::new();
        let mut off = 0;
        for blob in &blobs {
            offsets.push(off);
            off += blob.len() as u64;
        }
        for (blob, off) in blobs.iter().zip(&offsets).rev() {
            LocalDestination::write_sparse_at(&file, *off, blob, block).unwrap();
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
