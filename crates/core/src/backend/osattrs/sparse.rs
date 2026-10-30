//! Holes in regular files (`unix.sparse`). The restore restores a file that
//! had holes sparse, so that a sparse disk image doesn't fill the disk, and
//! allocates every other, so that a swap file or a preallocated file comes
//! back allocated (see `write_sparse` in the restore).

use std::{
    fs::{File, Metadata},
    io,
    os::unix::fs::MetadataExt,
    path::Path,
};

use log::debug;

/// Whether a regular file of `size` bytes with `blocks` 512-byte blocks
/// may have holes. A preallocated file has all its blocks, even where
/// `SEEK_HOLE` finds holes (unwritten extents); a file on a compressing file
/// system has fewer than its size without holes, which `SEEK_HOLE` tells.
pub(super) fn maybe_sparse(size: u64, blocks: u64) -> bool {
    size > 0 && blocks.saturating_mul(512) < size
}

/// Whether a regular file of `size` bytes with `blocks` 512-byte blocks has
/// holes, by the rule BackOtter's restic follows too:
/// - blocks for all its bytes (or no bytes): no holes;
/// - a system without `SEEK_HOLE` (`first_hole` is `None`): the blocks
///   decide, so holes;
/// - `first_hole` gives the offset of the first hole (the size where there
///   is none): holes if it's before the end;
/// - `first_hole` fails with `EINVAL`, `ENOTSUP`, `EOPNOTSUPP` or `ENOTTY`
///   (a file system that can't answer): the blocks decide, so holes;
/// - it fails otherwise (the file couldn't be opened, `ENXIO`, `EACCES`,
///   ...): no holes.
///
/// `first_hole` is only called when the blocks leave room for a hole.
pub(super) fn decide(
    size: u64,
    blocks: u64,
    first_hole: Option<impl FnOnce() -> io::Result<u64>>,
) -> bool {
    if !maybe_sparse(size, blocks) {
        return false;
    }
    let Some(first_hole) = first_hole else {
        return true;
    };
    match first_hole() {
        Ok(hole) => hole < size,
        Err(err) => {
            let no_answer = err.raw_os_error().is_some_and(|code| {
                [libc::EINVAL, libc::ENOTSUP, libc::EOPNOTSUPP, libc::ENOTTY].contains(&code)
            });
            debug!("no SEEK_HOLE: {err}; the blocks decide: {no_answer}");
            no_answer
        }
    }
}

/// Whether the regular file at `path`, with metadata `m` (its lstat), has
/// holes, by [`decide`]. On Linux `SEEK_HOLE` goes to `f`, the file as
/// opened for its flags (`open_for_attrs`): without it the file couldn't be
/// opened, and is taken to have none. Elsewhere the file is opened here.
#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
pub(super) fn has_holes(path: &Path, m: &Metadata, f: Option<&File>) -> bool {
    #[cfg(target_os = "linux")]
    let first_hole = Some(|| {
        f.map_or_else(
            || Err(io::Error::other(format!("{} not opened", path.display()))),
            seek_hole,
        )
    });
    #[cfg(any(
        target_os = "android",
        target_os = "freebsd",
        target_os = "illumos",
        target_vendor = "apple"
    ))]
    let first_hole = Some(|| {
        seek_hole(&open(path, m).inspect_err(|err| debug!("open {}: {err}", path.display()))?)
    });
    // Systems without SEEK_HOLE (NetBSD, OpenBSD, DragonFly, Solaris): the
    // blocks decide. DragonFly has it, but HAMMER2 answers EOPNOTSUPP, and
    // tmpfs always the file's size, which would hide real holes; Solaris is
    // left out as BackOtter's restic leaves it out.
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "illumos",
        target_vendor = "apple"
    )))]
    let first_hole = None::<fn() -> io::Result<u64>>;
    decide(m.len(), m.blocks(), first_hole)
}

/// The offset of the first hole in the regular file `f`, which is its size
/// where it has none.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "illumos",
    target_vendor = "apple"
))]
fn seek_hole(f: &File) -> io::Result<u64> {
    use std::os::fd::AsRawFd;

    // SAFETY: f is an open file.
    let hole = unsafe { libc::lseek(f.as_raw_fd(), 0, libc::SEEK_HOLE) };
    u64::try_from(hole).map_err(|_| io::Error::last_os_error())
}

/// Opens the regular file at `path` for [`seek_hole`] as `lsattr(1)` opens
/// files, so as not to follow a symlink, wait on a lock or take a terminal.
/// An error unless it is still the file `m` (its lstat) describes.
#[cfg(any(
    target_os = "android",
    target_os = "freebsd",
    target_os = "illumos",
    target_vendor = "apple"
))]
fn open(path: &Path, m: &Metadata) -> io::Result<File> {
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?;
    let fm = f.metadata()?;
    if !fm.is_file() || fm.dev() != m.dev() || fm.ino() != m.ino() {
        return Err(io::Error::other("replaced since it was listed"));
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{Seek, SeekFrom, Write},
    };

    use super::*;

    #[test]
    fn maybe_sparse_by_blocks() {
        assert!(!maybe_sparse(0, 0)); // empty
        assert!(maybe_sparse(1, 0)); // a hole, or inline data (btrfs, ext4)
        assert!(maybe_sparse(1 << 20, 8)); // a hole, or compressed
        assert!(!maybe_sparse(4096, 8)); // allocated
        assert!(!maybe_sparse(1, 8)); // allocated, a block for a byte
        assert!(!maybe_sparse(1 << 20, 4096)); // preallocated past its end
        assert!(!maybe_sparse(u64::MAX, u64::MAX));
    }

    // The cases of TestHasHoles in BackOtter's restic.
    #[test]
    fn decide_by_blocks_and_seek_hole() {
        type FirstHole = Box<dyn FnOnce() -> io::Result<u64>>;
        let hole = |off: u64| -> Option<FirstHole> { Some(Box::new(move || Ok(off))) };
        let fails = |errno: i32| -> Option<FirstHole> {
            Some(Box::new(move || Err(io::Error::from_raw_os_error(errno))))
        };
        let must_not_seek = || -> Option<FirstHole> {
            Some(Box::new(|| {
                panic!("SEEK_HOLE on a file whose blocks leave no room for holes")
            }))
        };

        for (name, size, blocks, first_hole, want) in [
            ("empty", 0, 0, must_not_seek(), false),
            ("dense", 4096, 8, must_not_seek(), false),
            ("last block part used", 4000, 8, must_not_seek(), false),
            ("preallocated beyond its size", 4096, 64, must_not_seek(), false),
            ("all hole", 1 << 30, 0, hole(0), true),
            ("hole in the middle", 1 << 20, 8, hole(4096), true),
            ("compressed, no holes", 1 << 20, 8, hole(1 << 20), false),
            ("SEEK_HOLE fails with EINVAL", 1 << 20, 8, fails(libc::EINVAL), true),
            ("SEEK_HOLE fails with EOPNOTSUPP", 1 << 20, 8, fails(libc::EOPNOTSUPP), true),
            ("SEEK_HOLE fails with ENOTTY", 1 << 20, 8, fails(libc::ENOTTY), true),
            ("SEEK_HOLE fails with ENXIO", 1 << 20, 8, fails(libc::ENXIO), false),
            ("SEEK_HOLE fails with EACCES", 1 << 20, 8, fails(libc::EACCES), false),
            ("no SEEK_HOLE", 1 << 20, 8, None, true),
            ("no SEEK_HOLE, dense", 1 << 20, 2048, None, false),
        ] {
            assert_eq!(decide(size, blocks, first_hole), want, "{name}");
        }
    }

    /// The file at `path` as the backup opens it for [`has_holes`] on this
    /// system: on Linux along with its flags, elsewhere not at all.
    fn opened(path: &Path) -> Option<File> {
        cfg!(target_os = "linux").then(|| File::open(path).unwrap())
    }

    #[test]
    fn has_holes_finds_holes() {
        let dir = tempfile::tempdir().unwrap();
        let data = vec![1_u8; 1 << 16];

        // Zeros written out: no holes, whether the file system compresses
        // them (SEEK_HOLE sees through that) or not.
        let full = dir.path().join("full");
        let mut f = File::create(&full).unwrap();
        f.write_all(&data).unwrap();
        f.write_all(&vec![0; 8 << 20]).unwrap();
        f.write_all(&data).unwrap();
        f.sync_all().unwrap();
        drop(f);
        let m = std::fs::symlink_metadata(&full).unwrap();
        assert!(!has_holes(&full, &m, opened(&full).as_ref()));

        let sparse = dir.path().join("sparse");
        let mut f = File::create(&sparse).unwrap();
        f.write_all(&data).unwrap();
        _ = f.seek(SeekFrom::Current(8 << 20)).unwrap();
        f.write_all(&data).unwrap();
        f.sync_all().unwrap();
        drop(f);
        let m = std::fs::symlink_metadata(&sparse).unwrap();
        if !maybe_sparse(m.len(), m.blocks()) {
            // A file system without holes.
            return;
        }
        assert!(has_holes(&sparse, &m, opened(&sparse).as_ref()));
        // On Linux a file the backup couldn't open has none.
        if cfg!(target_os = "linux") {
            assert!(!has_holes(&sparse, &m, None));
        }
    }

    // A preallocated file (a swap file) has unwritten extents, which
    // SEEK_HOLE may report as holes, and all its blocks: no holes.
    #[cfg(target_os = "linux")]
    #[test]
    fn preallocated_has_no_holes() {
        use std::os::fd::AsRawFd;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swap");
        let f = File::create(&path).unwrap();
        // SAFETY: f is an open file.
        if unsafe { libc::fallocate(f.as_raw_fd(), 0, 0, 4 << 20) } != 0 {
            // A file system without fallocate.
            return;
        }
        drop(f);
        let m = std::fs::symlink_metadata(&path).unwrap();
        assert!(!maybe_sparse(m.len(), m.blocks()));
        assert!(!has_holes(&path, &m, Some(&File::open(&path).unwrap())));
    }
}
