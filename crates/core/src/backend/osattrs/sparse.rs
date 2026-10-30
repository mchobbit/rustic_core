//! Holes in regular files (`unix.sparse`). The restore turns the zero chunks
//! of a file that had holes back into holes, and writes out every byte of
//! any other, so that a sparse disk image doesn't fill the disk, and a swap
//! file or a preallocated file comes back allocated.

use std::{fs::Metadata, io, os::unix::fs::MetadataExt, path::Path};

use log::debug;

/// Whether a regular file of `size` bytes with `blocks` 512-byte blocks
/// may have holes. A preallocated file has all its blocks, even where
/// `SEEK_HOLE` finds holes (unwritten extents); a file on a compressing file
/// system has fewer than its size without holes, which `SEEK_HOLE` tells.
pub(super) fn maybe_sparse(size: u64, blocks: u64) -> bool {
    size > 0 && blocks.saturating_mul(512) < size
}

/// Whether the regular file at `path`, with metadata `m`, has holes: fewer
/// blocks than its size and, where the system has `SEEK_HOLE`, a hole before
/// its end. Where `SEEK_HOLE` can't say (a system or file system without it,
/// a file that can't be opened), the blocks decide: a file taken for sparse
/// only gets holes for its zero chunks, one taken for not sparse may not fit.
pub(super) fn has_holes(path: &Path, m: &Metadata) -> bool {
    if !maybe_sparse(m.len(), m.blocks()) {
        return false;
    }
    match first_hole(path) {
        Ok(hole) => hole < m.len(),
        Err(err) => {
            debug!("no SEEK_HOLE for {}: {err}", path.display());
            true
        }
    }
}

/// The offset of the first hole in the regular file at `path`, which is its
/// size where it has none. Opened as `lsattr(1)` opens files, so as not to
/// follow a symlink or wait on a lock.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "illumos",
    target_os = "solaris",
    target_vendor = "apple"
))]
fn first_hole(path: &Path) -> io::Result<u64> {
    use std::{
        fs::OpenOptions,
        os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    };

    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    // SAFETY: f is an open file.
    let hole = unsafe { libc::lseek(f.as_raw_fd(), 0, libc::SEEK_HOLE) };
    u64::try_from(hole).map_err(|_| io::Error::last_os_error())
}

/// Systems without `SEEK_HOLE` (NetBSD, OpenBSD): the blocks decide.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "illumos",
    target_os = "solaris",
    target_vendor = "apple"
)))]
fn first_hole(_path: &Path) -> io::Result<u64> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
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

    #[test]
    fn has_holes_finds_holes() {
        let dir = tempfile::tempdir().unwrap();
        let data = vec![1_u8; 1 << 16];

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
        assert!(has_holes(&sparse, &m));

        let full = dir.path().join("full");
        let mut f = File::create(&full).unwrap();
        f.write_all(&data).unwrap();
        f.write_all(&vec![0; 8 << 20]).unwrap();
        f.write_all(&data).unwrap();
        f.sync_all().unwrap();
        drop(f);
        let m = std::fs::symlink_metadata(&full).unwrap();
        if maybe_sparse(m.len(), m.blocks()) {
            // A compressing file system, which SEEK_HOLE should see through,
            // where there is one.
            return;
        }
        assert!(!has_holes(&full, &m));
    }
}
