//! Holes in regular files (`unix.sparse`). The backup reads a file with
//! holes by its data extents, giving the chunker zeros for its holes without
//! reading them (`HoleReader`). The restore restores a file that had holes
//! sparse, in blocks of the file system ([`hole_block_size`]), so that a
//! sparse disk image doesn't fill the disk, and allocates every other, so
//! that a swap file or a preallocated file comes back allocated (see
//! `write_sparse` in the restore).

use std::{
    fs::{File, Metadata},
    io,
    os::unix::fs::MetadataExt,
    path::Path,
};

use log::debug;

// The systems whose `SEEK_HOLE` the backup probes for holes with, and reads
// a file with holes by: Linux and Android, FreeBSD, illumos and macOS. This
// is the one place that lists them: `seek` has what they need, `no_seek`
// what the others get instead (the blocks decide, and a file is read
// plainly), and `hole_reader`, which reads by extents, is built for the
// tests on every system.
#[cfg(any(
    test,
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "illumos",
    target_vendor = "apple"
))]
mod hole_reader;
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "illumos",
    target_vendor = "apple"
)))]
#[path = "sparse/no_seek.rs"]
mod seek;
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "illumos",
    target_vendor = "apple"
))]
pub(super) mod seek;

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
///   (a file system that can't answer): the blocks decide, so holes; on
///   Linux's JFS and nilfs2 (`GENERIC_SEEK_HOLE`) it fails so, without a
///   probe;
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
            let no_answer = super::unsupported(&err);
            debug!("no SEEK_HOLE: {err}; the blocks decide: {no_answer}");
            no_answer
        }
    }
}

/// Whether the regular file at `path`, with metadata `m` (its lstat), has
/// holes, by [`decide`]. On Linux `SEEK_HOLE` goes to `f`, the file as
/// opened for its flags (`open_for_attrs`): without it the file couldn't be
/// opened, and is taken to have none; on JFS and nilfs2, whose `SEEK_HOLE`
/// always answers the size, it isn't asked, and the blocks decide
/// (`generic_seek_hole`). Elsewhere the file is opened here, where the
/// backup probes with `SEEK_HOLE` at all (`seek::first_hole`).
pub(super) fn has_holes(path: &Path, m: &Metadata, f: Option<&File>) -> bool {
    decide(m.len(), m.blocks(), seek::first_hole(path, m, f))
}

/// statfs(2)'s `f_type` of the Linux file systems whose `SEEK_HOLE` is the
/// kernel's generic one, which finds no hole before the size (Linux 6.12,
/// 6.17): JFS (`JFS_SUPER_MAGIC`) and nilfs2 (`NILFS_SUPER_MAGIC`). Neither
/// compresses nor keeps data in the inode, so their blocks tell holes apart:
/// fewer blocks than the size mean holes.
#[cfg(any(test, target_os = "linux"))]
const GENERIC_SEEK_HOLE: [u32; 2] = [0x3153_464a, 0x3434];

/// Whether the file system whose statfs(2) `f_type` is `f_type` can't find
/// holes with `SEEK_HOLE` ([`GENERIC_SEEK_HOLE`]).
#[cfg(any(test, target_os = "linux"))]
fn generic_seek_hole_type(f_type: u32) -> bool {
    GENERIC_SEEK_HOLE.contains(&f_type)
}

/// Whether the file `f` is on a file system whose `SEEK_HOLE` can't find
/// holes ([`GENERIC_SEEK_HOLE`]), by `fstatfs(2)`; not if that fails.
#[cfg(target_os = "linux")]
fn generic_seek_hole(f: &File) -> bool {
    fs_type(f).is_some_and(generic_seek_hole_type)
}

/// statfs(2)'s `f_type` of the file system of `f`, by `fstatfs(2)`; `None`
/// if that fails.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn fs_type(f: &File) -> Option<u32> {
    statfs_type(f).inspect_err(|err| debug!("fstatfs: {err}")).ok()
}

/// A file system's magic number (`ZFS_SUPER_MAGIC` and the like) from
/// statfs(2)'s `f_type`: its low 32 bits. `f_type` is a signed 32-bit word
/// on 32-bit glibc, where btrfs's and bcachefs's magic numbers (bit 31 set)
/// come out negative; a signed 64-bit one on 64-bit glibc, and unsigned on
/// musl and Android. The one place that reads an `f_type`, for
/// `statfs_type` and `statfs_type_path`.
#[cfg(any(test, target_os = "linux", target_os = "android"))]
fn magic(f_type: i128) -> u32 {
    // Masked to 32 bits, it fits.
    u32::try_from(f_type & 0xffff_ffff).unwrap_or_default()
}

/// The magic number ([`magic`]) of the file system of `f`, by `fstatfs(2)`
/// (`fstatfs64` where plain `fstatfs` may fail with `EOVERFLOW`:
/// [`seek::lfs`]).
///
/// # Errors
///
/// * `fstatfs(2)`'s.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn statfs_type(f: &File) -> io::Result<u32> {
    use std::os::fd::AsRawFd;

    let mut st = std::mem::MaybeUninit::<seek::lfs::statfs>::uninit();
    // SAFETY: f is an open file, and st is written by fstatfs.
    if unsafe { seek::lfs::fstatfs(f.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatfs succeeded, so it wrote the struct.
    let st = unsafe { st.assume_init() };
    Ok(magic(i128::from(st.f_type)))
}

/// The magic number ([`magic`]) of the file system `path` is on (followed,
/// if a symlink), by `statfs(2)`.
///
/// # Errors
///
/// * `statfs(2)`'s, or a path with a NUL byte.
#[cfg(target_os = "linux")]
pub(super) fn statfs_type_path(path: &Path) -> io::Result<u32> {
    let path = super::c_path(path)?;
    let mut st = std::mem::MaybeUninit::<seek::lfs::statfs>::uninit();
    // SAFETY: path is a C string, and st is written by statfs.
    if unsafe { seek::lfs::statfs(path.as_ptr(), st.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: statfs succeeded, so it wrote the struct.
    let st = unsafe { st.assume_init() };
    Ok(magic(i128::from(st.f_type)))
}

/// statfs(2)'s `f_type` of ZFS (`ZFS_SUPER_MAGIC`).
#[cfg(any(test, target_os = "linux", target_os = "android"))]
pub(super) const ZFS_SUPER_MAGIC: u32 = 0x2fc1_2fc1;

/// Whether holes can be filled on the file system whose statfs(2) `f_type`
/// is `f_type`: not on ZFS, where `fallocate(2)` succeeds and allocates
/// nothing, and whose compression keeps written zeros as holes, which would
/// have the file opened for writing at every restore for nothing. As
/// BackOtter's restic (`fileHoles`).
#[cfg(any(test, target_os = "linux", target_os = "android"))]
fn fills_holes_type(f_type: u32) -> bool {
    f_type != ZFS_SUPER_MAGIC
}

/// statfs(2)'s `f_type` of btrfs (`BTRFS_SUPER_MAGIC`).
#[cfg(any(test, target_os = "linux", target_os = "android"))]
const BTRFS_SUPER_MAGIC: u32 = 0x9123_683e;

/// statfs(2)'s `f_type` of bcachefs (`BCACHEFS_SUPER_MAGIC`).
#[cfg(any(test, target_os = "linux", target_os = "android"))]
pub(super) const BCACHEFS_SUPER_MAGIC: u32 = 0xca45_1a4e;

/// btrfs's no-copy-on-write file flag (`FS_NOCOW_FL`, `C`), from
/// `<linux/fs.h>`.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) const FS_NOCOW_FL: u32 = 0x0080_0000;

/// The inode flags of the file `f` (`FS_IOC_GETFLAGS`), `chattr(1)`'s and
/// the file system's own.
///
/// # Errors
///
/// * The ioctl's.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn get_flags(f: &File) -> io::Result<u32> {
    use std::os::fd::AsRawFd;

    let mut flags: libc::c_int = 0;
    // SAFETY: FS_IOC_GETFLAGS writes an int to the pointer.
    if unsafe { libc::ioctl(f.as_raw_fd(), libc::FS_IOC_GETFLAGS, &raw mut flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(u32::from_ne_bytes(flags.to_ne_bytes()))
}

/// Whether `fallocate(2)` is to allocate a file (preallocate it, or fill its
/// holes) on the file system whose statfs(2) `f_type` is `f_type`, `nocow`
/// telling whether the file has btrfs's no-copy-on-write flag: not on btrfs
/// but for a NOCOW file (a swap file), and never on bcachefs. Neither
/// compresses what `fallocate(2)` allocated, so a restore onto a compressing
/// mount (`compress=zstd`) would need every file's full size, and might not
/// fit where the source did. A NOCOW file isn't compressed anyway, and a
/// swap file must have no holes. bcachefs's no-copy-on-write is an inode
/// option, not a file flag, and it has no swap files.
#[cfg(any(test, target_os = "linux", target_os = "android"))]
fn allocates_type(f_type: u32, nocow: impl FnOnce() -> bool) -> bool {
    match f_type {
        BTRFS_SUPER_MAGIC => nocow(),
        BCACHEFS_SUPER_MAGIC => false,
        _ => true,
    }
}

/// Whether `fallocate(2)` is to allocate the file `f` ([`allocates_type`]);
/// where the file system can't be told, it is.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn allocates_on(f: &File) -> bool {
    fs_type(f).is_none_or(|t| allocates_type(t, || is_nocow(f)))
}

/// Whether the file `f` has btrfs's no-copy-on-write flag; not if
/// `FS_IOC_GETFLAGS` fails.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn is_nocow(f: &File) -> bool {
    get_flags(f).is_ok_and(|flags| flags & FS_NOCOW_FL != 0)
}

/// Whether holes of the file `f` can be filled: [`fills_holes_type`], and
/// [`allocates_type`], so that a file whose holes wouldn't be filled isn't
/// opened for writing, nor counted as modified by `--dry-run`; where the
/// file system can't be told, they are tried.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn fills_holes_on(f: &File) -> bool {
    fs_type(f).is_none_or(|t| fills_holes_type(t) && allocates_type(t, || is_nocow(f)))
}

/// The smallest block a file restored sparse has its holes in: a sector,
/// the block of bcachefs formatted with `block_size` 512, the smallest any
/// file system has. A file system's own smaller blocks (XFS, ext2/3/4 with
/// 1 KiB blocks, bcachefs) get holes as small as its source's.
const MIN_HOLE_BLOCK: u64 = 512;

/// The block a file restored sparse has its holes in where the file
/// system's block size isn't known.
const DEFAULT_HOLE_BLOCK: u64 = 4096;

/// The size of the blocks a file restored sparse has its holes in, `f`
/// being that file: the block size of its file system (`f_bsize` of
/// `fstatfs(2)`, of `fstatvfs(2)` on NetBSD and illumos), else its
/// `st_blksize`, at least 512 bytes; 4096 if neither is known
/// ([`hole_block`]). As BackOtter's restic (`fs.HoleBlockSize`).
pub(super) fn hole_block_size(f: &File) -> u64 {
    hole_block(
        fs_block_size(f)
            .filter(|&size| size > 0)
            .or_else(|| f.metadata().ok().map(|m| m.blksize())),
    )
}

/// The block a file restored sparse has its holes in on a file system whose
/// block size is `size` (`None` or 0: not known): `size`, at least
/// [`MIN_HOLE_BLOCK`]; [`DEFAULT_HOLE_BLOCK`] where it isn't known.
fn hole_block(size: Option<u64>) -> u64 {
    match size {
        Some(size) if size > 0 => size.max(MIN_HOLE_BLOCK),
        _ => DEFAULT_HOLE_BLOCK,
    }
}

/// `f_bsize` of `fstatfs(2)` of `f`.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_vendor = "apple"
))]
fn fs_block_size(f: &File) -> Option<u64> {
    use std::os::fd::AsRawFd;

    let mut st = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: f is an open file, and st is written by fstatfs.
    if unsafe { libc::fstatfs(f.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: fstatfs succeeded.
    let st = unsafe { st.assume_init() };
    u64::try_from(st.f_bsize).ok()
}

/// `f_bsize` of `fstatvfs(2)` of `f` (`fstatvfs`'s, not `fstatfs`'s, on
/// the BSDs and macOS, is the size of the best transfer, not of a block).
#[cfg(any(target_os = "netbsd", target_os = "illumos", target_os = "solaris"))]
fn fs_block_size(f: &File) -> Option<u64> {
    use std::os::fd::AsRawFd;

    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: f is an open file, and st is written by fstatvfs.
    if unsafe { libc::fstatvfs(f.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: fstatvfs succeeded.
    let st = unsafe { st.assume_init() };
    u64::try_from(st.f_bsize).ok()
}

/// No file system block size known here.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_vendor = "apple",
    target_os = "netbsd",
    target_os = "illumos",
    target_os = "solaris"
)))]
const fn fs_block_size(_f: &File) -> Option<u64> {
    None
}

/// The reader the backup gives the chunker for the regular file `f`, which
/// `sparse` says has holes (`unix.sparse`, as [`has_holes`] found): on the
/// systems that probe for holes with `SEEK_HOLE`, a file with holes is read
/// by its data extents (`HoleReader`), if it still has a hole as opened
/// (`seek::holes_now`); any other is `f` itself. Either way the bytes are
/// those plain reading gives, so are the chunks.
pub(super) fn backup_reader(f: File, sparse: bool) -> Box<dyn io::Read + Send> {
    seek::backup_reader(f, sparse)
}

/// [`super::fill_holes`]: the holes of the regular file at `path`, of `len`
/// bytes, filled, where it still is such a file and has any.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn fill_holes(path: &Path, len: u64) -> super::FilledHoles {
    let mut done = super::FilledHoles::default();
    if let Err(err) = fill_holes_with(path, len, &mut done) {
        done.error = Some(err);
    }
    done
}

/// [`super::holes_to_fill`]: whether [`fill_holes`] would fill holes of the
/// regular file at `path`, of `len` bytes ([`file_holes`]), for
/// `restore --dry-run`. As BackOtter's restic (`fs.HasHolesToFill`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn holes_to_fill(path: &Path, len: u64) -> bool {
    match file_holes(path, len) {
        Ok(holes) => holes.is_some(),
        Err(err) => {
            debug!("holes of {} not checked: {err}", path.display());
            false
        }
    }
}

/// Whether the regular file at `path`, of `len` bytes, has holes that
/// [`fill_holes`] fills, with its lstat if so: it has fewer blocks than
/// bytes, and then, opened for reading only, `SEEK_HOLE` finds a hole (a
/// file on a file system that compresses has few blocks and no holes).
/// Never on ZFS, nor on btrfs but for a NOCOW file, nor on bcachefs
/// ([`fills_holes_on`]). A file with all its blocks (most)
/// is only lstat'ed.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn file_holes(path: &Path, len: u64) -> io::Result<Option<Metadata>> {
    let m = std::fs::symlink_metadata(path)?;
    // Most files: all their blocks, nothing more to look at.
    if !m.is_file() || m.len() != len || !maybe_sparse(len, m.blocks()) {
        return Ok(None);
    }
    // Fewer blocks than bytes (holes, or a file system that compresses):
    // SEEK_HOLE tells, on the file opened for reading only.
    let probe = seek::open(path, &m)?;
    // Never on ZFS, where nothing is allocated, nor where nothing is to be
    // (fills_holes_on).
    if !fills_holes_on(&probe) {
        return Ok(None);
    }
    #[cfg(target_os = "linux")]
    let holes = has_holes(path, &m, Some(&probe));
    #[cfg(not(target_os = "linux"))]
    let holes = decide(len, m.blocks(), Some(|| seek::seek_hole(&probe)));
    Ok(holes.then_some(m))
}

/// [`fill_holes`], which sets `done.changed` once the file has more blocks
/// than before, even where filling them failed (`ENOSPC` after some were
/// allocated), and gives the error that kept it from filling them all.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn fill_holes_with(path: &Path, len: u64, done: &mut super::FilledHoles) -> io::Result<()> {
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

    let Some(m) = file_holes(path, len)? else {
        return Ok(());
    };
    debug!("filling the holes of {}", path.display());
    let f = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?;
    let before = f.metadata()?;
    if !before.is_file() || before.dev() != m.dev() || before.ino() != m.ino() {
        return Err(io::Error::other("replaced since it was looked at"));
    }
    let filled = allocate_holes(&f, len);
    // Looked at again whether or not it failed: a file system out of space
    // may have allocated some.
    done.changed = f.metadata().is_ok_and(|after| after.blocks() > before.blocks());
    filled
}

/// Allocates the first `len` bytes of `f`, holes included: `fallocate(2)`
/// with mode 0, which leaves data as it is. A file system that can't
/// (`EOPNOTSUPP`, `ENOSYS`: ext4 on indirect-block files, older ZFS) is
/// nothing to do, as in BackOtter's restic ([`cannot_allocate`]).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn allocate_holes(f: &File, len: u64) -> io::Result<()> {
    match super::os_preallocate(f, len) {
        Err(err) if cannot_allocate(&err) => {
            debug!("holes not filled: {err}");
            Ok(())
        }
        done => done,
    }
}

/// Whether `err`, from `fallocate(2)`, says the file system can't allocate
/// (`EOPNOTSUPP`, `ENOSYS`), which leaves nothing to do.
#[cfg(any(test, target_os = "linux", target_os = "android"))]
fn cannot_allocate(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::EOPNOTSUPP | libc::ENOSYS))
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{Seek, SeekFrom, Write},
    };

    use super::*;

    /// A file with holes that SEEK_HOLE finds, here (a file system that
    /// keeps holes), or `None`.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn sparse_file(dir: &Path, name: &str, len: u64) -> Option<std::path::PathBuf> {
        let path = dir.join(name);
        let mut f = File::create(&path).unwrap();
        _ = f.seek(SeekFrom::Start(len - 1)).unwrap();
        f.write_all(b"x").unwrap();
        drop(f);
        let m = std::fs::metadata(&path).unwrap();
        maybe_sparse(len, m.blocks()).then_some(path)
    }

    /// BackOtter: a file with holes gets them filled, and says it changed;
    /// a file without (or filled already) isn't opened for writing at all:
    /// one that can't be (read-only, not as root) is no error.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn fill_holes_only_where_there_are_holes() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let len = 4 << 20;
        let Some(path) = sparse_file(dir.path(), "holes", len) else {
            eprintln!("no holes in {}", dir.path().display());
            return;
        };
        if !fills_holes_on(&File::open(&path).unwrap()) {
            eprintln!("ZFS, btrfs or bcachefs: no holes filled in {}", dir.path().display());
            assert!(!holes_to_fill(&path, len));
            return;
        }
        // --dry-run: holes to fill, and none filled.
        let blocks = std::fs::metadata(&path).unwrap().blocks();
        assert!(holes_to_fill(&path, len));
        assert_eq!(std::fs::metadata(&path).unwrap().blocks(), blocks);
        let filled = fill_holes(&path, len);
        assert!(filled.error.is_none(), "{:?}", filled.error);
        if !filled.changed && maybe_sparse(len, std::fs::metadata(&path).unwrap().blocks()) {
            eprintln!("no fallocate in {}", dir.path().display());
            return;
        }
        assert!(filled.changed);
        let m = std::fs::metadata(&path).unwrap();
        assert!(!maybe_sparse(len, m.blocks()), "{} blocks", m.blocks());
        assert_eq!(std::fs::read(&path).unwrap().iter().filter(|&&b| b != 0).count(), 1);

        // Filled already: nothing to do, read-only or not.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert!(!holes_to_fill(&path, len));
        let again = fill_holes(&path, len);
        assert!(again.error.is_none(), "{:?}", again.error);
        assert!(!again.changed);

        // A dense file, read-only: not opened for writing.
        let dense = dir.path().join("dense");
        std::fs::write(&dense, vec![1_u8; 1 << 16]).unwrap();
        std::fs::set_permissions(&dense, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert!(!holes_to_fill(&dense, 1 << 16));
        let none = fill_holes(&dense, 1 << 16);
        assert!(none.error.is_none(), "{:?}", none.error);
        assert!(!none.changed);

        // One with holes that can't be opened for writing (not as root):
        // the error says so, and nothing changed.
        if !nix::unistd::geteuid().is_root()
            && let Some(ro) = sparse_file(dir.path(), "ro", len)
        {
            std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o444)).unwrap();
            // --dry-run doesn't open it for writing, and can't tell.
            assert!(holes_to_fill(&ro, len));
            let refused = fill_holes(&ro, len);
            assert!(refused.error.is_some());
            assert!(!refused.changed);
        }
    }

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
        // them (SEEK_HOLE sees through that) or not; unless it makes holes
        // of them itself, as ZFS with compression does, which nobody can
        // tell from holes.
        let full = dir.path().join("full");
        let mut f = File::create(&full).unwrap();
        f.write_all(&data).unwrap();
        f.write_all(&vec![0; 8 << 20]).unwrap();
        f.write_all(&data).unwrap();
        f.sync_all().unwrap();
        drop(f);
        let m = std::fs::symlink_metadata(&full).unwrap();
        let made_holes = maybe_sparse(m.len(), m.blocks()) && seek::tests::finds_hole(&full, m.len());
        assert_eq!(has_holes(&full, &m, opened(&full).as_ref()), made_holes);

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
        if maybe_sparse(m.len(), m.blocks()) {
            // A file system that takes fallocate without allocating (ZFS).
            return;
        }
        assert!(!has_holes(&path, &m, Some(&File::open(&path).unwrap())));
    }

    /// BackOtter (ForkAudit1 G3-03): a magic number with bit 31 set
    /// (bcachefs's, btrfs's) is the same number whatever `f_type`'s type: a
    /// signed 32-bit word on 32-bit glibc, where it is negative and
    /// `u32::try_from` took it for no file system at all; signed 64-bit on
    /// 64-bit glibc; unsigned on musl and Android.
    #[test]
    fn magic_is_f_types_low_32_bits() {
        for (name, want) in [
            ("bcachefs", BCACHEFS_SUPER_MAGIC),
            ("btrfs", BTRFS_SUPER_MAGIC),
            ("ZFS", ZFS_SUPER_MAGIC),
        ] {
            assert_eq!(magic(i128::from(want.cast_signed())), want, "{name}: i32");
            assert_eq!(magic(i128::from(i64::from(want))), want, "{name}: i64");
            assert_eq!(magic(i128::from(u64::from(want))), want, "{name}: unsigned long");
        }
        assert!(BCACHEFS_SUPER_MAGIC.cast_signed() < 0 && BTRFS_SUPER_MAGIC.cast_signed() < 0);
    }

    /// `fstatfs(2)` of a file and `statfs(2)` of its directory name the same
    /// file system.
    #[cfg(target_os = "linux")]
    #[test]
    fn statfs_type_of_a_file_and_of_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let f = File::create(dir.path().join("f")).unwrap();
        let by_file = statfs_type(&f).unwrap();
        assert_ne!(by_file, 0);
        assert_eq!(statfs_type_path(dir.path()).unwrap(), by_file);
        assert!(statfs_type_path(&dir.path().join("none")).is_err());
    }

    /// Holes are never filled on ZFS, where `fallocate(2)` allocates
    /// nothing; and a file system that can't allocate is nothing to do.
    #[test]
    fn fills_holes_types() {
        for (name, f_type, want) in [
            ("ZFS", 0x2fc1_2fc1, false),
            ("ext4", 0xef53, true),
            ("tmpfs", 0x0102_1994, true),
            ("XFS", 0x5846_5342, true),
            ("btrfs", 0x9123_683e, true),
        ] {
            assert_eq!(fills_holes_type(f_type), want, "{name}");
        }
        for (errno, want) in [
            (libc::EOPNOTSUPP, true),
            (libc::ENOSYS, true),
            (libc::ENOSPC, false),
            (libc::EIO, false),
        ] {
            assert_eq!(cannot_allocate(&io::Error::from_raw_os_error(errno)), want, "{errno}");
        }
    }

    /// btrfs allocates only a NOCOW file, bcachefs none, the others every
    /// file (ZFS too: holes are left alone there by `fills_holes_type`).
    #[test]
    fn allocates_types() {
        for (name, f_type, nocow, want) in [
            ("btrfs", 0x9123_683e, false, false),
            ("btrfs NOCOW", 0x9123_683e, true, true),
            ("bcachefs", 0xca45_1a4e, false, false),
            ("bcachefs nocow", 0xca45_1a4e, true, false),
            ("ext4", 0xef53, false, true),
            ("XFS", 0x5846_5342, false, true),
            ("ZFS", 0x2fc1_2fc1, false, true),
        ] {
            assert_eq!(allocates_type(f_type, || nocow), want, "{name}");
        }
    }

    /// `BKO_TEST_ZFS_DIR` names a directory on ZFS with compression: a file
    /// whose zero records ZFS keeps as holes is left alone, not opened for
    /// writing (it is read-only, which fails as anyone but root), and not
    /// changed.
    #[cfg(target_os = "linux")]
    #[test]
    fn zfs_holes_left_alone() {
        use std::os::unix::fs::PermissionsExt;

        let Some(dir) = std::env::var_os("BKO_TEST_ZFS_DIR") else {
            eprintln!("BKO_TEST_ZFS_DIR not set");
            return;
        };
        let dir = tempfile::tempdir_in(dir).unwrap();
        let path = dir.path().join("zeros");
        let len = 8 << 20;
        std::fs::write(&path, vec![0_u8; 8 << 20]).unwrap();
        File::open(&path).unwrap().sync_all().unwrap();
        assert_eq!(fs_type(&File::open(&path).unwrap()), Some(ZFS_SUPER_MAGIC), "not ZFS");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let m = std::fs::metadata(&path).unwrap();
        assert!(maybe_sparse(len, m.blocks()), "no compression: {} blocks", m.blocks());
        assert!(!holes_to_fill(&path, len));
        let filled = fill_holes(&path, len);
        assert!(filled.error.is_none(), "{:?}", filled.error);
        assert!(!filled.changed);
    }

    /// `BKO_TEST_BTRFS_DIR` names a directory on btrfs: a file is only sized
    /// by `preallocate`, and its holes are neither filled nor counted; a
    /// NOCOW file (`chattr +C`) is allocated, and its holes filled.
    #[cfg(target_os = "linux")]
    #[test]
    fn btrfs_allocates_only_nocow() {
        let Some(dir) = std::env::var_os("BKO_TEST_BTRFS_DIR") else {
            eprintln!("BKO_TEST_BTRFS_DIR not set");
            return;
        };
        let dir = tempfile::tempdir_in(dir).unwrap();
        let len: u64 = 4 << 20;
        let create = |name: &str, nocow: bool| {
            let path = dir.path().join(name);
            let f = File::create_new(&path).unwrap();
            if nocow {
                let out = std::process::Command::new("chattr").arg("+C").arg(&path).output().unwrap();
                assert!(out.status.success(), "chattr +C: {out:?}");
            }
            f.set_len(len).unwrap();
            (path, f)
        };
        let blocks = |path: &Path| std::fs::metadata(path).unwrap().blocks();

        let (plain, f) = create("plain", false);
        assert_eq!(fs_type(&f), Some(BTRFS_SUPER_MAGIC), "not btrfs");
        assert!(!allocates_on(&f));
        super::super::preallocate(&f, len);
        assert!(maybe_sparse(len, blocks(&plain)), "plain file preallocated");
        assert!(!holes_to_fill(&plain, len));
        let filled = fill_holes(&plain, len);
        assert!(filled.error.is_none(), "{:?}", filled.error);
        assert!(!filled.changed);
        assert!(maybe_sparse(len, blocks(&plain)), "plain file's holes filled");

        let (nocow, f) = create("nocow", true);
        assert!(allocates_on(&f));
        assert!(holes_to_fill(&nocow, len));
        let filled = fill_holes(&nocow, len);
        assert!(filled.error.is_none(), "{:?}", filled.error);
        assert!(filled.changed);
        assert!(!maybe_sparse(len, blocks(&nocow)), "NOCOW file's holes not filled");

        let (pre, f) = create("nocow-preallocated", true);
        super::super::preallocate(&f, len);
        assert!(!maybe_sparse(len, blocks(&pre)), "NOCOW file not preallocated");
    }

    // On JFS and nilfs2, SEEK_HOLE finds no hole before the size, so the
    // blocks decide.
    #[test]
    fn generic_seek_hole_types() {
        for (name, f_type, want) in [
            ("JFS", 0x3153_464a, true),
            ("nilfs2", 0x3434, true),
            ("ext4", 0xef53, false),
            ("tmpfs", 0x0102_1994, false),
            ("ZFS", 0x2fc1_2fc1, false),
        ] {
            assert_eq!(generic_seek_hole_type(f_type), want, "{name}");
        }
    }

    /// `BKO_TEST_GENERIC_SEEK_HOLE_DIR` names a directory on JFS or nilfs2:
    /// a file with holes there is marked sparse though `SEEK_HOLE` finds
    /// none, and read plainly.
    #[cfg(target_os = "linux")]
    #[test]
    fn has_holes_generic_seek_hole() {
        let Some(dir) = std::env::var_os("BKO_TEST_GENERIC_SEEK_HOLE_DIR") else {
            eprintln!("BKO_TEST_GENERIC_SEEK_HOLE_DIR not set");
            return;
        };
        let dir = tempfile::Builder::new().prefix("bko-").tempdir_in(dir).unwrap();
        let fill = |name: &str, off: u64, data: &[u8]| {
            let path = dir.path().join(name);
            let mut f = File::create(&path).unwrap();
            _ = f.seek(SeekFrom::Start(off)).unwrap();
            f.write_all(data).unwrap();
            drop(f);
            let m = std::fs::symlink_metadata(&path).unwrap();
            (path, m)
        };

        let (path, m) = fill("holes", 32 << 20, b"y");
        let f = File::open(&path).unwrap();
        assert!(generic_seek_hole(&f), "not on JFS or nilfs2");
        assert_eq!(seek::seek_hole(&f).unwrap(), m.len(), "not a generic SEEK_HOLE");
        assert!(maybe_sparse(m.len(), m.blocks()), "no holes: {} blocks", m.blocks());
        assert!(has_holes(&path, &m, Some(&File::open(&path).unwrap())));
        assert!(!seek::holes_now(&f));

        let (path, m) = fill("dense", 0, &vec![0; 1 << 20]);
        assert!(!has_holes(&path, &m, Some(&File::open(&path).unwrap())));
    }

    /// Holes are made in blocks of at least 512 bytes (whatever their size:
    /// some FUSE and network file systems report odd ones).
    #[test]
    fn hole_block_size_at_least_512() {
        let dir = tempfile::tempdir().unwrap();
        let f = File::create(dir.path().join("f")).unwrap();
        let size = hole_block_size(&f);
        eprintln!("block size {size}");
        assert!(size >= MIN_HOLE_BLOCK, "{size}");
        assert_eq!(MIN_HOLE_BLOCK, 512);
    }

    /// The file system's block size, at least 512 (bcachefs with
    /// `block_size` 512 has holes that small); 4096 where it isn't known.
    #[test]
    fn hole_block_rule() {
        for (size, want) in [
            (None, 4096),
            (Some(0), 4096),
            (Some(1), 512),
            (Some(511), 512),
            (Some(512), 512),
            (Some(1024), 1024),
            (Some(4096), 4096),
            (Some(65536), 65536),
            (Some(131_072), 131_072),
        ] {
            assert_eq!(hole_block(size), want, "{size:?}");
        }
    }
}
