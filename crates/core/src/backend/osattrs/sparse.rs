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
///   Linux's JFS and nilfs2 ([`GENERIC_SEEK_HOLE`]) it fails so, without a
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
/// opened, and is taken to have none; on JFS and nilfs2, whose `SEEK_HOLE`
/// always answers the size, it isn't asked, and the blocks decide
/// ([`generic_seek_hole`]). Elsewhere the file is opened here.
#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
pub(super) fn has_holes(path: &Path, m: &Metadata, f: Option<&File>) -> bool {
    #[cfg(target_os = "linux")]
    let first_hole = Some(|| match f {
        None => Err(io::Error::other(format!("{} not opened", path.display()))),
        // SEEK_HOLE would answer the size: the file system can't answer,
        // and the blocks decide.
        Some(f) if generic_seek_hole(f) => Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
        Some(f) => seek_hole(f),
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
    use std::os::fd::AsRawFd;

    let mut st = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: f is an open file, and st is written by fstatfs.
    if unsafe { libc::fstatfs(f.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        debug!("fstatfs: {}", io::Error::last_os_error());
        return None;
    }
    // SAFETY: fstatfs succeeded.
    let st = unsafe { st.assume_init() };
    u32::try_from(st.f_type).ok()
}

/// statfs(2)'s `f_type` of ZFS (`ZFS_SUPER_MAGIC`).
#[cfg(any(test, target_os = "linux", target_os = "android"))]
const ZFS_SUPER_MAGIC: u32 = 0x2fc1_2fc1;

/// Whether holes can be filled on the file system whose statfs(2) `f_type`
/// is `f_type`: not on ZFS, where `fallocate(2)` succeeds and allocates
/// nothing, and whose compression keeps written zeros as holes, which would
/// have the file opened for writing at every restore for nothing. As
/// BackOtter's restic (`fileHoles`).
#[cfg(any(test, target_os = "linux", target_os = "android"))]
fn fills_holes_type(f_type: u32) -> bool {
    f_type != ZFS_SUPER_MAGIC
}

/// Whether holes of the file `f` can be filled ([`fills_holes_type`]);
/// where the file system can't be told, they are tried.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn fills_holes_on(f: &File) -> bool {
    fs_type(f).is_none_or(fills_holes_type)
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
    lseek(f, 0, libc::SEEK_HOLE)
}

/// Opens the regular file at `path` for [`seek_hole`] as `lsattr(1)` opens
/// files, so as not to follow a symlink, wait on a lock or take a terminal.
/// An error unless it is still the file `m` (its lstat) describes.
#[cfg(any(
    target_os = "linux",
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
/// by its data extents ([`HoleReader`]), if it still has a hole as opened
/// ([`holes_now`]); any other is `f` itself. Either way the bytes are those
/// plain reading gives, so are the chunks.
pub(super) fn backup_reader(f: File, sparse: bool) -> Box<dyn io::Read + Send> {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "illumos",
        target_vendor = "apple"
    ))]
    if sparse {
        let holes = holes_now(&f);
        // SEEK_HOLE moved the offset plain reading starts at (HoleReader
        // reads with pread).
        if holes || lseek(&f, 0, libc::SEEK_SET).is_err() {
            return Box::new(HoleReader::new(f));
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "illumos",
        target_vendor = "apple"
    )))]
    let _ = sparse;
    Box::new(f)
}

/// Whether the regular file `f`, opened to be read, has a hole before its end
/// by `SEEK_HOLE`. The file marked when it was listed may have been replaced
/// since, or compressed by its file system: macOS answers `ENXIO` to
/// `SEEK_HOLE` and `SEEK_DATA` at every offset of a file compressed by the
/// file system (`UF_COMPRESSED`), whose data plain reading gives. On JFS and
/// nilfs2 `SEEK_HOLE` gives the size, so a file there is read whole, holes
/// and all. Moves the offset of `f`.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "illumos",
    target_vendor = "apple"
))]
fn holes_now(f: &File) -> bool {
    match (f.metadata(), seek_hole(f)) {
        (Ok(m), Ok(hole)) => hole < m.len(),
        (m, hole) => {
            debug!("no hole found as opened ({:?}, {hole:?}); reading plainly", m.err());
            false
        }
    }
}

#[cfg(any(
    test,
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "illumos",
    target_vendor = "apple"
))]
/// Where a file's data is, and its bytes: what [`HoleReader`] reads a file
/// with. A trait, so that the tests can give it files that change as they
/// are read.
pub(super) trait Extents {
    /// `lseek(SEEK_DATA)`: the offset of the first data at or after `off`
    /// (`ENXIO` if there is none).
    fn seek_data(&mut self, off: u64) -> io::Result<u64>;
    /// `lseek(SEEK_HOLE)`: the offset of the first hole at or after `off`,
    /// the size if there is none but the end of file.
    fn seek_hole(&mut self, off: u64) -> io::Result<u64>;
    /// The size of the file now.
    fn size(&mut self) -> io::Result<u64>;
    /// `pread(2)`.
    fn read_at(&mut self, buf: &mut [u8], off: u64) -> io::Result<usize>;
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "illumos",
    target_vendor = "apple"
))]
impl Extents for File {
    fn seek_data(&mut self, off: u64) -> io::Result<u64> {
        lseek(self, off, libc::SEEK_DATA)
    }

    fn seek_hole(&mut self, off: u64) -> io::Result<u64> {
        lseek(self, off, libc::SEEK_HOLE)
    }

    fn size(&mut self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }

    fn read_at(&mut self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        std::os::unix::fs::FileExt::read_at(self, buf, off)
    }
}

/// `lseek(2)` of `f` to `off` from `whence`.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "illumos",
    target_vendor = "apple"
))]
fn lseek(f: &File, off: u64, whence: libc::c_int) -> io::Result<u64> {
    use std::os::fd::AsRawFd;

    // 64-bit offsets where `off_t` may have 32 bits (32-bit glibc and
    // Android), which would leave a file over 2 GiB unread by its extents.
    #[cfg(any(
        target_os = "android",
        all(target_os = "linux", any(target_env = "gnu", target_env = "musl"))
    ))]
    use libc::{lseek64 as lseek, off64_t as off_t};
    #[cfg(not(any(
        target_os = "android",
        all(target_os = "linux", any(target_env = "gnu", target_env = "musl"))
    )))]
    use libc::{lseek, off_t};

    let off = off_t::try_from(off).map_err(io::Error::other)?;
    // SAFETY: f is an open file.
    let pos = unsafe { lseek(f.as_raw_fd(), off, whence) };
    u64::try_from(pos).map_err(|_| io::Error::last_os_error())
}

#[cfg(any(
    test,
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "illumos",
    target_vendor = "apple"
))]
/// All the rest of the file, read as data.
const PLAIN: u64 = u64::MAX;

#[cfg(any(
    test,
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "illumos",
    target_vendor = "apple"
))]
/// Reads a file with holes by its data extents. Up to `end` the file is a
/// hole (given as zeros, not read) or data (read with `pread(2)`); at `end`,
/// `SEEK_DATA` and `SEEK_HOLE` find the next extent. Once they fail, or the
/// file has no data left but a hole at its end, the rest is read as data, as
/// plain reading does: up to whatever end of file `pread` finds, so that a
/// file that grows or shrinks while it is read gives no more trouble than
/// it does to plain reading. The bytes are those plain reading gives.
#[derive(Debug)]
pub(super) struct HoleReader<F> {
    /// The file.
    f: F,
    /// The offset of the next byte to give.
    off: u64,
    /// Where the extent `off` is in ends.
    end: u64,
    /// Whether that extent is a hole.
    hole: bool,
    /// The bytes given as zeros without being read.
    zeros: u64,
}

#[cfg(any(
    test,
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "illumos",
    target_vendor = "apple"
))]
impl<F: Extents> HoleReader<F> {
    /// Reads `f` from its start.
    pub(super) const fn new(f: F) -> Self {
        Self {
            f,
            off: 0,
            end: 0,
            hole: false,
            zeros: 0,
        }
    }

    /// Finds the extent that starts at `off`.
    fn next_extent(&mut self) {
        let off = self.off;
        // The size before SEEK_DATA: data written at the end after this is
        // found by SEEK_DATA, not taken for a hole.
        let size = self.f.size();
        (self.hole, self.end) = match self.f.seek_data(off) {
            // No data from `off` on: a hole up to the end of file, or `off`
            // is at the end (or past it: the file shrank). The end is the
            // size before SEEK_DATA, or after it if the file shrank since.
            // A hole only where SEEK_HOLE finds one at `off` too: macOS
            // answers ENXIO to both at every offset of a file its file
            // system compresses, whose data plain reading gives.
            Err(err) if err.raw_os_error() == Some(libc::ENXIO) => {
                match size.and_then(|size| Ok(size.min(self.f.size()?))) {
                    Ok(size) if size > off && self.f.seek_hole(off).ok() == Some(off) => {
                        (true, size)
                    }
                    _ => (false, PLAIN),
                }
            }
            Err(err) => {
                debug!("no SEEK_DATA at {off}: {err}; reading the rest");
                (false, PLAIN)
            }
            // A hole up to the data, but not past the size before SEEK_DATA
            // (which a correct file system never puts data past).
            Ok(data) if data > off => match size {
                Ok(size) if data.min(size) > off => (true, data.min(size)),
                _ => (false, PLAIN),
            },
            Ok(_) => match self.f.seek_hole(off) {
                Ok(hole) if hole > off => (false, hole),
                other => {
                    debug!("no SEEK_HOLE at {off}: {other:?}; reading the rest");
                    (false, PLAIN)
                }
            },
        };
    }
}

#[cfg(any(
    test,
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "illumos",
    target_vendor = "apple"
))]
impl<F: Extents> io::Read for HoleReader<F> {
    /// Fills `buf` across extents, as a read of a regular file does, short
    /// only at the end of file (or on an error after some bytes, `EINTR`
    /// retried): the chunker reads on with a buffer no longer than the last
    /// read gave.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut done = 0;
        while done < buf.len() {
            match self.read_extent(&mut buf[done..]) {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(_) if done > 0 => break,
                Err(err) => return Err(err),
            }
        }
        Ok(done)
    }
}

#[cfg(any(
    test,
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "illumos",
    target_vendor = "apple"
))]
impl<F: Extents> HoleReader<F> {
    /// Reads into `buf`, not past the extent `off` is in.
    fn read_extent(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.off >= self.end {
            self.next_extent();
        } else if self.hole {
            // Further into a hole (`next_extent` has just asked), the hole
            // ends at the size `fstat` gives now, asked once a buffer: a
            // file cut short inside it is read as plain reading reads it,
            // up to its end of file now, and past that plainly (EOF).
            match self.f.size() {
                Ok(size) if size > self.off => self.end = self.end.min(size),
                _ => (self.hole, self.end) = (false, PLAIN),
            }
        }
        let len = usize::try_from(self.end - self.off).map_or(buf.len(), |n| n.min(buf.len()));
        let buf = &mut buf[..len];
        if self.hole {
            buf.fill(0);
            self.off += len as u64;
            self.zeros += len as u64;
            return Ok(len);
        }
        let n = self.f.read_at(buf, self.off)?;
        self.off += n as u64;
        Ok(n)
    }
}

#[cfg(any(
    test,
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "illumos",
    target_vendor = "apple"
))]
impl<F> Drop for HoleReader<F> {
    fn drop(&mut self) {
        debug!("{} bytes of holes given as zeros, not read", self.zeros);
    }
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
/// Never on ZFS ([`fills_holes_type`]). A file with all its blocks (most)
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
    let probe = open(path, &m)?;
    // Never on ZFS, where nothing is allocated (fills_holes_type).
    if !fills_holes_on(&probe) {
        return Ok(None);
    }
    #[cfg(target_os = "linux")]
    let holes = has_holes(path, &m, Some(&probe));
    #[cfg(not(target_os = "linux"))]
    let holes = decide(len, m.blocks(), Some(|| seek_hole(&probe)));
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
            eprintln!("ZFS: no holes filled in {}", dir.path().display());
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
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd",
            target_os = "illumos",
            target_vendor = "apple"
        ))]
        let made_holes = maybe_sparse(m.len(), m.blocks())
            && seek_hole(&File::open(&full).unwrap()).is_ok_and(|hole| hole < m.len());
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd",
            target_os = "illumos",
            target_vendor = "apple"
        )))]
        let made_holes = false;
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
        assert_eq!(seek_hole(&f).unwrap(), m.len(), "not a generic SEEK_HOLE");
        assert!(maybe_sparse(m.len(), m.blocks()), "no holes: {} blocks", m.blocks());
        assert!(has_holes(&path, &m, Some(&File::open(&path).unwrap())));
        assert!(!holes_now(&f));

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

    /// A file for [`HoleReader`]: its bytes, the holes its file system
    /// reports (zeros in `data`), and a change made to it at its `at`th
    /// call, as if by another process while it is read.
    #[derive(Debug, Clone)]
    struct SimFile {
        data: Vec<u8>,
        holes: Vec<std::ops::Range<u64>>,
        calls: usize,
        change: Option<(usize, Change)>,
        /// From the `.0`th call on, `SEEK_DATA` and `SEEK_HOLE` fail with
        /// the error `.1`.
        fail: Option<(usize, i32)>,
        /// The most bytes a read gives (short reads).
        short: usize,
        /// Every other read fails with `EINTR`.
        interrupt: bool,
        /// `SEEK_DATA` puts data past the end of file (a file system bug).
        data_past_eof: bool,
    }

    #[derive(Debug, Clone)]
    enum Change {
        /// Data written at the end.
        Append(Vec<u8>),
        /// The size grown by a hole.
        AppendHole(u64),
        /// Cut to this size.
        Truncate(u64),
    }

    impl SimFile {
        fn len(&self) -> u64 {
            self.data.len() as u64
        }

        /// Changes the file, as another program could at any time.
        fn apply(&mut self, change: Change) {
            match change {
                Change::Append(data) => self.data.extend(data),
                Change::AppendHole(n) => {
                    let len = self.len();
                    self.data.resize(self.data.len() + usize::try_from(n).unwrap(), 0);
                    self.holes.push(len..len + n);
                }
                Change::Truncate(len) => {
                    self.data.truncate(usize::try_from(len).unwrap());
                    self.holes.retain(|h| h.start < len);
                    if let Some(h) = self.holes.last_mut() {
                        h.end = h.end.min(len);
                    }
                }
            }
        }

        /// Counts a call, makes the change due, and says whether seeks
        /// fail now.
        fn call(&mut self) -> Option<io::Error> {
            let due = match &self.change {
                Some((at, change)) if *at == self.calls => Some(change.clone()),
                _ => None,
            };
            if let Some(change) = due {
                self.apply(change);
            }
            self.calls += 1;
            self.fail
                .filter(|(from, _)| self.calls > *from)
                .map(|(_, errno)| io::Error::from_raw_os_error(errno))
        }
    }

    impl Extents for SimFile {
        fn seek_data(&mut self, off: u64) -> io::Result<u64> {
            if let Some(err) = self.call() {
                return Err(err);
            }
            let mut pos = off;
            for h in &self.holes {
                if h.start <= pos && pos < h.end {
                    pos = h.end;
                }
            }
            if pos >= self.len() {
                if self.data_past_eof && off < self.len() {
                    return Ok(self.len() + 4096);
                }
                return Err(io::Error::from_raw_os_error(libc::ENXIO));
            }
            Ok(pos)
        }

        fn seek_hole(&mut self, off: u64) -> io::Result<u64> {
            if let Some(err) = self.call() {
                return Err(err);
            }
            if off >= self.len() {
                return Err(io::Error::from_raw_os_error(libc::ENXIO));
            }
            Ok(self
                .holes
                .iter()
                .find(|h| h.end > off)
                .map_or(self.len(), |h| h.start.max(off)))
        }

        fn size(&mut self) -> io::Result<u64> {
            _ = self.call();
            Ok(self.len())
        }

        fn read_at(&mut self, buf: &mut [u8], off: u64) -> io::Result<usize> {
            _ = self.call();
            if self.interrupt && self.calls.is_multiple_of(2) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let Some(rest) = usize::try_from(off).ok().and_then(|off| self.data.get(off..)) else {
                return Ok(0);
            };
            let n = rest.len().min(buf.len()).min(self.short);
            buf[..n].copy_from_slice(&rest[..n]);
            Ok(n)
        }
    }

    /// A file of `runs`: data (0), a hole (1), or zeros written out (2), of
    /// a length each; holes as a file system with blocks of `block` bytes
    /// reports them, in whole blocks, the rest of their zeros data.
    fn sim_file(runs: &[(u8, usize)], block: u64, seed: u64) -> SimFile {
        let mut data = Vec::new();
        let mut holes: Vec<std::ops::Range<u64>> = Vec::new();
        let mut x = seed | 1;
        for &(kind, len) in runs {
            let start = data.len() as u64;
            if kind == 0 {
                data.extend((0..len).map(|_| {
                    // xorshift; zeros among the data too.
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x.to_le_bytes()[0] & 0x3f
                }));
            } else {
                data.resize(data.len() + len, 0);
            }
            let end = data.len() as u64;
            if kind == 1 {
                let (start, end) = (start.next_multiple_of(block), end / block * block);
                if start < end {
                    match holes.last_mut() {
                        Some(h) if h.end == start => h.end = end,
                        _ => holes.push(start..end),
                    }
                }
            }
        }
        SimFile {
            data,
            holes,
            calls: 0,
            change: None,
            fail: None,
            short: usize::MAX,
            interrupt: false,
            data_past_eof: false,
        }
    }

    /// Reads all of `r`, `sizes` bytes at a time in turn, as the chunker
    /// asks for various amounts.
    fn read_all(mut r: impl io::Read, sizes: &[usize]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = vec![0xaa; sizes.iter().copied().max().unwrap_or(1).max(1)];
        for i in 0.. {
            let size = sizes.get(i % sizes.len().max(1)).copied().unwrap_or(4096).max(1);
            match r.read(&mut buf[..size]) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => panic!("{err}"),
            }
        }
        out
    }

    /// The chunks (length, ID) the chunker makes of `r`, with small chunks
    /// (the minimum no smaller than the chunker's buffer).
    fn chunks(r: impl io::Read + Send) -> Vec<(usize, crate::id::Id)> {
        use rustic_cdc::Rabin64;

        let rabin = Rabin64::new_with_polynom(6, &0x003D_A335_8B4D_C173);
        crate::chunker::rabin::ChunkIter::new(rabin, 1 << 14, 1 << 13, 1 << 16, r, 0)
            .unwrap()
            .map(|chunk| {
                let chunk = chunk.unwrap();
                (chunk.len(), crate::crypto::hasher::hash(&chunk))
            })
            .collect()
    }

    fn hole_bytes(f: &SimFile) -> u64 {
        f.holes.iter().map(|h| h.end - h.start).sum()
    }

    #[test]
    fn hole_reader_layouts() {
        const K: usize = 4096;
        for (name, runs) in [
            ("empty", vec![]),
            ("data only", vec![(0, 3 * K + 5)]),
            ("hole at start", vec![(1, 4 * K), (0, 100)]),
            ("hole in the middle", vec![(0, K + 1), (1, 5 * K), (0, 7)]),
            ("hole at end", vec![(0, 10), (1, 9 * K)]),
            ("whole-file hole", vec![(1, 8 * K)]),
            ("hole shorter than a block", vec![(0, 100), (1, 100), (0, 100)]),
            ("zeros written", vec![(0, 10), (2, 8 * K), (0, 10)]),
            ("data at EOF", vec![(1, 3 * K), (0, 1)]),
            ("holes back to back", vec![(1, 2 * K), (1, 2 * K), (2, K), (1, K)]),
        ] {
            let f = sim_file(&runs, K as u64, 7);
            let want = f.data.clone();
            let holes = hole_bytes(&f);
            for sizes in [&[4096][..], &[1], &[100, 7000, 3], &[1 << 20]] {
                let mut r = HoleReader::new(f.clone());
                assert_eq!(read_all(&mut r, sizes), want, "{name}");
                assert_eq!(r.zeros, holes, "{name}");
            }
            assert_eq!(chunks(HoleReader::new(f.clone())), chunks(&want[..]), "{name}");
        }
    }

    /// Reads fill the buffer, across extents and `EINTR`, until the end of
    /// file.
    #[test]
    fn hole_reader_fills_the_buffer() {
        use std::io::Read;

        const K: usize = 4096;
        for interrupt in [false, true] {
            let mut f = sim_file(&[(0, 100), (1, 3 * K), (0, 5), (1, 2 * K), (0, 7)], 512, 9);
            f.short = 1000;
            f.interrupt = interrupt;
            let want = f.data.clone();
            let mut r = HoleReader::new(f);
            let mut buf = vec![0; K];
            let mut got = Vec::new();
            loop {
                let n = r.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
                assert!(n == K || got.len() == want.len(), "{n} at {}", got.len());
            }
            assert_eq!(got, want, "interrupt {interrupt}");
        }
    }

    /// Where `SEEK_DATA` or `SEEK_HOLE` fails, before or along the way, the rest
    /// is read plainly. `ENXIO` at every offset is what macOS answers for a
    /// file its file system compresses: not a hole up to the end.
    #[test]
    fn hole_reader_seek_fails() {
        const K: usize = 4096;
        let f = sim_file(&[(0, K), (1, 4 * K), (0, K), (1, 4 * K), (0, 3)], K as u64, 3);
        for errno in [libc::EINVAL, libc::EOPNOTSUPP, libc::EIO, libc::ENXIO] {
            for at in 0..12 {
                let mut f = f.clone();
                f.fail = Some((at, errno));
                let r = HoleReader::new(f.clone());
                assert_eq!(read_all(r, &[K]), f.data, "{errno} at {at}");
            }
        }
    }

    /// Data that `SEEK_DATA` puts past the end of file gives no zeros past it.
    #[test]
    fn hole_reader_data_past_eof() {
        const K: usize = 4096;
        for runs in [vec![(0, K), (1, 4 * K)], vec![(1, 4 * K)], vec![(0, 3)]] {
            let mut f = sim_file(&runs, K as u64, 4);
            f.data_past_eof = true;
            assert_eq!(read_all(HoleReader::new(f.clone()), &[K]), f.data, "{runs:?}");
        }
    }

    /// A file that grows or shrinks while it is read, between two system
    /// calls or between two reads: no error, no bytes the file hadn't, and
    /// all of it that is there when the end is read. Cut short, it gives
    /// what plain reading gives: up to the new end, or to where the reader
    /// was if that is further (somewhere in the read that saw the cut, if
    /// it came within one).
    #[test]
    fn hole_reader_changing_file() {
        use std::io::Read;

        const K: usize = 4096;
        let f = sim_file(&[(0, K), (1, 4 * K), (0, K), (1, 4 * K)], K as u64, 5);
        let len = f.len();
        for (by_reads, at) in (0..24).map(|at| (false, at)).chain((0..12).map(|at| (true, at))) {
            for change in [
                Change::Append(vec![9; 3 * K]),
                Change::AppendHole(3 * K as u64),
                Change::Truncate(len / 2),
                Change::Truncate(K as u64 + 1),
                Change::Truncate(3 * K as u64),
                Change::Truncate(0),
            ] {
                for short in [usize::MAX, 1000] {
                    let mut f = f.clone();
                    if !by_reads {
                        f.change = Some((at, change.clone()));
                    }
                    f.short = short;
                    let mut r = HoleReader::new(f.clone());
                    let mut out = Vec::new();
                    let mut buf = vec![0; K];
                    // The output's length before and after the read in
                    // which the change was made (or before which).
                    let mut seen = None;
                    for i in 0.. {
                        let before = out.len() as u64;
                        if by_reads && i == at {
                            r.f.apply(change.clone());
                            seen = Some((before, before));
                        }
                        let n = r.read(&mut buf[..[K, 100][i % 2]]).unwrap();
                        out.extend_from_slice(&buf[..n]);
                        if !by_reads && seen.is_none() && r.f.calls > at {
                            seen = Some((before, out.len() as u64));
                        }
                        if n == 0 {
                            break;
                        }
                    }
                    let now = &r.f.data;
                    let what = format!("{change:?} at {at} (by reads: {by_reads}), short {short}");
                    match change {
                        Change::Append(_) | Change::AppendHole(_) if seen.is_some() => {
                            assert_eq!(&out, now, "{what}");
                        }
                        Change::Truncate(cut) if seen.is_some() => {
                            assert_eq!(out, f.data[..out.len()], "{what}");
                            let total = out.len() as u64;
                            let (before, after) = seen.unwrap();
                            assert!(
                                cut.max(before) <= total && total <= cut.max(after),
                                "{what}: {total} bytes, cut at {cut} in {before}..{after}"
                            );
                        }
                        // The end of file came first.
                        _ => assert_eq!(out, f.data, "{what}"),
                    }
                }
            }
        }
    }

    /// A file cut short while the reader is inside a hole gives what plain
    /// reading gives from there: the bytes up to the new end, and no more
    /// zeros past it.
    #[test]
    fn hole_reader_cut_in_a_hole() {
        use std::io::Read;

        const K: usize = 4096;
        let f = sim_file(&[(0, K), (1, 16 * K), (0, K)], K as u64, 6);
        let at = 2 * K as u64;
        for cut in [at + 1, 5 * K as u64, 10 * K as u64 + 7, 17 * K as u64, at, K as u64, 0] {
            for sizes in [&[K][..], &[100], &[1 << 20]] {
                let mut r = HoleReader::new(f.clone());
                let mut out = vec![0; 2 * K];
                r.read_exact(&mut out).unwrap();
                r.f.apply(Change::Truncate(cut));
                out.extend(read_all(&mut r, sizes));
                let what = format!("cut at {cut}, reads of {sizes:?}");
                assert_eq!(out.len() as u64, cut.max(at), "{what}");
                assert_eq!(out, f.data[..out.len()], "{what}");
            }
        }
    }

    proptest::proptest! {
        /// The bytes, and so the chunks, of any layout are the file's.
        #[test]
        fn hole_reader_gives_the_bytes(
            runs in proptest::collection::vec((0_u8..3, 1_usize..20_000), 0..12),
            block in proptest::sample::select(vec![1_u64, 512, 4096]),
            seed in proptest::num::u64::ANY,
            sizes in proptest::collection::vec(1_usize..70_000, 1..4),
            short in proptest::sample::select(vec![usize::MAX, 777]),
            interrupt in proptest::bool::ANY,
            data_past_eof in proptest::bool::ANY,
        ) {
            let mut f = sim_file(&runs, block, seed);
            f.short = short;
            f.interrupt = interrupt;
            f.data_past_eof = data_past_eof;
            let mut r = HoleReader::new(f.clone());
            proptest::prop_assert_eq!(&read_all(&mut r, &sizes), &f.data);
            proptest::prop_assert_eq!(r.zeros, hole_bytes(&f));
            proptest::prop_assert_eq!(chunks(HoleReader::new(f.clone())), chunks(&f.data[..]));
        }
    }

    /// Real files on this system's temporary directory, read by
    /// [`backup_reader`] as the backup reads them.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "illumos",
        target_vendor = "apple"
    ))]
    #[test]
    fn hole_reader_real_files() {
        use std::io::Read;

        const K: u64 = 4096;
        const M: u64 = 1 << 20;
        let dir = tempfile::tempdir().unwrap();
        // (offset, length) of the data written, and the size.
        for (name, writes, size) in [
            ("hole at start", vec![(4 * M, 3 * K)], 4 * M + 3 * K),
            ("hole in the middle", vec![(0, M + 1), (5 * M, 7)], 5 * M + 7),
            ("hole at end", vec![(0, 10)], 9 * M),
            ("whole-file hole", vec![], 8 * M),
            ("hole shorter than a page", vec![(0, 100), (200, 100)], 300),
            ("data at EOF", vec![(3 * M, 1)], 3 * M + 1),
            (
                "many extents",
                (0..64).map(|i| (i * 300 * K + i, K + i)).collect(),
                64 * 300 * K,
            ),
        ] {
            let path = dir.path().join(name);
            let mut f = File::create(&path).unwrap();
            for (i, &(off, len)) in writes.iter().enumerate() {
                _ = f.seek(SeekFrom::Start(off)).unwrap();
                f.write_all(&vec![u8::try_from(i % 250).unwrap() + 1; usize::try_from(len).unwrap()])
                    .unwrap();
            }
            f.set_len(size).unwrap();
            drop(f);
            let want = std::fs::read(&path).unwrap();
            let mut r = HoleReader::new(File::open(&path).unwrap());
            let mut got = Vec::new();
            _ = r.read_to_end(&mut got).unwrap();
            assert_eq!(got, want, "{name}");
            if name == "whole-file hole" && seek_hole(&File::open(&path).unwrap()).ok() == Some(0) {
                // Where the file system has holes, they aren't read.
                assert_eq!(r.zeros, size, "{name}");
            }
            assert_eq!(
                read_all(backup_reader(File::open(&path).unwrap(), true), &[4096, 1 << 19]),
                want,
                "{name}"
            );
            assert_eq!(
                chunks(backup_reader(File::open(&path).unwrap(), true)),
                chunks(&want[..]),
                "{name}"
            );
        }
    }

    /// A real file that grows while it is read is read to its new end.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "illumos",
        target_vendor = "apple"
    ))]
    #[test]
    fn hole_reader_real_file_grows() {
        use std::io::Read;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grows");
        let mut f = File::create(&path).unwrap();
        f.write_all(&[1; 4096]).unwrap();
        f.set_len(4 << 20).unwrap();
        let mut r = HoleReader::new(File::open(&path).unwrap());
        let mut got = vec![0; 8192];
        r.read_exact(&mut got).unwrap();
        // A hole and data after the end, and data in the hole.
        _ = f.seek(SeekFrom::Start(6 << 20)).unwrap();
        f.write_all(&[2; 100]).unwrap();
        _ = f.seek(SeekFrom::Start(2 << 20)).unwrap();
        f.write_all(&[3; 100]).unwrap();
        drop(f);
        _ = r.read_to_end(&mut got).unwrap();
        let want = std::fs::read(&path).unwrap();
        assert_eq!(got.len(), want.len());
        // The data written into the hole may have come too late.
        assert_eq!(got[..2 << 20], want[..2 << 20]);
        assert_eq!(got[(2 << 20) + 100..], want[(2 << 20) + 100..]);
    }

    /// Reads all of `a` in various amounts and compares it with plain
    /// reading of `b`; gives the length.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "illumos",
        target_vendor = "apple"
    ))]
    fn same_as_plain(mut a: impl io::Read, mut b: impl io::Read, what: &str) -> u64 {
        let (mut ba, mut bb) = (vec![0_u8; 1 << 20], vec![0_u8; 1 << 20]);
        let sizes = [1 << 20, 4096, 777, 1 << 16, 1];
        let mut total = 0;
        for i in 0.. {
            let n = a.read(&mut ba[..sizes[i % sizes.len()]]).unwrap();
            if n == 0 {
                let mut rest = Vec::new();
                _ = b.read_to_end(&mut rest).unwrap();
                assert!(rest.is_empty(), "{what}: {} bytes more read plainly", rest.len());
                break;
            }
            b.read_exact(&mut bb[..n]).unwrap_or_else(|err| panic!("{what}: at {total}: {err}"));
            assert!(ba[..n] == bb[..n], "{what}: differ in {total}..+{n}");
            total += n as u64;
        }
        total
    }

    /// Random layouts of real files, read before their data reaches the disk,
    /// and a file over 4 GiB with data across the 4 GiB line and at its end:
    /// the bytes plain reading gives.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "illumos",
        target_vendor = "apple"
    ))]
    #[test]
    fn hole_reader_real_random_layouts() {
        let dir = tempfile::tempdir().unwrap();
        let mut x = 0x9e37_79b9_7f4a_7c15_u64;
        let mut rand = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for round in 0..16 {
            let path = dir.path().join(format!("f{round}"));
            let mut f = File::create(&path).unwrap();
            let size = match round {
                0 => (5 << 30) + 12345,
                1 => 1,
                2 => 4095,
                _ => rand() % (48 << 20) + 1,
            };
            let mut writes = Vec::new();
            if round == 0 {
                writes.extend([((4 << 30) - 3000, 9000), (1 << 32, 1), (size - 1, 1)]);
            }
            for _ in 0..rand() % 25 {
                let off = rand() % size;
                writes.push((off, (rand() % 400_000).min(size - off)));
            }
            for (off, len) in writes {
                _ = f.seek(SeekFrom::Start(off)).unwrap();
                // Zeros among the data too.
                let buf: Vec<u8> = (0..len).map(|_| (rand() % 3) as u8 * 85).collect();
                f.write_all(&buf).unwrap();
            }
            f.set_len(size).unwrap();
            let m = f.metadata().unwrap();
            if round == 0 && !maybe_sparse(m.len(), m.blocks()) {
                // A file system without holes: not 5 GiB of zeros.
                continue;
            }
            let what = format!("round {round}, size {size}");
            let n = same_as_plain(
                backup_reader(File::open(&path).unwrap(), true),
                File::open(&path).unwrap(),
                &what,
            );
            assert_eq!(n, size, "{what}");
            drop(f);
            std::fs::remove_file(&path).unwrap();
        }
    }

    /// A real file of 6 GiB and 7 bytes with data just below 4 GiB and past
    /// 5 GiB: the same length and SHA-256 by its extents as read plainly.
    /// Its holes take no disk.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "illumos",
        target_vendor = "apple"
    ))]
    #[test]
    fn hole_reader_past_4_gib() {
        use sha2::{Digest, Sha256};

        const G: u64 = 1 << 30;
        fn digest(mut r: impl io::Read) -> (u64, Vec<u8>) {
            let mut hasher = Sha256::new();
            let mut buf = vec![0; 1 << 20];
            let mut len = 0;
            loop {
                let n = r.read(&mut buf).unwrap();
                if n == 0 {
                    return (len, hasher.finalize().to_vec());
                }
                hasher.update(&buf[..n]);
                len += n as u64;
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big");
        let mut f = File::create(&path).unwrap();
        let size = 6 * G + 7;
        f.set_len(size).unwrap();
        for (off, byte) in [(4 * G - 2, 1), (5 * G + 12345, 2)] {
            _ = f.seek(SeekFrom::Start(off)).unwrap();
            f.write_all(&vec![byte; 70_000]).unwrap();
        }
        drop(f);
        let f = File::open(&path).unwrap();
        let m = f.metadata().unwrap();
        if !maybe_sparse(m.len(), m.blocks()) || !seek_hole(&f).is_ok_and(|hole| hole < size) {
            // A file system without holes: not 6 GiB of zeros.
            return;
        }
        let plain = digest(File::open(&path).unwrap());
        assert_eq!(plain.0, size);
        let mut r = HoleReader::new(f);
        assert_eq!(digest(&mut r), plain);
        assert!(r.zeros > 5 * G, "{} bytes of holes", r.zeros);
        assert_eq!(digest(backup_reader(File::open(&path).unwrap(), true)), plain);
    }

    /// Another thread writes into the holes, appends and truncates while a
    /// real file is read: no error, every byte one the file had, no more
    /// bytes than it ever had.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "illumos",
        target_vendor = "apple"
    ))]
    #[test]
    fn hole_reader_concurrent_writer() {
        use std::{
            io::Read,
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
            },
        };

        const M: u64 = 1 << 20;
        let dir = tempfile::tempdir().unwrap();
        for round in 0..8 {
            let path = dir.path().join(format!("c{round}"));
            let mut f = File::create(&path).unwrap();
            f.write_all(&[7; 5000]).unwrap();
            f.set_len(64 * M).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let writer = {
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let mut x = round + 11;
                    let mut rand = move || {
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        x
                    };
                    let mut max = 64 * M;
                    while !stop.load(Ordering::Relaxed) {
                        match rand() % 10 {
                            0 => f.set_len(rand() % (96 * M)).unwrap(),
                            1 => {
                                let len = rand() % (32 * M) + 64 * M;
                                max = max.max(len);
                                f.set_len(len).unwrap();
                            }
                            _ => {
                                let off = rand() % (96 * M);
                                _ = f.seek(SeekFrom::Start(off)).unwrap();
                                f.write_all(&[9; 8192]).unwrap();
                                max = max.max(off + 8192);
                            }
                        }
                    }
                    max
                })
            };
            let mut out = Vec::new();
            _ = backup_reader(File::open(&path).unwrap(), true)
                .read_to_end(&mut out)
                .unwrap();
            stop.store(true, Ordering::Relaxed);
            let max = writer.join().unwrap();
            assert!(out.len() as u64 <= max, "round {round}");
            assert!(out.iter().all(|&b| [0, 7, 9].contains(&b)), "round {round}");
        }
    }
}
