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

/// The smallest block a file restored sparse has its holes in, and the
/// one used where the file system's block size isn't known.
const MIN_HOLE_BLOCK: u64 = 4096;

/// The size of the blocks a file restored sparse has its holes in, `f`
/// being that file: the block size of its file system (`f_bsize` of
/// `fstatfs(2)`, of `fstatvfs(2)` on NetBSD and illumos), else its
/// `st_blksize`, at least 4096 bytes; 4096 if neither is known. As
/// BackOtter's restic (`fs.HoleBlockSize`).
pub(super) fn hole_block_size(f: &File) -> u64 {
    fs_block_size(f)
        .filter(|&size| size > 0)
        .or_else(|| f.metadata().ok().map(|m| m.blksize()))
        .unwrap_or(0)
        .max(MIN_HOLE_BLOCK)
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
/// by its data extents ([`HoleReader`]); any other is `f` itself. Either way
/// the bytes are those plain reading gives, so are the chunks.
pub(super) fn backup_reader(f: File, sparse: bool) -> Box<dyn io::Read + Send> {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "illumos",
        target_vendor = "apple"
    ))]
    if sparse {
        return Box::new(HoleReader::new(f));
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

    let off = libc::off_t::try_from(off).map_err(io::Error::other)?;
    // SAFETY: f is an open file.
    let pos = unsafe { libc::lseek(f.as_raw_fd(), off, whence) };
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
            Err(err) if err.raw_os_error() == Some(libc::ENXIO) => {
                match size.and_then(|size| Ok(size.min(self.f.size()?))) {
                    Ok(size) if size > off => (true, size),
                    _ => (false, PLAIN),
                }
            }
            Err(err) => {
                debug!("no SEEK_DATA at {off}: {err}; reading the rest");
                (false, PLAIN)
            }
            Ok(data) if data > off => (true, data),
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
    /// only at the end of file (or on an error after some bytes): the
    /// chunker reads on with a buffer no longer than the last read gave.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut done = 0;
        while done < buf.len() {
            match self.read_extent(&mut buf[done..]) {
                Ok(0) => break,
                Ok(n) => done += n,
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

    /// Holes are made in blocks of at least 4096 bytes, a power of two.
    #[test]
    fn hole_block_size_at_least_4096() {
        let dir = tempfile::tempdir().unwrap();
        let f = File::create(dir.path().join("f")).unwrap();
        let size = hole_block_size(&f);
        eprintln!("block size {size}");
        assert!(size >= MIN_HOLE_BLOCK && size.is_power_of_two(), "{size}");
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

        /// Counts a call, makes the change due, and says whether seeks
        /// fail now.
        fn call(&mut self) -> Option<io::Error> {
            let due = match &self.change {
                Some((at, change)) if *at == self.calls => Some(change.clone()),
                _ => None,
            };
            if let Some(change) = due {
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

    /// Reads fill the buffer, across extents, until the end of file.
    #[test]
    fn hole_reader_fills_the_buffer() {
        use std::io::Read;

        const K: usize = 4096;
        let mut f = sim_file(&[(0, 100), (1, 3 * K), (0, 5), (1, 2 * K), (0, 7)], 512, 9);
        f.short = 1000;
        let len = f.data.len();
        let mut r = HoleReader::new(f);
        let mut buf = vec![0; K];
        let mut got = 0;
        loop {
            let n = r.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            got += n;
            assert!(n == K || got == len, "{n} at {got}");
        }
        assert_eq!(got, len);
    }

    /// Where `SEEK_DATA` or `SEEK_HOLE` fails, before or along the way, the rest
    /// is read plainly.
    #[test]
    fn hole_reader_seek_fails() {
        const K: usize = 4096;
        let f = sim_file(&[(0, K), (1, 4 * K), (0, K), (1, 4 * K), (0, 3)], K as u64, 3);
        for errno in [libc::EINVAL, libc::EOPNOTSUPP, libc::EIO] {
            for at in 0..12 {
                let mut f = f.clone();
                f.fail = Some((at, errno));
                let r = HoleReader::new(f.clone());
                assert_eq!(read_all(r, &[K]), f.data, "{errno} at {at}");
            }
        }
    }

    /// A file that grows or shrinks while it is read: no error, no bytes
    /// the file hadn't, and all of it that is there when the end is read.
    #[test]
    fn hole_reader_changing_file() {
        const K: usize = 4096;
        let f = sim_file(&[(0, K), (1, 4 * K), (0, K), (1, 4 * K)], K as u64, 5);
        let len = f.len();
        for at in 0..16 {
            for change in [
                Change::Append(vec![9; 3 * K]),
                Change::AppendHole(3 * K as u64),
                Change::Truncate(len / 2),
                Change::Truncate(K as u64 + 1),
                Change::Truncate(0),
            ] {
                for short in [usize::MAX, 1000] {
                    let mut f = f.clone();
                    f.change = Some((at, change.clone()));
                    f.short = short;
                    let mut r = HoleReader::new(f.clone());
                    let out = read_all(&mut r, &[K, 100]);
                    let now = &r.f.data;
                    let what = format!("{change:?} at {at}, short {short}");
                    match change {
                        Change::Append(_) | Change::AppendHole(_) => assert_eq!(&out, now, "{what}"),
                        Change::Truncate(cut) => {
                            assert_eq!(out, f.data[..out.len()], "{what}");
                            assert!(out.len() as u64 >= cut, "{what}");
                        }
                    }
                }
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
        ) {
            let mut f = sim_file(&runs, block, seed);
            f.short = short;
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
}
