//! BackOtter: `SEEK_HOLE` and `SEEK_DATA`, on the systems where the backup
//! probes for holes with them and reads a file with holes by its data
//! extents: Linux and Android, FreeBSD, illumos and macOS (`sparse.rs` lists
//! them, once). Not NetBSD, OpenBSD or DragonFly, nor Solaris, which get
//! `no_seek.rs`: there the blocks decide. DragonFly has `SEEK_HOLE`, but
//! HAMMER2 answers `EOPNOTSUPP`, and tmpfs always the file's size, which
//! would hide real holes; Solaris is left out as BackOtter's restic leaves
//! it out.

use std::{
    fs::{File, Metadata},
    io,
    os::unix::fs::MetadataExt,
    path::Path,
};

use log::debug;

use super::hole_reader::{Extents, HoleReader};

/// What [`has_holes`](super::has_holes) finds the first hole of the regular
/// file at `path`, with metadata `m` (its lstat), with: on Linux `SEEK_HOLE`
/// on `f`, the file as opened for its flags (`open_for_attrs`): without it
/// the file couldn't be opened, and the probe fails; on JFS and nilfs2,
/// whose `SEEK_HOLE` always answers the size, it isn't asked, and fails as
/// a file system that can't answer (`generic_seek_hole`). Elsewhere the
/// file is opened here ([`open`]). Always a probe: `no_seek.rs`'s has none.
#[allow(clippy::unnecessary_wraps)]
pub(super) fn first_hole<'a>(
    path: &'a Path,
    m: &'a Metadata,
    f: Option<&'a File>,
) -> Option<impl FnOnce() -> io::Result<u64> + 'a> {
    #[cfg(target_os = "linux")]
    {
        _ = m;
        Some(move || match f {
            None => Err(io::Error::other(format!("{} not opened", path.display()))),
            // SEEK_HOLE would answer the size: the file system can't answer,
            // and the blocks decide.
            Some(f) if super::generic_seek_hole(f) => {
                Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
            }
            Some(f) => seek_hole(f),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        _ = f;
        Some(move || {
            seek_hole(&open(path, m).inspect_err(|err| debug!("open {}: {err}", path.display()))?)
        })
    }
}

/// The offset of the first hole in the regular file `f`, which is its size
/// where it has none.
pub(super) fn seek_hole(f: &File) -> io::Result<u64> {
    lseek(f, 0, libc::SEEK_HOLE)
}

/// Opens the regular file at `path` for [`seek_hole`] as `lsattr(1)` opens
/// files, so as not to follow a symlink, wait on a lock or take a terminal.
/// An error unless it is still the file `m` (its lstat) describes.
pub(super) fn open(path: &Path, m: &Metadata) -> io::Result<File> {
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

/// [`backup_reader`](super::backup_reader): a file with holes (`sparse`)
/// is read by its data extents ([`HoleReader`]), if it still has a hole as
/// opened ([`holes_now`]); any other is `f` itself.
pub(super) fn backup_reader(f: File, sparse: bool) -> Box<dyn io::Read + Send> {
    if sparse {
        let holes = holes_now(&f);
        // SEEK_HOLE moved the offset plain reading starts at (HoleReader
        // reads with pread).
        if holes || lseek(&f, 0, libc::SEEK_SET).is_err() {
            return Box::new(HoleReader::new(f));
        }
    }
    Box::new(f)
}

/// Whether the regular file `f`, opened to be read, has a hole before its end
/// by `SEEK_HOLE`. The file marked when it was listed may have been replaced
/// since, or compressed by its file system: macOS answers `ENXIO` to
/// `SEEK_HOLE` and `SEEK_DATA` at every offset of a file compressed by the
/// file system (`UF_COMPRESSED`), whose data plain reading gives. On JFS and
/// nilfs2 `SEEK_HOLE` gives the size, so a file there is read whole, holes
/// and all. Moves the offset of `f`.
pub(super) fn holes_now(f: &File) -> bool {
    match (f.metadata(), seek_hole(f)) {
        (Ok(m), Ok(hole)) => hole < m.len(),
        (m, hole) => {
            debug!(
                "no hole found as opened ({:?}, {hole:?}); reading plainly",
                m.err()
            );
            false
        }
    }
}

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

/// `off_t` and the calls that take one, with 64-bit offsets where `off_t`
/// may have 32 bits (32-bit glibc and Android), which would leave a file
/// over 2 GiB unread by its extents ([`lseek`]) or unallocated
/// (`os_preallocate`); and on Linux and Android `statfs(2)` and
/// `fstatfs(2)` with their struct, the 64-bit ones there too: the plain
/// ones can fail with `EOVERFLOW` on a large file system.
pub(in crate::backend::osattrs) mod lfs {
    #[cfg(all(target_os = "linux", not(any(target_env = "gnu", target_env = "musl"))))]
    pub(in crate::backend::osattrs) use libc::{fallocate, fstatfs, statfs};
    #[cfg(any(
        target_os = "android",
        all(target_os = "linux", any(target_env = "gnu", target_env = "musl"))
    ))]
    pub(in crate::backend::osattrs) use libc::{
        fallocate64 as fallocate, fstatfs64 as fstatfs, lseek64 as lseek, off64_t as off_t,
        statfs64 as statfs,
    };
    #[cfg(not(any(
        target_os = "android",
        all(target_os = "linux", any(target_env = "gnu", target_env = "musl"))
    )))]
    pub(in crate::backend::osattrs) use libc::{lseek, off_t};

    // Every system but 32-bit uClibc Linux has 64-bit offsets here.
    #[cfg(not(all(target_os = "linux", not(any(target_env = "gnu", target_env = "musl")))))]
    const _: () = assert!(size_of::<off_t>() == 8);
}

/// `lseek(2)` of `f` to `off` from `whence`.
#[allow(unsafe_code)]
fn lseek(f: &File, off: u64, whence: libc::c_int) -> io::Result<u64> {
    use lfs::{lseek, off_t};
    use std::os::fd::AsRawFd;

    let off = off_t::try_from(off).map_err(io::Error::other)?;
    // SAFETY: f is an open file.
    let pos = unsafe { lseek(f.as_raw_fd(), off, whence) };
    u64::try_from(pos).map_err(|_| io::Error::last_os_error())
}

#[cfg(test)]
pub(super) mod tests {
    use std::io::{Seek, SeekFrom, Write};

    use super::{
        super::{
            hole_reader::tests::{chunks, read_all},
            maybe_sparse,
        },
        *,
    };

    /// Whether `SEEK_HOLE` finds a hole in the file at `path`, of `len`
    /// bytes, for the tests of `sparse.rs`.
    pub(in crate::backend::osattrs::sparse) fn finds_hole(path: &Path, len: u64) -> bool {
        seek_hole(&File::open(path).unwrap()).is_ok_and(|hole| hole < len)
    }

    /// Real files on this system's temporary directory, read by
    /// [`backup_reader`] as the backup reads them.
    #[test]
    fn hole_reader_real_files() {
        use std::io::Read;

        const K: u64 = 4096;
        const M: u64 = 1 << 20;
        let dir = tempfile::tempdir().unwrap();
        // (offset, length) of the data written, and the size.
        for (name, writes, size) in [
            ("hole at start", vec![(4 * M, 3 * K)], 4 * M + 3 * K),
            (
                "hole in the middle",
                vec![(0, M + 1), (5 * M, 7)],
                5 * M + 7,
            ),
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
                f.write_all(&vec![
                    u8::try_from(i % 250).unwrap() + 1;
                    usize::try_from(len).unwrap()
                ])
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
                read_all(
                    backup_reader(File::open(&path).unwrap(), true),
                    &[4096, 1 << 19]
                ),
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
    fn same_as_plain(mut a: impl io::Read, mut b: impl io::Read, what: &str) -> u64 {
        let (mut ba, mut bb) = (vec![0_u8; 1 << 20], vec![0_u8; 1 << 20]);
        let sizes = [1 << 20, 4096, 777, 1 << 16, 1];
        let mut total = 0;
        for i in 0.. {
            let n = a.read(&mut ba[..sizes[i % sizes.len()]]).unwrap();
            if n == 0 {
                let mut rest = Vec::new();
                _ = b.read_to_end(&mut rest).unwrap();
                assert!(
                    rest.is_empty(),
                    "{what}: {} bytes more read plainly",
                    rest.len()
                );
                break;
            }
            b.read_exact(&mut bb[..n])
                .unwrap_or_else(|err| panic!("{what}: at {total}: {err}"));
            assert!(ba[..n] == bb[..n], "{what}: differ in {total}..+{n}");
            total += n as u64;
        }
        total
    }

    /// Random layouts of real files, read before their data reaches the disk,
    /// and a file over 4 GiB with data across the 4 GiB line and at its end:
    /// the bytes plain reading gives.
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
        assert_eq!(
            digest(backup_reader(File::open(&path).unwrap(), true)),
            plain
        );
    }

    /// Another thread writes into the holes, appends and truncates while a
    /// real file is read: no error, every byte one the file had, no more
    /// bytes than it ever had.
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
                            0 => {
                                let len = rand() % (96 * M);
                                max = max.max(len);
                                f.set_len(len).unwrap();
                            }
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
