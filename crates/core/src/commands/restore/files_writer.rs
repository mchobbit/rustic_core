//! BackOtter: the restore's writes of file contents, through one handle per
//! file, kept open while the file has writes under way or to come.
//!
//! Stock rustic opened, wrote and closed a file for each blob, and once
//! more to size it. On ext4 an inode's block preallocation is dropped when
//! its last writer closes it, so while writeback ran during a big parallel
//! restore, the parts of a file written out of order were allocated in
//! scattered places: the Kali guest's 14.5 MB vmlinuz came back in 5 extents
//! or more instead of 1. Past 4 extents ext4 takes a block for the extent
//! tree, and a file with a 512-byte hole at its end then looked fully
//! allocated to BackOtter's checks. BackOtter's restic keeps one handle per
//! file while it has users, and the idle ones in a bounded cache
//! (`internal/restorer/fileswriter.go`); so does this, and it closes a
//! file's handle once its last write is done.

use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    fmt::Display,
    fs::File,
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
};

use log::{debug, error};

use crate::backend::local_destination::LocalDestination;

/// The buckets the files are spread over, by index: a file is sized
/// (created, allocated) or opened under its bucket's lock, which the writes
/// of other files rarely wait for, with a restore's 20 threads at most. As
/// in BackOtter's restic.
const BUCKETS: usize = 1024;

/// The idle handles a restore with `threads` threads keeps open: those of
/// files with writes still to come, typically in a pack of their own (a
/// file cut in two by a pack's end, a blob shared with other files). One
/// per thread, as up to as many packs are written at once, and 50 more, as
/// BackOtter's restic keeps (its writers plus 50). The handles in use, one
/// per thread at most, come on top: 2 × 20 + 50 = 90 descriptors at most,
/// well below the usual limit of 1024, which leaves the rest to the
/// backend. An idle handle evicted is closed; the file's next write opens
/// it again.
pub(super) const fn max_idle(threads: usize) -> usize {
    threads.saturating_add(50)
}

/// BackOtter: the files of a restore, written through a handle each while
/// they have writes under way, and kept open (up to [`max_idle`]) while
/// they have writes to come.
pub(super) struct FilesWriter<'a> {
    dest: &'a LocalDestination,
    filenames: &'a [PathBuf],
    sparse: &'a [bool],
    /// The files, `file_idx % BUCKETS` in each, at `file_idx / BUCKETS`.
    buckets: Vec<Mutex<Bucket>>,
    /// The handles of files with no write under way and writes to come,
    /// the least recently used first; a file's handle is either here or in
    /// its bucket's `busy`, never both.
    idle: Mutex<VecDeque<(usize, Arc<File>)>>,
    max_idle: usize,
    /// The files that couldn't be written, each reported once.
    failed: Mutex<BTreeSet<usize>>,
    /// The files sized, each at its first write.
    sized: AtomicUsize,
    /// The handles opened again after they were evicted.
    reopened: AtomicUsize,
}

/// Files of a [`FilesWriter`], by their place in the bucket.
#[derive(Default)]
struct Bucket {
    /// The size each file gets at its first write; 0 once it is sized (a
    /// file of 0 bytes has no writes).
    sizes: Vec<u64>,
    /// The writes each file has under way or to come.
    left: Vec<usize>,
    /// The files with writes under way, by index: the handle, and how many.
    busy: HashMap<usize, (Arc<File>, usize)>,
}

/// Locks `mutex`, poisoned or not: a panic in a write leaves the counts
/// as they are, and the restore's scope passes the panic on.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<'a> FilesWriter<'a> {
    /// The files `filenames` of `dest`, with their `sizes`, whether each is
    /// restored `sparse`, and the `writes` each gets: as many as the
    /// restore's blobs to write to it, each one call of [`Self::write`].
    pub(super) fn new(
        dest: &'a LocalDestination,
        filenames: &'a [PathBuf],
        sparse: &'a [bool],
        sizes: &[u64],
        writes: Vec<usize>,
        max_idle: usize,
    ) -> Self {
        let mut buckets: Vec<_> = std::iter::repeat_with(Bucket::default)
            .take(BUCKETS)
            .collect();
        for (file_idx, (size, left)) in sizes.iter().zip(writes).enumerate() {
            let bucket = &mut buckets[file_idx % BUCKETS];
            bucket.sizes.push(*size);
            bucket.left.push(left);
        }
        Self {
            dest,
            filenames,
            sparse,
            buckets: buckets.into_iter().map(Mutex::new).collect(),
            idle: Mutex::new(VecDeque::new()),
            max_idle,
            failed: Mutex::new(BTreeSet::new()),
            sized: AtomicUsize::new(0),
            reopened: AtomicUsize::new(0),
        }
    }

    /// Reports that the contents of the file `file_idx` couldn't be
    /// restored, with `err`, the first time; its writes are skipped after.
    pub(super) fn fail(&self, file_idx: usize, err: &dyn Display) {
        if lock(&self.failed).insert(file_idx) {
            error!(
                "restore {}: contents not restored: {err}",
                self.filenames[file_idx].display()
            );
        }
    }

    fn is_failed(&self, file_idx: usize) -> bool {
        lock(&self.failed).contains(&file_idx)
    }

    /// Writes `data`, a blob (all zeros if `zeros`), at `start` of the file
    /// `file_idx`, which is sized at its first write. In a file restored
    /// sparse the blob's all-zero parts of the file system's blocks stay
    /// holes, as BackOtter's restic leaves them, and an all-zero blob isn't
    /// written at all; any other file gets every byte, so that it is
    /// allocated. A file that fails is reported ([`Self::fail`]) and gets
    /// no write after. Each call is one of the file's writes done, written
    /// or not; its handle is closed after the last.
    pub(super) fn write(&self, file_idx: usize, start: u64, data: &[u8], zeros: bool) {
        let sparse = self.sparse[file_idx];
        let file = self.acquire(file_idx, !(sparse && zeros));
        if let Some(file) = &file {
            let written = if !sparse {
                LocalDestination::write_at(file, start, data)
            } else if zeros {
                Ok(())
            } else {
                LocalDestination::write_sparse_at(file, start, data)
            };
            if let Err(err) = written {
                self.fail(file_idx, &err);
            }
        }
        self.release(file_idx, file);
    }

    /// The handle for a write to the file `file_idx`: the one in use, the
    /// idle one, or one opened, which at the file's first write sizes it
    /// ([`LocalDestination::set_length`]). `None` for a file that failed,
    /// and for a write that needs no handle (`needed` is false) to a file
    /// sized already.
    // The bucket's lock is held throughout, so that the file's other
    // writes wait until it is sized or opened, and use that handle.
    #[allow(clippy::significant_drop_tightening)]
    fn acquire(&self, file_idx: usize, needed: bool) -> Option<Arc<File>> {
        let mut bucket = lock(&self.buckets[file_idx % BUCKETS]);
        if self.is_failed(file_idx) {
            return None;
        }
        if let Some((file, users)) = bucket.busy.get_mut(&file_idx) {
            if !needed {
                return None;
            }
            *users += 1;
            return Some(Arc::clone(file));
        }
        let path = &self.filenames[file_idx];
        let size = std::mem::take(&mut bucket.sizes[file_idx / BUCKETS]);
        let file = if size > 0 {
            match self.dest.set_length(path, size, self.sparse[file_idx]) {
                Ok(file) => {
                    _ = self.sized.fetch_add(1, Ordering::Relaxed);
                    Arc::new(file)
                }
                Err(err) => {
                    self.fail(file_idx, &err);
                    return None;
                }
            }
        } else if !needed {
            return None;
        } else if let Some(file) = self.take_idle(file_idx) {
            file
        } else {
            match self.dest.open_for_write(path) {
                Ok(file) => {
                    _ = self.reopened.fetch_add(1, Ordering::Relaxed);
                    Arc::new(file)
                }
                Err(err) => {
                    self.fail(file_idx, &err);
                    return None;
                }
            }
        };
        _ = bucket.busy.insert(file_idx, (Arc::clone(&file), 1));
        Some(file)
    }

    /// Counts one write of the file `file_idx` done, which had the handle
    /// `file` or none. The handle, once no write has it, is kept idle if
    /// the file has writes to come, and closed after its last; an idle
    /// handle evicted is closed. Handles are closed with no lock held.
    fn release(&self, file_idx: usize, file: Option<Arc<File>>) {
        let had = file.is_some();
        drop(file);
        let mut bucket = lock(&self.buckets[file_idx % BUCKETS]);
        let left = {
            let left = &mut bucket.left[file_idx / BUCKETS];
            debug_assert!(*left > 0, "more writes than counted");
            *left = left.saturating_sub(1);
            *left
        };
        let unused = if had {
            match bucket.busy.get_mut(&file_idx) {
                Some((_, users)) if *users > 1 => {
                    *users -= 1;
                    return;
                }
                _ => bucket.busy.remove(&file_idx).map(|(file, _)| file),
            }
        } else {
            None
        };
        // With writes left the file has none under way but those counted
        // here; with none left, no other has its handle.
        let close = match unused {
            Some(file) if left > 0 => self.park(file_idx, file),
            Some(file) => Some(file),
            None if left == 0 => self.take_idle(file_idx),
            None => None,
        };
        drop(bucket);
        drop(close);
    }

    /// Keeps the handle `file` of the file `file_idx` idle, and gives back
    /// the least recently used one if there are too many.
    fn park(&self, file_idx: usize, file: Arc<File>) -> Option<Arc<File>> {
        let mut idle = lock(&self.idle);
        idle.push_back((file_idx, file));
        if idle.len() > self.max_idle {
            idle.pop_front().map(|(_, file)| file)
        } else {
            None
        }
    }

    /// The idle handle of the file `file_idx`, if there is one, taken out.
    fn take_idle(&self, file_idx: usize) -> Option<Arc<File>> {
        let mut idle = lock(&self.idle);
        let at = idle.iter().position(|(idx, _)| *idx == file_idx)?;
        idle.remove(at).map(|(_, file)| file)
    }

    /// The handles open, in use or idle.
    #[cfg(test)]
    fn open(&self) -> usize {
        self.buckets.iter().map(|b| lock(b).busy.len()).sum::<usize>() + lock(&self.idle).len()
    }

    /// Closes the handles left (none, unless a pack wasn't read) and gives
    /// the number of files that couldn't be written.
    pub(super) fn finish(self) -> usize {
        debug!(
            "restore: {} files sized, {} handles opened again after their eviction",
            self.sized.load(Ordering::Relaxed),
            self.reopened.load(Ordering::Relaxed)
        );
        lock(&self.failed).len()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::Path,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    use crate::backend::local_destination::is_zero;

    /// A blob: the file, where, what, and whether it is all zeros.
    type Blob = (usize, u64, Vec<u8>, bool);

    /// `len` bytes of noise, from `seed`.
    fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x.to_le_bytes()[0]
            })
            .collect()
    }

    /// `items` in an order from `seed`.
    fn shuffle<T>(items: &mut [T], seed: u64) {
        let mut x = seed | 1;
        for i in (1..items.len()).rev() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            items.swap(i, usize::try_from(x % (i as u64 + 1)).unwrap());
        }
    }

    /// The blobs of `contents`, cut into pieces of `piece` bytes.
    fn blobs(contents: &[Vec<u8>], piece: usize) -> Vec<Blob> {
        let mut blobs = Vec::new();
        for (file_idx, data) in contents.iter().enumerate() {
            for (n, chunk) in data.chunks(piece).enumerate() {
                let start = (n * piece) as u64;
                blobs.push((file_idx, start, chunk.to_vec(), is_zero(chunk)));
            }
        }
        blobs
    }

    /// The writes each of `files` files gets from `blobs`.
    fn writes(files: usize, blobs: &[Blob]) -> Vec<usize> {
        let mut writes = vec![0; files];
        for (file_idx, ..) in blobs {
            writes[*file_idx] += 1;
        }
        writes
    }

    /// Writes `blobs` through `writer` on `threads` threads, each taking the
    /// next blob.
    fn write_all(writer: &FilesWriter<'_>, blobs: &[Blob], threads: usize) {
        let next = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..threads {
                _ = s.spawn(|| {
                    while let Some((file_idx, start, data, zeros)) =
                        blobs.get(next.fetch_add(1, Ordering::Relaxed))
                    {
                        writer.write(*file_idx, *start, data, *zeros);
                    }
                });
            }
        });
    }

    fn dest(dir: &Path) -> LocalDestination {
        LocalDestination::new(dir.to_str().unwrap(), false, false).unwrap()
    }

    fn names(files: usize) -> Vec<PathBuf> {
        (0..files)
            .map(|i| PathBuf::from(format!("d{}/f{i}", i % 3)))
            .collect()
    }

    /// Files of sizes not a multiple of the blobs', the first two there
    /// already with other contents (one longer, one shorter).
    fn contents(dir: &Path, files: usize) -> Vec<Vec<u8>> {
        let contents: Vec<_> = (0..files)
            .map(|i| noise(i as u64 + 1, 20_000 * (i + 1) + 777))
            .collect();
        for (name, len) in names(2).iter().zip([1 << 20, 100]) {
            let path = dir.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, vec![0xee; len]).unwrap();
        }
        contents
    }

    fn check(dir: &Path, contents: &[Vec<u8>]) {
        for (name, want) in names(contents.len()).iter().zip(contents) {
            let got = fs::read(dir.join(name)).unwrap();
            assert_eq!(got.len(), want.len(), "{}", name.display());
            assert!(got == *want, "{}: contents differ", name.display());
        }
    }

    /// Blobs of several files written in any order by many threads, with
    /// no idle handle kept (every one is evicted at once) or only one:
    /// the files come out exact, each sized once, and a file opened again
    /// keeps what was written before (it isn't emptied, nor resized).
    #[test]
    fn interleaved_writes_with_evictions() {
        const FILES: usize = 12;
        for (max_idle, threads) in [(0, 1), (0, 8), (1, 8), (3, 16)] {
            let dir = tempfile::tempdir().unwrap();
            let dest = dest(dir.path());
            let contents = contents(dir.path(), FILES);
            let mut blobs = blobs(&contents, 4096 + 13);
            shuffle(&mut blobs, max_idle as u64 * 31 + threads as u64);
            let names = names(FILES);
            let sizes: Vec<_> = contents.iter().map(|c| c.len() as u64).collect();
            let sparse = vec![false; FILES];
            let writer = FilesWriter::new(
                &dest,
                &names,
                &sparse,
                &sizes,
                writes(FILES, &blobs),
                max_idle,
            );
            write_all(&writer, &blobs, threads);
            assert_eq!(writer.open(), 0, "handles left open");
            assert_eq!(writer.sized.load(Ordering::Relaxed), FILES);
            let reopened = writer.reopened.load(Ordering::Relaxed);
            match (max_idle, threads) {
                // One write at a time, none kept: each after a file's first
                // opens it again.
                (0, 1) => assert_eq!(reopened, blobs.len() - FILES),
                // Some file has no write under way between two of its own.
                (0, _) => assert!(reopened > 0, "{threads} threads"),
                _ => eprintln!("max_idle {max_idle}, {threads} threads: {reopened} reopened"),
            }
            assert_eq!(writer.finish(), 0);
            check(dir.path(), &contents);
        }
    }

    /// With room for every handle, each file is opened once, at its first
    /// write, which sizes it, and never again.
    #[test]
    fn each_file_opened_once() {
        const FILES: usize = 12;
        let dir = tempfile::tempdir().unwrap();
        let dest = dest(dir.path());
        let contents = contents(dir.path(), FILES);
        let mut blobs = blobs(&contents, 1000);
        shuffle(&mut blobs, 7);
        let names = names(FILES);
        let sizes: Vec<_> = contents.iter().map(|c| c.len() as u64).collect();
        let sparse = vec![false; FILES];
        let writer = FilesWriter::new(
            &dest,
            &names,
            &sparse,
            &sizes,
            writes(FILES, &blobs),
            max_idle(8),
        );
        write_all(&writer, &blobs, 8);
        assert_eq!(writer.sized.load(Ordering::Relaxed), FILES);
        assert_eq!(writer.reopened.load(Ordering::Relaxed), 0);
        assert_eq!(writer.open(), 0, "handles left open");
        assert_eq!(writer.finish(), 0);
        check(dir.path(), &contents);
    }

    /// A file that can't be opened (a directory is in its place) fails
    /// once, its writes are skipped, and the others are written; no handle
    /// is left open.
    #[test]
    fn failed_file_skipped() {
        const FILES: usize = 4;
        let dir = tempfile::tempdir().unwrap();
        let dest = dest(dir.path());
        let contents: Vec<_> = (0..FILES).map(|i| noise(i as u64, 50_000)).collect();
        let names = names(FILES);
        fs::create_dir_all(dir.path().join(&names[2])).unwrap();
        let mut blobs = blobs(&contents, 3000);
        shuffle(&mut blobs, 3);
        let sizes: Vec<_> = contents.iter().map(|c| c.len() as u64).collect();
        let sparse = vec![false; FILES];
        let writer =
            FilesWriter::new(&dest, &names, &sparse, &sizes, writes(FILES, &blobs), 1);
        write_all(&writer, &blobs, 4);
        assert_eq!(writer.open(), 0, "handles left open");
        assert_eq!(writer.sized.load(Ordering::Relaxed), FILES - 1);
        assert_eq!(writer.finish(), 1);
        assert!(dir.path().join(&names[2]).is_dir());
        for i in [0, 1, 3] {
            assert_eq!(fs::read(dir.path().join(&names[i])).unwrap(), contents[i]);
        }
    }

    /// The descriptors of this process open on a file under `dir`.
    #[cfg(target_os = "linux")]
    fn fds_under(dir: &Path) -> usize {
        fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|fd| fs::read_link(fd.ok()?.path()).ok())
            .filter(|target| target.starts_with(dir))
            .count()
    }

    /// Once the files' last writes are done, none of them is open, before
    /// the writer is dropped; while they are written, no more are open than
    /// the writes under way and the idle handles kept.
    #[cfg(target_os = "linux")]
    #[test]
    fn no_handle_left_open() {
        const FILES: usize = 30;
        const THREADS: usize = 6;
        const MAX_IDLE: usize = 4;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let dest = dest(&root);
        let contents = contents(&root, FILES);
        let mut blobs = blobs(&contents, 2000);
        shuffle(&mut blobs, 11);
        let names = names(FILES);
        let sizes: Vec<_> = contents.iter().map(|c| c.len() as u64).collect();
        let sparse = vec![false; FILES];
        let writer = FilesWriter::new(
            &dest,
            &names,
            &sparse,
            &sizes,
            writes(FILES, &blobs),
            MAX_IDLE,
        );
        assert_eq!(fds_under(&root), 0);
        let most = AtomicUsize::new(0);
        let next = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..THREADS {
                _ = s.spawn(|| {
                    while let Some((file_idx, start, data, zeros)) =
                        blobs.get(next.fetch_add(1, Ordering::Relaxed))
                    {
                        writer.write(*file_idx, *start, data, *zeros);
                        _ = most.fetch_max(fds_under(&root), Ordering::Relaxed);
                    }
                });
            }
        });
        // One handle per write under way (or one evicted, being closed) and
        // the idle ones; twice the threads, as the count isn't atomic: an
        // entry of /proc/self/fd may be closed, and its number reused, by
        // the time it is looked at.
        let most = most.into_inner();
        assert!(most <= 2 * THREADS + MAX_IDLE, "{most} open");
        assert_eq!(fds_under(&root), 0, "files left open");
        assert_eq!(writer.open(), 0);
        assert_eq!(writer.finish(), 0);
        check(&root, &contents);
    }

    /// Files restored sparse through the writer keep their holes, with an
    /// all-zero blob as a file's first write (which sizes it) and as its
    /// last, and with evictions.
    #[cfg(target_os = "linux")]
    #[test]
    fn sparse_files_keep_holes() {
        use nix::unistd::{Whence, lseek};

        const MIB: usize = 1 << 20;
        let dir = tempfile::tempdir().unwrap();
        let dest = dest(dir.path());
        // Data, a hole of 4 MiB, data, a hole of 3 MiB to the end.
        let file = |seed| {
            let mut data = noise(seed, MIB);
            data.extend(vec![0; 4 * MIB]);
            data.extend(noise(seed + 1, MIB));
            data.extend(vec![0; 3 * MIB]);
            data
        };
        let contents = vec![file(1), file(3), file(5)];
        let names = names(contents.len());
        let sizes: Vec<_> = contents.iter().map(|c| c.len() as u64).collect();
        let sparse = vec![true; contents.len()];
        let mut blobs = blobs(&contents, MIB / 2);
        // The first file's blobs from its end, alone (its first write is
        // all zeros), the others' shuffled, on threads.
        let mut rest = blobs.split_off(blobs.iter().position(|b| b.0 == 1).unwrap());
        blobs.reverse();
        shuffle(&mut rest, 5);
        let writer = FilesWriter::new(
            &dest,
            &names,
            &sparse,
            &sizes,
            writes(contents.len(), &[blobs.clone(), rest.clone()].concat()),
            0,
        );
        write_all(&writer, &blobs, 1);
        write_all(&writer, &rest, 4);
        assert_eq!(writer.open(), 0, "handles left open");
        assert_eq!(writer.sized.load(Ordering::Relaxed), contents.len());
        assert_eq!(writer.finish(), 0);
        check(dir.path(), &contents);
        for name in &names {
            let f = File::open(dir.path().join(name)).unwrap();
            let size = i64::try_from(f.metadata().unwrap().len()).unwrap();
            let mib = i64::try_from(MIB).unwrap();
            let hole = lseek(&f, 0, Whence::SeekHole).unwrap();
            if hole == size {
                eprintln!("no holes in {}", dir.path().display());
                return;
            }
            assert_eq!(hole, mib, "{}", name.display());
            assert_eq!(lseek(&f, mib, Whence::SeekData).unwrap(), 5 * mib);
            assert_eq!(lseek(&f, 5 * mib, Whence::SeekHole).unwrap(), 6 * mib);
            // No data after: ENXIO.
            assert!(lseek(&f, 6 * mib, Whence::SeekData).is_err());
        }
    }
}
