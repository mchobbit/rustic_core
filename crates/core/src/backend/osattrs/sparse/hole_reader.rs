//! BackOtter: a file with holes read by its data extents (`HoleReader`),
//! for the backup, which gives the chunker zeros for the holes without
//! reading them. The extents come through a trait ([`Extents`]): `SEEK_DATA`
//! and `SEEK_HOLE` of a file where the backup probes with them
//! (`sparse::seek`), files that change as they are read in the tests, which
//! run on every system.

use std::io;

use log::debug;

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

/// All the rest of the file, read as data.
const PLAIN: u64 = u64::MAX;

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
    pub(super) zeros: u64,
}

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

impl<F> Drop for HoleReader<F> {
    fn drop(&mut self) {
        debug!("{} bytes of holes given as zeros, not read", self.zeros);
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

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
                    self.data
                        .resize(self.data.len() + usize::try_from(n).unwrap(), 0);
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
            let Some(rest) = usize::try_from(off)
                .ok()
                .and_then(|off| self.data.get(off..))
            else {
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
    pub(in crate::backend::osattrs::sparse) fn read_all(
        mut r: impl io::Read,
        sizes: &[usize],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = vec![0xaa; sizes.iter().copied().max().unwrap_or(1).max(1)];
        for i in 0.. {
            let size = sizes
                .get(i % sizes.len().max(1))
                .copied()
                .unwrap_or(4096)
                .max(1);
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
    pub(in crate::backend::osattrs::sparse) fn chunks(
        r: impl io::Read + Send,
    ) -> Vec<(usize, crate::id::Id)> {
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
            (
                "hole shorter than a block",
                vec![(0, 100), (1, 100), (0, 100)],
            ),
            ("zeros written", vec![(0, 10), (2, 8 * K), (0, 10)]),
            ("data at EOF", vec![(1, 3 * K), (0, 1)]),
            (
                "holes back to back",
                vec![(1, 2 * K), (1, 2 * K), (2, K), (1, K)],
            ),
        ] {
            let f = sim_file(&runs, K as u64, 7);
            let want = f.data.clone();
            let holes = hole_bytes(&f);
            for sizes in [&[4096][..], &[1], &[100, 7000, 3], &[1 << 20]] {
                let mut r = HoleReader::new(f.clone());
                assert_eq!(read_all(&mut r, sizes), want, "{name}");
                assert_eq!(r.zeros, holes, "{name}");
            }
            assert_eq!(chunks(HoleReader::new(f)), chunks(&want[..]), "{name}");
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
        let f = sim_file(
            &[(0, K), (1, 4 * K), (0, K), (1, 4 * K), (0, 3)],
            K as u64,
            3,
        );
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
            assert_eq!(
                read_all(HoleReader::new(f.clone()), &[K]),
                f.data,
                "{runs:?}"
            );
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
        for (by_reads, at) in (0..24)
            .map(|at| (false, at))
            .chain((0..12).map(|at| (true, at)))
        {
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
        for cut in [
            at + 1,
            5 * K as u64,
            10 * K as u64 + 7,
            17 * K as u64,
            at,
            K as u64,
            0,
        ] {
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

    /// BackOtter (ForkAudit1 F2): a file whose `SEEK_DATA`, `SEEK_HOLE` and
    /// size answer anything at all (a buggy or changing file system: before
    /// or past the offset asked, past the end, errors), and whose reads give
    /// its bytes: the reader ends, gives each byte as the file has it or as
    /// a zero, no more bytes than the largest size it was told, and never
    /// panics.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn hole_reader_any_answers() {
        use std::io::Read;

        struct Lying {
            data: Vec<u8>,
            x: u64,
            biggest: u64,
        }

        impl Lying {
            fn next(&mut self) -> u64 {
                self.x ^= self.x << 13;
                self.x ^= self.x >> 7;
                self.x ^= self.x << 17;
                self.x
            }

            /// An offset near `off`, the end or 0, or far off; or an error.
            fn answer(&mut self, off: u64) -> io::Result<u64> {
                let len = self.data.len() as u64;
                let r = self.next();
                let near = |d: u64| {
                    [
                        off.saturating_sub(d),
                        off.saturating_add(d),
                        len.saturating_sub(d),
                        len + d,
                        d,
                    ]
                };
                Ok(match r % 16 {
                    0 => return Err(io::Error::from_raw_os_error(libc::ENXIO)),
                    1 => return Err(io::Error::from_raw_os_error(libc::EIO)),
                    2 => u64::MAX - (r >> 60),
                    3 => off,
                    _ => near((r >> 8) % 600)[usize::try_from((r >> 32) % 5).unwrap()],
                })
            }
        }

        impl Extents for Lying {
            fn seek_data(&mut self, off: u64) -> io::Result<u64> {
                self.answer(off)
            }

            fn seek_hole(&mut self, off: u64) -> io::Result<u64> {
                self.answer(off)
            }

            fn size(&mut self) -> io::Result<u64> {
                let len = self.data.len() as u64;
                let size = match self.next() % 8 {
                    0 => return Err(io::Error::from_raw_os_error(libc::EIO)),
                    1 => 0,
                    2 => len / 2,
                    3 => len * 2,
                    _ => len,
                };
                self.biggest = self.biggest.max(size);
                Ok(size)
            }

            fn read_at(&mut self, buf: &mut [u8], off: u64) -> io::Result<usize> {
                let Some(rest) = usize::try_from(off)
                    .ok()
                    .and_then(|off| self.data.get(off..))
                else {
                    return Ok(0);
                };
                let n = rest.len().min(buf.len());
                buf[..n].copy_from_slice(&rest[..n]);
                Ok(n)
            }
        }

        let seeds: u64 = if cfg!(miri) { 40 } else { 20_000 };
        for seed in 1..=seeds {
            let data: Vec<u8> = (0..1000_u32)
                .map(|i| u8::try_from(i % 251 + 1).unwrap())
                .collect();
            let len = data.len() as u64;
            let mut r = HoleReader::new(Lying {
                data: data.clone(),
                x: seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1,
                biggest: 0,
            });
            let mut out = Vec::new();
            let mut buf = [0_u8; 97];
            let mut reads = 0;
            loop {
                reads += 1;
                assert!(
                    reads < 10_000,
                    "seed {seed}: no end after {} bytes",
                    out.len()
                );
                match r.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => out.extend_from_slice(&buf[..n]),
                }
            }
            let most = r.f.biggest.max(len);
            assert!(
                out.len() as u64 <= most,
                "seed {seed}: {} bytes of a file of at most {most}",
                out.len()
            );
            for (i, &b) in out.iter().enumerate() {
                assert!(
                    b == 0 || data.get(i) == Some(&b),
                    "seed {seed}: byte {i} is {b}"
                );
            }
        }
    }
}
