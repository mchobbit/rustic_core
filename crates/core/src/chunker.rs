use std::{cell::RefCell, io::Read};

mod fixed_size;
pub mod rabin;

use fixed_size::ChunkIter as FixedSizeChunkIter;
use rabin::ChunkIter as RabinChunkIter;
use rustic_cdc::Rabin64;

use crate::{
    RusticResult,
    repofile::{ConfigFile, configfile::Chunker},
};

/// `ChunkIter` is an iterator that chunks data.
pub(crate) enum ChunkIter<R: Read + Send> {
    Rabin(Box<RabinChunkIter<R>>),
    FixedSize(FixedSizeChunkIter<R>),
}

impl<R: Read + Send> ChunkIter<R> {
    pub(crate) fn from_config(
        config: &ConfigFile,
        reader: R,
        size_hint: usize,
    ) -> RusticResult<Self> {
        let iter = match config.chunker() {
            Chunker::Rabin => {
                let rabin = rabin64(config.poly()?);
                Self::Rabin(Box::new(RabinChunkIter::new(
                    rabin,
                    config.chunk_size(),
                    config.chunk_min_size(),
                    config.chunk_max_size(),
                    reader,
                    size_hint,
                )?))
            }
            Chunker::FixedSize => Self::FixedSize(FixedSizeChunkIter::new(
                config.chunk_size(),
                reader,
                size_hint,
            )),
        };
        Ok(iter)
    }
}

// BackOtter: a fresh [`Rabin64`] for `poly`, its tables computed once per
// thread instead of once per file.
//
// `Rabin64::new_with_polynom` computes 2 x 256 table entries by polynomial
// division, about 0.2 ms: that was 15 % of a backup's CPU time over a tree
// of small files. A clone of a new one is the same as a new one.
fn rabin64(poly: u64) -> Rabin64 {
    thread_local! {
        static RABIN: RefCell<Option<(u64, Rabin64)>> = const { RefCell::new(None) };
    }
    RABIN.with_borrow_mut(|cached| match cached {
        Some((p, rabin)) if *p == poly => rabin.clone(),
        _ => cached
            .insert((poly, Rabin64::new_with_polynom(6, &poly)))
            .1
            .clone(),
    })
}

impl<R: Read + Send> Iterator for ChunkIter<R> {
    type Item = RusticResult<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Rabin(rabin) => rabin.next(),
            Self::FixedSize(fixed_size) => fixed_size.next(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustic_cdc::RollingHash64;

    #[test]
    fn cached_rabin_chunks_as_a_new_one() {
        // BackOtter: the same chunks with a cached Rabin64 (cloned) as
        // with a new one, for two polynomials in turn.
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let data: Vec<u8> = (0..6 << 20)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x.to_le_bytes()[0]
            })
            .collect();
        for poly in [
            0x003D_A335_8B4D_C173,
            0x0038_29A8_6A4E_D2A5,
            0x003D_A335_8B4D_C173,
        ] {
            let chunks = |rabin: Rabin64| -> Vec<Vec<u8>> {
                RabinChunkIter::new(rabin, 1 << 20, 512 << 10, 8 << 20, &data[..], data.len())
                    .unwrap()
                    .map(Result::unwrap)
                    .collect()
            };
            let fresh = chunks(Rabin64::new_with_polynom(6, &poly));
            assert!(fresh.len() > 2);
            assert!(chunks(rabin64(poly)) == fresh);
            assert!(chunks(rabin64(poly)) == fresh);
            assert_eq!(
                rabin64(poly).get_hash(),
                Rabin64::new_with_polynom(6, &poly).get_hash()
            );
        }
    }
}
