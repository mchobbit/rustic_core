//! BackOtter: what the systems whose `SEEK_HOLE` the backup doesn't probe
//! with get in place of `seek.rs` (NetBSD, OpenBSD, DragonFly, Solaris, and
//! any other Unix): the blocks decide whether a file has holes, and it is
//! read plainly. DragonFly has `SEEK_HOLE`, but HAMMER2 answers `EOPNOTSUPP`,
//! and tmpfs always the file's size, which would hide real holes; Solaris is
//! left out as BackOtter's restic leaves it out.

use std::{
    fs::{File, Metadata},
    io,
    path::Path,
};

/// No probe for [`has_holes`](super::has_holes): the blocks decide.
pub(super) const fn first_hole(
    _path: &Path,
    _m: &Metadata,
    _f: Option<&File>,
) -> Option<fn() -> io::Result<u64>> {
    None
}

/// [`backup_reader`](super::backup_reader): `f` itself.
pub(super) fn backup_reader(f: File, _sparse: bool) -> Box<dyn io::Read + Send> {
    Box::new(f)
}

#[cfg(test)]
pub(super) mod tests {
    use std::path::Path;

    /// No `SEEK_HOLE` to find a hole with, for the tests of `sparse.rs`.
    pub(in crate::backend::osattrs::sparse) const fn finds_hole(_path: &Path, _len: u64) -> bool {
        false
    }
}
