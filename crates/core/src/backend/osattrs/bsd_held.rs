//! BackOtter: restricting flags held for putting back, on FreeBSD, NetBSD,
//! OpenBSD and DragonFly ([`super::clear_restricting_flags_held`]): the
//! file stays open (`O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY`) from before
//! its flags come off, and they go back on it through `fchflags(2)`. What
//! can't be opened (a symlink, which `O_NOFOLLOW` refuses; a device, which
//! isn't opened; a file the restore may not open) has them cleared and put
//! back by path. As in BackOtter's restic (`restrictflags_bsd.go`). The
//! plain clear, [`clear_restricting_flags`], is here too, the same on each.

use std::{
    fs::{File, Metadata, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

use log::debug;

use super::{HeldFlags, c_path, check, path_error, set_flags_best_effort};

#[cfg(target_os = "dragonfly")]
use super::bsd_flags::DRAGONFLY_RESTRICTING_FLAGS as RESTRICTING;
#[cfg(target_os = "freebsd")]
use super::bsd_flags::FREEBSD_RESTRICTING_FLAGS as RESTRICTING;
#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
use super::bsd_flags::NETBSD_OPENBSD_RESTRICTING_FLAGS as RESTRICTING;

/// The file flags (`st_flags`) of the file `m` describes.
fn st_flags(m: &Metadata) -> u32 {
    #[cfg(target_os = "dragonfly")]
    use std::os::dragonfly::fs::MetadataExt as _;
    #[cfg(target_os = "freebsd")]
    use std::os::freebsd::fs::MetadataExt as _;
    #[cfg(target_os = "netbsd")]
    use std::os::netbsd::fs::MetadataExt as _;
    #[cfg(target_os = "openbsd")]
    use std::os::openbsd::fs::MetadataExt as _;
    m.st_flags()
}

/// Gives the file open as `f` the flags `flags`.
// fchflags(2) takes the flags as a c_ulong but on OpenBSD, a u32: the
// conversion is one on the other three.
#[cfg_attr(target_os = "openbsd", allow(clippy::useless_conversion))]
fn set_fd_flags(f: &File, path: &Path, flags: u32) -> io::Result<()> {
    // SAFETY: f is open for the call's duration.
    check(unsafe { libc::fchflags(f.as_raw_fd(), flags.into()) })
        .map(drop)
        .map_err(|err| path_error("fchflags", path, &err))
}

/// Gives the file at `path`, not following a symlink, the flags `flags`;
/// an error names the call made ([`PATH_OP`]).
fn set_path_flags(path: &Path, flags: u32) -> io::Result<()> {
    set_path_flags_raw(path, flags).map_err(|err| path_error(PATH_OP, path, &err))
}

/// [`set_path_flags`], with the system's error as it is.
fn set_path_flags_raw(path: &Path, flags: u32) -> io::Result<()> {
    let p = c_path(path)?;
    #[cfg(target_os = "openbsd")]
    // SAFETY: p is a C string.
    let r = unsafe { libc::chflagsat(libc::AT_FDCWD, p.as_ptr(), flags, libc::AT_SYMLINK_NOFOLLOW) };
    #[cfg(not(target_os = "openbsd"))]
    // SAFETY: p is a C string.
    let r = unsafe { libc::lchflags(p.as_ptr(), flags.into()) };
    check(r).map(drop)
}

/// The call [`set_path_flags`] makes, for its errors: OpenBSD has no
/// `lchflags(2)`.
#[cfg(target_os = "openbsd")]
const PATH_OP: &str = "chflagsat";
#[cfg(not(target_os = "openbsd"))]
const PATH_OP: &str = "lchflags";

/// Clears the flags of the file at `path` that keep a restore from
/// rewriting, replacing or changing it ([`RESTRICTING`]), leaving the others
/// as they are; the late flags pass sets the node's.
///
/// # Errors
///
/// * If the file can't be `lstat`ed (the error as it is), or its flags
///   can't be set (`lchflags(2)`, `chflagsat(2)` on OpenBSD).
pub(super) fn clear_restricting_flags(path: &Path) -> io::Result<()> {
    let flags = st_flags(&std::fs::symlink_metadata(path)?);
    if flags & RESTRICTING == 0 {
        return Ok(());
    }
    set_path_flags(path, flags & !RESTRICTING)
}

/// Gives the file at `path`, not following a symlink, the flags a node
/// without the flags attribute `attr` stands for in a snapshot of
/// BackOtter's, which records a file's flags wherever it has any: `none` of
/// those kept (`kept`; 0, or `uarch` on FreeBSD's ZFS), where it has others
/// now (`nodump` or `hidden` set since the backup, say; the restricting
/// ones came off before the restore changed the file). The late flags pass
/// sets only the flags a node holds, so these stayed, and `restore --exact`
/// set such a file's metadata again on every run. Flags outside `kept` stay
/// as they are, and a file with just `none` is not written to. One flag
/// that can't be changed (root's, as another user) doesn't keep the others.
///
/// # Errors
///
/// * If the file can't be `lstat`ed, or a flag couldn't be changed: as
///   [`set_flags_best_effort`] reports it, naming the flags.
pub(super) fn restore_no_flags(
    path: &Path,
    attr: &'static str,
    kept: u32,
    none: u32,
) -> io::Result<()> {
    let m = std::fs::symlink_metadata(path).map_err(|err| path_error("lstat", path, &err))?;
    let current = st_flags(&m);
    if current & kept == none & kept {
        return Ok(());
    }
    let own = current & !kept;
    set_flags_best_effort(attr, path, PATH_OP, Some(current & kept), none & kept, |bits| {
        set_path_flags_raw(path, own | bits)
    })
}

/// Clears the restricting flags of the file at `path`, held for putting
/// back ([`HeldFlags`]).
///
/// # Errors
///
/// * If the file can't be `lstat`ed (the error as it is).
/// * If the file opened for holding isn't the one `lstat`ed (its device and
///   inode differ): "replaced before its flags were cleared".
/// * If its flags can't be set: `fchflags(2)`'s error on the file held,
///   `lchflags(2)`'s (`chflagsat(2)`'s on OpenBSD) on one cleared by path.
pub(super) fn clear_restricting_flags_held(path: &Path) -> io::Result<HeldFlags> {
    let m = std::fs::symlink_metadata(path)?;
    if st_flags(&m) & RESTRICTING == 0 {
        return Ok(HeldFlags::Nothing);
    }
    if m.is_file() || m.is_dir() {
        let opened = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(path)
            .and_then(|f| f.metadata().map(|fm| (f, fm)));
        match opened {
            Ok((file, fm)) if (fm.dev(), fm.ino()) == (m.dev(), m.ino()) => {
                let flags = st_flags(&fm);
                set_fd_flags(&file, path, flags & !RESTRICTING)?;
                return Ok(HeldFlags::Held {
                    file,
                    cleared: flags & RESTRICTING,
                    path: path.to_path_buf(),
                });
            }
            Ok(_) => {
                return Err(io::Error::other(format!(
                    "{} was replaced before its flags were cleared",
                    path.display()
                )));
            }
            Err(err) => debug!("{} not held for its flags: {err}", path.display()),
        }
    }
    let flags = st_flags(&m);
    set_path_flags(path, flags & !RESTRICTING)?;
    Ok(HeldFlags::ByPath {
        path: path.to_path_buf(),
        dev: m.dev(),
        ino: m.ino(),
        linked: !m.is_dir() && m.nlink() > 1,
        cleared: flags & RESTRICTING,
    })
}

/// Sets `cleared`, the restricting flags [`clear_restricting_flags_held`]
/// cleared, again on the file open as `f` (at `path`, for errors).
///
/// # Errors
///
/// * If the file's flags can't be read (`fstat(2)`, the error as it is) or
///   set (`fchflags(2)`).
pub(super) fn put_back_restricting_flags(f: &File, path: &Path, cleared: u32) -> io::Result<()> {
    let flags = st_flags(&f.metadata()?);
    if flags | cleared == flags {
        return Ok(());
    }
    set_fd_flags(f, path, flags | cleared)
}

/// Sets `cleared` again on the file at `path`, by path.
///
/// # Errors
///
/// * If the file's flags can't be read (`lstat(2)`, the error as it is) or
///   set (`lchflags(2)`, `chflagsat(2)` on OpenBSD).
pub(super) fn put_back_restricting_flags_path(path: &Path, cleared: u32) -> io::Result<()> {
    let flags = st_flags(&std::fs::symlink_metadata(path)?);
    if flags | cleared == flags {
        return Ok(());
    }
    set_path_flags(path, flags | cleared)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::node::{Metadata as NodeMetadata, Node, NodeType};

    const UF_NODUMP: u32 = 0x1; // "nodump", an owner's to set on every BSD

    fn flags_and_ctime(path: &Path) -> (u32, i64, i64) {
        // A moment later, so that a write after this moves the change time.
        std::thread::sleep(std::time::Duration::from_millis(30));
        let m = std::fs::symlink_metadata(path).unwrap();
        (st_flags(&m), m.ctime(), m.ctime_nsec())
    }

    /// G4-03: a flag a file has and its node doesn't goes in a snapshot of
    /// BackOtter's, where a node without flags says its file had none, and
    /// stays in any other; a file with a new file's flags isn't written to.
    /// The late flags pass alone, which sets a node's own flags, left it.
    #[test]
    fn restore_takes_off_flags_the_node_lacks() {
        let dir = tempfile::tempdir().unwrap();
        for typ in [NodeType::File, NodeType::Dir, NodeType::from_link(Path::new("f"))] {
            let path = dir.path().join(format!("{typ:?}").split(' ').next().unwrap());
            match typ {
                NodeType::File => std::fs::write(&path, "x").unwrap(),
                NodeType::Dir => std::fs::create_dir(&path).unwrap(),
                _ => std::os::unix::fs::symlink("f", &path).unwrap(),
            }
            let (new_file, ..) = flags_and_ctime(&path);
            if let Err(err) = set_path_flags(&path, new_file | UF_NODUMP) {
                eprintln!("restore_takes_off_flags_the_node_lacks: {err}: nothing tested");
                return;
            }
            let node = Node::new_node(std::ffi::OsStr::new("n"), typ, NodeMetadata::default());
            let restore = |known_bko| super::super::os::restore_attributes(&path, &node, known_bko);

            restore(false).unwrap();
            assert_eq!(flags_and_ctime(&path).0, new_file | UF_NODUMP, "not BackOtter's: kept");
            restore(true).unwrap();
            let after = flags_and_ctime(&path);
            assert_eq!(after.0, new_file, "{}", path.display());
            restore(true).unwrap();
            assert_eq!(flags_and_ctime(&path), after, "a second restore wrote to the file");
        }
    }
}
