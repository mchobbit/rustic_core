//! BackOtter: restricting flags held for putting back, on FreeBSD, NetBSD,
//! OpenBSD and DragonFly ([`super::clear_restricting_flags_held`]): the
//! file stays open (`O_RDONLY|O_NOFOLLOW|O_NONBLOCK`) from before its
//! flags come off, and they go back on it through `fchflags(2)`. What
//! can't be opened (a symlink, which `O_NOFOLLOW` refuses; a device, which
//! isn't opened; a file the restore may not open) has them cleared and put
//! back by path. As in BackOtter's restic (`restrictflags_bsd.go`).

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

use super::{HeldFlags, c_path, check, path_error};

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
fn set_fd_flags(f: &File, path: &Path, flags: u32) -> io::Result<()> {
    // SAFETY: f is open for the call's duration.
    check(unsafe { libc::fchflags(f.as_raw_fd(), flags.into()) })
        .map(drop)
        .map_err(|err| path_error("fchflags", path, &err))
}

/// Gives the file at `path`, not following a symlink, the flags `flags`.
fn set_path_flags(path: &Path, flags: u32) -> io::Result<()> {
    let p = c_path(path)?;
    #[cfg(target_os = "openbsd")]
    // SAFETY: p is a C string.
    let r = unsafe { libc::chflagsat(libc::AT_FDCWD, p.as_ptr(), flags, libc::AT_SYMLINK_NOFOLLOW) };
    #[cfg(not(target_os = "openbsd"))]
    // SAFETY: p is a C string.
    let r = unsafe { libc::lchflags(p.as_ptr(), flags.into()) };
    check(r).map(drop).map_err(|err| path_error("lchflags", path, &err))
}

/// Clears the restricting flags of the file at `path`, held for putting
/// back ([`HeldFlags`]).
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
                    "{} was replaced while it was read",
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
pub(super) fn put_back_restricting_flags(f: &File, path: &Path, cleared: u32) -> io::Result<()> {
    let flags = st_flags(&f.metadata()?);
    if flags | cleared == flags {
        return Ok(());
    }
    set_fd_flags(f, path, flags | cleared)
}

/// Sets `cleared` again on the file at `path`, by path.
pub(super) fn put_back_restricting_flags_path(path: &Path, cleared: u32) -> io::Result<()> {
    let flags = st_flags(&std::fs::symlink_metadata(path)?);
    if flags | cleared == flags {
        return Ok(());
    }
    set_path_flags(path, flags | cleared)
}
