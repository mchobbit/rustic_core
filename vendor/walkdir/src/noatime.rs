// BackOtter: reading a directory without updating its access time.
//
// On Linux a directory opened with O_NOATIME keeps its access time while it
// is read, which a backup saves and must not change (BackOtter's restic
// reads directories that way too). std::fs::read_dir has no way to ask for
// that, so this reads them with open(2), fdopendir(3) and readdir(3). The
// flag takes owning the directory (or CAP_FOWNER): without it, the
// directory is opened as std opens it.

use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// An entry of a directory, as `readdir(3)` gives it.
pub(crate) struct RawEntry {
    /// The directory's path joined with the entry's name.
    pub(crate) path: PathBuf,
    /// `d_type`, which may be `DT_UNKNOWN`.
    pub(crate) d_type: u8,
    /// `d_ino`.
    pub(crate) ino: u64,
}

/// The entries of a directory, but `.` and `..`, as `std::fs::ReadDir`
/// gives them.
pub(crate) struct ReadDir {
    dir: *mut libc::DIR,
    path: PathBuf,
    done: bool,
}

// SAFETY: the DIR stream is only used through &mut self, and only one thread
// at a time can have that, as with std::fs::ReadDir.
unsafe impl Send for ReadDir {}
// SAFETY: as above; &self gives no access to the stream.
unsafe impl Sync for ReadDir {}

impl fmt::Debug for ReadDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ReadDir").field(&self.path).finish()
    }
}

/// Opens the directory at `path` for reading, without updating its access
/// time where the caller may ask for that.
pub(crate) fn read_dir(path: &Path) -> io::Result<ReadDir> {
    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let how = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    // SAFETY: c_path is a C string.
    let mut fd = unsafe { libc::open(c_path.as_ptr(), how | libc::O_NOATIME) };
    if fd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
        // SAFETY: as above.
        fd = unsafe { libc::open(c_path.as_ptr(), how) };
    }
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is an open directory, which the stream owns from here.
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() {
        let err = io::Error::last_os_error();
        // SAFETY: fd is open, and not owned by a stream.
        unsafe { libc::close(fd) };
        return Err(err);
    }
    Ok(ReadDir { dir, path: path.to_path_buf(), done: false })
}

#[cfg(target_os = "android")]
unsafe fn clear_errno() {
    *libc::__errno() = 0;
}

#[cfg(not(target_os = "android"))]
unsafe fn clear_errno() {
    *libc::__errno_location() = 0;
}

impl Iterator for ReadDir {
    type Item = io::Result<RawEntry>;

    fn next(&mut self) -> Option<io::Result<RawEntry>> {
        while !self.done {
            // SAFETY: readdir(3) returns null at the end, setting errno only
            // on an error; the entry it returns lives until the next call.
            let ent = unsafe {
                clear_errno();
                #[cfg(all(target_os = "linux", target_env = "gnu"))]
                let ent = libc::readdir64(self.dir);
                #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
                let ent = libc::readdir(self.dir);
                ent
            };
            if ent.is_null() {
                self.done = true;
                let err = io::Error::last_os_error();
                return match err.raw_os_error() {
                    Some(0) | None => None,
                    Some(_) => Some(Err(err)),
                };
            }
            // SAFETY: ent is a valid entry, d_name a C string in it.
            let (name, d_type, ino) = unsafe {
                let ent = &*ent;
                (CStr::from_ptr(ent.d_name.as_ptr()), ent.d_type, ent.d_ino)
            };
            let name = name.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            return Some(Ok(RawEntry {
                path: self.path.join(OsStr::from_bytes(name)),
                d_type,
                #[allow(clippy::useless_conversion)]
                ino: u64::from(ino),
            }));
        }
        None
    }
}

impl Drop for ReadDir {
    fn drop(&mut self) {
        // SAFETY: dir is an open stream, closed once.
        unsafe { libc::closedir(self.dir) };
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    use super::*;

    #[test]
    fn reads_like_std() {
        let dir = std::env::temp_dir().join(format!("walkdir-noatime-{}", std::process::id()));
        fs::create_dir_all(dir.join("d")).unwrap();
        fs::write(dir.join("f"), b"x").unwrap();
        std::os::unix::fs::symlink("f", dir.join("l")).unwrap();

        let mut got: Vec<_> = read_dir(&dir)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.path.clone(), e.ino)
            })
            .collect();
        got.sort();
        let mut want: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.path(), e.metadata().unwrap().ino())
            })
            .collect();
        want.sort();
        assert_eq!(got, want);
        assert!(read_dir(&dir.join("f")).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
