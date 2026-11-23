//! BackOtter: reading a directory without updating its access time.
//!
//! On Linux a directory opened with `O_NOATIME` keeps its access time while it
//! is read, which a backup saves and must not change (BackOtter's restic
//! reads directories that way too). `std::fs::read_dir` has no way to ask for
//! that, so this reads them with `open(2)`, `fdopendir(3)` and `readdir(3)`. The
//! flag takes owning the directory (or `CAP_FOWNER`): without it, the
//! directory is opened as std opens it.

use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// An entry of a directory, as `readdir(3)` gives it.
#[derive(Debug)]
pub struct RawEntry {
    /// The directory's path joined with the entry's name.
    pub(crate) path: PathBuf,
    /// `d_type`, which may be `DT_UNKNOWN`.
    pub(crate) d_type: u8,
    /// `d_ino`.
    pub(crate) ino: u64,
}

/// The entries of a directory, but `.` and `..`, as `std::fs::ReadDir`
/// gives them.
pub struct ReadDir {
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
pub fn read_dir(path: &Path) -> io::Result<ReadDir> {
    // Past PATH_MAX, through a short path to it (longpath.rs); its entries
    // keep the long one.
    let c_path = CString::new(crate::short_path(path).as_os_str().as_bytes())?;
    let how = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    // SAFETY: c_path is a C string.
    let mut fd = unsafe { libc::open(c_path.as_ptr(), how | libc::O_NOATIME) };
    if fd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    {
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

/// Sets `errno` to 0, so that a null from `readdir(3)` can be told apart:
/// the end of the stream, or an error.
#[cfg(target_os = "android")]
fn clear_errno() {
    // SAFETY: __errno takes nothing, and gives this thread's errno.
    let errno = unsafe { libc::__errno() };
    // SAFETY: errno is valid for writes, for as long as the thread runs.
    unsafe { *errno = 0 };
}

/// Sets `errno` to 0, so that a null from `readdir(3)` can be told apart:
/// the end of the stream, or an error.
#[cfg(not(target_os = "android"))]
fn clear_errno() {
    // SAFETY: __errno_location takes nothing, and gives this thread's errno.
    let errno = unsafe { libc::__errno_location() };
    // SAFETY: errno is valid for writes, for as long as the thread runs.
    unsafe { *errno = 0 };
}

impl Iterator for ReadDir {
    type Item = io::Result<RawEntry>;

    fn next(&mut self) -> Option<io::Result<RawEntry>> {
        while !self.done {
            clear_errno();
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            // SAFETY: self.dir is an open stream; readdir(3) returns null at
            // the end, setting errno only on an error; the entry it returns
            // lives until the next call.
            let ent = unsafe { libc::readdir64(self.dir) };
            #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
            // SAFETY: as above.
            let ent = unsafe { libc::readdir(self.dir) };
            if ent.is_null() {
                self.done = true;
                let err = io::Error::last_os_error();
                return match err.raw_os_error() {
                    Some(0) | None => None,
                    Some(_) => Some(Err(err)),
                };
            }
            // ent is the entry readdir just gave, valid until the next
            // readdir. The record is only as long as its name (d_reclen),
            // shorter than libc's struct, so no reference to the whole struct
            // or its d_name array is made: the fields are read through ent
            // itself, as std's readdir does.
            // SAFETY: d_type is in the record, before the name.
            let d_type = unsafe { (*ent).d_type };
            // SAFETY: d_ino is in the record, before the name.
            let ino = unsafe { (*ent).d_ino };
            // SAFETY: d_name starts inside the record; no reference is made.
            let name_ptr = unsafe { std::ptr::addr_of!((*ent).d_name) }.cast();
            // SAFETY: d_name is a C string NUL-terminated inside the record,
            // which is valid until the next readdir.
            let name = unsafe { CStr::from_ptr(name_ptr) };
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
        let dir = std::env::temp_dir()
            .join(format!("walkdir-noatime-{}", std::process::id()));
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

    /// RustAudit1 R8-13: listing a directory the user owns leaves its
    /// access time as it was (`O_NOATIME`), by `read_dir` and by a walk,
    /// though it is older than the modification time, when `relatime`
    /// moves it on a read.
    #[test]
    fn a_listing_leaves_the_access_time_of_an_owned_directory() {
        use std::time::{Duration, SystemTime};

        let dir = std::env::temp_dir()
            .join(format!("walkdir-noatime-atime-{}", std::process::id()));
        fs::create_dir_all(dir.join("d")).unwrap();
        fs::write(dir.join("d").join("f"), b"x").unwrap();
        let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let atime = |p: &Path| fs::metadata(p).unwrap().accessed().unwrap();
        for p in [dir.clone(), dir.join("d")] {
            let times = fs::FileTimes::new().set_accessed(old);
            fs::File::open(&p).unwrap().set_times(times).unwrap();
            assert_eq!(atime(&p), old);
        }
        assert_eq!(read_dir(&dir).unwrap().count(), 1);
        assert_eq!(atime(&dir), old);
        let walked: Vec<_> = crate::WalkDir::new(&dir)
            .into_iter()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(walked.len(), 3);
        assert_eq!(atime(&dir), old);
        assert_eq!(atime(&dir.join("d")), old);
        fs::remove_dir_all(&dir).unwrap();
    }
}
