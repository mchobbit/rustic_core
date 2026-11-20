// BackOtter: paths of PATH_MAX bytes or more.
//
// A file system holds files deeper than a path a system call takes
// (PATH_MAX, 4096 bytes on Linux, its NUL included: ENAMETOOLONG past it),
// and a backup must read them and a restore make them, as tar and rsync do.
// `short_path` gives, for such a path, a shorter one to the same file: the
// directory at a prefix of the path (of at most PATH_MAX / 2 bytes, ending
// at a component) is reached through a symbolic link to it, in a directory
// of this process's own (mode 0700, in the temporary directory, removed at
// exit), and the rest of the path follows the link; a rest still too long
// is shortened the same way, from that link. A link is followed by name, as
// the long path's own components are, so the short path names whatever the
// long one names, now and after the tree changes; and each prefix has one
// link, so a path gets the same short path every time.
//
// Only on Linux and Android, where the rest of BackOtter's rustic_core is
// tested past PATH_MAX; elsewhere a path is given back as it is, and a
// system call on one too long fails as before.

use std::borrow::Cow;
use std::path::Path;

/// BackOtter: a path to the file at `path` that a system call takes: `path`
/// itself, unless it has `PATH_MAX` bytes or more, when it is a shorter one
/// through a symbolic link to a directory along it (see this module). If
/// that can't be made (no temporary directory to make links in), `path` as
/// it is, which then fails as before (`ENAMETOOLONG`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn short_path(path: &Path) -> Cow<'_, Path> {
    use std::os::unix::ffi::OsStrExt;

    if path.as_os_str().as_bytes().len() < imp::MAX {
        return Cow::Borrowed(path);
    }
    imp::shorten(path).map_or(Cow::Borrowed(path), Cow::Owned)
}

/// BackOtter: `path` as it is (see this module).
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn short_path(path: &Path) -> Cow<'_, Path> {
    Cow::Borrowed(path)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock, PoisonError};

    /// The bytes a path given to a system call has fewer than.
    pub(super) const MAX: usize = libc::PATH_MAX as usize;
    /// The longest prefix a link leads to.
    const CHUNK: usize = MAX / 2;

    /// The directory the links are in, once made.
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    /// The link made to each prefix.
    static LINKS: Mutex<Option<HashMap<PathBuf, PathBuf>>> = Mutex::new(None);

    fn too_long() -> io::Error {
        io::Error::from_raw_os_error(libc::ENAMETOOLONG)
    }

    pub(super) fn shorten(path: &Path) -> io::Result<PathBuf> {
        // Absolute, for a link to lead to; without doubled slashes or "."
        // components, so that one prefix is always spelled one way.
        let mut p: PathBuf = if path.is_absolute() {
            path.components().collect()
        } else {
            std::env::current_dir()?.join(path).components().collect()
        };
        while p.as_os_str().as_bytes().len() >= MAX {
            let b = p.as_os_str().as_bytes();
            let cut = b[..=CHUNK]
                .iter()
                .rposition(|&c| c == b'/')
                .filter(|&i| i > 0)
                .ok_or_else(too_long)?;
            let link = link_to(Path::new(OsStr::from_bytes(&b[..cut])))?;
            // Each round must shorten it (a component of thousands of bytes
            // can't be cut).
            if link.as_os_str().as_bytes().len() >= cut {
                return Err(too_long());
            }
            p = link.join(OsStr::from_bytes(&b[cut + 1..]));
        }
        Ok(p)
    }

    /// The link to the directory at `prefix`, made the first time.
    fn link_to(prefix: &Path) -> io::Result<PathBuf> {
        let mut links = LINKS.lock().unwrap_or_else(PoisonError::into_inner);
        let links = links.get_or_insert_with(HashMap::new);
        if let Some(link) = links.get(prefix) {
            return Ok(link.clone());
        }
        let dir = match DIR.get() {
            Some(dir) => dir.clone(),
            None => make_dir()?,
        };
        let link = dir.join(links.len().to_string());
        std::os::unix::fs::symlink(prefix, &link)?;
        let _ = links.insert(prefix.to_path_buf(), link.clone());
        Ok(link)
    }

    /// Makes the directory of this process's links, a new one only it can
    /// enter (another user's of the same name is passed over), removed at
    /// exit. Called with `LINKS` held.
    fn make_dir() -> io::Result<PathBuf> {
        use std::os::unix::fs::DirBuilderExt;

        let tmp = std::env::temp_dir();
        if !tmp.is_absolute() || tmp.as_os_str().as_bytes().len() > CHUNK / 2 {
            return Err(too_long());
        }
        let pid = std::process::id();
        for n in 0..1000u32 {
            let dir = tmp.join(format!(".bko-longpath-{pid}-{n}"));
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {
                    let _ = DIR.set(dir.clone());
                    // SAFETY: remove_dir is an extern "C" fn taking nothing.
                    let _ = unsafe { libc::atexit(remove_dir) };
                    return Ok(dir);
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err),
            }
        }
        Err(io::Error::from(io::ErrorKind::AlreadyExists))
    }

    /// Removes the links' directory at exit: the links only, never what
    /// they lead to (remove_dir_all follows no symbolic link).
    extern "C" fn remove_dir() {
        if let Some(dir) = DIR.get() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// The links' directory, for tests.
    #[cfg(test)]
    pub(super) fn dir() -> Option<PathBuf> {
        DIR.get().cloned()
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    use super::*;

    /// Makes `depth` directories of 40-byte names below `top`, through
    /// descriptors (the path soon gets too long for a system call), with a
    /// file `leaf` holding "deep" at the bottom; returns the bottom
    /// directory's path and its device and inode.
    fn deep_tree(top: &Path, depth: usize) -> (PathBuf, (u64, u64)) {
        let c = |s: &[u8]| CString::new(s).unwrap();
        let mut path = top.to_path_buf();
        // SAFETY: plain system calls on C strings and descriptors this owns.
        unsafe {
            let mut fd = libc::open(c(top.as_os_str().as_bytes()).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
            assert!(fd >= 0);
            for i in 0..depth {
                let name = format!("d{i:03}{}", "x".repeat(36));
                path.push(&name);
                let n = c(name.as_bytes());
                assert_eq!(libc::mkdirat(fd, n.as_ptr(), 0o755), 0);
                let next = libc::openat(fd, n.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
                assert!(next >= 0);
                libc::close(fd);
                fd = next;
            }
            let f = libc::openat(fd, c(b"leaf").as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o644);
            assert!(f >= 0);
            assert_eq!(libc::write(f, b"deep".as_ptr().cast(), 4), 4);
            libc::close(f);
            let mut st: libc::stat = std::mem::zeroed();
            assert_eq!(libc::fstat(fd, &mut st), 0);
            libc::close(fd);
            (path, (st.st_dev as u64, st.st_ino as u64))
        }
    }

    fn top(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("walkdir-longpath-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn short_paths_are_given_as_they_are() {
        let p = Path::new("/a/b/c");
        assert!(matches!(short_path(p), Cow::Borrowed(q) if q == p));
        let p = PathBuf::from(format!("/{}", "a/".repeat(2000)));
        assert!(p.as_os_str().len() < imp::MAX);
        assert!(matches!(short_path(&p), Cow::Borrowed(_)));
    }

    #[test]
    fn long_paths_reach_the_same_file() {
        let top = top("same");
        // Over three times PATH_MAX: links through links.
        let (bottom, id) = deep_tree(&top, 330);
        assert!(bottom.as_os_str().len() > 3 * imp::MAX);
        assert!(fs::symlink_metadata(&bottom).is_err());
        let short = short_path(&bottom);
        assert!(short.as_os_str().len() < imp::MAX, "{}", short.display());
        let m = fs::symlink_metadata(&short).unwrap();
        assert!(m.is_dir());
        assert_eq!((m.dev(), m.ino()), id);
        // The same short path each time, and a file below it reached too.
        assert_eq!(short_path(&bottom), short);
        let leaf = bottom.join("leaf");
        assert_eq!(fs::read(short_path(&leaf)).unwrap(), b"deep");
        // A file made through it is where the long path says.
        fs::write(short_path(&bottom.join("new")), b"made").unwrap();
        assert!(fs::read_dir(&short).unwrap().any(|e| e.unwrap().file_name() == "new"));
        // The links are in a directory only this user can enter.
        let links = imp::dir().unwrap();
        assert!(links.starts_with(std::env::temp_dir()));
        let mode = fs::symlink_metadata(&links).unwrap().mode();
        assert_eq!(mode & 0o777, 0o700);
        // GNU rm removes a tree of any depth.
        let _ = std::process::Command::new("rm").arg("-rf").arg(&top).status();
    }

    #[test]
    fn a_walk_reads_past_path_max() {
        let top = top("walk");
        let depth = 120;
        let (bottom, _) = deep_tree(&top, depth);
        assert!(bottom.as_os_str().len() > imp::MAX);
        let mut seen = 0;
        let mut leaf = None;
        for entry in crate::WalkDir::new(&top).sort_by_file_name() {
            let entry = entry.unwrap();
            let m = entry.metadata().unwrap();
            seen += 1;
            if entry.file_name() == "leaf" {
                assert!(m.is_file());
                assert_eq!(m.len(), 4);
                leaf = Some(entry.into_path());
            }
        }
        // The top, each directory, and the leaf.
        assert_eq!(seen, depth + 2);
        assert_eq!(leaf.unwrap(), bottom.join("leaf"));
        let _ = std::process::Command::new("rm").arg("-rf").arg(&top).status();
    }
}
