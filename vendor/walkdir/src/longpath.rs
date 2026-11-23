// BackOtter: paths of PATH_MAX bytes or more.
//
// A file system holds files deeper than a path a system call takes
// (PATH_MAX, 4096 bytes on Linux, its NUL included: ENAMETOOLONG past it),
// and a backup must read them and a restore make them, as tar and rsync do.
// `short_path` gives, for such a path, a shorter one to the same file: the
// directory at a prefix of the path (ending at a component) is reached
// through a symbolic link to it, in a directory of this process's own (mode
// 0700, in the temporary directory, removed at exit), and the rest of the
// path follows the link; a rest still too long is shortened the same way,
// from that link. A link is followed by name, as the long path's own
// components are, so the short path names whatever the long one names, now
// and after the tree changes; and each prefix has one link, so a path gets
// the same short path every time.
//
// A prefix is at most 2048 bytes (PATH_MAX / 2) where the links' directory
// takes a link's target of that many bytes, and at most 1000 where it
// doesn't: XFS refuses a target past 1024 bytes, ext2/3/4 and minix past
// a block less its NUL, 1023 bytes on 1 KiB blocks and 2047 on 2 KiB ones
// (symlink(2) ENAMETOOLONG). Which one is decided
// once per process, by a link made in the new directory before any other
// (`probe`), so a prefix is always cut at the same place.
//
// Depth: a system call follows at most 40 symbolic links in a path (Linux's
// MAXSYMLINKS; ELOOP past it), and a short path made in k rounds follows k
// links (each link's target starts with the link before), so a path that
// takes more than 40 rounds fails (ELOOP), as one too long did before. A
// round cuts its prefix less the link's own path (its directory and some
// 30 bytes), so the deepest path reached is about, with 2048-byte prefixes,
// 82 KB (names of 40 bytes, an 18-byte $TMPDIR), 77 KB (names of 200
// bytes), 55 KB (names of 255 bytes, a 495-byte $TMPDIR) and 35 KB at worst
// (names of 255 bytes, a 1024-byte $TMPDIR); with 1000-byte prefixes 42 KB,
// 36 KB and 14 KB (a $TMPDIR of at most 500 bytes). The links' directory is in
// $TMPDIR's canonical path, with no symbolic link in it: a link's path is
// in its target's, and so in every later round's, and a symbolic link
// there would be followed again in each round (0.13.0+backotter.16 to .20:
// one halved the depth reached). Symbolic links in the long path's first
// prefix count toward the 40 too, once.
//
// A link is checked each time it is used (readlink): one that is gone, or
// leads elsewhere, is made again, and its directory too (new, mode 0700;
// one there must still be this user's alone), so a short path never goes
// through a link that isn't there. Without that, a `restore --delete` with
// $TMPDIR in its destination removed the links as extra entries, and
// create_dir_all of the next short path then built the rest of the path as
// real directories inside $TMPDIR, where the files were written and removed
// at exit (0.13.0+backotter.16 to 0.14.0+backotter.1: ForkAudit1 G7-01).
// A walk of a tree that holds $TMPDIR finds the links' directory in it:
// `is_short_path_dir` says which entry it is, for a backup to leave out and
// a restore to leave alone.
//
// Where a short path can't be made, `short_path` gives the path as it is,
// whose system call then fails as before, and the reason goes once to the
// function given to `report_short_path_errors` (walkdir has no logger of
// its own); `try_short_path` returns it.
//
// Only on Linux and Android, where the rest of BackOtter's rustic_core is
// tested past PATH_MAX; elsewhere a path is given back as it is, and a
// system call on one too long fails as before.

use std::borrow::Cow;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

/// BackOtter: a path to the file at `path` that a system call takes: `path`
/// itself, unless it has `PATH_MAX` bytes or more, when it is a shorter one
/// through symbolic links to directories along it (see this module).
///
/// Where a link can't be made (no usable temporary directory for the
/// links, a link refused, a path with no '/' to cut it at: the errors of
/// [`try_short_path`]), it is `path` as it is, which then fails as before
/// (`ENAMETOOLONG`), and why goes, the first time, to the function given to
/// [`report_short_path_errors`]. A path that takes more than 40 links
/// (about 82 KB with 40-byte names; see this module) gets a short path all
/// the same, which fails with `ELOOP` ("Too many levels of symbolic
/// links").
pub fn short_path(path: &Path) -> Cow<'_, Path> {
    try_short_path(path).unwrap_or_else(|err| {
        report(&err);
        Cow::Borrowed(path)
    })
}

/// BackOtter: [`short_path`], or why it couldn't shorten `path`.
///
/// # Errors
///
/// For a path of `PATH_MAX` bytes or more (Linux and Android), if a link to
/// shorten it with couldn't be made: no directory for the links in the
/// temporary directory (none, not writable, not absolute, or over 1024
/// bytes, or over 500 where links lead to 1000-byte prefixes), a link
/// refused (`symlink(2)`: no space, a quota, a file system without
/// symbolic links), or a path that can't be cut (no '/' to cut it at); or,
/// for a relative one, no current directory.
/// The error says what failed, and where. A directory for the links that
/// couldn't be made is the process's for good: each later call gives that
/// error again, without trying again.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn try_short_path(path: &Path) -> io::Result<Cow<'_, Path>> {
    use std::os::unix::ffi::OsStrExt;

    if path.as_os_str().as_bytes().len() < imp::MAX {
        return Ok(Cow::Borrowed(path));
    }
    imp::shorten(path).map(Cow::Owned)
}

/// BackOtter: `path` as it is (see this module).
///
/// # Errors
///
/// None here.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn try_short_path(path: &Path) -> io::Result<Cow<'_, Path>> {
    Ok(Cow::Borrowed(path))
}

/// BackOtter: whether `path` is the directory this process keeps its links
/// in (see this module): `.bko-longpath-PID-N` in the temporary directory,
/// there once a path of `PATH_MAX` bytes or more was shortened. By device
/// and inode, so however `path` spells it (relative, or through a symbolic
/// link). For a walk of a tree that holds the temporary directory: it is no
/// part of the tree, so a backup leaves it out and a restore leaves it
/// alone (ForkAudit1 G7-01, G7-02). Never true elsewhere than on Linux and
/// Android, where there is none.
#[must_use]
pub fn is_short_path_dir(path: &Path) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        imp::is_links_dir(path)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = path;
        false
    }
}

/// BackOtter: has `report` called with the error, the first time in the
/// process that [`short_path`] can't shorten a path (later ones are mostly
/// the same, a directory for the links that couldn't be made, and their
/// paths fail as `ENAMETOOLONG` each): for the caller to log, so that a
/// path left out says why. Only the first `report` given is kept.
pub fn report_short_path_errors(report: fn(&io::Error)) {
    let _ = REPORT.set(report);
}

/// What [`report_short_path_errors`] was given.
static REPORT: OnceLock<fn(&io::Error)> = OnceLock::new();
/// Whether an error went to it.
static REPORTED: AtomicBool = AtomicBool::new(false);

/// `err` to [`REPORT`], if it is set and has had none.
fn report(err: &io::Error) {
    if let Some(report) = REPORT.get() {
        if !REPORTED.swap(true, Ordering::Relaxed) {
            report(err);
        }
    }
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
    /// The longest prefix a link leads to where the links' directory takes
    /// a link's target of this many bytes (tmpfs, btrfs, f2fs, ZFS, ext4 on
    /// 4 KiB blocks: a page, a block or PATH_MAX).
    pub(super) const LONG: usize = MAX / 2;
    /// The longest prefix a link leads to where it doesn't: XFS keeps a
    /// target to 1024 bytes (XFS_SYMLINK_MAXLEN), ext2/3/4 and minix to a
    /// block with its NUL (1023 on 1 KiB blocks, 2047 on 2 KiB blocks: under
    /// LONG, but over SHORT). A component is at most
    /// 255 bytes, so each link still cuts hundreds of bytes off.
    pub(super) const SHORT: usize = 1000;
    /// The longest temporary directory the links are made in, for prefixes
    /// of at most `chunk` bytes: a link's path (it, `/.bko-longpath-PID-N/`,
    /// a number: under 50 bytes more) must be shorter than the shortest
    /// prefix a round cuts, which ends at the last '/' in its first chunk +
    /// 1 bytes, past chunk - NAME_MAX (255), so that each round shortens the
    /// path: 1024 bytes for LONG, 500 for SHORT. `make_dir` takes one of up
    /// to LONG's, and `Links::for_process` refuses one past SHORT's where
    /// `probe` chooses SHORT (0.13.0+backotter.19 and .20 refused one past
    /// 500 bytes everywhere).
    const fn tmp_max(chunk: usize) -> usize {
        chunk / 2
    }
    const _: () = assert!(tmp_max(SHORT) + 50 < SHORT - 255);
    const _: () = assert!(tmp_max(LONG) + 50 < LONG - 255);
    const _: () = assert!(SHORT < LONG && LONG < MAX);

    /// What a links' directory's name begins with: `.bko-longpath-PID-N`.
    const NAME: &str = ".bko-longpath-";

    /// The directory of this process's links, once made (for `remove_dir`).
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    /// This process's links, once their directory is made.
    static LINKS: Mutex<Option<Links>> = Mutex::new(None);
    /// Why their directory couldn't be made, for good: the error's kind and
    /// message.
    static FAILED: OnceLock<(io::ErrorKind, String)> = OnceLock::new();

    /// Links to prefixes, in a directory only they are made in.
    pub(super) struct Links {
        dir: PathBuf,
        /// The longest prefix a link leads to: LONG or SHORT, for good.
        chunk: usize,
        /// The link made to each prefix.
        map: HashMap<PathBuf, PathBuf>,
    }

    /// `ENAMETOOLONG`, saying why.
    fn too_long(why: String) -> io::Error {
        let kind = io::Error::from_raw_os_error(libc::ENAMETOOLONG).kind();
        io::Error::new(kind, why)
    }

    /// `err`, saying what failed first.
    fn failed(what: String, err: io::Error) -> io::Error {
        io::Error::new(err.kind(), format!("{}: {}", what, err))
    }

    /// Absolute, for a link to lead to; without doubled slashes or "."
    /// components, so that one prefix is always spelled one way.
    pub(super) fn absolute(path: &Path) -> io::Result<PathBuf> {
        Ok(if path.is_absolute() {
            path.components().collect()
        } else {
            let cwd = std::env::current_dir()
                .map_err(|err| failed("no current directory for a relative path".into(), err))?;
            cwd.join(path).components().collect()
        })
    }

    pub(super) fn shorten(path: &Path) -> io::Result<PathBuf> {
        let p = absolute(path)?;
        let mut guard = LINKS.lock().unwrap_or_else(PoisonError::into_inner);
        let links = match guard.take() {
            Some(links) => links,
            None => {
                if let Some((kind, why)) = FAILED.get() {
                    return Err(io::Error::new(*kind, why.clone()));
                }
                Links::for_process().inspect_err(|err| {
                    let _ = FAILED.set((err.kind(), err.to_string()));
                })?
            }
        };
        guard.insert(links).shorten(p)
    }

    impl Links {
        /// This process's: a new directory, removed at exit, and the chunk
        /// its file system takes. Called with `LINKS` held, so made once.
        fn for_process() -> io::Result<Links> {
            let dir = make_dir()?;
            let chunk = probe(&dir);
            // A temporary directory within the bound for its chunk (tmp_max):
            // make_dir takes one within LONG's.
            let tmp = dir.parent().unwrap_or(&dir);
            if tmp.as_os_str().as_bytes().len() > tmp_max(chunk) {
                let why = format!(
                    "the temporary directory {} is over {} bytes, where links lead to {} at most",
                    tmp.display(),
                    tmp_max(chunk),
                    chunk
                );
                let _ = std::fs::remove_dir_all(&dir);
                return Err(too_long(why));
            }
            let _ = DIR.set(dir.clone());
            // SAFETY: remove_dir is an extern "C" fn taking nothing.
            let _ = unsafe { libc::atexit(remove_dir) };
            Ok(Links::with_chunk(dir, chunk))
        }

        /// In `dir`, with prefixes of at most `chunk` bytes (LONG or SHORT).
        pub(super) fn with_chunk(dir: PathBuf, chunk: usize) -> Links {
            assert!(chunk == LONG || chunk == SHORT);
            Links { dir, chunk, map: HashMap::new() }
        }

        /// `p` (absolute, as `absolute` spells it) shortened below MAX.
        pub(super) fn shorten(&mut self, mut p: PathBuf) -> io::Result<PathBuf> {
            while p.as_os_str().as_bytes().len() >= MAX {
                let b = p.as_os_str().as_bytes();
                // In bounds: chunk + 1 <= MAX <= the path's length.
                let cut = b[..=self.chunk]
                    .iter()
                    .rposition(|&c| c == b'/')
                    .filter(|&i| i > 0)
                    .ok_or_else(|| too_long(format!("no '/' to cut a path at in its first {} bytes", self.chunk + 1)))?;
                let link = self.link_to(Path::new(OsStr::from_bytes(&b[..cut])))?;
                // Each round must shorten it (a component of thousands of
                // bytes can't be cut).
                if link.as_os_str().as_bytes().len() >= cut {
                    return Err(too_long(format!("the link {} isn't shorter than the {} bytes it leads to", link.display(), cut)));
                }
                p = link.join(OsStr::from_bytes(&b[cut + 1..]));
            }
            Ok(p)
        }

        /// The link to the directory at `prefix`, made the first time, and
        /// again if it has gone since or leads elsewhere (`remake`): a
        /// path through a link that isn't there would be made, by
        /// create_dir_all, as real directories in the links' directory.
        fn link_to(&mut self, prefix: &Path) -> io::Result<PathBuf> {
            if let Some(link) = self.map.get(prefix) {
                if !std::fs::read_link(link).is_ok_and(|to| to == prefix) {
                    self.remake(link, prefix)?;
                }
                return Ok(link.clone());
            }
            let link = self.dir.join(self.map.len().to_string());
            std::os::unix::fs::symlink(prefix, &link)
                .map_err(|err| failed(format!("no link {} made", link.display()), err))?;
            let _ = self.map.insert(prefix.to_path_buf(), link.clone());
            Ok(link)
        }

        /// Makes `link`, one of `map`'s that is gone or leads elsewhere,
        /// to `prefix` again (something removed it: a `restore --delete`
        /// of a tree with the temporary directory in it, a cleaner of
        /// temporary files). The links' directory too, if it is gone: new
        /// and mode 0700, as `make_dir` made it. One that is there must
        /// still be what `make_dir` made, a directory of this user's that
        /// no one else can enter, or the link isn't made in it.
        fn remake(&self, link: &Path, prefix: &Path) -> io::Result<()> {
            use std::os::unix::fs::{DirBuilderExt, MetadataExt};

            match std::fs::DirBuilder::new().mode(0o700).create(&self.dir) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                    let m = std::fs::symlink_metadata(&self.dir)
                        .map_err(|err| failed(format!("no link {} made again", link.display()), err))?;
                    // SAFETY: geteuid takes nothing and always succeeds.
                    let euid = unsafe { libc::geteuid() };
                    if !m.is_dir() || m.uid() != euid || m.mode() & 0o077 != 0 {
                        let why = format!(
                            "no link {} made again: {} is no longer a directory of this process's alone",
                            link.display(),
                            self.dir.display()
                        );
                        return Err(io::Error::new(io::ErrorKind::PermissionDenied, why));
                    }
                    // What is in the link's place, if anything.
                    match std::fs::remove_file(link) {
                        Ok(()) => {}
                        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                        Err(err) => return Err(failed(format!("no link {} made again", link.display()), err)),
                    }
                }
                Err(err) => {
                    return Err(failed(format!("no directory {} made for links again", self.dir.display()), err))
                }
            }
            std::os::unix::fs::symlink(prefix, link)
                .map_err(|err| failed(format!("no link {} made again", link.display()), err))
        }
    }

    /// Whether `path` is this process's links' directory: by its name
    /// first (no system call for any other entry of a walk), then by
    /// device and inode, as `path` may spell it another way than `DIR`
    /// does (relative, through a symbolic link). `LINKS` is taken, so a
    /// directory being made by another thread is known once it answers.
    pub(super) fn is_links_dir(path: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;

        let Some(name) = path.file_name() else {
            return false;
        };
        if !name.as_bytes().starts_with(NAME.as_bytes()) {
            return false;
        }
        // Before LINKS is taken: a short path takes it too.
        let Ok(m) = std::fs::symlink_metadata(super::short_path(path)) else {
            return false;
        };
        let guard = LINKS.lock().unwrap_or_else(PoisonError::into_inner);
        guard.as_ref().is_some_and(|links| {
            links.dir.file_name() == Some(name)
                && std::fs::symlink_metadata(&links.dir).is_ok_and(|d| (d.dev(), d.ino()) == (m.dev(), m.ino()))
        })
    }

    /// LONG if a link in `dir` (new, and only this process's) takes a
    /// target of LONG bytes and keeps it whole, else SHORT: symlink(2)
    /// ENAMETOOLONG (XFS, ext2/3/4 and minix on 1 or 2 KiB blocks), or any other
    /// failure, where SHORT does as well as LONG. The link, `probe` (the
    /// others are numbers), is removed again.
    fn probe(dir: &Path) -> usize {
        let link = dir.join("probe");
        let target = vec![b'p'; LONG];
        let target = Path::new(OsStr::from_bytes(&target));
        if std::os::unix::fs::symlink(target, &link).is_err() {
            return SHORT;
        }
        let kept = std::fs::read_link(&link).is_ok_and(|t| t == target);
        let _ = std::fs::remove_file(&link);
        if kept {
            LONG
        } else {
            SHORT
        }
    }

    /// Makes a directory for links, a new one only this process can enter
    /// (another user's of the same name is passed over), in the temporary
    /// directory, by its canonical path (as it is if it has none): with no
    /// symbolic link in a link's path, which each round would follow again.
    pub(super) fn make_dir() -> io::Result<PathBuf> {
        use std::os::unix::fs::DirBuilderExt;

        let tmp = std::env::temp_dir();
        let tmp = std::fs::canonicalize(&tmp).unwrap_or(tmp);
        if !tmp.is_absolute() {
            let why = format!("the temporary directory {} isn't absolute", tmp.display());
            return Err(io::Error::new(io::ErrorKind::InvalidInput, why));
        }
        if tmp.as_os_str().as_bytes().len() > tmp_max(LONG) {
            return Err(too_long(format!("the temporary directory {} is over {} bytes", tmp.display(), tmp_max(LONG))));
        }
        let pid = std::process::id();
        for n in 0..1000u32 {
            let dir = tmp.join(format!("{NAME}{pid}-{n}"));
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => return Ok(dir),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(failed(format!("no directory {} made for links", dir.display()), err)),
            }
        }
        let why = format!("{NAME}{pid}-0 to -999 all in {}", tmp.display());
        Err(io::Error::new(io::ErrorKind::AlreadyExists, why))
    }

    /// Removes the links' directory at exit: the links only, never what
    /// they lead to (remove_dir_all follows no symbolic link).
    extern "C" fn remove_dir() {
        if let Some(dir) = DIR.get() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// The process's links' directory and chunk, for tests.
    #[cfg(test)]
    pub(super) fn dir() -> Option<(PathBuf, usize)> {
        let guard = LINKS.lock().unwrap_or_else(PoisonError::into_inner);
        guard.as_ref().map(|links| (links.dir.clone(), links.chunk))
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
        deep_tree_of(top, depth, 40)
    }

    /// `deep_tree` with names of `len` bytes.
    fn deep_tree_of(top: &Path, depth: usize, len: usize) -> (PathBuf, (u64, u64)) {
        let c = |s: &[u8]| CString::new(s).unwrap();
        let mut path = top.to_path_buf();
        // SAFETY: plain system calls on C strings and descriptors this owns.
        unsafe {
            let mut fd = libc::open(c(top.as_os_str().as_bytes()).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
            assert!(fd >= 0);
            for i in 0..depth {
                let name = format!("d{i:03}{}", "x".repeat(len - 4));
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

    /// Every link in `dir` leads to at most `chunk` bytes, and with the
    /// short chunk to at most XFS's 1024; returns how many there are.
    fn check_targets(dir: &Path, chunk: usize) -> usize {
        let mut n = 0;
        for e in fs::read_dir(dir).unwrap() {
            let target = fs::read_link(e.unwrap().path()).unwrap();
            let len = target.as_os_str().len();
            assert!(len <= chunk, "{} bytes, chunk {}", len, chunk);
            if chunk == imp::SHORT {
                assert!(len <= 1024, "{} bytes, past XFS's 1024", len);
            }
            n += 1;
        }
        n
    }

    /// Whether a link to a target of LONG bytes can be made in the
    /// temporary directory's file system (in a directory of its own) and
    /// reads back whole: what `probe` asks, asked again. (Over 1024 bytes
    /// isn't enough: ext2/3/4 on 2 KiB blocks takes 2047.)
    fn takes_long_targets() -> bool {
        let dir = imp::make_dir().unwrap();
        let target = PathBuf::from("x".repeat(imp::LONG));
        let link = dir.join("long");
        let ok = std::os::unix::fs::symlink(&target, &link).is_ok()
            && fs::read_link(&link).is_ok_and(|t| t == target);
        fs::remove_dir_all(&dir).unwrap();
        ok
    }

    /// The variable that tells a test it runs in a child process (`child`).
    const CHILD: &str = "BKO_LONGPATH_CHILD";

    /// Whether this is the child process `child` runs a test in. In the
    /// parent, it runs the test `name` (of this module) again in a child
    /// process, with `tmp` the temporary directory, for what a process
    /// decides once, and checks that it ran and passed.
    fn child(name: &str, tmp: &Path) -> bool {
        if std::env::var_os(CHILD).is_some() {
            return true;
        }
        let test = format!("longpath::tests::{}", name);
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .env("TMPDIR", tmp)
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{}", text);
        assert!(text.contains("test result: ok. 1 passed"), "{}", text);
        false
    }

    #[test]
    fn a_link_directory_not_made_is_reported() {
        // No such temporary directory.
        let missing = std::env::temp_dir().join(format!("walkdir-longpath-missing-{}", std::process::id()));
        if !child("a_link_directory_not_made_is_reported", &missing) {
            return;
        }
        let missing = std::env::temp_dir();
        let long = PathBuf::from(format!("/{}", "d/".repeat(3000)));
        let err = try_short_path(&long).unwrap_err();
        eprintln!("{}", err);
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(err.to_string().contains(&*missing.to_string_lossy()), "{}", err);
        // The same error again, without trying again: not once it is there.
        fs::create_dir(&missing).unwrap();
        assert_eq!(try_short_path(&long).unwrap_err().to_string(), err.to_string());
        assert_eq!(fs::read_dir(&missing).unwrap().count(), 0);
        fs::remove_dir(&missing).unwrap();
        // short_path gives the path as it is, and reports it once.
        static SEEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        fn seen(err: &std::io::Error) {
            assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
            SEEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        report_short_path_errors(seen);
        assert!(matches!(short_path(&long), Cow::Borrowed(p) if p == long));
        assert!(matches!(short_path(&long), Cow::Borrowed(_)));
        assert_eq!(SEEN.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn a_symlink_in_the_temporary_directory_is_followed_once() {
        // $TMPDIR is a symbolic link to a directory.
        let base = top("symtmp");
        if std::env::var_os(CHILD).is_none() {
            fs::create_dir(base.join("real")).unwrap();
            std::os::unix::fs::symlink("real", base.join("tmp")).unwrap();
        }
        let tmp = base.join("tmp");
        if !child("a_symlink_in_the_temporary_directory_is_followed_once", &tmp) {
            let _ = std::process::Command::new("rm").arg("-rf").arg(&base).status();
            return;
        }
        let tmp = std::env::temp_dir();
        let canonical = fs::canonicalize(&tmp).unwrap();
        assert_ne!(canonical, tmp);
        let dir = imp::make_dir().unwrap();
        // A path that takes some 27 rounds with the short chunk: through a
        // link to the symbolic link each, it would follow 54 (ELOOP).
        let top = top("deep");
        let (bottom, id) = deep_tree(&top, 700);
        let mut links = imp::Links::with_chunk(dir.clone(), imp::SHORT);
        let short = links.shorten(imp::absolute(&bottom).unwrap()).unwrap();
        let n = check_targets(&dir, imp::SHORT);
        assert!((25..=40).contains(&n), "{} links", n);
        let m = fs::symlink_metadata(&short).unwrap_or_else(|err| panic!("{} links: {}", n, err));
        assert_eq!((m.dev(), m.ino()), id);
        assert_eq!(fs::read(short.join("leaf")).unwrap(), b"deep");
        assert!(dir.starts_with(&canonical), "{}", dir.display());
        fs::remove_dir_all(&dir).unwrap();
        let _ = std::process::Command::new("rm").arg("-rf").arg(&top).status();
    }

    #[test]
    fn a_long_temporary_directory_serves_the_long_chunk() {
        // $TMPDIR of over 500 bytes (of 1024 at most).
        if std::env::var_os(CHILD).is_none() {
            let base = top("tmp700");
            let mut tmp = base.clone();
            while tmp.as_os_str().len() < 700 {
                tmp.push("t".repeat(100));
            }
            fs::create_dir_all(&tmp).unwrap();
            assert!(!child("a_long_temporary_directory_serves_the_long_chunk", &tmp));
            let _ = std::process::Command::new("rm").arg("-rf").arg(&base).status();
            return;
        }
        let tmp = std::env::temp_dir();
        assert!(tmp.as_os_str().len() > 500 && tmp.as_os_str().len() <= 1024);
        let long_ok = takes_long_targets();
        let top = top("deep");
        let (bottom, id) = deep_tree(&top, 330);
        let short = try_short_path(&bottom);
        eprintln!("a {}-byte $TMPDIR; a target of 2048 bytes taken: {}", tmp.as_os_str().len(), long_ok);
        if long_ok {
            // Links to 2048-byte prefixes, as in .16 to .18.
            let short = short.unwrap();
            assert!(short.as_os_str().len() < imp::MAX, "{}", short.display());
            let m = fs::symlink_metadata(&short).unwrap();
            assert_eq!((m.dev(), m.ino()), id);
            assert_eq!(imp::dir().unwrap().1, imp::LONG);
        } else {
            // With the short chunk a link would be too long: refused, and
            // nothing left in $TMPDIR.
            let err = short.unwrap_err();
            assert!(err.to_string().contains("over 500 bytes"), "{}", err);
            let pid = format!(".bko-longpath-{}-", std::process::id());
            assert!(!fs::read_dir(&tmp).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with(&pid)));
        }
        let _ = std::process::Command::new("rm").arg("-rf").arg(&top).status();
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
        let (links, chunk) = imp::dir().unwrap();
        assert!(links.starts_with(fs::canonicalize(std::env::temp_dir()).unwrap()));
        let mode = fs::symlink_metadata(&links).unwrap().mode();
        assert_eq!(mode & 0o777, 0o700);
        // The short chunk where the temporary directory's file system
        // refuses a target of 2048 bytes (XFS: rustic-bko
        // 0.11.4+backotter.17's 2048-byte targets were ENAMETOOLONG there,
        // the long paths left out), the long one where it takes them.
        let long_ok = takes_long_targets();
        eprintln!("links in {}: chunk {chunk}; a target of 2048 bytes taken: {long_ok}", links.display());
        assert_eq!(chunk, if long_ok { imp::LONG } else { imp::SHORT });
        // Each link's target is within it, and fits XFS with the short one.
        let n = check_targets(&links, chunk);
        assert!(n >= 2, "{} links", n);
        // GNU rm removes a tree of any depth.
        let _ = std::process::Command::new("rm").arg("-rf").arg(&top).status();
    }

    #[test]
    fn names_of_name_max_bytes_are_cut_too() {
        // A '/' every 256 bytes: a prefix is cut as far as 255 bytes short
        // of the chunk, and each round still shortens the path.
        let top = top("namemax");
        let (bottom, id) = deep_tree_of(&top, 40, 255);
        assert!(bottom.as_os_str().len() > 2 * imp::MAX);
        let short = short_path(&bottom);
        assert!(short.as_os_str().len() < imp::MAX, "{}", short.display());
        let m = fs::symlink_metadata(&short).unwrap();
        assert_eq!((m.dev(), m.ino()), id);
        assert_eq!(fs::read(short_path(&bottom.join("leaf"))).unwrap(), b"deep");
        let (links, chunk) = imp::dir().unwrap();
        let _ = check_targets(&links, chunk);
        let _ = std::process::Command::new("rm").arg("-rf").arg(&top).status();
    }

    #[test]
    fn the_short_chunk_reaches_the_same_file() {
        // The fallback for XFS and 1 or 2 KiB-block ext2/3/4, wherever the
        // temporary directory is: links of their own, in a directory of
        // their own, to prefixes of at most SHORT bytes.
        let top = top("fallback");
        let (bottom, id) = deep_tree(&top, 330);
        let dir = imp::make_dir().unwrap();
        let mut links = imp::Links::with_chunk(dir.clone(), imp::SHORT);
        let long = imp::absolute(&bottom).unwrap();
        let short = links.shorten(long.clone()).unwrap();
        assert!(short.as_os_str().len() < imp::MAX, "{}", short.display());
        let m = fs::symlink_metadata(&short).unwrap();
        assert_eq!((m.dev(), m.ino()), id);
        assert_eq!(fs::read(short.join("leaf")).unwrap(), b"deep");
        // At least one link per SHORT bytes cut; the same short path again,
        // and no new link for it.
        let n = check_targets(&dir, imp::SHORT);
        assert!(n * imp::SHORT >= long.as_os_str().len() - imp::MAX, "{} links", n);
        assert_eq!(links.shorten(long).unwrap(), short);
        assert_eq!(check_targets(&dir, imp::SHORT), n);
        // 255-byte names too: a '/' every 256 bytes.
        let names = top.join("namemax");
        fs::create_dir(&names).unwrap();
        let (bottom, id) = deep_tree_of(&names, 40, 255);
        let short = links.shorten(imp::absolute(&bottom).unwrap()).unwrap();
        assert!(short.as_os_str().len() < imp::MAX, "{}", short.display());
        let m = fs::symlink_metadata(&short).unwrap();
        assert_eq!((m.dev(), m.ino()), id);
        assert!(check_targets(&dir, imp::SHORT) > n);
        fs::remove_dir_all(&dir).unwrap();
        let _ = std::process::Command::new("rm").arg("-rf").arg(&top).status();
    }

    /// ForkAudit1 G7-01: a link that has gone (a `restore --delete` of a
    /// tree with the temporary directory in it removed the links'
    /// directory as an extra entry) is made again, its directory too, and
    /// the short path reaches the same file; 0.14.0+backotter.1 gave the
    /// path through the missing link, which create_dir_all then built as
    /// real directories in the temporary directory.
    #[test]
    fn a_link_that_is_gone_is_made_again() {
        let top = top("regone");
        let (bottom, id) = deep_tree(&top, 330);
        let dir = imp::make_dir().unwrap();
        let mut links = imp::Links::with_chunk(dir.clone(), imp::SHORT);
        let long = imp::absolute(&bottom).unwrap();
        let short = links.shorten(long.clone()).unwrap();
        let n = check_targets(&dir, imp::SHORT);
        assert!(n >= 2, "{} links", n);
        let reaches = |short: &Path| {
            let m = fs::symlink_metadata(short).unwrap();
            assert_eq!((m.dev(), m.ino()), id);
            assert_eq!(fs::read(short.join("leaf")).unwrap(), b"deep");
        };
        reaches(&short);
        // One link gone: made again, and no other made.
        fs::remove_file(dir.join("1")).unwrap();
        assert!(fs::symlink_metadata(&short).is_err());
        assert_eq!(links.shorten(long.clone()).unwrap(), short);
        reaches(&short);
        assert_eq!(check_targets(&dir, imp::SHORT), n);
        // One that leads elsewhere: put right.
        fs::remove_file(dir.join("0")).unwrap();
        std::os::unix::fs::symlink("/nowhere", dir.join("0")).unwrap();
        assert_eq!(links.shorten(long.clone()).unwrap(), short);
        reaches(&short);
        // The whole directory gone: made again, mode 0700, with every link.
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(links.shorten(long.clone()).unwrap(), short);
        reaches(&short);
        assert_eq!(fs::symlink_metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(check_targets(&dir, imp::SHORT), n);
        // Nothing real was made in the temporary directory for the path.
        for e in fs::read_dir(&dir).unwrap() {
            assert!(e.unwrap().file_type().unwrap().is_symlink());
        }
        // A directory in its place that others can enter isn't used.
        fs::remove_dir_all(&dir).unwrap();
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let err = links.shorten(long.clone()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{}", err);
        assert!(err.to_string().contains("no longer a directory of this process's alone"), "{}", err);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        // Nor a file there; and no temporary directory at all is an error
        // that names the directory.
        fs::remove_dir(&dir).unwrap();
        fs::write(&dir, b"").unwrap();
        assert!(links.shorten(long.clone()).is_err());
        fs::remove_file(&dir).unwrap();
        let mut gone = imp::Links::with_chunk(top.join("no-such-tmp").join("links"), imp::SHORT);
        let _ = fs::create_dir_all(top.join("no-such-tmp").join("links"));
        let short = gone.shorten(long.clone()).unwrap();
        reaches(&short);
        fs::remove_dir_all(top.join("no-such-tmp")).unwrap();
        let err = gone.shorten(long).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{}", err);
        assert!(err.to_string().contains("made for links again"), "{}", err);
        let _ = std::process::Command::new("rm").arg("-rf").arg(&top).status();
    }

    /// ForkAudit1 G7-01, G7-02: the process's links' directory is known
    /// however its path is spelled, and no other directory is taken for it.
    #[test]
    fn the_links_directory_is_known() {
        let top = top("known");
        let (bottom, _) = deep_tree(&top, 120);
        let _ = short_path(&bottom.join("leaf"));
        let (links, _) = imp::dir().unwrap();
        assert!(is_short_path_dir(&links));
        // Through a symbolic link to the temporary directory, and relative.
        let name = links.file_name().unwrap();
        std::os::unix::fs::symlink(links.parent().unwrap(), top.join("tmp")).unwrap();
        assert!(is_short_path_dir(&top.join("tmp").join(name)));
        let cwd = std::env::current_dir().unwrap();
        let up = "../".repeat(cwd.components().count());
        let relative = PathBuf::from(format!("{}{}", up, links.to_str().unwrap().trim_start_matches('/')));
        assert!(relative.is_relative());
        assert!(is_short_path_dir(&relative));
        // Not its parent, a link in it, one of the same name elsewhere,
        // another process's beside it, or one that isn't there.
        assert!(!is_short_path_dir(links.parent().unwrap()));
        assert!(!is_short_path_dir(&links.join("0")));
        fs::create_dir(top.join(name)).unwrap();
        assert!(!is_short_path_dir(&top.join(name)));
        let other = links.parent().unwrap().join(".bko-longpath-0-0");
        assert!(!is_short_path_dir(&other));
        assert!(!is_short_path_dir(Path::new("/")));
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
