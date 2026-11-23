//! BackOtter: whether a restore's destination is fresh
//! ([`restore_target_is_fresh`]), and so gets the metadata of the node
//! restored there.

use std::path::Path;

/// BackOtter: whether a restore into `dest` gives `dest` the metadata of
/// the node it restores there (`restore SNAP:subfolder DEST`).
///
/// Only when `dest` is fresh: it doesn't exist (the restore creates it), or
/// every entry found walking it (no symlink followed) is one of
///
/// - (a) an entry a file system makes itself ([`made_by_file_system`]:
///   `lost+found`, a directory; FreeBSD UFS's `.snap`, a directory, and
///   `.sujournal`, a regular file; nilfs2's `.nilfs`, an empty regular
///   file), whatever it holds; on Haiku also the empty `trash` directory
///   its Tracker makes on every volume mounted ([`made_by_tracker`]);
/// - (b) a directory that is a mount point: its device (`st_dev`) differs
///   from its parent's. That is also a ZFS dataset's and a btrfs
///   subvolume's root, which have devices of their own. What it holds
///   must again be (a), (b) or (c), relative to it;
/// - (c) a directory on the path to one: it holds only (a), (b) and (c),
///   and at least one (b) at some depth;
///
/// in at most 4096 directories ([`FRESH_TARGET_MAX_DIRS`]). That is a new
/// file system's root with the new file systems of the system restored
/// mounted below it (`/boot`, `/boot/efi`, `/home`, ZFS datasets, btrfs
/// subvolumes): BackOtter's bare-metal restore. Anything else (a file, a
/// symlink, a device, a plain directory, even empty, on `dest`'s own file
/// system, a directory that can't be read) means `dest` stays as it is
/// (owner, mode, times, extended attributes, ACLs and flags), as in stock
/// rustic: a freshly booted server's `/tmp`, with nothing in it but empty
/// `.X11-unix`, `.ICE-unix` and `systemd-private-*/tmp`, keeps its sticky
/// bit. A symlink at `dest` is not fresh. Nor is an existing `dest` that
/// is sticky or that others may write in (mode bits 01000 or 0002,
/// [`shared_dir`]), even empty: a shared directory such as an empty
/// `/tmp` or `/dev/shm` keeps its mode, owner, extended attributes and
/// ACLs. mkfs, newfs, `zfs create` and `btrfs subvolume create` never
/// make such a root. Where there are no device numbers (Windows), no
/// directory is a mount point, and there are no such mode bits. As in
/// BackOtter's restic. Call it before the restore starts.
#[must_use]
pub fn restore_target_is_fresh(dest: impl AsRef<Path>) -> bool {
    fresh_target_with(dest.as_ref(), &|_, meta| device_of(meta))
}

/// The device of the file of `meta`, where there is one.
#[cfg(unix)]
#[allow(clippy::unnecessary_wraps)] // None on other systems
fn device_of(meta: &std::fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(meta.dev())
}

/// The device of the file of `meta`, where there is one.
#[cfg(not(unix))]
const fn device_of(_meta: &std::fs::Metadata) -> Option<u64> {
    None
}

/// Whether the directory of `meta` is sticky or others may write in it
/// (mode bits 01000 or 0002): a directory shared by its users, like
/// `/tmp`, never a new file system's root.
#[cfg(unix)]
fn shared_dir(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o1002 != 0
}

/// Whether the directory of `meta` is sticky or others may write in it:
/// never, where there are no such mode bits.
#[cfg(not(unix))]
const fn shared_dir(_meta: &std::fs::Metadata) -> bool {
    false
}

/// The device of a path, given its (`lstat`) metadata.
type DeviceOf<'a> = dyn Fn(&Path, &std::fs::Metadata) -> Option<u64> + 'a;

/// [`restore_target_is_fresh`], with the devices from `device`.
fn fresh_target_with(dest: &Path, device: &DeviceOf<'_>) -> bool {
    match std::fs::symlink_metadata(dest) {
        Err(err) => err.kind() == std::io::ErrorKind::NotFound,
        Ok(meta) if meta.is_dir() && !shared_dir(&meta) => {
            let mut budget = FRESH_TARGET_MAX_DIRS;
            fresh_dir(dest, device(dest, &meta), device, &mut budget).is_some()
        }
        Ok(_) => false,
    }
}

/// The most directories [`restore_target_is_fresh`] looks at, `dest`
/// included: a destination with more isn't fresh. As BackOtter's restic.
const FRESH_TARGET_MAX_DIRS: usize = 4096;

/// Whether the directory `dir`, on the device `dev`, holds only entries of
/// a fresh target (see [`restore_target_is_fresh`]): None if not, else
/// whether it holds a mount point at some depth. Looks at no more than
/// `budget` directories, `dir` included, and takes those off it.
fn fresh_dir(
    dir: &Path,
    dev: Option<u64>,
    device: &DeviceOf<'_>,
    budget: &mut usize,
) -> Option<bool> {
    *budget = budget.checked_sub(1)?;
    let mut holds_mount = false;
    for entry in std::fs::read_dir(dir).ok()? {
        let path = entry.ok()?.path();
        // Doesn't follow a symlink; does see what is mounted on `path`.
        let meta = std::fs::symlink_metadata(&path).ok()?;
        if made_by_file_system(path.file_name()?, &meta) || made_by_tracker(&path, &meta) {
            continue;
        }
        if !meta.is_dir() {
            return None;
        }
        let sub_dev = device(&path, &meta);
        let mount_point = sub_dev.is_some() && dev.is_some() && sub_dev != dev;
        let holds = fresh_dir(&path, sub_dev, device, budget)?;
        if !(mount_point || holds) {
            // A plain directory on `dir`'s file system.
            return None;
        }
        holds_mount = true;
    }
    Some(holds_mount)
}

/// Whether the entry `name`, with the (`lstat`) metadata `meta`, is one a
/// new file system has: `lost+found`, a directory (ext2/3/4, bcachefs,
/// illumos UFS); FreeBSD UFS's `.snap`, a directory (newfs without `-n`),
/// and `.sujournal`, a regular file (newfs `-j`); nilfs2's `.nilfs`, an
/// empty regular file (mkfs.nilfs2 2.0.0 to 2.2.9, as in Ubuntu 24.04).
/// As BackOtter's restic.
fn made_by_file_system(name: &std::ffi::OsStr, meta: &std::fs::Metadata) -> bool {
    let file_type = meta.file_type();
    (file_type.is_dir() && (name == "lost+found" || name == ".snap"))
        || (file_type.is_file() && name == ".sujournal")
        || (file_type.is_file() && name == ".nilfs" && meta.len() == 0)
}

/// BackOtter: whether the entry `path`, with the (`lstat`) metadata
/// `meta`, is the `trash` directory that Haiku's Tracker makes, empty, on
/// every BFS volume as soon as it is mounted, a new one too (a Haiku
/// rescuer runs the desktop): on Haiku only, where a new file system's
/// root would otherwise never be fresh, and the restore would leave it
/// mkfs's metadata and the time of its last entry's creation. One that
/// holds anything, or isn't a directory, isn't Tracker's alone.
fn made_by_tracker(path: &Path, meta: &std::fs::Metadata) -> bool {
    cfg!(target_os = "haiku") && empty_trash(path, meta)
}

/// Whether `path`, with the (`lstat`) metadata `meta`, is an empty
/// directory named `trash` ([`made_by_tracker`], on any system).
fn empty_trash(path: &Path, meta: &std::fs::Metadata) -> bool {
    meta.is_dir()
        && path.file_name() == Some(std::ffi::OsStr::new("trash"))
        && std::fs::read_dir(path).is_ok_and(|mut dir| dir.next().is_none())
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, path::PathBuf};

    use super::*;

    /// A destination is fresh when it doesn't exist, or holds only what a
    /// file system makes itself (`lost+found`, `.snap`, `.sujournal`,
    /// an empty `.nilfs`),
    /// mount points, and directories on the path to them, at any depth. The
    /// mount points are made up here: a directory in `mounts` and what is
    /// below it are on a device of their own.
    #[cfg(unix)]
    #[test]
    fn target_fresh_only_when_new_or_empty() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("d");
        let mounts = RefCell::new(Vec::<PathBuf>::new());
        let device = |path: &Path, _: &std::fs::Metadata| {
            let mounts = mounts.borrow();
            let i = mounts.iter().position(|m| path.starts_with(m));
            Some(i.map_or(0, |i| i as u64 + 1))
        };
        let fresh = |d: &Path| fresh_target_with(d, &device);
        let mount = |sub: &str| {
            std::fs::create_dir_all(d.join(sub)).unwrap();
            // The deepest first, so that it is found first.
            mounts.borrow_mut().insert(0, d.join(sub));
        };
        assert!(fresh(&d));
        std::fs::create_dir(&d).unwrap();
        // As mkfs makes it, whatever the umask.
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(fresh(&d));
        std::fs::create_dir(d.join("lost+found")).unwrap();
        std::fs::write(d.join("lost+found/#123"), b"x").unwrap();
        assert!(fresh(&d), "lost+found only");
        std::fs::write(d.join(".sujournal"), b"").unwrap();
        std::fs::create_dir(d.join(".snap")).unwrap();
        assert!(fresh(&d), "UFS's own entries");

        // A freshly booted server's /tmp: empty directories on its own
        // file system.
        let tmp = dir.path().join("tmp");
        for sub in [".X11-unix", ".ICE-unix", ".font-unix", "systemd-private-1-x/tmp"] {
            std::fs::create_dir_all(tmp.join(sub)).unwrap();
        }
        assert!(!fresh(&tmp), "/tmp");
        std::fs::create_dir(d.join("srv")).unwrap();
        assert!(!fresh(&d), "an empty directory");
        std::fs::remove_dir(d.join("srv")).unwrap();

        // Mount points: /boot and /boot/efi, /home with its lost+found,
        // /var with UFS's own, /usr/local below a plain /usr (a ZFS
        // dataset's parent).
        for sub in ["boot", "boot/efi", "home", "var", "usr/local"] {
            mount(sub);
        }
        std::fs::create_dir(d.join("home/lost+found")).unwrap();
        std::fs::create_dir(d.join("var/.snap")).unwrap();
        std::fs::write(d.join("var/.sujournal"), b"").unwrap();
        assert!(fresh(&d), "bare-metal root");

        // Anything else, at any depth, is not.
        for (what, make) in [
            ("file", "f"),
            ("file in a mount point", "boot/efi/f"),
            ("file on the path to a mount point", "usr/f"),
            ("empty directory in a mount point", "boot/grub/"),
            ("empty directory beside a mount point", "usr/share/"),
            ("lost+found file", "usr/lost+found"),
            (".sujournal directory", "home/.sujournal/"),
            (".snap file", "home/.snap"),
        ] {
            let path = d.join(make.trim_end_matches('/'));
            if make.ends_with('/') {
                std::fs::create_dir(&path).unwrap();
            } else {
                std::fs::write(&path, b"x").unwrap();
            }
            assert!(!fresh(&d), "{what}");
            if path.is_dir() {
                std::fs::remove_dir(&path).unwrap();
            } else {
                std::fs::remove_file(&path).unwrap();
            }
            assert!(fresh(&d), "{what} removed");
        }
        // A directory on the path to a mount point holding only
        // lost+found is a plain directory.
        std::fs::create_dir_all(d.join("opt/lost+found")).unwrap();
        assert!(!fresh(&d), "a plain directory with lost+found");
        std::fs::remove_dir_all(d.join("opt")).unwrap();

        // At most 4096 directories: d, boot, efi, home, var, usr, local,
        // many and those in it (not lost+found or .snap).
        let have = 8;
        mount("many");
        for i in 0..FRESH_TARGET_MAX_DIRS - have {
            mount(&format!("many/{i}"));
        }
        assert!(fresh(&d), "4096 directories");
        mount("many/one more");
        assert!(!fresh(&d), "4097 directories");
        std::fs::remove_dir_all(d.join("many")).unwrap();
        assert!(fresh(&d));

        // A symlink, even to a directory, is not followed.
        std::os::unix::fs::symlink("/", d.join("boot/link")).unwrap();
        assert!(!fresh(&d), "symlink");
        std::fs::remove_file(d.join("boot/link")).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&d, &link).unwrap();
        assert!(!fresh(&link), "symlink as the destination");
        let f = dir.path().join("f");
        std::fs::write(&f, b"x").unwrap();
        assert!(!fresh(&f), "file as the destination");

        // A shared directory, sticky or writable by others, is not fresh,
        // even empty: an empty /tmp or /dev/shm.
        let shm = dir.path().join("shm");
        std::fs::create_dir(&shm).unwrap();
        for (mode, want) in [
            (0o1777, false),
            (0o1755, false),
            (0o777, false),
            (0o757, false),
            (0o775, true),
            (0o755, true),
            (0o700, true),
        ] {
            std::fs::set_permissions(&shm, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(fresh(&shm), want, "empty, mode {mode:o}");
            assert_eq!(restore_target_is_fresh(&shm), want, "empty, mode {mode:o}");
        }
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(!fresh(&d), "bare-metal root, mode 1777");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(fresh(&d));

        // The devices restore_target_is_fresh itself sees: none of these
        // directories is a mount point.
        assert!(restore_target_is_fresh(dir.path().join("new")));
        let lf = dir.path().join("lf");
        std::fs::create_dir_all(lf.join("lost+found/x")).unwrap();
        assert!(restore_target_is_fresh(&lf));
        assert!(!restore_target_is_fresh(&d));
        assert!(!restore_target_is_fresh(&tmp));
    }

    /// A new nilfs2 file system's root may hold `.nilfs`, an empty regular
    /// file (mkfs.nilfs2 2.0.0 to 2.2.9): it is fresh, as are its mount
    /// points' roots with one. A `.nilfs` with something in it, or of
    /// another type, is not what mkfs made. The mount points are made up
    /// here, as above.
    #[cfg(unix)]
    #[test]
    fn target_fresh_with_nilfs_entry() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("d");
        let mounts = RefCell::new(Vec::<PathBuf>::new());
        let device = |path: &Path, _: &std::fs::Metadata| {
            let mounts = mounts.borrow();
            let i = mounts.iter().position(|m| path.starts_with(m));
            Some(i.map_or(0, |i| i as u64 + 1))
        };
        let fresh = |d: &Path| fresh_target_with(d, &device);
        let nilfs = d.join(".nilfs");
        std::fs::create_dir(&d).unwrap();
        std::fs::write(&nilfs, b"").unwrap();
        assert!(fresh(&d), "an empty .nilfs only");
        assert!(restore_target_is_fresh(&d), "an empty .nilfs only");

        std::fs::write(&nilfs, b"x").unwrap();
        assert!(!fresh(&d), ".nilfs with data");
        assert!(!restore_target_is_fresh(&d), ".nilfs with data");
        std::fs::remove_file(&nilfs).unwrap();
        std::fs::create_dir(&nilfs).unwrap();
        assert!(!fresh(&d), ".nilfs directory");
        std::fs::remove_dir(&nilfs).unwrap();
        // To an empty regular file, so following it would accept it.
        let empty = dir.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        std::os::unix::fs::symlink(&empty, &nilfs).unwrap();
        assert!(!fresh(&d), ".nilfs symlink to an empty file");
        assert!(!restore_target_is_fresh(&d), ".nilfs symlink to an empty file");
        std::fs::remove_file(&nilfs).unwrap();
        std::fs::write(d.join(".nilfs2"), b"").unwrap();
        assert!(!fresh(&d), "another name");
        std::fs::remove_file(d.join(".nilfs2")).unwrap();

        std::fs::write(&nilfs, b"").unwrap();
        std::fs::create_dir(d.join("lost+found")).unwrap();
        assert!(fresh(&d), ".nilfs and lost+found");
        std::fs::remove_dir(d.join("lost+found")).unwrap();

        // A mount point below, itself a new nilfs2 root.
        let boot = d.join("boot");
        std::fs::create_dir(&boot).unwrap();
        mounts.borrow_mut().push(boot.clone());
        assert!(fresh(&d), ".nilfs and a mount point");
        std::fs::write(boot.join(".nilfs"), b"").unwrap();
        assert!(fresh(&d), ".nilfs in the root and in a mount point");
        std::fs::write(boot.join(".nilfs"), b"x").unwrap();
        assert!(!fresh(&d), ".nilfs with data in a mount point");
        std::fs::write(boot.join(".nilfs"), b"").unwrap();
        std::fs::write(boot.join("f"), b"").unwrap();
        assert!(!fresh(&d), "an empty file beside .nilfs");
    }

    /// Haiku's Tracker puts an empty `trash` directory on every volume it
    /// sees mounted, a new one too: on Haiku that root is fresh, as with
    /// lost+found, elsewhere not; a `trash` with something in it, or of
    /// another type, or another name, is not Tracker's alone anywhere.
    #[cfg(unix)]
    #[test]
    fn target_fresh_with_tracker_trash() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("d");
        let trash = d.join("trash");
        let lstat = |p: &Path| std::fs::symlink_metadata(p).unwrap();
        std::fs::create_dir_all(&trash).unwrap();
        assert!(empty_trash(&trash, &lstat(&trash)));
        assert_eq!(
            restore_target_is_fresh(&d),
            cfg!(target_os = "haiku"),
            "an empty trash only"
        );
        std::fs::create_dir(d.join("lost+found")).unwrap();
        assert_eq!(
            restore_target_is_fresh(&d),
            cfg!(target_os = "haiku"),
            "with lost+found"
        );
        std::fs::remove_dir(d.join("lost+found")).unwrap();

        std::fs::write(trash.join("f"), b"").unwrap();
        assert!(!empty_trash(&trash, &lstat(&trash)), "trash with a file");
        assert!(!restore_target_is_fresh(&d), "trash with a file");
        std::fs::remove_file(trash.join("f")).unwrap();
        std::fs::remove_dir(&trash).unwrap();

        std::fs::write(&trash, b"").unwrap();
        assert!(!empty_trash(&trash, &lstat(&trash)), "trash a file");
        assert!(!restore_target_is_fresh(&d), "trash a file");
        std::fs::remove_file(&trash).unwrap();
        // To an empty directory, so following it would accept it.
        let empty = dir.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        std::os::unix::fs::symlink(&empty, &trash).unwrap();
        assert!(!empty_trash(&trash, &lstat(&trash)), "trash symlink");
        assert!(!restore_target_is_fresh(&d), "trash symlink");
        std::fs::remove_file(&trash).unwrap();
        let other = d.join("Trash");
        std::fs::create_dir(&other).unwrap();
        assert!(!empty_trash(&other, &lstat(&other)), "another name");
        assert!(!restore_target_is_fresh(&d), "another name");
    }

    /// As root on Linux, with tmpfs mounts: a new root with /boot and
    /// /boot/efi mounted below it is fresh; an empty directory or a file
    /// on any of them is not.
    #[cfg(target_os = "linux")]
    #[test]
    fn target_fresh_with_a_mount_in_it() {
        if !nix::unistd::geteuid().is_root() {
            eprintln!("not root: no mount");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let boot = d.join("boot");
        let efi = boot.join("efi");
        let mount = |at: &Path| {
            std::fs::create_dir_all(at).unwrap();
            std::process::Command::new("mount")
                .args(["-t", "tmpfs", "bkotest"])
                .arg(at)
                .status()
                .is_ok_and(|s| s.success())
        };
        if !mount(&boot) {
            eprintln!("tmpfs not mounted");
            return;
        }
        let results = (|| {
            if !mount(&efi) {
                return None;
            }
            // An empty tmpfs (mode 1777) as the destination, as /dev/shm,
            // is not fresh; mounted below a fresh one, it may be.
            let mut results = vec![("empty tmpfs", false, restore_target_is_fresh(&efi))];
            std::fs::create_dir(efi.join("lost+found")).unwrap();
            results.push(("boot and boot/efi mounted", true, restore_target_is_fresh(d)));
            for (what, sub) in [
                ("empty directory in efi", "efi/EFI"),
                ("empty directory in boot", "grub"),
            ] {
                std::fs::create_dir(boot.join(sub)).unwrap();
                results.push((what, false, restore_target_is_fresh(d)));
                std::fs::remove_dir(boot.join(sub)).unwrap();
            }
            std::fs::write(efi.join("vmlinuz"), b"x").unwrap();
            results.push(("file in efi", false, restore_target_is_fresh(d)));
            std::fs::remove_file(efi.join("vmlinuz")).unwrap();
            std::fs::create_dir(d.join("tmp")).unwrap();
            results.push(("empty directory beside boot", false, restore_target_is_fresh(d)));
            std::fs::remove_dir(d.join("tmp")).unwrap();
            std::fs::write(d.join(".nilfs"), b"").unwrap();
            std::fs::write(boot.join(".nilfs"), b"").unwrap();
            results.push((
                "empty .nilfs in the root and in boot",
                true,
                restore_target_is_fresh(d),
            ));
            std::fs::write(boot.join(".nilfs"), b"x").unwrap();
            results.push((
                "a .nilfs with data in boot",
                false,
                restore_target_is_fresh(d),
            ));
            std::fs::remove_file(boot.join(".nilfs")).unwrap();
            std::fs::remove_file(d.join(".nilfs")).unwrap();
            results.push(("all removed", true, restore_target_is_fresh(d)));
            Some(results)
        })();
        let _ = std::process::Command::new("umount").arg(&efi).status();
        let _ = std::process::Command::new("umount").arg(&boot).status();
        let results = results.expect("tmpfs mounted on boot/efi");
        for (what, want, got) in results {
            assert_eq!(got, want, "{what}");
        }
    }
}
