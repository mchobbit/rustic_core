# rustic_core for BackOtter

This branch (`backotter`) is rustic_core with the patches that BackOtter's
rescue stick needs, kept on top of rustic_core's latest release. It is not a
separate project: the branch is rebased onto every new rustic_core release
rather than merged. rustic itself uses it through a `[patch.crates-io]` entry
on the `backotter` branch of github.com/mchobbit/rustic.

It writes the same metadata as BackOtter's restic (branch `backotter` of
github.com/mchobbit/restic), under the same names and in the same form, so
that either program restores what the other backed up.

## What it adds

- restic's generic attributes (`generic_attributes` in a tree's nodes), which
  stock rustic drops without a word: a node's `Metadata` carries them
  (`backend/node/generic_attributes.rs`), so they survive reading and writing
  trees, and a backup records these (`backend/osattrs/`):
  - `linux.inode_flags`: the `chattr(1)` flags (`FS_IOC_GETFLAGS`), limited
    to those a user can set, and casefolding (`F`).
  - `linux.project_id`: the project ID (`FS_IOC_FSGETXATTR`) that project
    quotas count by, of regular files and directories.
  - `freebsd.file_flags`: FreeBSD's `chflags(1)` flags (`st_flags`); `uarch`
    only along with others, since ZFS sets it on every file.
  - `freebsd.acl_access`, `freebsd.acl_default`: POSIX.1e ACLs (UFS mounted
    `acls`), access and directories' default.
  - `freebsd.acl_nfs4`: NFSv4 ACLs (ZFS, UFS mounted `nfsv4acls`).
  - `freebsd.system_extattrs`: extended attributes in the system namespace,
    except those UFS stores ACLs in.
  - `illumos.acl`: ZFS's ACLs on illumos (NFSv4-style ACEs).
  - `illumos.system_attributes`: illumos' system attributes (`chmod(1)`'s
    `S+v...`), as a mask; `archive` and `av_modified` only along with
    others, since ZFS sets them on every file.
  - `openbsd.file_flags`: OpenBSD's `chflags(1)` flags.
  - `netbsd.file_flags`: NetBSD's `chflags(1)` flags, all but the three
    the kernel manages (`SF_SNAPSHOT`, `SF_SNAPINVAL`, and `SF_LOG`, which
    it takes from userland but which marks the WAPBL journal's inode): the
    mask `0xff1fffff`.
  - `netbsd.acl_access`, `netbsd.acl_default`, `netbsd.acl_nfs4`,
    `netbsd.system_extattrs`: as the FreeBSD ones, in the same JSON form
    and by the same rules (NetBSD took FreeBSD's ACL code), on FFSv2ea
    (`newfs -O 2ea`) mounted with `posix1eacls` or `nfs4acls`; plain FFSv2
    has neither ACLs nor extended attributes, and gets none, quietly.
    Unlike FreeBSD, NetBSD gives symlinks ACLs of their own, which are kept
    and restored. The ACL system calls go by their numbers
    (`__acl_get_link` 487, `__acl_set_link` 488, `lpathconf` 499), and
    NetBSD's `pathconf(2)` names are its own (`_PC_ACL_EXTENDED` 14,
    `_PC_ACL_NFS4` 17, where FreeBSD has 59 and 64); the rest is one module,
    `osattrs/freebsd_netbsd.rs`, for both.
  - `dragonfly.file_flags`: DragonFly's `chflags(1)` flags, all 32 bits
    (root can set each of them on HAMMER2 and UFS). DragonFly's file
    systems have no ACLs or extended attributes.
  - `unix.sparse`: `true` for a regular file with holes, on every Unix, by
    the rule BackOtter's restic follows too, from the file's lstat:
    1. If its size is 0, or its 512-byte blocks cover its size, it has
       none (a preallocated file, a swap file).
    2. On a system without a `SEEK_HOLE` probe, the blocks decide: it has
       holes. The probing systems are Linux and Android, FreeBSD, macOS and
       illumos; NetBSD, OpenBSD, DragonFly, Solaris and the rest go by the
       blocks. DragonFly has `SEEK_HOLE`, but HAMMER2 answers `EOPNOTSUPP`
       and tmpfs always the file's size, which would hide real holes.
    3. Otherwise `lseek(fd, 0, SEEK_HOLE)`: a hole before the end means
       holes, none (the size) means none (a file on a compressing file
       system). `EINVAL`, `ENOTSUP`, `EOPNOTSUPP` or `ENOTTY` (a file system
       that can't answer) leave it to the blocks: holes. Any other error (a
       file that can't be opened, `ENXIO`, `EACCES`, ...) means none.
    4. On Linux the probe uses the descriptor the file is opened with for
       its flags and project ID, once per file; if that open failed, the
       file has none. Elsewhere the file is opened for the probe, with
       `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY|O_CLOEXEC`, and must still
       be the file the lstat saw.
    On ZFS a probe of a file with unwritten changes waits for them to be
    written (a transaction group), as it does for BackOtter's restic, which
    probes the same files.
  A file only gets an attribute when it has something the mode doesn't say
  (flags, a project ID, a non-trivial ACL, holes). A generic attribute
  rustic doesn't know at all gets a warning, once; one of another system is
  skipped quietly. A known attribute with a value that can't be read
  (`linux.inode_flags`, `linux.project_id`, `unix.sparse`, `*.file_flags`)
  is skipped with a warning once per attribute name, as in BackOtter's
  restic; it isn't an error. A project ID of 0 is left as the file has it.
- On Linux, regular files and directories are opened for their flags,
  project ID and holes with `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY|O_CLOEXEC`
  (and `O_DIRECTORY`), and the opened file checked: one of another type, or
  at backup another file than the lstat saw, is skipped. Symlinks, FIFOs,
  sockets and devices have no flags or project IDs either way.
- A backup keeps each file's access time, as BackOtter's restic does (stock
  rustic stores the mtime there; `backup --set-atime mtime` still does), and
  `rewrite` keeps it too (`--set-atime` defaults to `yes`, as `restic
  rewrite` keeps it). A backup doesn't change the access times it saves: on
  Linux and Android, files are read and directories listed with
  `O_NOATIME`, and, where that is refused (`EPERM`: neither the owner nor
  `CAP_FOWNER`), without it. Directories are listed by a vendored walkdir
  2.5.0 (`vendor/walkdir`, swapped in with `[patch.crates-io]`, which
  reaches the ignore crate's walker too): std's `read_dir` has no way to
  pass `O_NOATIME`. Other systems have no `O_NOATIME`, and update access
  times as BackOtter's restic does.
- A restore gives files the uid and gid they were saved with, as restic
  does: stock rustic looks the owners' names up in the users of the system
  it runs on, which on a rescue system are the wrong ones. `restore
  --by-name` (or `--ownership-by-name`, restic's name for it) looks them up
  by name; `--numeric-id` is still accepted.
- A file is restored sparse if, and only if, it is marked `unix.sparse` (or
  `restore --sparse by-content` asks for every file; `--sparse no` doesn't
  unmark one), and it goes into a new, empty file: nothing was at its path
  when the restore planned it (after `--delete` removed what was there).
  That is checked on disk, not by what the walk of the destination saw (a
  file below a symlinked directory). A file restored sparse is sized
  without being allocated, and each blob's longest all-zero prefix is left
  unwritten (an all-zero blob not written at all), as BackOtter's restic
  does; if it turns out not to be empty after all (a race), it is emptied
  first, so that no hole keeps old contents. Stock rustic's `--sparse
  by-content` left old contents where a zero chunk went.
- Every other file is allocated in full: a new file, or an existing one the
  restore writes into (cut to length first, if longer), is preallocated
  when it is sized (`fallocate(2)` on Linux, `F_PREALLOCATE` on macOS, as
  restic does; nothing elsewhere), and gets every byte, zeros included. An
  existing file left as it is, of the right contents, has its holes
  allocated on Linux and macOS, unless it is restored sparse: a swap file
  left with holes by an interrupted restore. Not under `--dry-run`.
- On FreeBSD and NetBSD, extended attributes are named as restic names them:
  the user namespace only, under bare names (stock rustic keeps both
  namespaces, as `user.NAME` and `system.NAME`, and restores the system
  namespace's raw UFS ACL storage). Stock rustic's FreeBSD snapshots
  therefore restore their user attributes with a `user.` in front.
- On FreeBSD and NetBSD the user namespace is listed directly: the xattr
  crate (1.6) names the last attribute of the system namespace as one of
  the user namespace, which a restore then creates, empty.
- On illumos, extended attributes are named attribute files (`runat(1)`),
  which the xattr crate doesn't support: they are read and written through
  `openat(2)` with `O_XATTR`, without the `SUNWattr_ro` and `SUNWattr_rw`
  system attribute views, as BackOtter's restic does.
- A file that can't have extended attributes (a FIFO on ZFS) has none,
  rather than a warning, as in restic.
- A backup keeps the metadata of the directory it backs up (stock rustic
  stores it as a bare directory, mode 0755 and nothing else), so that
  restoring `SNAP:path` can give the destination that directory's metadata,
  as BackOtter's rustic does. It goes by the name it's saved as
  (`--as-path`), and `/` still has no node, as in restic.
- A regular file without a mode is restored with permissions 0000: restic
  leaves a mode of 0 out of its JSON, so stock rustic leaves such a file
  (`/etc/shadow`) with the 0644 it was created with.
- On restore, the project ID is set along with the extended attributes,
  ACLs after the mode, which rewrites NFSv4 ACLs, and file flags after
  everything else (contents, hard links, ownership, xattrs, timestamps,
  mode, ACLs), once per hard-linked file, since an immutable or append-only
  file refuses most of those. Where the target file system doesn't support
  a flag, the others are still set and the restore warns about that one.
- Metadata the target file system doesn't support (flags, casefolding or a
  project ID it refuses with `ENOTTY`, `EOPNOTSUPP`/`ENOTSUP` or `EINVAL`)
  gets one warning per kind (attribute and refused flags) per restore,
  naming the first file, and the number of files at the end. Any other
  failure (`EPERM`, `EDQUOT`, `EIO`, ...) is warned about for each file.
  Neither changes the exit status: like stock rustic's, the restore only
  warns about metadata it can't set, where BackOtter's restic fails (exit
  1) for failures other than unsupported ones. That is the one difference in
  exit status left between the two.
  Where it doesn't support a POSIX.1e ACL, the restore warns and narrows the
  group bits to the owning group's own access, so a file never comes back
  more open. Flags a file has already aren't set again (on Linux: no
  `FS_IOC_SETFLAGS` when nothing differs).
- On btrfs every `FS_IOC_SETFLAGS` rewrites the `btrfs.compression`
  property (restored as an extended attribute), or deletes it. So when one
  is needed on a file with that property, the flags but immutable and
  append-only go on first, the property is set again, and immutable and
  append-only go on last through `FS_IOC_FSSETXATTR`, which leaves it
  alone (checked on Linux 6.12).
- btrfs's no-copy-on-write flag is set while a new file is still empty: btrfs
  ignores it on a file with data.
- Casefolding (`F`) is a creation-time flag: ext4 and f2fs refuse to change
  it on a directory with entries, and a new directory inherits it from its
  parent. So every directory the restore creates, and every one it finds
  empty (a mount point, the destination of `SNAP:subfolder`), gets its
  node's casefolding before anything goes in: set where the node has it,
  cleared where it hasn't (so that a directory without it in the snapshot,
  in one with it, doesn't come back case-insensitive and lose one of
  `Makefile` and `makefile`), with no `FS_IOC_SETFLAGS` when it is right
  already. A file system without it is no error there. The late flag pass
  leaves casefolding as the directory has it, and warns once per directory
  where it still differs from the node ("casefolding (F) not restored on
  DIR: directory not empty or not supported"). The destination of a whole
  snapshot has no node, and is left as it is.
- Partial restores (`--glob`, `--iglob`): directories above the matches
  that aren't matched themselves aren't streamed, so the restore creates
  them without any metadata, casefolding included, as stock rustic does.
- A restored symlink keeps its own permissions on FreeBSD (`lchmod(2)`) and
  on OpenBSD, NetBSD and DragonFly (`fchmodat(2)` with
  `AT_SYMLINK_NOFOLLOW`; OpenBSD has no `lchmod`), where stock rustic
  leaves the 0755 a new symlink gets. A file system that refuses
  (`EOPNOTSUPP`, `EINVAL`) is only noted in the debug log.
- On DragonFly, where `dev_t` is 32 bits, a device number that doesn't fit
  is an error for that device node, as on 32-bit Android, rather than a
  build failure: rustic_core builds for x86_64-unknown-dragonfly (a tier 3
  target: nightly with `-Zbuild-std`, or a native Rust >= 1.91).
- The version reads `X.Y.Z+backotter.N`.

The system calls need `unsafe`, which the workspace lints now deny (not
forbid), so that `backend/osattrs.rs` can allow it there alone.

Not handled, as no BackOtter build needs them: on a 32-bit glibc system,
`SEEK_HOLE` fails (`EOVERFLOW`) on a file over 2 GiB, which then isn't
marked `unix.sparse` (Go's restic seeks with 64-bit offsets there); and on
Windows, which isn't a BackOtter platform, a marked file is restored
without holes: NTFS needs `FSCTL_SET_SPARSE`, which rustic doesn't set.

## Moving to a new rustic_core release

    git fetch upstream --tags
    git rebase --onto rustic_core-vNEW rustic_core-vOLD backotter
    # set crates/core/Cargo.toml's version to "NEW+backotter.1"
    git push --force-with-lease origin backotter

Then move rustic's `backotter` branch to the rustic release that uses
rustic_core NEW (see BACKOTTER.md there).
