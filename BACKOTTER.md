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
  - `freebsd.file_flags`: FreeBSD's `chflags(1)` flags (`st_flags`). ZFS
    (`statfs(2)`'s `f_fstypename` `zfs`, looked up once per file system; a
    symlink's is its directory's) sets `uarch` on every file it writes, as
    Linux's ZFS its archive DOS flag, so there a file with `uarch` alone gets
    no attribute, and one with no flags at all gets 0 (archive cleared),
    which the restore sets, as any value it finds. On other file systems
    (UFS) no flags get no attribute, and `uarch` alone, which only
    `chflags(1)` sets there, is kept.
  - `freebsd.acl_access`, `freebsd.acl_default`: POSIX.1e ACLs (UFS mounted
    `acls`), access and directories' default.
  - `freebsd.acl_nfs4`: NFSv4 ACLs (ZFS, UFS mounted `nfsv4acls`).
  - `freebsd.system_extattrs`: extended attributes in the system namespace,
    except those UFS stores ACLs in.
  - `illumos.acl`: ZFS's ACLs on illumos (NFSv4-style ACEs). An entry for
    a SID (a user or group with an ephemeral id, above 2147483647, and not
    `owner@`, `group@` or `everyone@`) has the SID too, in `"sid"`, which
    older readers ignore:
    `{"who":2147483650,"mask":1,"sid":"S-1-5-21-1111-2222-3333-1004"}`.
  - `illumos.owner_sid`, `illumos.group_sid`: the SID a file's owner or
    group is, as a string (`"S-1-5-21-1111-2222-3333-1001"`), when its uid
    or gid is ephemeral. See "SIDs on illumos" below.
  - `illumos.system_attributes`: illumos' system attributes (`chmod(1)`'s
    `S+v...`), as a mask, whenever they aren't what ZFS gives a new file
    (`archive` and `av_modified`), 0 included: a file whose archive or
    av_modified was cleared keeps that. They are read and written through
    each file's `SUNWattr_rw` view, a packed nvlist, read in one `read(2)`
    (illumos packs the view afresh for each read, from its start, whatever
    the offset); a restore writes an nvlist of the attributes' booleans
    alone, never the view it read, which would set the creation time too
    (refused on an immutable file).
  - `illumos.xattr_meta`: the owner, group, mode, times and ACL of each of
    a file's extended attributes (attribute files, `runat(1)`), by name:
    `{"note":{"uid":1500,"gid":1501,"mode":416,"mtime":"2001-09-09T01:46:40.123456789Z","atime":"2001-09-09T01:46:40Z","acl":[...]}}`,
    the times in the form of the node's, `"acl"` only when the ACL says
    more than the mode, in `illumos.acl`'s form, SIDs included. Written for
    every file with extended attributes (unless `--set-xattrs no`), read
    with `fstatat(2)` and `facl(2)` on the attribute directory before the
    values: reading a value moves the attribute's atime (illumos has no
    `O_NOATIME`), so the next backup keeps the time of this one's read, and
    a file with extended attributes gets a new node in each snapshot, as
    with BackOtter's restic. For this the backup reads every file's
    extended attributes after its other metadata (stock rustic reads them
    first).
  - `illumos.zfs_project`: a file's ZFS project ID and whether it hands it
    down (`zfs project -p 77 -s`), as `{"id":77,"inherit":true}`
    (`"inherit"` left out when false), when it has either; regular files
    and directories.
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
  - `linux.zfs_dos_flags`: on Linux, the DOS flags OpenZFS keeps for SMB
    (`ZFS_IOC_GETDOSFLAGS`, ioctl `0x80088301`), of regular files and
    directories on ZFS (`statfs` type `0x2fc12fc1`; the ioctl goes to no
    other file system, where its number could mean something else): a
    64-bit number, the flags masked with `0x302f00000000` (read-only,
    hidden, system, archive, nounlink, offline, sparse). Immutable,
    append-only and nodump are inode flags too, and kept in
    `linux.inode_flags`; reparse can't be set. ZFS gives every new file
    archive, and sets it again on every write, so a file with archive alone
    gets no attribute, and one with none at all gets 0 (archive cleared, as
    by a Windows backup over SMB), which is restored too. A ZFS without the
    ioctl is only noted in the debug log. FreeBSD and illumos keep these
    flags in `freebsd.file_flags` and `illumos.system_attributes`; they
    aren't mapped from one system to another.
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
    On DragonFly's HAMMER2 the blocks mark more than files with holes, in
    both tools alike: a file of up to 512 bytes, kept in its inode (0
    blocks), a compressed one (LZ4 by default) and runs of zeros, which
    HAMMER2 doesn't store. That does no harm: such a file is restored sparse,
    which writes every byte of it but each blob's leading zeros, so it comes
    back the same, only with holes where those zeros were (HAMMER2 itself
    stores no zeros anyway).
    On ZFS a probe of a file with unwritten changes waits for them to be
    written (a transaction group), as it does for BackOtter's restic, which
    probes the same files.
  - `unix.birthtime`: a file's birth (creation) time, on FreeBSD and NetBSD
    (`st_birthtim`, every type of file) and illumos (ZFS's `crtime` from
    the `SUNWattr_rw` view, regular files and directories), as a string in
    the form of a node's mtime, as Go writes it: RFC 3339 in UTC with every
    nanosecond and no trailing zeros, such as
    `"2001-09-09T01:46:40.123456789Z"` or `"2001-09-09T01:46:40Z"`; any
    offset and number of digits is read. Not when the file system reports
    second 0 or -1 (UFS1, NetBSD's FFSv1), but otherwise always, even when
    it equals the mtime (a restored ZFS file's `crtime` on illumos would be
    the time of the restore). Not on Linux, which can read one but not set
    it, nor OpenBSD or DragonFly, which keep none. (`windows.creation_time`
    is a FILETIME, in 100 ns ticks, and restic on Windows would apply it.)
  A file only gets an attribute when it has something the mode doesn't say
  (flags, a project ID, a non-trivial ACL, holes, a SID), except for its
  birth time on FreeBSD, NetBSD and illumos and its extended attributes'
  metadata on illumos. A generic attribute
  rustic doesn't know at all gets a warning, once; one of another system is
  skipped quietly. A known attribute with a value that can't be read
  (`linux.inode_flags`, `linux.project_id`, `unix.sparse`,
  `unix.birthtime`, `*.file_flags`)
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
  `CAP_FOWNER`), without it. Symlinks can't be spared: Linux's
  `readlink(2)` updates a symlink's atime as any read does (always on
  `strictatime`), and has no `O_NOATIME`, so a backup with either tool
  moves the atimes of the source's symlinks. The snapshot still has the
  old ones (the `lstat` comes before the `readlink`), and a restore gives
  them back. Directories are listed by a vendored walkdir
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
  system attribute views, and stored in name order, not the attribute
  directory's, as BackOtter's restic does (elsewhere both store them in the
  order the system lists them). A restore creates an
  attribute file with mode 0600, so that it is never readable by others
  before it gets its own owner, mode, ACL and times (`illumos.xattr_meta`),
  with `fchownat(2)`, `fchmodat(2)`, `facl(2)` and `utimensat(2)` on the
  attribute directory, in that order, once the values are written (in
  `osattrs::restore_attributes`); an attribute the restore left out is left
  alone. This goes before the file's own times (writing an attribute file
  leaves them) and flags. A snapshot without the attribute restores as
  before.
- illumos ZFS project IDs are restored with the extended attributes'
  metadata, before the flags, as each node's own ID and inheritance,
  whatever a file got from the directory it was created in; on another file
  system than ZFS (`ENOTTY`) they get one warning per restore, as other
  unsupported metadata. ZFS on illumos has no `FS_IOC_FSGETXATTR`, but
  ioctls `'X'` 31 and 32 (`0x4008581f`, `0x80085820`) with an 8-byte struct
  of the flags, of which only inheritance (`0x20000000`) is used, and the
  project ID (checked on OmniOS r151058, with `truss` and `zfs project`).
- **SIDs on illumos.** A file owned by a SID (a Windows user or group, as
  the SMB server and ZFS keep them) has an ephemeral uid or gid, which
  idmapd hands out when asked and forgets at a reboot: restored as a number
  after a reboot, it becomes another SID's or nobody (60001). So a backup
  asks libidmap for the SID of every ephemeral owner, group and ACL entry
  and keeps it, and a restore asks it for the id the SID has now, and gives
  the file that (a second `lchown(2)`, right after the one with the numbers,
  before the mode: `osattrs::restore_owner`, a no-op elsewhere) and the ACL
  entry that. A SID idmap can't map gets nobody (60001), never the number
  the backup saw, which may be another SID's by now, with a warning once
  per attribute and the number of files at the end; it isn't an error. A
  backup where idmap gives no SID warns once (`idmap offline: SID owners
  not kept`); with idmapd not running at all, `stat(2)` already gives every
  ephemeral id as 60001, and nothing can be kept. So **svc:/system/idmap
  must be online** at backup and at restore: BackOtter's illumos rescue
  system should run `svcadm enable -s idmap`. libidmap is private to
  illumos (no header installed), so rustic opens `libidmap.so.1` with
  `dlopen(3C)` the first time it needs it rather than link with it: the
  binary doesn't depend on it, and where it can't be opened, that is
  treated as idmap failing. The calls are `idmap_get_create`,
  `idmap_get_sidbyuid`/`_sidbygid`, `idmap_get_uidbysid`/`_gidbysid`,
  `idmap_get_mappings` and `idmap_get_destroy`; their answers are kept
  for the run.
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
- A hard link replaces whatever has its name already, as in BackOtter's
  restic: the same link, where a restore is run again over its own result,
  or another file. Stock rustic tried to link over it, failed (`EEXIST`)
  and stopped there, leaving the rest of the metadata, the late flags pass
  included, unset.
- On restore, the project ID is set along with the extended attributes,
  ACLs after the mode, which rewrites NFSv4 ACLs, and file flags after
  everything else (contents, hard links, ownership, xattrs, timestamps,
  mode, ACLs), once per hard-linked file, since an immutable or append-only
  file refuses most of those. Where the target file system doesn't support
  a flag, the others are still set and the restore warns about that one.
- ZFS's DOS flags (`linux.zfs_dos_flags`) go on in the same last pass, once
  per hard-linked file, just before the file flags: a read-only file
  refuses writes, a nounlink one unlinking and renaming, and every write
  sets archive again. `ZFS_IOC_SETDOSFLAGS` replaces all of them, so the
  restore reads the file's flags and changes only the kept ones, leaving
  immutable, append-only, nodump and reparse as they are (which also needs
  no `CAP_LINUX_IMMUTABLE`), and sets nothing when they are right already.
  The inode flags after them leave them alone. Where the whole mask is
  refused, each flag is tried alone, and the restore warns naming those
  refused. On a file system other than ZFS they aren't set, with one
  warning per restore ("ZFS DOS flags 0x... not restored: not ZFS") and the
  number of files at the end.
- An extended attribute the restore can't set (`trusted.*` not as root,
  one the file system refuses) doesn't keep the others from being set, or
  those the node hasn't from being removed, as in BackOtter's restic: each
  file gets one warning naming every attribute that wasn't set, with its
  error (`restore f: setting extended attributes failed: trusted.a:
  Operation not permitted (os error 1); ...`). Stock rustic stopped at the
  first, leaving the rest unset, and said neither which nor why. On
  illumos too.
- Metadata the target file system doesn't support (flags, casefolding or a
  project ID it refuses with `ENOTTY`, `EOPNOTSUPP`/`ENOTSUP` or `EINVAL`)
  gets one warning per kind (attribute and refused flags) per restore,
  naming the first file, and the number of files at the end, as do SIDs
  idmap can't map on illumos (per attribute). Any other
  failure (`EPERM`, `EDQUOT`, `EIO`, ...) is warned about for each file.
  Neither changes the exit status: like stock rustic's, the restore only
  warns about metadata it can't set, where BackOtter's restic fails (exit
  1) for failures other than unsupported ones. That is the one difference in
  exit status left between the two.
  Where it doesn't support a POSIX.1e ACL, the restore warns and narrows the
  group bits to the owning group's own access, so a file never comes back
  more open. Flags a file has already aren't set again (on Linux: no
  `FS_IOC_SETFLAGS` when nothing differs). Where flags of 0 (all cleared)
  are refused, that is warned about too, though there is no flag to name.
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
- A restore over an existing tree removes what has a node's name but
  another type, with or without `--delete`, as BackOtter's restic does: a
  symlink where the snapshot has a directory is replaced by the directory
  (stock rustic restored the directory's files through the symlink,
  wherever it pointed, outside the destination too), a file in the place
  of something else is made anew, and so is every special file (symlink,
  device, FIFO, socket), which stock rustic left as it found it, with a
  warning. Without `--delete` a directory in the way only goes if it is
  empty; one with entries is an error for that node, as in restic. A
  special file that can't be made (a device node, as an unprivileged user)
  gets one warning and nothing else, not one more for each metadata step
  after. restic reports it once too, but as an error (`ignoring error for
  /chardev: mknod ...`, exit 1): the one difference in exit status left,
  above.
- A backup stores special files' nodes as restic does: a character
  device's mode has Go's `ModeDevice` and `ModeCharDevice` (stock rustic
  ANDs the two bits, which gives none), only a regular file has a size
  (stock rustic stores a symlink's target length), and a FIFO or a socket
  has no link count. Sockets are still kept, which restic skips.
- Directories above the backed-up path (`/home` in a backup of
  `/home/m`) get nodes of rustic's own making, as in stock rustic
  (`archiver/tree.rs`): a directory with mode `0o755`, without Go's
  directory bit in it, and no owner, times or anything else. restic stores
  those directories' own metadata (their `lstat`). The paths rustic
  archives may not be where those directories are (`--as-path`, stdin), so
  this is left as it is; it only matters for what a restore of the whole
  snapshot gives the directories above the backed-up one. The backed-up
  directory itself has its own metadata (see above).
- Partial restores (`--glob`, `--iglob`): directories above the matches
  that aren't matched themselves aren't streamed, so the restore creates
  them without any metadata, casefolding included, as stock rustic does.
- Birth times are restored just before the atime and mtime, as part of
  setting the times, after contents, extended attributes, mode and ACLs
  (none of which changes them) and before the late flags pass. illumos sets
  any `crtime` (later than the mtime too) by writing an nvlist of `crtime`
  alone to the file's `SUNWattr_rw` view; an immutable file would refuse
  it. FreeBSD and NetBSD have no call that sets a birth time, but their
  kernels lower it to any mtime set earlier than it (UFS2, FFSv2, ZFS;
  files, directories and symlinks; owners too). So a birth time earlier
  than the mtime is first set as the mtime, with `utimensat(2)`, the atime
  omitted (`UTIME_OMIT`) and `AT_SYMLINK_NOFOLLOW`, and nanoseconds (the
  filetime crate drops them where it goes through `utimes(2)`); the real
  times, set next, leave it. One that isn't earlier comes back as the
  mtime, the closest those systems can get. Elsewhere, and on a file system
  without them (illumos' UFS and tmpfs: `ENOENT`, `EINVAL`, `ENOTSUP` on
  the view), the attribute is only noted in the debug log. A failure
  (`EPERM` as neither owner nor root) is warned about, as for the times.
- A restored symlink keeps its own permissions on FreeBSD (`lchmod(2)`) and
  on OpenBSD, NetBSD and DragonFly (`fchmodat(2)` with
  `AT_SYMLINK_NOFOLLOW`; OpenBSD has no `lchmod`), where stock rustic
  leaves the 0755 a new symlink gets. A file system that refuses
  (`EOPNOTSUPP`, `EINVAL`) is only noted in the debug log.
- On DragonFly the restore sets atimes and mtimes with `utimensat(2)`
  (`AT_SYMLINK_NOFOLLOW`), to the nanosecond, as BackOtter's restic does:
  the filetime crate goes through `utimes(2)` and `lutimes(2)` there, which
  take microseconds. DragonFly's UFS keeps the nanoseconds; HAMMER2 keeps
  microseconds anyway. Elsewhere filetime goes through `utimensat(2)`
  already (Linux, the other BSDs, illumos; macOS from 10.13).
- On DragonFly, where `dev_t` is 32 bits, a device number that doesn't fit
  is an error for that device node, as on 32-bit Android, rather than a
  build failure: rustic_core builds for x86_64-unknown-dragonfly (a tier 3
  target: nightly with `-Zbuild-std`, or a native Rust >= 1.91).
- A node's times are written as restic writes them (Go's RFC 3339 with
  nanoseconds) in UTC too: `2001-09-09T01:46:40.5Z`, where stock rustic
  writes `+00:00` for a zero offset (as on a rescue system, which has no
  time zone). Either form is read by both tools, and means the same time;
  only the trees' bytes, and so their ids, differed. Other offsets were
  already written alike (`+02:00`). A snapshot's own `time` still has
  `+00:00` (stock rustic).
- The owner names a backup keeps are looked up once per uid and gid in a
  run, and on restore with `--by-name` the ids once per name, found or not:
  the cached crate (2.x) stopped caching a lookup that found nothing, so
  without `/etc/passwd` and `/etc/group`, as on a minimal rescue system,
  rustic looked each file's owner up again and warned for every file
  (`error getting user from uid 0: ENOENT`). Now it warns once per id. A
  name not found on restore falls back to the saved id, as the warning
  now says (it said UID 0).
- The version reads `X.Y.Z+backotter.N`.

The system calls need `unsafe`, which the workspace lints now deny (not
forbid), so that `backend/osattrs.rs` can allow it there alone. Each
system's module (`osattrs/linux.rs`, `freebsd.rs`, `netbsd.rs`,
`openbsd.rs`, `dragonfly.rs`, `illumos.rs`, and `other.rs` for the rest)
defines the same functions and constants, those of `other.rs`, which does
nothing; `osattrs.rs` calls them without `cfg`s.

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
