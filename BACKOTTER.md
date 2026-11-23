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
    quotas count by, of regular files and directories. bcachefs (Linux
    6.12) gives there the ID a file had when its inode was read in, 0 for
    one set since (`chattr -p`, a restore) until it is read in again, and
    the ID it has in the extended attribute `bcachefs_effective.project`:
    on bcachefs that is read instead, where there is one. The restore sets
    it with `FS_IOC_FSSETXATTR`, as anywhere (setting the attribute does
    nothing, `bcachefs.project` is refused). On bcachefs a directory gets
    its project ID, with its own options, as soon as the restore creates it
    (below, with casefolding), and its entries inherit it then; the restore
    gives no file an ID it has already, so an entry that inherited its ID
    in the original comes back inheriting it, with no `bcachefs.project` of
    its own, and there a node without `linux.project_id` in a snapshot of
    BackOtter's gets 0 where the file inherited another (in another
    snapshot it keeps the inherited one). Elsewhere a node without one leaves the file's
    ID as it is. Accepted difference (both tools): a bcachefs file given its
    directory's project ID by hand comes back inheriting it.
  - `freebsd.file_flags`: FreeBSD's `chflags(1)` flags (`st_flags`). ZFS
    (`statfs(2)`'s `f_fstypename` `zfs`, or, under another name, a file or
    directory that answers ZFS's project ioctl, `ZFS_IOC_FSGETXATTR`, which
    other file systems refuse with `ENOTTY`: a nullfs mount of a ZFS
    dataset, as a jail's, is `nullfs` to `statfs(2)` and its files are
    ZFS's all the same; looked up once per file system; a symlink's is its
    directory's) sets `uarch` on every file it writes, as
    Linux's ZFS its archive DOS flag, so there a file with `uarch` alone gets
    no attribute, and one with no flags at all gets 0 (archive cleared),
    which the restore sets, as any value it finds. On other file systems
    (UFS) no flags get no attribute, and `uarch` alone, which only
    `chflags(1)` sets there, is kept.
  - `freebsd.acl_access`, `freebsd.acl_default`: POSIX.1e ACLs (UFS mounted
    `acls`), access and directories' default. A symlink's own ACL is kept
    and restored too (`setfacl -h`; on UFS a symlink made in a directory
    with a default ACL inherits one, and ZFS takes an NFSv4 one), read and
    set without following it (`__acl_get_link`, `__acl_set_link`), since
    0.14.0+backotter.2: until then FreeBSD's symlinks were taken to have
    none, and a snapshot made before has none for them, as BackOtter's
    restic's have none (a restore of one gives a symlink no ACL).
  - `freebsd.acl_nfs4`: NFSv4 ACLs (ZFS, UFS mounted `nfsv4acls`). An ACL
    the backup may not read (`EACCES`, `EPERM`: an NFSv4 ACL that denies
    the user `read_acl`) is warned about ("ignoring attributes of ...") and
    counted in `items_incomplete`, as an extended attribute that can't be
    read is; only a file system without ACLs (`EOPNOTSUPP`, `EINVAL`) is
    passed over quietly (until 0.14.0+backotter.1 a refusal was too, and
    the node said the file had no ACL).
  - `freebsd.system_extattrs`: extended attributes in the system namespace,
    except those UFS stores ACLs in.
  - `illumos.acl`: ZFS's ACLs on illumos (NFSv4-style ACEs). An entry for
    a SID (a user or group with an ephemeral id, above 2147483647, and not
    `owner@`, `group@` or `everyone@`) has the SID too, in `"sid"`, which
    older readers ignore:
    `{"who":2147483650,"mask":1,"sid":"S-1-5-21-1111-2222-3333-1004"}`.
    An ACL that says no more than the mode (a trivial one, what `ls(1)`
    shows no `+` for) is not kept. So in a snapshot of BackOtter's a node
    without `illumos.acl` had a trivial ACL, and a restore gives its file
    the trivial ACL of its mode (as `acl_strip(3SEC)` builds it: `owner@`,
    `group@` and `everyone@`, with deny entries where a class has less than
    a later one) wherever the file has another: named or deny entries
    added since the backup, or handed down by the directory it is restored
    into. `chmod(2)` takes those off only under ZFS's default
    `aclmode=discard`; under `passthrough` and `groupmask` they stay, and
    under `restricted` it fails. The same for an attribute file whose
    `illumos.xattr_meta` has no `"acl"`. In any other snapshot the ACL is
    unknown, and the file keeps the one it has (0.14.0+backotter.2; before,
    nothing took such an ACL off, access the snapshot never granted stayed
    without a warning, and `--exact` set such a file's metadata again on
    every run).
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
    more than the mode, in `illumos.acl`'s form, SIDs included. An owner
    or group that is a SID (an ephemeral uid or gid) has the SID too, in
    `"owner_sid"` and `"group_sid"` after `"gid"`, left out otherwise,
    which older readers ignore; a restore gives the attribute the id the
    SID has there, or nobody and a warning, as for a file's own
    (0.14.0+backotter.2; before, the number alone was kept, which after a
    reboot is another SID's or nobody). Written for
    every file with extended attributes (unless `--set-xattrs no`), read
    with `fstatat(2)` and `facl(2)` on the attribute directory before the
    values: reading a value moves the attribute's atime (illumos has no
    `O_NOATIME`), so the next backup keeps the time of this one's read, and
    a file with extended attributes gets a new node in each snapshot, as
    with BackOtter's restic. For this the backup reads every file's
    extended attributes after its other metadata (stock rustic reads them
    first).
    Read before the values, it has the entry of an attribute whose value
    the backup then left out (one it couldn't read, or one too large for a
    repository) as well. A restore sets nothing for an attribute the node
    has no value for, and `--exact` compares the entries of those it has
    one for alone (0.14.0+backotter.2; before, a file a restore had taken
    such an attribute off, or a new one, never matched its node, and
    every `--exact` run set its metadata again).
  - `illumos.zfs_project`: a file's ZFS project ID and whether it hands it
    down (`zfs project -p 77 -s`), as `{"id":77,"inherit":true}`
    (`"inherit"` left out when false), when it has either; regular files
    and directories.
  - `freebsd.zfs_project`: the same on FreeBSD's ZFS (`zfs project`), in
    the same form, of regular files and directories on ZFS (`statfs(2)`'s
    `f_fstypename`, as for the archive flag), read through a descriptor
    opened as on Linux (`O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY|O_CLOEXEC`,
    and `O_DIRECTORY`; the file the lstat saw). OpenZFS takes Linux's
    `struct fsxattr` (28 bytes) there, with ioctls `'X'` 31 and 32
    (`0x401c581f`, `0x801c5820`, as `truss(1)` shows `zfs project` calling
    them on FreeBSD 15.1); only inheritance (`0x20000000`) of its flags is
    used. Project quotas (`projectquota@N`) count by it.
  - `illumos.unread_size`: the size in bytes (a JSON number) of a regular
    file whose contents weren't backed up, because illumos quarantined it
    (`av_quarantined`) and no one could read it: its node has no contents
    and size 0. See `av_quarantined` below.
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
    As on FreeBSD, symlinks have ACLs of their own, which are kept and
    restored. The ACL system calls go by their names in libc
    (`__acl_get_link`, `__acl_set_link`, `__acl_delete_link`, `lpathconf`,
    which NetBSD's libc exports since NetBSD 10, the first with ACLs), and
    NetBSD's `pathconf(2)` names are its own (`_PC_ACL_EXTENDED` 14,
    `_PC_ACL_NFS4` 17 in `sys/sys/unistd.h` of netbsd-10 and netbsd-11,
    where FreeBSD has 59 and 64); the rest is one module,
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
  - `linux.fat_attrs`: on Linux, the attributes of a file on FAT (vfat,
    msdos: `statfs` type `0x4d44`; `FAT_IOCTL_GET_ATTRIBUTES`, ioctl
    `0x80047210`, which goes to no other file system), as a number:
    read-only (`0x01`), hidden (`0x02`), system (`0x04`) and archive
    (`0x20`); volume label and directory can't be set. Regular files and
    directories, only when they aren't what Linux gives a new one and the
    restore would give it anyway: archive alone for a regular file,
    read-only or not (its mode's write bits say that), none for a directory
    (whose read-only the mode doesn't show). Archive cleared is kept, as 0.
    FreeBSD keeps FAT's attributes in `freebsd.file_flags`.
  - `linux.xfs_options`: on Linux, a file's options on XFS (`statfs` type
    `0x58465342`; `FS_IOC_FSGETXATTR`) that `linux.inode_flags` and
    `linux.project_id` don't carry, as
    `{"cowextsize":2097152,"extsize":1048576,"xflags":67584}`: of
    `fsx_xflags`, realtime inheritance (`t`, `0x100`, directories only),
    nosymlinks (`n`, `0x400`), the extent size hint (`e`, `0x800`), its
    inheritance (`E`, `0x1000`), nodefrag (`f`, `0x2000`), filestream
    (`S`, `0x4000`) and the copy-on-write extent size hint (`C`,
    `0x10000`), with the hints' sizes in bytes, each left out when 0 (XFS
    gives a size only with its flag); the keys in byte order, as serde_json
    writes them and BackOtter's restic too. Regular files and directories
    that have any of them. Realtime inheritance is only a directory's (XFS
    gives a regular file none), and a directory takes it without a realtime
    device; not realtime (`r`, `0x1`), which only a regular file on a
    realtime device has, nor DAX; nor preallocated (`p`), which a dense
    restore gives every file it preallocates, and a sparse one none:
    an accepted difference, in both tools, as the blocks themselves are.
  - `haiku.attributes`: Haiku's file attributes (BFS, `listattr(1)`) other
    than its extended attributes (below), with their type codes. BackOtter's
    rustic alone writes it, since restic doesn't run on Haiku.
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
       On Linux's JFS and nilfs2 (`statfs` `f_type` `0x3153464a` and
       `0x3434`), whose `SEEK_HOLE` is the kernel's generic one and always
       answers the size, the probe isn't made and the blocks decide too:
       neither compresses nor keeps data in the inode, so fewer blocks than
       the size mean holes.
    4. On Linux the probe uses the descriptor the file is opened with for
       its flags and project ID, once per file; if that open failed, the
       file has none. Elsewhere the file is opened for the probe, with
       `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY|O_CLOEXEC`, and must still
       be the file the lstat saw.
    On DragonFly's HAMMER2 the blocks mark more than files with holes, in
    both tools alike: a file of up to 512 bytes, kept in its inode (0
    blocks), a compressed one (LZ4 by default) and runs of zeros, which
    HAMMER2 doesn't store. That does no harm: such a file is restored sparse,
    which writes every byte of it but its all-zero blocks, so it comes back
    the same, only with holes where those zeros were (HAMMER2 itself stores
    no zeros anyway).
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
  birth time on FreeBSD, NetBSD and illumos, its extended attributes'
  metadata on illumos, and `haiku.attributes`, which says that a file has
  no typed attributes too (below). A generic attribute
  rustic doesn't know at all gets a warning, once; one of another system is
  skipped quietly. A known attribute with a value that can't be read
  (`linux.inode_flags`, `linux.project_id`, `unix.sparse`,
  `unix.birthtime`, `*.file_flags`, `*.zfs_project`)
  is skipped with a warning once per attribute name, as in BackOtter's
  restic; it isn't an error. A project ID of 0 is left as the file has it.
- On Linux, regular files and directories are opened for their flags,
  project ID and holes with `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY|O_CLOEXEC`
  (and `O_DIRECTORY`), and the opened file checked: one of another type, or
  at backup another file than the lstat saw, is skipped. Symlinks, FIFOs,
  sockets and devices have no flags or project IDs either way.
- A backup stores the mtime as each file's access time by default, as stock
  rustic does (and stock restic without `--with-atime`); `backup --set-atime
  yes` (or `set-atime = "yes"` in the config), which BackOtter passes, keeps
  each file's own, as BackOtter's restic does with `--with-atime`. Stored
  atimes change whenever something reads a file, so they cost new trees on
  backups where nothing else changed (about 2.3 MB a backup for a
  1,164-directory tree with symlinks; 2026-11-03): a step back from stock
  for anyone who didn't ask for them. `rewrite` keeps the stored atimes by
  default (`--set-atime yes`), as BackOtter's restic does; `--set-atime
  mtime` or `no` still replace them (stock rustic's rewrite gave every node
  its mtime as its atime by default). With `--set-atime yes` a backup
  doesn't change the access times it saves: on
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
  pass `O_NOATIME`. Other systems have no `O_NOATIME`: there listing a
  directory moves its access time (where the file system keeps them: not
  read-only, `noatime` or ZFS's `atime=off`), so the walker takes a
  directory's metadata before it reads it, the backup's root included
  (`DirEntry::keep_metadata` in the vendored walkdir; stock walkdir and
  rustic took it after, and stored the listing's time), as BackOtter's
  restic does, and a backup with `--set-atime yes` doesn't scan the source
  for its size there (as `--no-scan`; `osattrs::scan_moves_saved_atimes`):
  the scan runs beside the backup, and would list directories before the
  backup takes their metadata. Progress then shows no total or ETA, in both
  tools. With the default (`mtime`) or `no` the scan runs on every system,
  as in stock rustic. Files' access times are those before the backup read
  them.
- Paths past `PATH_MAX` (Linux and Android, 0.13.0+backotter.16): a tree
  deeper than a path a system call takes (4096 bytes, its NUL included) is
  backed up and restored whole, as tar and rsync keep it. Stock rustic and
  0.13.0+backotter.15 left out of a backup everything past it, warning
  ("ignoring error ... File name too long") and exiting 0 without
  `--strict-exit`, and couldn't restore it (`ENAMETOOLONG`); BackOtter's
  restic still leaves it out (exit 3). Each system call on such a path
  goes through `walkdir::short_path` (the vendored walkdir's
  `src/longpath.rs`): a shorter path to the same file, through a symbolic
  link to a directory at a prefix of the path (at most 2048 bytes, or 1000
  where `$TMPDIR`'s file system refuses a link to 2048 bytes, as XFS does;
  ending at a component), and links to links for a longer one. The links
  are in a
  directory of the process's own (`$TMPDIR/.bko-longpath-PID-N`, mode
  0700, a new one only it made), removed at exit (`atexit`); one per prefix,
  so a path always gets the same short path, and followed by name, as the
  long path's components are, so the short path names what the long one
  names after the tree changes too. A link's target is the prefix, and XFS
  refuses one over 1024 bytes (`XFS_SYMLINK_MAXLEN`; ext2/3/4 and minix
  one over a block less its NUL: 1023 bytes on 1 KiB blocks, 2047 on 2 KiB
  ones), so 0.13.0+backotter.16 to .18, whose prefixes
  were up to 2048 bytes, left the long paths out of a backup ("File name
  too long") and couldn't restore them where `$TMPDIR` is on XFS;
  0.13.0+backotter.19 cut every prefix to 1000 bytes, on every file system.
  Since 0.13.0+backotter.20 the 2048-byte prefixes are kept where the links'
  directory takes them: a process decides once, before its first link, by
  making a link to a 2048-byte target there (`probe`), and takes 1000-byte
  prefixes where that fails (`ENAMETOOLONG`, or anything else) or doesn't
  read back whole. Since 0.14.0+backotter.2 `probe` first makes a link to
  the links' directory itself and follows it: a `$TMPDIR` whose file system
  takes no symbolic link (vfat, exFAT: `EPERM`; read-only: `EROFS`) or
  doesn't follow one (mounted `nosymfollow`: `ELOOP`) shortens no path, and
  the one warning says so, naming the directory ("no link made in
  /tmp/.bko-longpath-...: Operation not permitted", "a link in ... isn't
  followed: Too many levels of symbolic links"). Before, the first was
  taken for a file system with short link targets, so a `$TMPDIR` of 501
  to 1024 bytes was refused as "over 500 bytes", and the second chose
  2048-byte prefixes and failed each long path with `ELOOP`, without the
  warning (ForkAudit1 G7-08, F7-06). Depth limit: a system call follows at most 40 symbolic
  links in a path (Linux's `MAXSYMLINKS`, `ELOOP` past it), and each link
  leads to the one before, so a path that takes more than 40 links gets a
  short path all the same, which fails with `ELOOP` ("Too many levels of
  symbolic links", not "File name too long"), and is left out of a backup
  as before. Each link cuts its prefix less its own path
  (`$TMPDIR` and some 30 bytes), so the deepest path reached is about 82 KB
  with 2048-byte prefixes (40-byte names, an 18-byte `$TMPDIR`), 77 KB with
  200-byte names, 55 KB with 255-byte names under a 495-byte `$TMPDIR` and
  35 KB at worst (255-byte names, a 1024-byte `$TMPDIR`); with 1000-byte
  prefixes (XFS) 42 KB, 36 KB and 14 KB (.19's, on every
  file system). The links' directory is in `$TMPDIR`'s canonical path, so
  that no link's own path has a symbolic link in it: a link's path is in
  the next link's target, and such a symbolic link was followed again in
  every round, so with one in `$TMPDIR` (on an ostree system, `/home` ->
  `var/home`) .16 to .20 reached half as deep (`ELOOP` at about 20
  links). Symbolic links in the long path's own first prefix count once.
  `$TMPDIR` and each directory above it are trusted, as every user of
  `mktemp` trusts them: the links' directory and its contents are the
  process's alone, but its name isn't, and is used again for each link
  and short path, so a user who could rename an entry in `$TMPDIR` (one
  that owns it or a directory above it, or can write to one that isn't
  sticky) could put a directory of their own in its place, whose links a
  restore run as root would then follow (ForkAudit1 F7-01). Root's own
  `$TMPDIR` is that: setuid `sudo` and `su` drop an inherited `TMPDIR` on
  glibc, and BackOtter runs rustic-bko with `/tmp`.
  Since 0.14.0+backotter.2 a link is checked each time it is used
  (`readlink`): one that is gone or leads elsewhere is made again, and the
  links' directory too (new, mode 0700; one that is there must still be a
  directory of the user's alone, or the path fails, saying so), and a
  restore's walk of a destination that holds `$TMPDIR` takes the links'
  directory for no entry of it (`walkdir::is_short_path_dir`, by device and
  inode): not counted as additional, and never removed. From .16 to
  0.14.0+backotter.1 `restore --delete` (and `--exact`) with `$TMPDIR` in
  the destination removed it as an extra entry; `create_dir_all` of the next
  short path then made the links' directory and the rest of the path again,
  as real directories in `$TMPDIR`, the files past `PATH_MAX` were written
  there and removed at exit, and the restore said "restore done." (exit 0)
  without them (ForkAudit1 G7-01). Where `$TMPDIR` itself is an extra
  entry, `--delete` removes what is in it but the links' directory and its
  links (`remove_tree` asks each entry of its walk, which gives a directory
  after its contents: walkdir's `filter_entry` kept the directory there but
  not its links, and left what `$TMPDIR` lists after it, uncounted), and
  reports `$TMPDIR` as not removed ("Directory not empty", an error); the
  links go at exit, and the next run removes it. A backup of a source that
  holds `$TMPDIR` leaves the links' directory out the same way
  (`LocalSourceWalker`'s entry filter: a debug line, no warning, not
  counted as incomplete): it is the backup's own, not the source's. From
  .16 to 0.14.0+backotter.1 it was saved with its links
  (`tmp/.bko-longpath-PID-N/0`, ...) whenever a path past `PATH_MAX` sorted
  before `$TMPDIR`, under a name that holds the process id, so that two
  backups of an unchanged tree differed, and a restore made the stale
  directory again (ForkAudit1 G7-02). Making and removing the links'
  directory still moves `$TMPDIR`'s own mtime and ctime, which a backup
  saves where it reads `$TMPDIR`'s metadata after its first long path.
  Where a link can't be made, a long path fails as before
  (`ENAMETOOLONG`): no usable temporary directory for the links (none, not
  writable, not absolute, or of over 1024 bytes, or of over 500 where the
  links lead to 1000-byte prefixes, which would leave a link too long to
  shorten a path: .19 and .20 refused one of over 500 bytes everywhere,
  where .16 to .18 took one of up to 1024), a link refused (`symlink(2)`:
  no space, a quota, a file system without symbolic links), or a path with
  no '/' to cut it at. Since
  0.13.0+backotter.21 the first such failure in a run is warned about,
  once, saying why ("paths of PATH_MAX bytes or more can't be reached, and
  fail as "File name too long": no directory /tmp/.bko-longpath-... made
  for links: Read-only file system"; `walkdir::report_short_path_errors`,
  `try_short_path`), and a directory for the links that couldn't be made
  isn't tried again for each path. .16 to .20 said only "File name too
  long", for each path, which hid .16 to .18's XFS failure (above). Only the system calls
  take the short paths: the walk's entries, the restore's comparisons with
  what the destination holds (`--delete`), its aliases and the messages
  keep the long ones, but for the errors the system modules make of their
  calls' errors (`osattrs/linux.rs`: an ioctl's error naming the file, its
  debug messages), which name the short one. `LocalDestination`'s own
  errors that hold a path (a symlink or a hard link that couldn't be made)
  name the long one since 0.14.0+backotter.2 (RustAudit1 R6-01); to .1
  they named the short one. 0.13.0+backotter.16 to .20 named
  the short one, under `$TMPDIR/.bko-longpath-PID-N` (gone at exit), in a
  few more: a backup's warnings about flags, attributes and extended
  attributes and its symlink errors, `--delete`'s "entries not removed",
  `--exact`'s clone errors and the temporary file one leaves, and the
  flags not put back on a file's other names. The calls so routed: the
  walker's listing and `lstat` (walkdir: `noatime::read_dir`,
  `DirEntry::metadata`, `--one-file-system`'s device), a backup's reads of
  an entry's metadata (`map_path`), contents (`OpenFile::open`) and
  `--exclude-if-present`/`--exclude-if-xattr`; every `osattrs` function that
  takes a path; `LocalDestination`'s calls; and the restore's own (`lstat`,
  removals, `--exact`'s clones and comparisons). `--delete`'s alias check
  (`no_symlink_to`), which compares canonical paths, and there are none
  past `PATH_MAX`, looks at each directory below the destination instead
  (`no_symlink_below`). Not handled: a backed-up path itself (a `backup`
  argument) or a destination past `PATH_MAX`, and the other systems (BSDs,
  illumos, Haiku: their `PATH_MAX` is 1024), where a long path fails as
  before; and custom ignore files, `.gitignore` files and a repository's
  `.git` (`--git-ignore`) past it, which the ignore crate looks for by
  path and takes for missing there (`ENAMETOOLONG`, no error), so their
  rules aren't applied and what they exclude is backed up. 0.13.0+backotter.16
  to .20 did that without a word; since 0.13.0+backotter.21 the backup warns
  about each directory with one ("... not read (a path of PATH_MAX bytes or
  more) ...") and counts it as incomplete (exit 3 with `--strict-exit`).
  Tested by `test_backup_restore_past_path_max` (a tree of 4.9 KB paths:
  modes, mtimes, an extended attribute, contents and a symlink, restored,
  restored again, and with `--delete`), `test_backup_past_path_max_ignorefile`,
  `tests/integration/bko_tmpdir.rs` (`$TMPDIR` in the tree, each test in a
  child process of its own) and walkdir's `longpath` tests.
- A restore looks the owners up by user and group name, falling back to
  the saved uid and gid, as stock rustic does (`--by-name`, or
  `--ownership-by-name`, restic's name for it, says so explicitly);
  `restore --numeric-id`, which BackOtter passes, gives files the uid and
  gid they were saved with, as restic does: on a rescue system the users
  of the system it runs on are the wrong ones to look names up in.
- A backup reads a regular file marked `unix.sparse` on a probing system
  (Linux and Android, FreeBSD, macOS, illumos) by its data extents, as
  BackOtter's restic does, if it still has a hole as opened (`SEEK_HOLE`
  from 0 before its end; it may have been replaced or compressed since it
  was listed): from where it is, `lseek(SEEK_DATA)` finds the
  next data and `lseek(SEEK_HOLE)` the next hole, only the data is read
  (`pread(2)`), and the chunker is given zeros for the holes without their
  being read, never past the size `fstat` gave before `SEEK_DATA`. Once a
  seek fails (`EINVAL`, `ENOTSUP`, ...), or nothing but
  a hole is left (`ENXIO` from `SEEK_DATA` with `SEEK_HOLE` finding the hole
  where it is: macOS answers `ENXIO` to both at every offset of a file its
  file system compresses; the hole ends at the size `fstat` gives before
  `SEEK_DATA`, or after it if smaller, so that data appended meanwhile
  isn't taken for a hole), the rest is read plainly, up to whatever end of
  file a read finds. Each read fills the chunker's buffer across extents
  and `EINTR`, as a read of a regular file does: rustic's chunker reads on
  with a buffer no longer than the last read gave, which reads short at
  every extent's end would shrink to a byte. The chunker gets the
  same bytes as from plain reading, so the chunks, blob IDs, trees and
  snapshots are the same bit for bit; a file that grows or shrinks while
  it is read is read as plain reading reads it, but for a hole already
  found, which gives zeros even if data was written there since (as if it
  had been read before the write). Inside a hole each buffer of zeros
  ends at the size `fstat` gives then: a file cut short there gives the
  zeros up to its new end and no more, and at or past it the rest is read
  plainly (the end of file). Other files, and every file elsewhere,
  are read plainly. On JFS and nilfs2 (`unix.sparse`, above),
  `SEEK_HOLE` gives the size, so a file there is read whole, holes and
  all. An all-zero chunk at the length runs of zeros are cut at (holes
  give many) isn't hashed: upstream's 0abb59f (#611, in 0.14.0) gives it
  the ID it computes once per backup (`chunk_len_zeroes`: the minimum
  chunk size with Rabin, whose hash of a window of zeros is 0, the chunk
  size with fixed-size chunks), and the hole reader's zero runs are cut at
  just that length. The fork's own cache, one hashed ID per file and
  length of all-zero chunk (`chunk_id`, `zero_ids` in
  `archiver/file_archiver.rs`), was dropped in the rebase onto 0.14.0; an
  all-zero chunk of another length (a file's last) is hashed. The same
  bytes give the same ID either way. The rolling hash isn't skipped over
  long zero runs: all-zero data already gives a boundary at the minimum
  chunk size, with no rolling over its bytes.
- A file is restored sparse if, and only if, it is marked `unix.sparse` (or
  `restore --sparse by-content` asks for every file; `--sparse no` doesn't
  unmark one), and it goes into a new, empty file: nothing was at its path
  when the restore planned it (after `--delete` removed what was there).
  That is checked on disk, not by what the walk of the destination saw (a
  file below a symlinked directory). A file restored sparse is sized
  without being allocated (`ftruncate`), and each blob is written by the
  blocks of the destination file system's block size (`f_bsize` of
  `fstatfs(2)`, of `fstatvfs(2)` on NetBSD and illumos, else the file's
  `st_blksize`; at least 512 bytes, 4096 where none is known: 512 on
  bcachefs formatted with `block_size` 512 and on FreeBSD's ZFS, 1024 on
  ext2/3/4 and XFS with 1 KiB blocks), aligned to the offsets in the
  file, as BackOtter's restic writes it: of each block
  the blob reaches into, the part inside the blob is left unwritten if it
  is all zeros, else written, and nothing outside the blob is ever
  written (adjacent parts in one write; an all-zero blob, which holes give
  many of at many offsets, is looked at once). As the file is new and
  sized without being allocated, what no blob writes reads as zeros, and
  a block is allocated only if some blob put a byte other than zero in
  it: the blocks with data, which a source whose holes are whole blocks
  has too (measured on ext4, XFS and ZFS with and without compression:
  the source's block count exactly, at the old rule's speed). This
  replaced writing the partial blocks at a blob's ends whatever they held
  (up to a block more for each blob boundary: 71% more blocks on ext4 and
  XFS, 26 times as many on uncompressed ZFS, for a disk image), and
  before it, leaving each blob's longest all-zero prefix unwritten. Until
  round 23 the block was at least 4096 bytes, and a file whose holes were
  all smaller (512-byte holes on bcachefs with 512-byte blocks, which
  `cp --sparse=always` makes) came back dense. A block smaller than the
  file system can make a hole of (FreeBSD's ZFS reports 512, OpenBSD's
  FFS its fragment) only cuts blobs into more writes, not the blocks they
  take: about 60 times as many for a disk image of an ext4 file system
  (52,000 writes for 3 GiB, against 860 at 4096), 3 times as many for
  executables. If
  the file turns out not to be empty after all (a race), it is emptied
  first, so that no hole keeps old contents. Stock rustic's
  `--sparse by-content` left old contents where a zero chunk went.
- Every other file is allocated in full: a new file, or an existing one the
  restore writes into (cut to length first, if longer), is preallocated
  when it is sized (`fallocate(2)` on Linux, `F_PREALLOCATE` on macOS, as
  restic does; nothing elsewhere), and gets every byte, zeros included.
  Not on btrfs, though, but for a no-copy-on-write file (`C`, a swap file),
  and never on bcachefs (`fstatfs(2)`, then `FS_IOC_GETFLAGS`): neither
  compresses what `fallocate(2)` allocated, so a restore onto a compressing
  mount (`compress=zstd`) would need every file's full size, and might not
  fit where the source did. A NOCOW file isn't compressed anyway, and gets
  its flag when it is created, before it is sized; bcachefs's
  no-copy-on-write is an inode option, not a file flag, and it has no swap
  files. A new file still gets every byte, so it has no holes either way;
  one the restore writes into keeps any hole that a blob of zeros already
  matched (an interrupted restore's), where nothing allocates it. An
  existing file left as it is, of the right contents, has its holes
  allocated on Linux (a swap file left with holes by an
  interrupted restore), only where the snapshot says it had none: a
  snapshot of BackOtter's (its program version has `+backotter`, which
  marks every file with holes `unix.sparse`), for a node without the mark,
  and not with `--sparse by-content`. In any other snapshot (stock restic's
  or rustic's, which mark no file) such a file stays as it is, as in stock
  rustic: it may have had its holes at backup too, and filling them could
  fill the disk. The file is looked at first (`lstat`: fewer blocks than
  bytes, then `SEEK_HOLE` on it opened read-only) and opened for writing
  only to fill holes it has, so that a file without holes gets no
  close-write event (sync clients, indexers) and a running program no
  `ETXTBSY`. Linux fills them with `fallocate(2)`. Other systems fill
  none, as BackOtter's restic: macOS's `F_PREALLOCATE` only adds space past
  the end of a file, and the only other way, writing zeros into each hole,
  writes into a file whose contents are right already. Never on ZFS
  (`fstatfs(2)` of the file opened read-only: `f_type` 0x2fc12fc1),
  where `fallocate(2)` allocates nothing and compression keeps written
  zeros as holes, so that such a file would be opened for writing at every
  restore for nothing; a file system that can't allocate (`fallocate(2)`
  failing with `EOPNOTSUPP` or `ENOSYS`: ext4 on an ext3-format file's
  indirect blocks, older ZFS) is nothing to do, as in BackOtter's restic.
  Nor on btrfs but for a NOCOW file, nor on bcachefs, as above: such a file
  isn't opened for writing, nor counted as modified by `--dry-run`. A
  file whose holes were filled counts as modified, not unchanged, and so
  does one that got blocks from a fill that then failed (`ENOSPC` once the
  file system has allocated part of it: its blocks are looked at again
  after any failure); one whose holes couldn't be filled otherwise
  (`ENOSPC`, `EIO`, can't be opened for writing) is a warning ("holes not
  filled"), and the restore goes on, exiting 0 even under rustic's
  `--strict-exit`, as restic only warns.
  `--dry-run` looks at the file the same way (never opening it for
  writing) and counts one whose holes would be filled as modified, as
  BackOtter's restic reports it as updated.
- On FreeBSD and NetBSD, extended attributes are named as restic names them:
  the user namespace only, under bare names (stock rustic keeps both
  namespaces, as `user.NAME` and `system.NAME`, and restores the system
  namespace's raw UFS ACL storage). In a snapshot not BackOtter's (no
  `+backotter` in its program version) a name that begins with `user.` or
  `system.` is stock rustic's: it is restored under that namespace and the
  bare name, and the attribute the file has under it isn't removed as one
  the node lacks (`xattr_restore_names` in `local_destination.rs`).
  BackOtter's snapshots keep the bare names.
- On FreeBSD and NetBSD the user namespace is listed directly: the xattr
  crate (1.6.1, and 1.7.0, which the lock has since 0.14.0: its
  `sys/bsd.rs` is the same) names the last attribute of the system
  namespace as one of the user namespace, which a restore then creates,
  empty. Both namespaces'
  values are read by their names' bytes; a node keeps a name that isn't
  UTF-8 with U+FFFD for what isn't, as a Linux one and as BackOtter's
  restic's JSON keep it (0.13.0+backotter.18; before, such a name read a
  name that doesn't exist, so a user attribute kept no value and a system
  one was dropped).
- On illumos, extended attributes are named attribute files (`runat(1)`),
  which the xattr crate doesn't support: they are read and written through
  `openat(2)` with `O_XATTR`, without the `SUNWattr_ro` and `SUNWattr_rw`
  system attribute views, and stored in name order, not the attribute
  directory's, as BackOtter's restic does. An attribute is read and
  removed by its name's bytes, and a node keeps a name that isn't UTF-8
  with U+FFFD for what isn't, as on the other systems and as BackOtter's
  restic's JSON keeps it: a restore gives the file the attribute under
  that name, and removes the one whose name no node can hold
  (0.14.0+backotter.2; before, such an attribute was opened by the U+FFFD
  name, so a backup left it out with "No such file or directory" and a
  restore could not remove it). The listing's `readdir(3C)` errors are
  errors (before, one cut the listing short, silently). A restore creates
  an attribute file with mode 0600, so that it is never readable by others
  before it gets its own owner, mode, ACL and times (`illumos.xattr_meta`),
  with `fchownat(2)`, `fchmodat(2)`, `facl(2)` and `utimensat(2)` on the
  attribute directory, in that order, once the values are written (in
  `osattrs::restore_attributes`); an attribute the restore left out is left
  alone. This goes before the file's own times (writing an attribute file
  leaves them) and flags. An attribute gets an owner and group only where
  the restore sets owners: none under `--no-ownership`, and one that was
  its file's owner's (or group's) at backup gets the owner (group) the
  restore gave the file, by name (the default) or as its SID's id here,
  whatever the snapshot's number; another user's keeps its number, as a
  node has no name for it. A change of owner refused to a restore not
  running as root is no warning, as for the file itself, and `--exact`
  compares the attributes' owners only where it compares the file's
  (0.14.0+backotter.2; before, every attribute was given the snapshot's
  uid and gid in every mode: under `--no-ownership` too, and by name the
  backup host's numbers, which may be another user's here, who could then
  read a 0600 attribute of a file that isn't his). A snapshot without the
  attribute restores as before. An attribute the file has already, with
  its node's value, is
  left as it is (read and compared first; only one of the same size is
  read), as on every other system and in BackOtter's restic. A snapshot's
  attribute whose name isn't an attribute file's (empty, `.`, `..`, which
  is the file itself there, one with a `/` or a NUL, a system attribute
  view) is neither set nor given its metadata, a warning
  (0.13.0+backotter.18; before, `..` truncated and wrote the file and a `/`
  led out of the attribute directory).
- FreeBSD ZFS project IDs (`freebsd.zfs_project`) are restored with the
  system extended attributes, before the flags, as each node's own ID and
  inheritance, as on illumos; on UFS (`ENOTTY`) they get one warning per
  restore, as other unsupported metadata.
- Before the restore changes a file or directory it finds at a node's path
  (rewrites it, fills its holes, gives it its metadata, replaces it, links
  over it or to it, breaks its hard link, makes, removes or renames an
  entry in it), it clears the flags that would refuse that, keeping the
  others, where the node says which flags the file had, so that the late
  flag pass puts those back (`osattrs::node_sets_flags`): a node with file
  flags, or any node of a snapshot of BackOtter's, which records the flags
  of every file that has any, so that one without them had none. In a
  snapshot of stock restic or rustic, which record none, what the restore
  finds keeps its flags, as in stock rustic, and what they refuse fails
  with its error. They come off only for what the restore changes
  (0.13.0+backotter.13; before, every entry found lost them as the walk
  reached it): a directory that was there keeps them, and on XFS its
  options, until an entry is made, removed or renamed in it
  (`commands/restore/prepare.rs`, `DirChanges`) or its metadata set; a
  file until it is written, cloned over, its holes filled or its metadata
  set. So an
  immutable file or directory whose contents and metadata match keeps
  them, and its inode its change time, under `--exact`. A file whose name
  the restore removes or renames another file over (replacing it by
  another type, linking over it, `--exact` breaking its hard link, one
  whose contents weren't backed up) is held open
  (`O_RDONLY|O_NOFOLLOW|O_NONBLOCK`) from before its flags come off
  (`osattrs::clear_restricting_flags_held`), and they go back on it
  through that descriptor once the name is gone, or wasn't
  (`HeldFlags::put_back`: `fchflags(2)` on the BSDs, `osattrs/bsd_held.rs`;
  `FS_IOC_FSSETXATTR` or `FS_IOC_SETFLAGS` on Linux): its other names,
  outside the destination too, keep them; that they can't be put back is
  an error. What `--delete` removes, and what lies below a directory
  replaced by a node of another type, never loses its flags, as in stock
  rustic (an immutable file isn't removed, and the error says so), but for
  a name of a file the restore replaced another name of (below). The flags
  cleared (`osattrs::clear_restricting_flags`):
  on FreeBSD immutable, append-only and undeletable, the owner's and the
  system's (`uchg`, `uappnd`, `uunlnk`, `schg`, `sappnd`, `sunlnk`), and
  ZFS's DOS read-only (`urdonly`), which refuses writes too; on NetBSD and
  OpenBSD `uchg`, `uappnd`, `schg`, `sappnd`; on DragonFly those and
  `uunlnk`, `sunlnk`; on Linux immutable and append-only (`i`, `a`), through
  `FS_IOC_FSSETXATTR` where the file system has it (it leaves btrfs's
  `btrfs.compression` alone), else `FS_IOC_SETFLAGS`. The late flag pass
  then gives every file its node's flags, so a restore over an installed
  FreeBSD (whose `libc.so.7`, `ld-elf.so.1`, `init` and `su` are `schg`)
  puts back the snapshot's contents and metadata, as BackOtter's restic
  does. Clearing a system flag takes root at securelevel 0 or below (a
  rescue system's is -1); where it is refused (only logged), what the
  restore does next fails, with its error. illumos' immutable, appendonly
  and nounlink system attributes are not cleared yet, in either tool.
- On illumos, in a snapshot of BackOtter's, a regular file or directory
  whose node has no `illumos.system_attributes` had a new file's at backup,
  and one without `illumos.zfs_project` no project: where the file at the
  destination has other system attributes (hidden, nodump, readonly,
  system, offline or sparse set since, `archive` or `av_modified` cleared)
  it gets a new file's again, and where it has a project ID or inheritance
  (given since, or got from the directory it was made in) that is taken
  off, with the extended attributes' metadata (`osattrs::
  restore_attributes`). Left as they are: `av_quarantined` (the file's
  contents may not have been replaced), and immutable, appendonly and
  nounlink (above), with which what the restore does to the file fails. A
  file whose view or project can't be read (UFS, tmpfs, a quarantined
  file) is left alone, silently. In any other snapshot they are unknown
  and stay (0.14.0+backotter.2; before, nothing took them off: the late
  flags pass sets only a node's own mask, so a restore, `--exact` too,
  left them, exit 0, and `--exact` set such a file's metadata again on
  every run). BackOtter's restic doesn't do this yet.
- `--delete` (plain or under `--exact`) removes what the snapshot hasn't
  got once the walk of the destination is done (0.13.0+backotter.13;
  before, as the walk met it), so that every file the restore replaced a
  name of is known by then, whatever order the names come in: the files
  with other names whose name the restore removed or renamed another file
  over, by device and inode (`Replaced`), and the later names of
  hard-linked files in the way of the links the metadata pass makes,
  which go first, held. An unexpected name of such a file loses the
  restricting flags that came off for the restore once more, held, and
  the file's other names get them back (`remove_extra`); every other
  entry keeps its flags. It goes on past what it can't remove, an error
  each; a directory is removed entry by entry, one name held at a time,
  past what fails, and the error says what failed first and how many
  entries were and weren't removed (`remove_tree`). The directory still
  gets its metadata, and its flags in the late pass. As BackOtter's
  restic 0.19.1+backotter.11 and .12. The later names of a hard-link
  group `--exact` breaks (`LinkGroup`) are in the way too, as in
  restic-bko (`linkedInTheWay`): 0.13.0+backotter.13 only counted them for
  the group, so an unexpected name of the file such a name was kept its
  restricting flags and stayed, an error (0.13.0+backotter.14).
  In a case-insensitive directory (ext4 or tmpfs casefolding, APFS, ZFS
  `casesensitivity=insensitive`) a name the walk sees, `SAME`, can be the
  entry of a snapshot name it doesn't, `same`: a target that isn't seen
  but is there, with nothing between it and the destination a symlink, is
  taken as there (a file or directory of another type is replaced first),
  and `--delete` leaves that entry, and of a directory so found removes
  only what is unexpected below it (`Aliases`, by paths folded to lower
  case and the same device and inode). 0.13.0+backotter.13 removed it
  once the walk was done, after planning the snapshot's file there, and
  then panicked reading the file's contents (exit 134: no metadata pass,
  the files not yet written missing too); .12 and before removed it as
  the walk met it, which lost the file when the snapshot's name sorted
  first (0.13.0+backotter.14). A directory so found that the snapshot's
  file of that name replaced stays as that file. A name that is the same
  only by its Unicode normal form is still removed. A file the restore planned to
  take blobs from that can't be read when it does (gone since the plan)
  is an error for each file that was to get them, and the restore goes
  on (stock rustic panicked: `unwrap`).
- A file whose contents can't be written (one the restore can't open for
  writing) is reported once (`restore PATH: contents not restored: ...`)
  and left as it is; the restore goes on with every other file and all the
  metadata, then fails (`The contents of N files could not be restored`,
  exit 1), as BackOtter's restic exits 1 for it. Stock rustic panicked at
  the first (an `unwrap` of the open), aborting the restore and leaving
  every file still pending stale. Such a file, and each other name of it
  (a hard link), gets its metadata but for its times (the birth time too,
  which FreeBSD and NetBSD set as an mtime): a restore trusts a size and
  an mtime that match (unless `--verify-existing`), so with the snapshot's
  mtime the next restore left the wrong contents and exited 0, a file
  sized in full before a write failed on a full target as well
  (0.14.0+backotter.2; before, the metadata pass gave it the node's times;
  stock rustic's panic came before that pass, so its second run repaired
  the file).
- An owner, a mode or times that can't be set are warned of as in stock
  rustic, to the letter (`restore PATH: setting UID/GID failed.`,
  `setting User/Group failed.`, `chmod failed.`, `setting file times
  failed.`): bko-holt matches those lines whole for the root of a FreeBSD
  msdosfs, which takes none of the three, and counts them against the
  errors `--strict-exit` reports. Since 0.14.0+backotter.2 a second
  warning right after gives the cause, which neither said (`restore PATH:
  chmod: setting file permissions failed: ...`).
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
  entry that. An extended attribute's own owner and group are kept and
  restored the same way (`illumos.xattr_meta`). A SID idmap can't map gets
  nobody (60001), never the number the backup saw, which may be another
  SID's by now, with a warning once
  per attribute (owner and group of the same file each get theirs) and
  the number of files at the end; it isn't an error. A
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
- On Haiku, every file, directory and symlink can have attributes, each
  with a name, a type code and data, which the xattr crate doesn't support.
  They are read and written through `fs_fopen_attr_dir(3)`,
  `fs_read_attr(3)` and the rest, on the file itself (`O_NOTRAVERSE`, so a
  symlink's own), and split by type, so that none is stored twice:
  - those of type `B_XATTR_TYPE` (`'XATR'`) are the extended attributes,
    under their names as they are: Haiku's own xattr functions
    (`getxattr(3)` in libgnu) write their attributes so, and read them so.
    Another system's extended attributes come back on Haiku as attributes
    of type `B_XATTR_TYPE`, under their names in the snapshot, and a Haiku
    snapshot's come back elsewhere under the names that system gives them:
    as they are on Linux and macOS, and with `user.` in front on FreeBSD
    and NetBSD, whose snapshots keep the user namespace under bare names
    (Haiku's `user.comment` is `user.user.comment` there, and FreeBSD's
    `comment` an attribute `comment` on Haiku). So a name without a
    namespace (FreeBSD's, or one a Haiku program chose) comes back only
    where the system takes it: Linux refuses it. (libgnu's names for the
    other attributes, `user.haiku.NAME#TYPE`, are not decoded: such an
    extended attribute comes back under that name, of type
    `B_XATTR_TYPE`.)
  - all the others are the generic attribute `haiku.attributes`, an object
    with an entry for each, by name: `{"type": TYPE, "value": "DATA"}`, the
    type code a number (the four characters read as a big-endian `uint32`:
    `'MIMS'` is 1296649555) and the data in base64 (empty data may also be
    null or left out), as in
    `{"BEOS:TYPE":{"type":1296649555,"value":"dGV4dC9wbGFpbgA="}}`. A file
    without any has `{}`, on a file system with attributes. An entry of
    type `B_XATTR_TYPE` is skipped with a warning: those are extended
    attributes. Other systems skip it quietly.
  A restore gives a file exactly the attributes of each kind that the
  snapshot has, as with extended attributes on other systems: one it has
  that the snapshot doesn't is removed, and one of another type or with
  other data written over (not removed first, so a failed write leaves it
  as it was). A node without `haiku.attributes` (a snapshot of another
  system, or of a file system without attributes) leaves a file's typed
  attributes as they are, as FreeBSD's system extended attributes. An
  attribute whose name isn't UTF-8 is left out of a backup with a
  warning, counted as one that couldn't be read (0.14.0+backotter.2;
  before, not counted), and left on the file by a restore. A restore goes
  on past an attribute whose `fs_stat_attr(3)` fails: the error names it,
  and the others are set and removed. Empty attributes are restored too,
  though BFS makes none of a write of no data: such a one
  is written with 16 KiB of zeros first, which BFS moves out of the inode,
  then truncated; a file system on which that doesn't work either gets a
  warning naming the attribute. The attributes are restored before the
  mode, not after it as on other systems, since BFS wants write access to
  a file to write its attributes, which a user other than root wouldn't
  have on a read-only file. A FIFO's or device's attributes aren't kept.
  Haiku's creation time (`st_crtim`) isn't kept: `unix.birthtime` is
  neither saved nor restored there.
- A file that can't have extended attributes (a FIFO on ZFS) has none,
  rather than a warning, as in restic; so does one whose attributes can't
  be listed with `ENOATTR` (`ENODATA` on Linux), as an SMB/CIFS mount
  gives, and an attribute whose value the file system says it doesn't
  support (`ENOTSUP`, `EOPNOTSUPP`, `ENOATTR`) is kept without a value, as
  restic's `handleXattrErr` takes these (`osattrs::xattr_unsupported`).
  On restore, these errors are unsupported metadata, as restic's
  `xattrUnsupported` says.
- Extended attributes are stored in the byte order of their names, on
  every system (Linux, macOS, FreeBSD, NetBSD, illumos), as BackOtter's
  restic stores them; stock rustic keeps the order the file system lists
  them in. The order means nothing to a restore, which sets each attribute
  by name.
- One extended attribute whose value can't be read is left out with a
  warning naming it (`ignoring extended attribute NAME of PATH: ERR`), and
  the file's others are kept, as in BackOtter's restic; stock rustic
  dropped them all, with one warning (`ignoring error obtaining xargs`),
  which is still what a list of them that can't be read gives
  (`LocalSourceSaveOptions::xattrs_with` in `backend/ignore/mapper.rs`; on
  illumos `xattrs_read` in `osattrs/illumos.rs`; on Haiku `read_kind` in
  `osattrs/haiku_attrs.rs`, for both kinds of attribute: one of
  `haiku.attributes` that can't be read, or whose `fs_stat_attr(3)` fails,
  is named with its error in one warning for the file, `ignoring
  attributes of PATH: NAME: ERR; ...; its others are kept`, and
  `haiku.attributes` holds the others; 0.14.0+backotter.2, before which
  the first failure lost a Haiku file all its attributes of that kind).
- bcachefs' `bcachefs_effective.*` extended attributes aren't kept, nor
  set or removed by a restore (one in a snapshot of stock restic's is
  skipped): they show the options a file has, its own (`bcachefs.*`, kept
  as any other) or inherited from its directory, and its project ID
  (`linux.project_id`), and setting one returns 0 and does nothing (Linux
  6.12). Nor is `bcachefs.project`, which bcachefs 1.39 (not Linux 6.12's)
  lists for a file given a project ID rather than inheriting it:
  `linux.project_id` carries the ID, and bcachefs refuses to have the
  attribute set to anything but 0 (`EINVAL`), so a restore of a snapshot
  that holds it (from an earlier build) skips it, as BackOtter's restic
  does.
- A file with illumos' `av_quarantined` can't be opened for reading, by
  root either (`EACCES`), but its metadata can be read: a backup keeps its
  node without its contents, as BackOtter's restic does. Where opening a
  regular file is refused with `EACCES` and
  its system attributes (read through its attribute directory, opened with
  libc's `__openattrdirat` as `getattrat(3C)` and `ls -/ v` open it,
  without opening the file) have `av_quarantined`, the node has its mode,
  owner, times, links, inode, device, SID owners, ACL, system attributes
  (`av_quarantined` included) and birth time, no `content` and size 0, and
  `illumos.unread_size`, the file's real size; its extended attributes and
  `illumos.xattr_meta` are left out, by choice, as BackOtter's restic
  leaves them out: both tools reach an attribute directory through the
  open file, which is refused, though `__openattrdirat` would reach it and
  the attribute files themselves aren't quarantined. So is its ZFS project
  (reading it opens the file). One warning names it
  (`PATH: av_quarantined: contents not backed up (N bytes)`) and the backup
  exits 0. Any other file that can't be opened is left out, as before,
  reported as upstream's archiver reports it since 0.14.0 (#561: `error:
  archival PATH: ...` through `Progress::error`, a JSON `error` line under
  rustic's `--json`; 0.13.0 logged `ignoring error: Failed to open ...`),
  and counted in `error_count` and `items_incomplete`: the backup exits 3
  under rustic's `--strict-exit` and, since rustic v0.12.0, without it
  too. The source's attribute is
  never cleared or changed. A restore makes such a file empty, a new one
  in place of any file there (which may be quarantined, its contents and
  extended attributes closed to the restore too), as BackOtter's restic
  does, gives it the rest of its metadata, the system attributes last as
  for any file (so it is quarantined again), and warns once for it
  (`PATH: contents were not backed up (av_quarantined at backup, N
  bytes)`), exit 0; on another system too, where the system attributes are
  left as for any illumos file. A version that doesn't know `illumos.unread_size` warns once about
  it as unknown and restores the empty file.
- A backup keeps the metadata of the directory it backs up (stock rustic
  stores it as a bare directory, mode 0755 and nothing else), so that
  restoring `SNAP:path` can give the destination that directory's metadata,
  as BackOtter's rustic does, where the destination is fresh
  (`restore_target_is_fresh`: it doesn't exist, or holds only mount
  points, the directories on the path to them, and what mkfs or newfs
  makes itself: a `lost+found` or `.snap` directory, a `.sujournal`
  regular file, nilfs2's empty regular file `.nilfs`, and on Haiku the
  empty `trash` directory its Tracker makes on every volume as it is
  mounted, a new one too, without which a restored BFS root kept mkfs's
  metadata and the time its last entry was made; never one that
  exists and is sticky or that others may write in, mode bits 01000 or
  0002, even an empty one such as /tmp or /dev/shm; rustic's
  BACKOTTER.md has the whole rule), or, fresh or not, under `--exact` or
  rustic's `--target-metadata`. It goes by the name it's saved as
  (`--as-path`), and `/` still has no node, as in restic.
- A regular file without a mode is restored with permissions 0000 where
  that is what it had: restic leaves a mode of 0 out of its JSON (and so
  did BackOtter's rustic until 2026-11-03), so stock rustic leaves such a
  file (`/etc/shadow`) with the 0644 it was created with. Only for a node
  read from a Unix file system (it has an inode number) in a snapshot of
  restic (any) or BackOtter's rustic (`SnapshotOrigin::omits_zero_mode`):
  a file read from stdin (`backup -`, `--stdin-command`: a database dump)
  or made on Windows has no inode number and no mode, and in a stock
  rustic snapshot a missing mode is unknown; such files keep the mode they
  are created with (0666 less the umask), as in stock rustic.
- What a node's missing attributes mean depends on what wrote the snapshot
  (`SnapshotOrigin`, from its `program_version`, which rustic's `restore`
  passes in `RestoreOptions::origin`; a caller that doesn't gets stock
  rustic's behaviour): in a snapshot of BackOtter's restic or rustic
  (`+backotter`), which record everything they can, a missing attribute
  was zero or absent at backup (no flags, no project ID, no holes); in any
  other it is unknown, and the restore leaves the destination as it is.
  A snapshot without a program version is restic's before 0.16, which wrote
  none (stock rustic always writes `rustic VERSION`): a stock restic
  snapshot, whose regular files without a mode had mode 0.
- On FreeBSD and NetBSD the restore acts on what such a missing attribute
  says (0.14.0+backotter.2; before, a restore set only what a node holds,
  so these stayed, exit 0, and `--exact`, which counts them as differences,
  set such a file's metadata again on every run), in a snapshot of
  BackOtter's only:
  - a node without an ACL attribute had no ACL of that type that says more
    than its mode, and the file loses one it has (`strip_acls` in
    `osattrs/freebsd_netbsd.rs`), after the mode is set and with the mode
    left as it is: an NFSv4 ACL that isn't trivial becomes the mode's
    trivial one (`chmod(2)` leaves the other entries on ZFS with
    `aclmode=passthrough`); a POSIX.1e access ACL of more than three
    entries becomes those three (`chmod(2)` only narrows the mask, so a
    named user kept what the mode's group bits allow: access the snapshot
    never gave); a directory's default ACL is removed
    (`__acl_delete_link`). So an entry given since the backup goes, and so
    does what a file or symlink the restore made inherited from a default
    ACL the destination's directory already had. A symlink too, which a
    snapshot from before 0.14.0+backotter.2, or one of BackOtter's restic,
    has no ACL for: restoring such a snapshot over a symlink that has an
    ACL of its own takes it off. An ACL that says no more than the mode is
    not written to;
  - a node without file flags had a new file's (none; `uarch` alone on
    FreeBSD's ZFS), on OpenBSD and DragonFly too: the kept flags the file
    has beyond them go (`nodump`, `hidden`, `opaque`, `uarch` off ZFS...;
    `bsd_held::restore_no_flags`, with the attributes, one flag at a time
    where they can't all change). The restricting ones came off before the
    restore changed the file. A file with a new file's flags is not
    written to. On Linux a flag the node lacks still stays (the late flags
    pass sets only a node's own);
  - a node with `freebsd.system_extattrs` (`netbsd.`) gives the file
    exactly those: one with the node's value already is left, any other
    the file has is removed (but for those UFS and FFSv2ea store ACLs in).
    A node without the attribute leaves the file's as they are, whatever
    wrote the snapshot: only root can list that namespace, so a backup by
    another user records none for a file that has some, and the node
    doesn't say which it was. `--exact` doesn't count them as a difference
    then (`osattrs::absent_is_unknown`), so it converges.
  BackOtter's restic does none of this yet (`nodeRestoreACLs` returns for
  a node without the attribute, `restorer.go` queues flags only for a node
  that has them): it needs the same for the two to restore alike.
- `merge` makes a snapshot of other snapshots' nodes: it is BackOtter's
  only if every snapshot merged is. Otherwise the program version it is
  given loses its `+backotter`, each word cut there (`rustic
  0.11.4+backotter.3` becomes `rustic 0.11.4`, stock rustic's own form),
  so that a stock snapshot's missing attributes stay unknown in it. Stock
  rustic stamps a merge with its own version whatever was merged.
  `rewrite`, `copy` and `repair snapshots` keep each snapshot's own
  program version, as in stock rustic.
- A hard link over an entry already at its name (upstream's 506a1da, #634,
  in 0.14.0):
  the right link, where a restore is run again over its own result, is
  left as it is; another file or a symlink is replaced; a directory is an
  error. Stock rustic 0.13.0 tried to link over it, failed (`EEXIST`) and
  stopped there, leaving the rest of the metadata, the late flags pass
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
- FAT's attributes (`linux.fat_attrs`) go on in that last pass too, before
  the file flags, for the same reason (a write sets archive), with
  `FAT_IOCTL_SET_ATTRIBUTES`, which also sets the mode's write bits from
  read-only, as a `chmod(2)` would: the restore reads the file's attributes
  and changes the kept ones only where they differ. A FAT file system's
  root directory takes none (`EINVAL`, unsupported). On a file system other
  than FAT they aren't set, with one warning per restore
  ("linux.fat_attrs not supported by the file system: not FAT") and the
  number of files at the end.
- So do XFS's options (`linux.xfs_options`): a directory's go on in that
  last pass, so the entries the restore makes in it inherit nothing (each
  has its own node); one that was there (an earlier restore's), the
  destination itself too, loses its options before they go in, and gets
  back in the last pass its node's, or those it had where its node has none
  (the destination, which keeps its own metadata, those it had). A restore
  that stops before (an error, a plan that isn't restored, an interrupt,
  for which a program calls `put_back_xfs_options` before it exits, as
  rustic-bko does, after which the restore makes no entry, its threads
  waiting for the exit, so that none inherits them) puts back those it
  had, which a node without options can't give. A regular file's go on also as
  soon as the restore creates it, while it is empty (with the
  no-copy-on-write flag), since XFS takes an extent size hint on no file
  with data (`EINVAL`), and again in the last pass, which leaves options
  that are right alone. A file the
  restore writes over (one that was there, with data) can't get a new
  extent size hint: that is unsupported, one warning per restore. A
  directory XFS refuses realtime inheritance along with an extent size
  hint's inheritance (`EINVAL`: a hint that isn't a multiple of the
  target's realtime extent size) gets the rest, and realtime inheritance
  alone is unsupported ("linux.xfs_options 0x100 not supported by the file
  system"). A snapshot from before rustic_core 0.13.0+backotter.9 or
  BackOtter's restic 0.19.1+backotter.6 has no realtime inheritance:
  restored over a directory that has it, a node with XFS options takes it
  off (they say it had none), one without leaves it: an accepted
  difference, in both tools. On a file system other than XFS: one warning
  per restore ("linux.xfs_options not supported by the file system: not
  XFS") and the number of files. As in BackOtter's restic.
- An extended attribute the restore can't set (`trusted.*` not as root,
  one the file system refuses) doesn't keep the others from being set, or
  those the node hasn't from being removed, as in BackOtter's restic: each
  file gets one warning naming every attribute that wasn't set, with its
  error (`restore f: setting extended attributes failed: trusted.a:
  Operation not permitted (os error 1); ...`). Stock rustic stopped at the
  first, leaving the rest unset, and said neither which nor why. On
  illumos too, and on a file system without extended attributes (NetBSD's
  FFSv1 and plain FFSv2): each of the file's attributes is named, with
  `Operation not supported`.
- Metadata the target file system doesn't support (flags, casefolding, FAT
  attributes, XFS options or a project ID it refuses with `ENOTTY`,
  `EOPNOTSUPP`/`ENOTSUP` or `EINVAL`)
  gets one warning per kind (attribute and refused flags) per restore,
  naming the first file, and the number of files at the end, as do SIDs
  idmap can't map on illumos (per attribute). Any other
  failure (`EPERM`, `EDQUOT`, `EIO`, ...) is warned about for each file.
  By default neither changes the exit status: like stock rustic's, the
  restore only warns about metadata it can't set. With rustic's
  `--strict-exit` the failures BackOtter's restic counts as errors make the
  restore exit 1, as restic does (`RestoreStats::errors` for those of the
  collect phase, `RestoreOutcome::errors` for the rest): a special file
  that couldn't be made, an owner, extended attribute, attribute (FreeBSD's
  system extended attributes, illumos' attribute metadata, project IDs,
  Haiku's attributes), mode, symlink mode, ACL, birth time or times that
  couldn't be set, flags that go on before a directory's entries or a
  file's contents, the late flags, DOS flags, FAT attributes and XFS
  options, an entry `--delete` couldn't remove (or a failed walk of the
  destination with `--delete`), and what has a node's name but another
  type and couldn't be removed. What stays a warning, exit 0, as in
  restic: metadata the file system doesn't support (`Unsupported`,
  `ErrorKind::Unsupported`), SIDs idmap couldn't map, a permission refused
  (`EPERM`, `EACCES`) to a restore not running as root for the owner,
  extended attributes, attributes, mode, ACLs, birth time and times (as
  restic's restore forgives them then: `trusted.*` and `security.*`
  attributes, files someone else owns; the late flags still count, as in
  restic), user or group names unknown here, casefolding not restored,
  unknown or malformed generic attributes, holes not filled, and a file
  whose contents weren't backed up (`av_quarantined`). Contents that
  couldn't be written fail the restore with or without it (above). ACLs
  the file system can't hold (`EOPNOTSUPP`/`ENOTSUP`, which the FreeBSD,
  NetBSD and illumos code gives as `ErrorKind::Unsupported`; on illumos an
  NFSv4 ACL, `illumos.acl` or one in `illumos.xattr_meta`, refused with
  `ENOSYS` by tmpfs and UFS, which have only POSIX-draft ACLs) are warned
  about per file, and the file keeps the mode restored before it;
  BackOtter's restic now does the same and exits 0 (it had failed, exit
  1), and so does rustic-bko under `--strict-exit`.
- A restore not running as root says nothing about an owner it isn't
  permitted to set (`EPERM`, `EACCES`; debug log only), as BackOtter's
  restic and stock restic (and `cp -a`, `rsync -a`) don't: stock rustic
  warned `setting UID/GID failed` for each such file, such as the
  root-owned directories above the restored path that rustic-bko now
  stores. Any other failure, and every one as root, is still warned about.
- A restore over a hard-linked file whose contents changed gives each of
  its names the snapshot's contents, as rustic always did. BackOtter's
  restic now does too: it replaced such a file by a new one before writing
  it, but kept the blobs that still matched out of it, so the group came
  back with NULs, or empty (stock restic still does).
  Where flags as a whole are refused (one only root may set, as the owner),
  the restore changes them from what the file has, one at a time, keeping
  each change accepted, and warns naming the bits it couldn't set or clear
  (`file flags 0x20 of 0x229 not set, 0x200 not cleared`): every write
  sets all of a file's flags, so trying them from none would clear, each
  time, one the owner may set but not clear (illumos' `av_modified`), and
  every try would fail.
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
  alone (checked on Linux 6.12). The flags are read back after that: where
  those two aren't what was asked, or the file system has no
  `FS_IOC_FSSETXATTR`, all the flags go on through `FS_IOC_SETFLAGS`, as
  where there is no property (0.13.0+backotter.17). That is a node with the
  property restored elsewhere: OpenZFS 2.2 reads `fsx_xflags` as
  `FS_IOC_GETFLAGS`'s flags, so that such a file came back immutable
  instead of append-only, or without either (immutable refused).
- btrfs's no-copy-on-write flag is set while a new file is still empty: btrfs
  ignores it on a file with data.
- Casefolding (`F`) is a creation-time flag: ext4 and f2fs refuse to change
  it on a directory with entries, and a new directory inherits it from its
  parent. So every directory the restore creates, and every one it finds
  empty (a mount point, the destination of `SNAP:subfolder`), gets its
  node's casefolding before anything goes in: set where the node has it,
  cleared where it hasn't in a snapshot of BackOtter's, which records the
  flags of every directory that has any (so that a directory without it in
  the snapshot, in one with it, doesn't come back case-insensitive and lose
  one of `Makefile` and `makefile`), with no `FS_IOC_SETFLAGS` when it is
  right already. In a snapshot of stock restic or rustic, which record no
  flags, a directory without them keeps what it inherited (casefolding
  from its parent: a casefolded Proton or Samba tree stays casefolded), as
  in stock rustic. A file system without it is no error there. The late flag pass
  leaves casefolding as the directory has it, and warns once per directory
  where it still differs from the node ("casefolding (F) not restored on
  DIR: directory not empty or not supported"). The destination of a whole
  snapshot has no node, and is left as it is.
- On bcachefs the same directories (those created, or found empty) get
  their own options then too, before anything goes in: their `bcachefs.*`
  extended attributes and their project ID, 0 where the node has none in a
  snapshot of BackOtter's (in another the inherited one stays, as do files'
  without one).
  bcachefs passes a directory's options only to entries created after they
  are set, so set at the end with the other metadata the entries would
  lose the compression, replicas, targets or nocow they inherited, and get
  their project ID as their own. Errors there are silent: the directory's
  metadata at the end sets again each that isn't right, and reports them.
  That pass, as every restore of extended attributes, leaves one the file
  has already with its node's value alone: bcachefs refuses
  `bcachefs.casefold` on a directory with entries (`ENOTEMPTY`), even the
  value it has. Where `bcachefs.casefold` still has to change on a
  directory with entries (an existing one, restored over), that refusal,
  setting or removing it, is a warning, "casefolding (bcachefs.casefold)
  not restored on DIR: directory not empty", as for F, not one of the
  file's errors. As BackOtter's restic does.
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
  /chardev: mknod ...`, exit 1); so does rustic-bko under `--strict-exit`,
  exit 1, as restic (above).
- A backup stores special files' nodes as restic does: a character
  device's mode has Go's `ModeDevice` and `ModeCharDevice` (stock rustic
  ANDs the two bits, which gives none), only a regular file has a size
  (stock rustic stores a symlink's target length), and a FIFO or a socket
  has no link count, and so no device ID (below).
- A node has a device ID (`device_id`) only where a restore needs one, to
  make hard links: a file, symlink or device with more than one link, as
  with stock rustic's default (`--set-devid hardlink`); not a directory, a
  file with one link, or a FIFO, whose link count isn't stored (stock
  rustic stored one for a hard-linked FIFO). BackOtter's restic stores it
  by the same rule (restic's `device-id-for-hardlinks`, which it turns on
  by default), so the two tools' snapshots of one tree have the same nodes
  (not the same tree IDs: below); stock restic stores it on every node. A device ID changes when the same files are seen through another
  device (a btrfs subvolume or snapshot, an LVM snapshot, the disk a rescue
  restored to), which would change every node, and so every tree, of the
  next backup. Restores use it as before: only for nodes with more than
  one link, so snapshots that have it on every node (stock restic's,
  BackOtter's restic's before) restore as they did.
- Sockets are skipped, as restic skips them: a backup leaves them out
  (stock rustic stored them), and a restore leaves out the socket nodes
  of older snapshots (stock rustic made them with `mknod`, which works on
  Linux only). A socket is only the name a running program listens on;
  the program makes it again when it starts, and a restored one has
  nobody listening.
- So are illumos doors (`S_IFDOOR`: `/etc/sysevent`, `/var/run`,
  `/etc/svc/volatile`), quietly (debug log), as in BackOtter's restic: a
  door is a running program's door server, made again when it starts, and
  a restored one would have nobody behind it. Stock rustic took one for a
  regular file, couldn't read it (`ENOSYS`) and warned about its
  directory; stock restic failed (exit 3). `skipped_type` in
  `backend/ignore.rs` skips any file of none of a node's types.
- Directories above the backed-up path (`/home` in a backup of
  `/home/m`) are stored with their own metadata (their `lstat`: mode,
  owner, times, inode, extended attributes, ACLs, flags and the rest), as
  restic stores them and as a backed-up directory is stored, so that the
  two tools' snapshots are the same and a restore of the whole snapshot,
  by either tool, gives those directories their own mode, owner and times
  (`ReadSource::dir_node`, `archiver/tree.rs`). Stock rustic made nodes of
  its own for them: mode `0o755`, without Go's directory bit, and no
  owner, times or anything else, so they came back `0755`, owned by
  root, with the restore's time. rustic still makes those for a directory
  above the snapshot's path that isn't one on disk: under `--as-path`, for
  stdin, and where the directory can't be read or isn't a directory (with
  a warning; restic's backup fails there). A restore sets no times for a
  node without an mtime (the directory keeps those the restore gave it),
  in either tool, so snapshots stock rustic made restore so; restic-bko
  used to set the zero time, which DragonFly refuses. A node without an
  atime gets its mtime as its atime, in either tool. One upstream test
  backs its file up `--as-path` for it (`test_prune_parallel_and_backup`,
  `tests/integration/prune.rs`): it expects three backups of one file to
  give one tree, and a directory above the file is the shared `$TMPDIR`,
  whose times other tests move. A second tree there meets what upstream's
  `prune` and `repair index` do with a stale prune plan (the plan's new
  index is written before its old index files are found gone; a pack
  listed both unmarked and marked keeps whichever entry is read first),
  and `check` then misses a tree that is still in the repository.
- A block or character device whose device number is 0 (`/dev/console`
  and `/dev/wd0a` on NetBSD and OpenBSD, or `mknod c 0 0`) has no
  `device` in its node, as restic leaves it out (Go's `omitempty`), so
  that the two tools' nodes are the same; stock rustic wrote
  `"device":0`. A node without one is device 0 to either tool.
- A regular file whose mode is 0 (permissions `0000`, as `/etc/shadow` has
  on Red Hat's and SUSE's systems) has `"mode":0` in its node, as stock
  rustic writes it, so that stock rustic's `ls` shows `----------` and its
  `dump --archive zip` keeps 0000 (without it, `?????????` and 0644).
  restic leaves it out (Go's `omitempty`), as BackOtter's rustic did until
  2026-11-03; a restore of either tool gives a regular file from a Unix
  file system without one permissions `0000` in a restic or BackOtter
  snapshot (above). Accepted difference: the two tools' nodes differ
  there, not in value.
- An extended attribute is a file of any size on illumos (a named
  attribute, an SMB alternate data stream) and on Haiku (a BFS attribute
  in an inode of its own), and a backup keeps it whole whatever its size,
  as far as a repository can hold it. A node holds the value inline, in
  base64, and its tree is one blob, whose length is kept in 32 bits: the
  most is 3221225469 bytes (`osattrs::NATIVE_XATTR_MAX`, 3 GiB less 3,
  the largest value whose base64 text is under 4 GiB). A tree with a
  larger one can't be saved by either tool, and the backup failed on it
  (stock rustic's "Failed to convert data length", restic's "blob is
  larger than 4GB"). The value is read into memory once, and its tree
  takes several times its size there on the way into the repository and
  out of it: for 220 MiB of attributes on one file, measured on OmniOS
  r151058, 1.75 GiB at the backup's peak and 1.3 GiB at a restore's.
  One over the most is left out by its size, before any of it is read,
  with the warning of an attribute that couldn't be read (`ignoring
  extended attribute NAME of PATH: too large to keep (N bytes, over
  3221225469)`; on Haiku one that isn't an extended attribute is named in
  `ignoring attributes of PATH: ...`), counted the same, and the file's
  others are kept; so is one whose size no memory can be had for (`no
  memory for its N bytes`: on a small machine, or a size a damaged BFS
  made up), which ended the backup (0.14.0+backotter.2). As for any
  attribute a backup couldn't read, a restore in place of that snapshot
  takes it off the file. There is no smaller limit: 0.14.0+backotter.2's
  first, 16 MiB, never in a release, left out attributes that had
  restored until then, and a restore then lost them. Several attributes
  that fit one by one and not together in their directory's tree still
  fail the backup, as a tree too large for any other reason does.
  BackOtter's restic reads one of any size too and fails on the tree of
  one over the limit: below it the two tools' nodes are the same.
- Extended attributes are read whole, however large, on Linux
  (`osattrs::xattr_get`, `xattr_list`: `lgetxattr(2)` and `llistxattr(2)`
  with the size they give, again on `ERANGE`). The xattr crate 1.6 (1.6.1,
  on rustix 1.1) reads a first 4 KiB and asks rustix for a larger value's
  size with an empty buffer, which rustix 1.1 answers with 0: every value
  over 4 KiB was backed up empty (a 15000-byte `user.*` on btrfs, 60000
  bytes on XFS), and so were ACLs that long. xattr 1.7.0, which the lock
  has since 0.14.0, asks rustix's `*_query` functions for the size
  instead. The fork's own reader stays: Cargo.toml takes any `xattr = "1"`,
  1.6 included, and nothing here tests the crate on a large value.
  Elsewhere the xattr crate reads them (its BSD code has no such step).
- A restore never removes a file's SELinux label (`security.selinux`)
  where its node has none (`osattrs::xattr_never_removed`): the system
  gives every new file one, and SELinux lets nobody remove it (`EACCES`,
  root too), so a restore onto Rocky or openSUSE warned for every file of
  a snapshot from a system without SELinux, a btrfs subvolume's root
  (which has none), and the directories above the backed-up path of an
  older snapshot; restic exited 1 there. The file keeps the label the
  restore gave it. A node with a label sets it, as before. The same in
  BackOtter's restic.
- Before a restore rewrites or gives metadata to an existing file, it
  clears its immutable and append-only flags through `FS_IOC_FSSETXATTR`,
  then through `FS_IOC_SETFLAGS` where that left either set
  (`clear_restricting_with` in `osattrs/linux.rs`): on Ubuntu 24.04's
  OpenZFS (2.2) `FS_IOC_FSSETXATTR` cleared immutable but left
  append-only, as if it read `fsx_xflags` as `FS_IOC_GETFLAGS`'s flags
  (where `FS_XFLAG_APPEND` is immutable), and a restore over an
  append-only file on ZFS couldn't change it (a warning per step; restic
  exited 1); OpenZFS 2.3.9 clears both. The same in BackOtter's restic.
- Partial restores (`--glob`, `--iglob`): directories above the matches
  that aren't matched themselves are streamed too, each just before the
  first match below it (`TreeStreamerOptions::with_parents`, which rustic's
  restore sets; `ls`, `find`, `diff` and `dump` keep the stock stream), so
  the restore gives them their metadata and casefolding, as BackOtter's
  restic does; stock rustic created them without any. Accepted
  difference: a directory whose only match is a socket is created (restic
  skips sockets before matching). As in stock rustic, the children of a
  directory excluded with `--glob '!dir'` are still restored (each path is
  matched on its own); that directory now gets its metadata too.
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
  without them (illumos' UFS: `ENOENT`, `EINVAL`, `ENOTSUP` on the view;
  tmpfs, which has the view but refuses a `crtime` in it with `EINVAL`),
  the attribute is only noted in the debug log, in either tool (both had
  reported each file on tmpfs, restic as an error). A failure
  (`EPERM` as neither owner nor root) is warned about, as for the times.
- A restored symlink keeps its own permissions on FreeBSD, OpenBSD, NetBSD
  and DragonFly (`fchmodat(2)` with `AT_SYMLINK_NOFOLLOW`, one function for
  the four; OpenBSD has no `lchmod`), where stock rustic leaves the 0755 a
  new symlink gets. A file system that refuses (`EOPNOTSUPP`, `EINVAL`) is
  only noted in the debug log, on FreeBSD too since 0.14.0+backotter.2
  (it had its own `lchmod(2)` call, whose every failure was a warning for
  the symlink, and `EINVAL` an error of the restore).
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
  `+00:00` (stock rustic). A time whose zone offset has seconds (a zone's
  local mean time: Europe/Paris, +00:09:21 until 1911; Africa/Monrovia,
  -00:44:30 until 1972) is written in UTC as well, since RFC 3339 has no
  seconds in an offset: stock rustic, and BackOtter's restic, write the
  local time with the offset's minutes only, and the time reads back
  wrong by up to a minute (a file dated 1850 at Europe/Paris, 21 s late).
- Accepted difference (both tools): the two tools' snapshots of one tree
  have the same nodes but not the same trees' bytes, so not the same tree
  IDs, even in one repository. rustic writes a symlink's `linktarget` and
  `linktarget_raw`, and a device's `device`, right after `type` (serde's
  `flatten` of `NodeType`); restic writes them after `links`, in its `Node`
  struct's order. And restic escapes `<`, `>` and `&` in names and other
  strings (`\u003c`, Go's `json.Marshal`), which serde_json doesn't. So a
  directory holding a symlink, a device or such a name gets a different
  tree in each tool, and so does every directory above it, the root
  included. The files' data blobs, and the trees that hold none of these,
  are shared between the tools. Either tool restores the other's
  snapshots; BackOtter's checks compare the two tools' snapshots node by
  node, never by tree ID.
- The owner names a backup keeps are looked up once per uid and gid in a
  run, and on restore with `--by-name` the ids once per name, found or not:
  the cached crate (2.x) stopped caching a lookup that found nothing, so
  without `/etc/passwd` and `/etc/group`, as on a minimal rescue system,
  rustic looked each file's owner up again and warned for every file
  (`error getting user from uid 0: ENOENT`). Now it warns once per id. A
  name not found on restore falls back to the saved id, as the warning
  now says (it said UID 0).
- The chunker cuts where restic's does (`chunker/rabin.rs`). rustic_core
  0.13.0 hashed only 63 of the 64 bytes before a chunk's minimum size
  (rustic_cdc's `reset_and_prefill_window`), leaving out the last of them,
  which restic hashes, so a cut in the 64 bytes after the minimum size could
  differ, and every later blob of the file with it. The fork hashed all 64
  bytes; upstream's 43740bf (#638, in 0.14.0) does it now, and the fork's
  own change was dropped in the rebase onto 0.14.0. What stays is the test
  `chunk_like_restic`, whose lengths come from restic's chunker
  (github.com/restic/chunker v0.4.0), to check that the cuts stay restic's.
  A file that met the case is cut differently from a rustic 0.13 snapshot
  of it, so its data after that cut is stored again once.
- A file's size in the snapshot is the number of bytes the backup read
  (`archiver/file_archiver.rs`), as restic's is, not the size `lstat` gave
  when the file was listed. A file cut short (or grown) while it was read
  kept its listed size, which its content no longer had, and the tools
  restored it to different lengths: restic to that size, padded with zeros,
  rustic to the content's. A file backed up from stdin had size 0; it now
  has the length read.
- Compression and chunking cost less (`backend/decrypt.rs`, `chunker.rs`),
  for the same bytes: each thread keeps one zstd compression context and
  one decompression context from blob to blob (stock rustic made new ones
  for each), reset to zstd's defaults and given the level before each use,
  so a blob compresses exactly as with `zstd::stream::encode_all` (a test
  checks it); and each thread computes the Rabin tables for the
  repository's polynomial once and clones them for each file, instead of
  computing them per file (about 0.2 ms, 15% of a backup's CPU time over
  small files). zstd allocates its workspace (3.5 MiB to compress at level
  3, 2.4 MiB to decompress) with the C library's malloc; musl's, in the
  static Linux build, mapped and unmapped it for every blob, compressed and
  then decompressed again to verify it (about 106,000 `mmap`/`munmap`
  pairs for a Debian system's backup). A backup of a 35,000-path, 1.4 GB
  tree took 13.5 s before and takes 4.0 s now, with the same snapshot,
  tree IDs and all (see BACKOTTER.md in rustic, "Building").
- What a backup left out, and what a restore couldn't do, are counted, for
  rustic's `--strict-exit` to exit as BackOtter's restic does (3 for an
  incomplete backup, 1 for a restore with errors); without it a restore
  changes nothing, the counts are only there, and a backup exits as stock
  rustic does: since v0.12.0 that is 3 too where upstream's own
  `error_count` (#561, below) isn't 0, which counts fewer things.
  `SnapshotSummary::items_incomplete`
  (not saved in the snapshot: `#[serde(skip)]`, so snapshot files and
  `--json` stay as they were) counts the entries, or parts of their
  metadata, a backup left out because they couldn't be read, each warned
  about; the archiver sums its own drops (`archiver.rs`), the parent trees
  it couldn't load and the unchanged files it re-read for blobs missing
  from the index (`archiver/parent.rs`) and the source's own count
  (`ReadSource::incomplete`, 0 by default; `LocalSource` counts in each of
  its walkers). Counted, as restic counts them: an entry the walk couldn't
  give (a directory that can't be listed, an `lstat` or `readlink` that
  failed, a backup path that doesn't exist, an ignore file's error), an
  entry the parent's tree stack lost, a file that couldn't be opened or
  read, a parent tree that couldn't be loaded, an unchanged file whose
  blobs are missing from the index (`missing blobs in index for unchanged
  file ...; re-reading file`, as restic's `parts of ... not found in the
  repository index; storing the file again`), file flags or attributes
  (ACLs, project IDs, DOS, FAT and XFS attributes, system attributes) that
  couldn't be read, extended attributes that couldn't be listed or read
  (but not, for a directory above the backed-up paths, a permission
  refused, which restic ignores there), and a directory above the
  backed-up paths saved without its own metadata (restic fails such a
  snapshot; rustic-bko keeps it, with a node of its own making, and exits
  3); such a directory that is a symlink (a relative path's `home` ->
  `usr/home`) is stored with the metadata of the directory it leads to, as
  restic follows it, not counted. Not counted, as restic only warns or
  never sees them: an entry below a backed-up path deleted after its
  directory was listed (its `lstat`, or listing it, gives `NotFound`:
  still warned about, `ignoring error: ...`, where restic is silent), a
  parent node that is no tree, extended attributes the file system says
  it doesn't support (`ENOTSUP`, `EOPNOTSUPP`, or `ENOATTR`/`ENODATA`, as
  an SMB/CIFS mount gives: no attributes listed, or one kept without a
  value, as restic's `handleXattrErr`), `idmap offline: SID owners not
  kept`, `av_quarantined: contents not
  backed up`, errors of the size
  scan, `--exclude-if-xattr` errors (the entry is still backed up), sockets
  and doors skipped, and the errors of opening a file for its flags, which
  are only logged at debug level. On restore,
  `RestoreStats::errors` counts the failures of preparing (walking the
  destination for `--delete`, removing what is in the way, flags before
  entries or contents) and `Repository::restore` returns a
  `RestoreOutcome`, whose `errors` counts those of setting metadata and
  making special files, by restic's rules (above, under metadata the target
  file system doesn't support).
- A restore's memory is bounded (`commands/restore.rs`,
  `restore_contents`; `restore/budget.rs`, `ByteBudget`): at most 256 MiB
  of pack data
  (`MAX_RESTORE_BYTES_IN_FLIGHT`), counted as read plus decrypted, is held
  at once, taken before a pack's reader task is spawned and given back when
  the last write of it is done; a larger read goes alone. The pool has 4
  threads per CPU, at most 20 (stock rustic: always 20). Stock rustic
  queued every pack at once, and its 20 readers each held a coalesced read
  of up to 40 MiB and its blobs while their writes waited: rustic-bko grew
  to ~1.7 GB and was killed in the OpenBSD rescue image (3 GiB, no swap).
  A 3.5 GiB restore now peaks at ~0.4 GB, in about the same time.
- A restore writes each file through one handle (`commands/restore.rs`,
  `restore/files_writer.rs`, `FilesWriter`, the design of BackOtter's
  restic's `internal/restorer/fileswriter.go`): it is opened once, kept
  open while it has writes to come, at most threads + 50 idle handles at
  once, and closed after its last write. Stock rustic opened and closed the
  file for each blob, and ext4 drops an inode's preallocation when its last
  writer closes it, so a big parallel restore left files in 5 extents or
  more; past 4 ext4 takes a block for the extent tree, which pushed
  `st_blocks` past the size of a file with a sub-block tail hole, and
  BackOtter's checks saw its holes lost (Kali's vmlinuz, restic->rustic).
  Eight copies of it written in restic's blob ranges, with a sync every
  3-20 ms: per blob, 43 of 320 files past their size and up to 8 extents;
  through one handle, none, and at most 2.
- `restore --exact` (`RestoreOptions::exact`) and rustic's `--clone-from`
  (its BACKOTTER.md; `Repository::clone_sources` and
  `commands/restore/exact.rs` here), for bko-holt load's shared btrfs
  snapshots (backotter `docs/design/btrfs-snapshots.md`), as in BackOtter's
  restic 0.19.1+backotter.12. `--exact` makes a destination that is there
  already exactly the snapshot, writing only what differs:
  - it implies `--delete` and `--verify-existing`;
  - an existing regular file with more than one link gets a file of its
    own first: a reflink clone of itself (`FICLONE` into a new temporary
    file in its directory, `.bko-exact-` and random digits, made `O_EXCL`
    and `O_NOFOLLOW`, renamed over it), or, where the file system can't
    clone, nothing, the name removed, so no write or metadata change
    reaches its other names; the metadata pass then makes the snapshot's
    links. Not a hard-link group whose names in the destination are
    already exactly the snapshot's: one file, with a link for each name
    the restore has for it and no more (none outside the destination),
    known once the walk has seen them all (`LinkGroup::kept`). It stays,
    inode and all; contents that differ are written into it, as into a
    file of its own (BackOtter's restic breaks such a group, to write a
    new file: either way nothing reaches a name the snapshot hasn't got).
    A file whose link can't be broken is an error and is left exactly as
    it is, contents, holes, metadata and flags (those that came off for
    the break go back on), and the snapshot's other names for it aren't
    linked to it (an error each). A clone that fails and can't remove its
    temporary file leaves the file as it is too, with an error naming the
    temporary file;
  - an entry whose metadata already matches is left untouched: what a
    backup with real atimes would record for it now is its node, but for
    what a restore doesn't set (change time, inode, device, link count,
    owner names, contents, holes: `unix.sparse`), and the owner's IDs
    only as root (with ownership by name, the default, as root nothing
    matches: use `--numeric-id`). The mtime stands for an atime the node
    hasn't got, as the restore sets it, and so does the mode: a node
    without one matches a file of mode 0 where that is what the restore
    sets (a regular file in a snapshot that leaves a mode of 0 out:
    `/etc/shadow` from BackOtter's restic), and any mode where the restore
    sets none (0.14.0+backotter.2; before, it matched nothing, and every
    run set such a file's metadata again). A generic attribute the node lacks
    counts only in a snapshot of BackOtter's (where it was none); in
    another it is unknown, and left as the file has it. A birth time
    counts only where both have one: FreeBSD and NetBSD record one for
    every file, which a node from elsewhere lacks, and since they can only
    lower a birth time, one at or before both the node's and its mtime is
    what a restore would leave. So an exact restore over a matching tree
    moves no ctime, hard-linked files' included, nor its restricting
    flags;
  - but on a mount with atimes the restore's own reads move atimes where
    there is no `O_NOATIME`: each directory's when it is listed, a
    symlink's when it is read, and off Linux each file's when its contents
    are compared. The restore sets them back, which moves their ctimes.
    Mount such a destination `noatime` to keep them (not on NetBSD:
    below). On Linux a file is read (compared, or a blob taken from it)
    with `O_NOATIME`, which root and its owner have, and `O_NOFOLLOW`
    (0.13.0+backotter.13). On NetBSD
    an entry whose metadata match but for the atime gets that back alone
    (`utimensat(2)` with the mtime `UTIME_OMIT`), which NetBSD's FFS does
    without moving the ctime (every other setting of times moves it); one
    where that fails (a restricting flag) gets its metadata whole
    (`exact::atime_put_back`, 0.13.0+backotter.15). NetBSD's FFS, as
    installed (`log`, with atimes), moves a file's atime on any read, one
    that doesn't reach the end too, so .13 and .14 set the metadata of
    every file `--exact` compared (`chown`, `chmod`, `utimensat`) on every
    run (BackOtter's restic sets it back on NetBSD, moving the ctime, and
    its test allows for it: `readsKeepAtimes`). An entry that doesn't
    match is looked at twice there (`lstat` and its attributes listed, by
    `already_matches`, then by `atime_put_back`): cost only. A NetBSD FFS
    mounted `noatime` takes no atime from `utimensat(2)`, alone or with
    the mtime: the call returns 0 and leaves it. So every atime restored
    there is lost without an error, and `atime_put_back`, which takes the
    call's success for the atime put back and doesn't read it again, logs
    such an entry as matching: don't mount a NetBSD destination `noatime`.
    FreeBSD 15's UFS moves atimes on reads too (`cat`'s, `head -c 1`'s, a
    past or a 2099 one alike), but not on a read of exactly the file's
    size from pages in memory, the one each of the test's files gets: only
    that lets `test_restore_exact_twice_changes_nothing` pass there. An
    atime-only `utimensat(2)` moves the ctime on FreeBSD, so the NetBSD
    put-back couldn't help there;
  - a symlink to the same target, a FIFO and the same device stay;
  - an SELinux label the node lacks is removed; a removal that fails but
    for a file system without extended attributes (`ENOTSUP`) or a file
    without the label (`ENODATA`) is the file's error. Wherever SELinux is
    active, permissive too, the kernel refuses to remove a label
    (`EACCES`), root's too, so a snapshot without labels would give one
    error per file: those refusals are one error for the whole restore,
    as root or not, with their count (`SELinux labels the snapshot hasn't
    got not removed: N files in all, the first ...`); any other failure,
    `EPERM` too, is the file's.

  `--clone-from`: a file the restore would write whose contents a file
  restored elsewhere on the file system has, and that takes no flag or
  XFS option before its data (no-copy-on-write), is cloned whole and given
  its metadata after. The clone goes into a new temporary file in the
  file's directory, as above, renamed over it, so a clone that fails
  leaves the file as it was, for the restore to write what differs
  (sparse only if it is new); one whose temporary file can't be removed
  is a warning naming it. The source is opened
  `O_RDONLY|O_NOFOLLOW|O_NONBLOCK` and checked with `fstat` (a regular
  file of its size, not the file cloned onto by any name: S11). A
  directory to clone from that is inside the restore's destination is
  refused before anything is written (`clone_sources`): the restore
  changes what is there, so a later clone could take what it wrote. One
  outside it that is only written through it (`DEST/../seed`) is taken;
  one reached through an entry of the destination (a symlink there that
  leads out) is refused, as the restore may change that entry. A
  node of the `--clone-from` tree whose path would leave the directory
  (`..`, an absolute path: a damaged or crafted snapshot) names no source
  (0.14.0+backotter.2), as the restore itself refuses such a path. Only
  Linux clones; elsewhere nothing is tried, the file is written, and a
  hard link is broken by removing the name.

  In a restore, plain or `--exact`, a hard link the metadata pass can't
  make is an error of its own, and the restore goes on: every entry after
  it gets its metadata, and the late flag pass puts back what came off
  (stock rustic stopped there). So does a node stream that fails: the
  restore stops, but the late flags go on first.

  Known limits, as in BackOtter's restic: a kept special file with more
  than one link (a FIFO, a device) gets its metadata in place, which its
  other names see; a clone source is trusted on its size (it must be
  unchanged since it was restored), and the guard against cloning from the
  destination goes by path. Restricting flags that came off stay off when
  the restore stops before the late pass sets them (an interrupt, a fatal
  error, contents that couldn't be read from the repository); a re-run
  sets them. On Linux a clear that fails after `FS_IOC_FSSETXATTR`, at the
  second `FS_IOC_GETFLAGS` or the `FS_IOC_SETFLAGS`, reports nothing
  cleared, so nothing is put back on a file left shared or the other names
  of one replaced. A hard-linked symlink's flags on the BSDs (it can't be
  held open) are put back by path, which its other names don't get once
  that name is gone (an error then). A file with other names that a
  restore without `--exact` rewrites is written in place, as in stock
  rustic, and its other names see it (BackOtter's restic writes a new
  file).

  Known limits found by the review of 0.13.0+backotter.13, not fixed: a
  directory in the way of a snapshot file or special file is removed
  during the walk, under `--delete` entry by entry (`remove_tree`), when
  `Replaced` holds only what the walk has passed, so whether a hard-link
  name inside it of a file the restore replaces another name of loses its
  flags (and goes) still depends on the order of the names (restic-bko .12
  defers that for directories its second pass leaves before the
  replacement); `remove_tree` removes by path (`WalkDir`), where std's
  `remove_dir_all` works through `openat`/`unlinkat` and doesn't follow a
  parent swapped for a symlink during the removal (CVE-2022-21658), a
  little less protection on every `--delete`; a kept hard-link group
  whose contents differ is, under `--clone-from` when a source is found,
  cloned into a temporary file renamed over its first name, not written
  in place as above, after its restricting flags came off its shared
  inode without being held: the group is split until the metadata pass
  links its other names again, and if that pass doesn't run, or a link
  fails (an error, the restore goes on), those names keep the old
  contents without their flags. The tests of restricting flags
  (`restricting_flags_held_go_back_on_other_names`,
  `test_restore_exact_flags_*`, `test_restore_exact_delete_link_group_*`,
  `test_restore_delete_leaves_a_case_variant`) pass without testing
  anything when not run as root (they say so on stderr): run them as root
  too. `test_restore_exact_twice_changes_nothing` checks regular files
  only, so the claim for directories and symlinks has no test of its own,
  and of those only the inode and the ctime after the second restore, not
  that the atimes are the snapshot's (2099) again: NetBSD's put-back is
  tested by the ctime it leaves, not by the atime it sets.

  0.13.0+backotter.13 fixed, after the review of restic-bko .8-.12: a
  fixed temporary name (`.bko-exact-NAME`, opened create+truncate,
  following symlinks) that truncated what a symlink of that name pointed
  at, outside the destination too, and truncated, renamed over or removed
  a snapshot entry of that name, with no error; a restore that went on
  writing into a file whose link it couldn't break, and gave it holes,
  metadata and the snapshot's other names; a clone that emptied an
  existing file before failing (every one, off Linux or without reflinks),
  losing the blobs that matched; hard-link groups broken and made again on
  every run; the clone source opened following symlinks and blocking on a
  FIFO; the other names of a replaced file losing its restricting flags
  for good; `--delete` failing or not on an unexpected name of such a file
  by the order of the names; restricting flags (and XFS options) cleared
  on every entry found, moving the ctime of every immutable or append-only
  entry on every `--exact` run; `--exact` never matching on FreeBSD and
  NetBSD (birth times), on a generic attribute a stock node lacks, on
  `unix.sparse`, on a node without an atime, or, not root, by owner; an
  SELinux label refused per file; a failed hard link aborting the restore
  before the late flags; a failed clone dropping the file and leaving its
  temporary file without a word; and a verified file's atime moved by the
  restore's own read.
- Upstream's b78f648 (#561, in 0.14.0) counts the entries a backup's walk
  or archiver couldn't read in `SnapshotSummary::error_count`, which is
  saved in the snapshot when it isn't 0 (restic ignores the field; restic-bko
  doesn't write it). The fork keeps it as upstream has it, and each error
  counted there counts toward `items_incomplete` too (`archiver.rs`), which
  also counts what upstream's doesn't (above). The walker's errors keep
  upstream's message and path (`ignore.rs`); an entry that vanished below a
  backed-up path is still only warned about, in neither count.
- The version reads `X.Y.Z+backotter.N`.

The system calls need `unsafe`, which the workspace lints now deny (not
forbid), so that the system-call code under `backend/osattrs` can allow
it; one helper of the Linux integration tests
(`tests/integration/restore.rs`) allows it too. The vendored walkdir is
no workspace member, so the lints don't reach its `unsafe` (`noatime.rs`,
`longpath.rs`). Each system's module (`osattrs/linux.rs`, `freebsd.rs`,
`netbsd.rs`, `openbsd.rs`, `dragonfly.rs`, `illumos.rs`, `haiku.rs`, and
`other.rs` for the rest) defines the same functions and constants, those
of `other.rs`, which does nothing; `osattrs.rs` calls them without
`cfg`s. Beside them are helper modules. Three are built only on their
systems and make system calls: `bsd_held.rs` (the four BSDs),
`freebsd_netbsd.rs` and `illumos_idmap.rs`; so does `sparse.rs` (holes,
on Unix). The others hold formats and maps, with no `unsafe`, and are
built everywhere (`bsd_extattr.rs` on Unix), so that they are tested on
any system: `bsd_flags.rs`, `freebsd_acl.rs`, `illumos_acl.rs`,
`illumos_project.rs`, `illumos_sysattr.rs`, `illumos_xattrmeta.rs` and
`haiku_attrs.rs`. `osattrs.rs` itself keeps what the restore and the
backup call; its errors and how a restore reports and counts them are in
`errors.rs`, what goes around the xattr crate in `xattr.rs`, and its tests
in `tests.rs` (`osattrs.rs` re-exports the first two whole).

The allow of `unsafe` is not for the tree: `osattrs.rs` puts it on each
module that makes system calls (the systems' modules but `other.rs`,
`bsd_held.rs`, `freebsd_netbsd.rs`, `illumos_idmap.rs`) and on the
functions that do in `osattrs.rs`, `sparse.rs` and `sparse/seek.rs`; the
other modules are under the workspace's deny, and the tree warns
`clippy::undocumented_unsafe_blocks`.

`sparse.rs` names the systems whose `SEEK_HOLE` the backup probes with
(Linux and Android, FreeBSD, illumos, macOS) in one place, for three
modules: `sparse/seek.rs` (those systems: the seeks, and reading a file
by its extents), `sparse/no_seek.rs` (the others: the blocks decide, a
file is read plainly) and `sparse/hole_reader.rs` (the reader, built for
the tests on every system).

`SEEK_HOLE` and `SEEK_DATA` take 64-bit offsets (`lseek64`) on Linux
(glibc and musl) and Android: on a 32-bit glibc or Android system `off_t`
has 32 bits, and a file over 2 GiB would otherwise be neither marked
`unix.sparse` nor read by its extents (Go's restic seeks with 64-bit
offsets there too). `fallocate(2)`, `statfs(2)` and `fstatfs(2)` are the
64-bit ones there for the same reason (`sparse::seek::lfs`), and a file
system's magic number is the low 32 bits of `f_type`, which is a signed
32-bit word on 32-bit glibc.

Not handled, as no BackOtter build needs it: on Windows, which isn't a
BackOtter platform, a marked file is restored without holes: NTFS needs
`FSCTL_SET_SPARSE`, which rustic doesn't set.

## Base: rustic_core 0.14.0

Since 2026-11-22 the branch is on rustic_core-v0.14.0 (bf1de63, #545;
rustic_backend-v0.8.0 at the same commit, rustic_config 0.2.5 and
rustic_testing 0.5.0 as in 0.13.0), version 0.14.0+backotter.1; it was on
0.13.0 (0.13.0+backotter.1 to .22). The rebase kept every BackOtter
commit but for these:

- The cherry-picks below, all in 0.14.0, were dropped, with the
  dependency pins (0.14.0's lock has the same or newer releases: zstd
  0.14.3, zstd-safe 8.3.0, zstd-sys 2.1.3, still zstd 1.5.7, so the same
  compressed bytes; rustls 0.23.46, rustls-webpki 0.103.17, ctutils 0.4.8,
  chacha20 0.10.2; suppaftp 10.0.2 with opendal 0.59.5). The one line
  of them the rebase left, tempfile's dependency on `getrandom 0.4.3`
  from 708f1c9, which undid a side effect of the pins, is 0.14.0's
  `0.3.4` again (ForkAudit1 G8-06, G9-06; tempfile 3.27.0 takes either):
  the lock differs from 0.14.0's by the fork's version, libc and the
  vendored walkdir only. Of #590's and
  #634's picks, which had conflicts, the fork's own part stays, as its own
  commit: the paths the fork's restore code touches are checked, and
  `hard_link`'s note.
- 9f88530, the chunker hashing all 64 bytes before a chunk's minimum
  size: upstream's 43740bf (#638) does the same. Its test,
  `chunk_like_restic`, stays (above).
- The per-file zero-chunk IDs of 8955dee (`chunk_id`, `zero_ids`):
  upstream's 0abb59f (#611) instead (above).

The versions in the commits from before the rebase read
0.14.0+backotter.N with their old N (their messages name 0.13.0's); the
first version on 0.14.0 is 0.14.0+backotter.1.

Upstream's changes that came with 0.14.0 and touch what the fork does:
#561's `error_count` (above, beside `items_incomplete`); #563, backup
paths no longer merged into their parents (rustic's `backup` has the
consequences); #629's clippy fixes and API changes (the fork's code
builds on them); #553, iOS beside macOS where a device ID is an `i32`
(Haiku's too, the fork's); #637's chunk size bounds; #639's prune rewrite; #558's `http-` option names and
#556, #598, #642's HTTP options, which rustic's own configuration takes.

### Upstream fixes taken before 0.14.0

Fixes from rustic_core's `main` after the 0.13.0 release, cherry-picked
(`git cherry-pick -x`, upstream's author kept) in version
0.13.0+backotter.4, and dropped in the rebase onto 0.14.0, which has them:

- 52a1839 (#544) the cache backend is guarded by locks (a file read and
  written by two threads at once).
- c4059e3 (#548), d56cc4a (#630) a path that can't be canonicalized is
  named in the error.
- 35aef00 (#547) the local backend's delete hook runs when a file is
  replaced. In `crates/backend`, which rustic-bko doesn't build: rustic
  takes rustic_backend from crates.io (0.7.0 then; 0.8.0, which has the
  fix, since rustic v0.12.0).
- 9d9e478 (#546) tree workers stop once the receiver is gone.
- d7e097c (#585) no underflow in `BlobLocation::data_length`.
- 4589ea7 (#586) `repair snapshots` handles a file node without contents.
- be62e24 (#588) a directory node without a subtree doesn't panic in
  `ls`, the node streamer or `merge_nodes`.
- 459bb53 (#589) no overflow in `BlobLocations::can_coalesce`.
- f5b8fd6 (#591) `BlobCopier` checks a blob's offset and length.
- 82b81d2 (#592) a key file with invalid or excessive scrypt parameters is
  refused.
- 0db92b6 (#607) tree loader threads are joined before the index goes.
- b77ecc8 (#590) a restore refuses a node path that leaves the destination
  (a `..`, root or prefix component). With conflicts: every path the
  fork's restore code touches by itself (`write_sparse_at`, illumos' and
  Haiku's extended attributes, `prepare_dir`, `prepare_file`, a
  quarantined file's removal, hole filling, `set_metadata`'s osattrs calls
  and the late flags) is checked the same way, through
  `LocalDestination::path`. Other names, non-UTF-8 ones included, are
  taken as they are.
- fba52fa (#587) `prune` handles a directory node without a subtree.
- 4c3d6fa (#633) `forget --keep-minutely` counts minutes within one hour.
- 00bd025 (#632) a backup compares inode numbers with the parent's unless
  `--ignore-inode` is given (stock compared them only with it), as restic
  does: a file whose inode changed is read again.
- 506a1da (#634) a restore's hard link over an entry already at its name:
  the right link is left as it is, anything else but a directory
  replaced. With conflicts: it takes the place of the fork's own fix
  (remove whatever is there, then link, as BackOtter's restic does), and
  also keeps the file when a symlinked directory makes both names one.
- b583e92 (#602) `init_with_config` takes `is_hot` from the repository.
- 01fe284 (#640) the OpenDAL backend passes on an error from checking for
  the config file instead of taking it as "no repository". Taken after
  0.13.0+backotter.5 with no new version: it is in `crates/backend`, which
  rustic-bko doesn't build (rustic took rustic_backend 0.7.0 from
  crates.io, without it; v0.12.0 takes 0.8.0, with it), so rustic-bko was
  unchanged by it.

Dependencies on 0.13.0 (Cargo.lock only, semver-compatible, each to its
first release that RustSec lists as patched; dropped with the rebase,
above): zstd 0.13.4, zstd-safe 7.4.0, zstd-sys 2.1.2 (still zstd 1.5.7:
the same compressed bytes), rustls 0.23.46, rustls-webpki 0.103.16,
ctutils 0.4.4. Also chacha20 0.10.2,
as 0.10.1 is yanked: its SSE2 backend, the one picked when AVX2 is
missing, runs SSE4.1's `_mm_extract_epi32` in the RNG that `rand::rng()`
gives (each nonce, `Id::random`, key salts), so a CPU with neither (AMD
K8/K10, Core 2 Merom/Conroe) can get SIGILL (RustCrypto/stream-ciphers
#579, fixed by #580). Left on 0.13.0, and fixed in 0.14.0: suppaftp 8 (FTP
command injection, RUSTSEC-2026-0271), fixed only in suppaftp 10, which
needs opendal 0.59 (upstream's #629), in rustic_backend 0.8.0. Left on
both: rsa 0.9 (RUSTSEC-2023-0071), which has no fix;
quinn-proto, webpki-root-certs and h2, which rustic-bko doesn't build;
quick-xml (0.38 on 0.13.0: RUSTSEC-2026-0194, -0195; 0.42 on 0.14.0),
which only rustic's self-update takes (its `release` feature, not
built).

Not ported on 0.13.0, and in the fork since the rebase onto 0.14.0:

- e01b17f (#553) iOS build: no BackOtter platform.
- ca81cfe (#549), e574765 (#552) documentation only.
- b7ab1ee (#556) more reqwest options for the rest and OpenDAL backends:
  a feature, and breaking.
- 6fa7b56 (#559) Serialize, Deserialize and Merge for `ConfigOptions`: a
  feature.
- e97a7dc (#562) OpenDAL retries logged on one line: a feature.
- b78f648 (#561) unreadable source files counted in the summary: a
  feature, which changes the snapshot summary.
- 647d00f (#563) backup paths no longer merged into their parents: a
  breaking change of behaviour.
- 4871132 (#629) clippy fixes and dependency updates: breaking (removes
  `Node`'s and `IndexEntry`'s constructors); its advisory fixes are
  covered above.
- e2b61aa (#558) HTTP transport options renamed with `http-`: breaking.
- 9565d4f (#580) type parameters tidied in `commands/backup`: no fix.
- eb72c72 (#598) a read timeout for HTTP backends: a feature.
- 18fa55c (#642) a connect timeout for HTTP backends: a feature.

From `main` after 2026-11-05, released in rustic_core 0.14.0 and
rustic_backend 0.8.0 (bf1de63, #545, 2026-11-17), which rustic v0.12.0
takes; in the fork since the rebase:

- 43740bf (#638) the chunker prefills the whole rolling hash window, so it
  cuts where restic does: breaking, as cuts move. 9f88530 here does the
  same (all 64 bytes hashed, above); it was dropped in the rebase, and
  `chunk_like_restic` (`chunker/rabin.rs`), whose lengths come from
  restic's chunker, checks that upstream's cuts the same.
- 0abb59f (#611) all-zero chunks aren't hashed: one ID per backup, at the
  minimum chunk size. The hole reader's `chunk_id` and `zero_ids` kept one
  per file and length, the same IDs; they were dropped in the rebase, as
  the hole reader's zero runs are cut at the length upstream checks
  (above).
- d658ed9 (#637) a minimum chunk size under 4 KiB no longer underflows
  (one chunk past the maximum) and one under 64 bytes is refused, not a
  panic: a fix, which changes no cut at 4 KiB or more; restic's
  repositories and rustic's default have 512 KiB.
- 8fe6703 (#639) prune with concurrent runs and recovered packs: a fix,
  breaking (`keep-delete` becomes `keep-marked`), a rewrite of
  `commands/prune.rs`. At 0.14.0+backotter.1 the fork's `prune.rs` is
  upstream's, with no hunk of ours: #587, which was cherry-picked onto
  0.13.0, is in the rewrite.
- 269f9dc (#653) dependency updates: newer releases of the pins above.
- 40152f3 (#648) CI only.

The rebase onto 0.14.0 was the user's decision of 2026-11-22 (ForkAudit1
F9-01); rustic's `backotter` branch moves to v0.12.0 with it.

## Moving to a new rustic_core release

    git fetch upstream --tags
    git rebase --onto rustic_core-vNEW rustic_core-vOLD backotter
    # set crates/core/Cargo.toml's version to "NEW+backotter.1"
    git push --force-with-lease origin backotter

In the rebase (what the move to 0.14.0 needed; "Base: rustic_core 0.14.0"
above has it as history):

- `commands/restore.rs` is upstream's file: its `collect_and_prepare`
  keeps upstream's loop and closures, and what the fork does there is in
  `commands/restore/prepare.rs` (`Prepare`, whose methods the loop and
  closures call), with the fork's other parts of the restore in
  `restore/{exact,files_writer,fresh,budget}.rs`. Where upstream changed
  the function, take its lines and keep the calls into `Prepare`
  (`target_of`, `found_under_another_name`, `existing_dir`, `created_dir`,
  `later_link_name`, `plan_node_file` in place of the match on
  `add_file`, `replace_existing`, `finish`, `into_plan`).
- Drop each cherry-pick the release has (`git cherry-pick -x` names
  upstream's commit in the message), and each BackOtter patch that
  upstream now does itself, keeping its test where that checks upstream's
  code against restic (`chunk_like_restic`). Where a pick had conflicts
  and carries a part that is the fork's own (#590's path checks, #634's
  `hard_link` note), keep that part, as a commit of its own.
- Take the release's Cargo.lock wherever ours conflicts, and drop the
  commits that only pinned dependencies once its lock has the same or
  newer releases. The fork's lock should then differ from the release's
  (`git diff rustic_core-vNEW backotter -- Cargo.lock`) only in
  rustic_core's version and its `libc` dependency, and in walkdir, which
  has no source or checksum (it is `vendor/walkdir`) and takes `libc`.
- Give a conflicting version line `NEW+backotter.N`, with the commit's
  own N; the commit that ends the rebase sets `NEW+backotter.1`.
- `vendor/walkdir` is crates.io's walkdir 2.5.0 with the fork's patch
  (its README.md): if the release's lock has a newer walkdir, redo the
  patch on that one.
- Write a "Base: rustic_core NEW" section as the one above (what was
  dropped, and which of upstream's changes touch what the fork does), and
  bring "What it adds" into line with upstream's new messages, counts and
  exit codes.

Then run both test suites on a host, the new release's own first
(backotter's `testvm/audit/stock-baseline.sh`, then
`testvm/audit/fork-tests.sh`): no test may fail on the fork that passes
on the stock release. After that move rustic's `backotter` branch to the
rustic release that uses rustic_core NEW (see BACKOTTER.md there).
