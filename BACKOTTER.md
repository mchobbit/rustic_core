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
  all. Each all-zero chunk (holes give many, all of the chunker's
  minimum size) is hashed once per file and length: the same bytes give
  the same ID. The rolling hash isn't skipped over long zero
  runs: all-zero data already gives a boundary at the minimum chunk size,
  with no rolling over its bytes.
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
  crate (1.6) names the last attribute of the system namespace as one of
  the user namespace, which a restore then creates, empty.
- On illumos, extended attributes are named attribute files (`runat(1)`),
  which the xattr crate doesn't support: they are read and written through
  `openat(2)` with `O_XATTR`, without the `SUNWattr_ro` and `SUNWattr_rw`
  system attribute views, and stored in name order, not the attribute
  directory's, as BackOtter's restic does. A restore creates an
  attribute file with mode 0600, so that it is never readable by others
  before it gets its own owner, mode, ACL and times (`illumos.xattr_meta`),
  with `fchownat(2)`, `fchmodat(2)`, `facl(2)` and `utimensat(2)` on the
  attribute directory, in that order, once the values are written (in
  `osattrs::restore_attributes`); an attribute the restore left out is left
  alone. This goes before the file's own times (writing an attribute file
  leaves them) and flags. A snapshot without the attribute restores as
  before. An attribute the file has already, with its node's value, is
  left as it is (read and compared first; only one of the same size is
  read), as on every other system and in BackOtter's restic.
- FreeBSD ZFS project IDs (`freebsd.zfs_project`) are restored with the
  system extended attributes, before the flags, as each node's own ID and
  inheritance, as on illumos; on UFS (`ENOTTY`) they get one warning per
  restore, as other unsupported metadata.
- Before the restore touches a file or directory it finds at a node's path
  (to rewrite it, give it its metadata, replace it, link over it, put
  entries in it), it clears the flags that would refuse that, keeping the
  others, where the node says which flags the file had, so that the late
  flag pass puts those back (`osattrs::node_sets_flags`): a node with file
  flags, or any node of a snapshot of BackOtter's, which records the flags
  of every file that has any, so that one without them had none. In a
  snapshot of stock restic or rustic, which record none, what the restore
  finds keeps its flags, as in stock rustic, and what they refuse fails
  with its error. What `--delete` removes, and what lies below a directory
  replaced by a node of another type, never loses its flags: an immutable
  file isn't removed, and the error says so, as in stock rustic. The flags
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
- A file whose contents can't be written (one the restore can't open for
  writing) is reported once (`restore PATH: contents not restored: ...`)
  and left as it is; the restore goes on with every other file and all the
  metadata, then fails (`The contents of N files could not be restored`,
  exit 1), as BackOtter's restic exits 1 for it. Stock rustic panicked at
  the first (an `unwrap` of the open), aborting the restore and leaving
  every file still pending stale.
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
  warning, and left on the file by a restore. Empty attributes are
  restored too, though BFS makes none of a write of no data: such a one
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
  illumos `xattrs_read` in `osattrs/illumos.rs`; Haiku's are read whole).
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
  root either (`EACCES`), nor its extended attributes, but its metadata can
  be read: a backup keeps its node without its contents, as BackOtter's
  restic does. Where opening a regular file is refused with `EACCES` and
  its system attributes (read through its attribute directory, opened with
  libc's `__openattrdirat` as `getattrat(3C)` and `ls -/ v` open it,
  without opening the file) have `av_quarantined`, the node has its mode,
  owner, times, links, inode, device, SID owners, ACL, system attributes
  (`av_quarantined` included) and birth time, no `content` and size 0, and
  `illumos.unread_size`, the file's real size; its extended attributes and
  `illumos.xattr_meta` are left out (they can't be read), as is its ZFS
  project (reading it opens the file). One warning names it
  (`PATH: av_quarantined: contents not backed up (N bytes)`) and the backup
  exits 0. Any other file that can't be opened is left out, as before,
  with `ignoring error: Failed to open ...`, and counts toward exit 3
  under rustic's `--strict-exit`. The source's attribute is
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
  BACKOTTER.md has the whole rule). It goes by the name it's saved as
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
- `merge` makes a snapshot of other snapshots' nodes: it is BackOtter's
  only if every snapshot merged is. Otherwise the program version it is
  given loses its `+backotter`, each word cut there (`rustic
  0.11.4+backotter.3` becomes `rustic 0.11.4`, stock rustic's own form),
  so that a stock snapshot's missing attributes stay unknown in it. Stock
  rustic stamps a merge with its own version whatever was merged.
  `rewrite`, `copy` and `repair snapshots` keep each snapshot's own
  program version, as in stock rustic.
- A hard link over an entry already at its name (upstream's #634, below):
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
  has its own node); a regular file's go on also as soon as the restore
  creates it, while it is empty (with the no-copy-on-write flag), since XFS
  takes an extent size hint on no file with data (`EINVAL`), and again in
  the last pass, which leaves options that are right alone. A file the
  restore writes over (one that was there, with data) can't get a new
  extent size hint: that is unsupported, one warning per restore. On a file
  system other than XFS: one warning per restore ("linux.xfs_options not
  supported by the file system: not XFS") and the number of files. As in
  BackOtter's restic.
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
  alone (checked on Linux 6.12).
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
  atime gets its mtime as its atime, in either tool.
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
- Extended attributes are read whole, however large, on Linux
  (`osattrs::xattr_get`, `xattr_list`: `lgetxattr(2)` and `llistxattr(2)`
  with the size they give, again on `ERANGE`). The xattr crate (1.6, on
  rustix 1.1) reads a first 4 KiB and asks rustix for a larger value's
  size with an empty buffer, which rustix 1.1 answers with 0: every value
  over 4 KiB was backed up empty (a 15000-byte `user.*` on btrfs, 60000
  bytes on XFS), and so were ACLs that long. Elsewhere the xattr crate
  reads them (its BSD code has no such step).
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
- The chunker cuts where restic's does (`chunker/rabin.rs`). It hashed only
  63 of the 64 bytes before a chunk's minimum size (rustic_cdc's
  `reset_and_prefill_window`), leaving out the last of them, which restic
  hashes, so a cut in the 64 bytes after the minimum size could differ: a
  file of zeros with one other byte just before the minimum size of a chunk
  (likelier in sparse images) was cut at the minimum size where restic cut
  a few bytes later, and every later blob of the file differed. Either tool
  restored the other's snapshots, but the file's data wasn't shared between
  them. Now all 64 bytes are hashed, as in restic, and the chunks are the
  same. A file that met the case is cut differently from an older rustic
  snapshot of it, so its data after that cut is stored again once.
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
  incomplete backup, 1 for a restore with errors); without it nothing
  changes, the counts are only there. `SnapshotSummary::items_incomplete`
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
  backed up`, a Haiku attribute name that isn't UTF-8, errors of the size
  scan, `--exclude-if-xattr` errors (the entry is still backed up), sockets
  and doors skipped, and the errors of opening a file for its flags, which
  are only logged at debug level. On restore,
  `RestoreStats::errors` counts the failures of preparing (walking the
  destination for `--delete`, removing what is in the way, flags before
  entries or contents) and `Repository::restore` returns a
  `RestoreOutcome`, whose `errors` counts those of setting metadata and
  making special files, by restic's rules (above, under metadata the target
  file system doesn't support).
- The version reads `X.Y.Z+backotter.N`.

The system calls need `unsafe`, which the workspace lints now deny (not
forbid), so that `backend/osattrs.rs` can allow it there alone. Each
system's module (`osattrs/linux.rs`, `freebsd.rs`, `netbsd.rs`,
`openbsd.rs`, `dragonfly.rs`, `illumos.rs`, and `other.rs` for the rest)
defines the same functions and constants, those of `other.rs`, which does
nothing; `osattrs.rs` calls them without `cfg`s.

`SEEK_HOLE` and `SEEK_DATA` take 64-bit offsets (`lseek64`) on Linux
(glibc and musl) and Android: on a 32-bit glibc or Android system `off_t`
has 32 bits, and a file over 2 GiB would otherwise be neither marked
`unix.sparse` nor read by its extents (Go's restic seeks with 64-bit
offsets there too).

Not handled, as no BackOtter build needs it: on Windows, which isn't a
BackOtter platform, a marked file is restored without holes: NTFS needs
`FSCTL_SET_SPARSE`, which rustic doesn't set.

## Upstream fixes after 0.13.0

Fixes from rustic_core's `main` after the 0.13.0 release, cherry-picked
(`git cherry-pick -x`, upstream's author kept) in version
0.13.0+backotter.4; a rebase onto a release that has them drops them:

- 52a1839 (#544) the cache backend is guarded by locks (a file read and
  written by two threads at once).
- c4059e3 (#548), d56cc4a (#630) a path that can't be canonicalized is
  named in the error.
- 35aef00 (#547) the local backend's delete hook runs when a file is
  replaced. In `crates/backend`, which rustic-bko doesn't build: rustic
  takes rustic_backend 0.7.0 from crates.io.
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
  rustic-bko doesn't build (rustic takes rustic_backend 0.7.0 from
  crates.io), so rustic-bko is unchanged by it.

Dependencies (Cargo.lock only, semver-compatible, each to its first
release that RustSec lists as patched): zstd 0.13.4, zstd-safe 7.4.0,
zstd-sys 2.1.2 (still zstd 1.5.7: the same compressed bytes), rustls
0.23.46, rustls-webpki 0.103.16, ctutils 0.4.4. Also chacha20 0.10.2,
as 0.10.1 is yanked: its SSE2 backend, the one picked when AVX2 is
missing, runs SSE4.1's `_mm_extract_epi32` in the RNG that `rand::rng()`
gives (each nonce, `Id::random`, key salts), so a CPU with neither (AMD
K8/K10, Core 2 Merom/Conroe) can get SIGILL (RustCrypto/stream-ciphers
#579, fixed by #580). Left: suppaftp 8 (FTP command injection,
RUSTSEC-2026-0271), fixed only in suppaftp 10, which needs opendal 0.59
(upstream's #629), and rustic takes opendal through crates.io's
rustic_backend 0.7.0; rsa 0.9 (RUSTSEC-2023-0071), which has no fix;
quinn-proto, webpki-root-certs and h2, which rustic-bko doesn't build;
quick-xml 0.38 (RUSTSEC-2026-0194, -0195), which only rustic's
self-update takes (its `release` feature, not built).

Not ported:

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

## Moving to a new rustic_core release

    git fetch upstream --tags
    git rebase --onto rustic_core-vNEW rustic_core-vOLD backotter
    # set crates/core/Cargo.toml's version to "NEW+backotter.1"
    git push --force-with-lease origin backotter

Then move rustic's `backotter` branch to the rustic release that uses
rustic_core NEW (see BACKOTTER.md there).
