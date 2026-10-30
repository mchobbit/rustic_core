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
  - `unix.sparse`: `true` for a regular file with holes, on every Unix:
    fewer 512-byte blocks than bytes and, where the system has `SEEK_HOLE`
    (Linux, FreeBSD, illumos), a hole before its end. Both
    tests are needed: a file on a compressing file system has fewer blocks
    and no holes, a preallocated one (a swap file) all its blocks and, to
    `SEEK_HOLE`, holes. Where `SEEK_HOLE` can't say (NetBSD, OpenBSD, a file
    system without it, a file that can't be opened), the blocks decide.
  A file only gets an attribute when it has something the mode doesn't say
  (flags, a project ID, a non-trivial ACL, holes). A generic attribute
  rustic doesn't know at all gets a warning, once; one of another system is
  skipped quietly.
- A backup keeps each file's access time, as BackOtter's restic does (stock
  rustic stores the mtime there; `backup --set-atime mtime` still does).
- A restore gives files the uid and gid they were saved with, as restic
  does: stock rustic looks the owners' names up in the users of the system
  it runs on, which on a rescue system are the wrong ones. `restore
  --by-name` looks them up by name; `--numeric-id` is still accepted.
- A file backed up with holes (`unix.sparse`) is restored sparse, its zero
  chunks as holes, as `restore --sparse by-content` restores every file. Any
  other file is written out in full, zeros and all, so that a swap file or
  a preallocated file comes back allocated; snapshots without the mark
  restore as they did. A file that exists already is always written in
  full: stock rustic's `--sparse by-content` left its old contents where a
  zero chunk went.
- On FreeBSD and NetBSD, extended attributes are named as restic names them:
  the user namespace only, under bare names (stock rustic keeps both
  namespaces, as `user.NAME` and `system.NAME`, and restores the system
  namespace's raw UFS ACL storage). Stock rustic's FreeBSD snapshots
  therefore restore their user attributes with a `user.` in front.
- On FreeBSD the user namespace is listed directly: the xattr crate (1.6)
  names the last attribute of the system namespace as one of the user
  namespace, which a restore then creates, empty.
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
  Where it doesn't support a POSIX.1e ACL, the restore warns and narrows the
  group bits to the owning group's own access, so a file never comes back
  more open. Flags a file has already aren't set again: on btrfs every
  `FS_IOC_SETFLAGS` rewrites the `btrfs.compression` property (restored as
  an extended attribute), or deletes it.
- btrfs's no-copy-on-write flag is set while a new file is still empty: btrfs
  ignores it on a file with data. Likewise casefolding goes on a directory
  the restore creates before anything goes in: ext4 and f2fs refuse it on a
  directory with entries.
- On FreeBSD a restored symlink keeps its own permissions (`lchmod(2)`).
- The version reads `X.Y.Z+backotter.N`.

The system calls need `unsafe`, which the workspace lints now deny (not
forbid), so that `backend/osattrs.rs` can allow it there alone.

## Moving to a new rustic_core release

    git fetch upstream --tags
    git rebase --onto rustic_core-vNEW rustic_core-vOLD backotter
    # set crates/core/Cargo.toml's version to "NEW+backotter.1"
    git push --force-with-lease origin backotter

Then move rustic's `backotter` branch to the rustic release that uses
rustic_core NEW (see BACKOTTER.md there).
