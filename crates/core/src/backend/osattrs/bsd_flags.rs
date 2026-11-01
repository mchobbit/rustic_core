//! The file flags (`st_flags`) kept on FreeBSD, NetBSD and DragonFly, where
//! they are the flags of `chflags(1)`, of every type of file. Portable, so
//! that they are tested on any system; the system calls are in `freebsd.rs`,
//! `netbsd.rs` and `dragonfly.rs`.

// FreeBSD's <sys/stat.h>.
const FREEBSD_UF_SETTABLE: u32 = 0x0000_ffff; // the flags an owner may set
const FREEBSD_SF_SETTABLE: u32 = 0xffff_0000; // the flags only root may set
const FREEBSD_UF_ARCHIVE: u32 = 0x0000_0800; // "uarch"
const FREEBSD_SF_SNAPSHOT: u32 = 0x0020_0000; // a UFS snapshot file

/// The flags kept on FreeBSD: all that an owner or root can set, which
/// leaves out `SF_SNAPSHOT`.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub(super) const FREEBSD_KEPT_FLAGS: u32 =
    (FREEBSD_UF_SETTABLE | FREEBSD_SF_SETTABLE) & !FREEBSD_SF_SNAPSHOT;

/// The `freebsd.file_flags` of a file with the flags `st_flags`, on ZFS
/// (`zfs`) or another file system, if it gets one: what a new file there
/// has gets none. ZFS gives every file it writes `UF_ARCHIVE`, as Windows
/// its archive bit, so archive alone gets no attribute there, and no flags
/// at all get 0 (archive cleared, as by a Windows backup over SMB), which
/// the restore sets. Elsewhere no flags get no attribute, and `uarch`
/// alone, which nothing sets there but `chflags(1)`, is kept.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub(super) fn freebsd_file_flags(st_flags: u32, zfs: bool) -> Option<u32> {
    let flags = st_flags & FREEBSD_KEPT_FLAGS;
    let new_file = if zfs { FREEBSD_UF_ARCHIVE } else { 0 };
    (flags != new_file).then_some(flags)
}

// The flags that keep a file from being written, appended to only, or
// removed and renamed (<sys/stat.h>), the same bits on every BSD that has
// them.
const UF_IMMUTABLE: u32 = 0x0000_0002; // "uchg"
const UF_APPEND: u32 = 0x0000_0004; // "uappnd"
const UF_NOUNLINK: u32 = 0x0000_0010; // "uunlnk" (FreeBSD, DragonFly)
const FREEBSD_UF_READONLY: u32 = 0x0000_1000; // "urdonly" (ZFS: DOS read-only)
const SF_IMMUTABLE: u32 = 0x0002_0000; // "schg"
const SF_APPEND: u32 = 0x0004_0000; // "sappnd"
const SF_NOUNLINK: u32 = 0x0010_0000; // "sunlnk" (FreeBSD, DragonFly)

/// The flags a restore clears from a file it finds in its way before it
/// changes it (`osattrs::clear_restricting_flags`), on FreeBSD: immutable,
/// append-only and undeletable, the owner's and the system's, and ZFS's DOS
/// read-only, which refuses writes too. The late flags pass sets the node's.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub(super) const FREEBSD_RESTRICTING_FLAGS: u32 = UF_IMMUTABLE
    | UF_APPEND
    | UF_NOUNLINK
    | FREEBSD_UF_READONLY
    | SF_IMMUTABLE
    | SF_APPEND
    | SF_NOUNLINK;

/// As [`FREEBSD_RESTRICTING_FLAGS`], on NetBSD and OpenBSD, which have no
/// undeletable or read-only flags.
#[cfg_attr(not(any(target_os = "netbsd", target_os = "openbsd")), allow(dead_code))]
pub(super) const NETBSD_OPENBSD_RESTRICTING_FLAGS: u32 =
    UF_IMMUTABLE | UF_APPEND | SF_IMMUTABLE | SF_APPEND;

/// As [`FREEBSD_RESTRICTING_FLAGS`], on DragonFly, which has no read-only
/// flag.
#[cfg_attr(not(target_os = "dragonfly"), allow(dead_code))]
pub(super) const DRAGONFLY_RESTRICTING_FLAGS: u32 =
    UF_IMMUTABLE | UF_APPEND | UF_NOUNLINK | SF_IMMUTABLE | SF_APPEND | SF_NOUNLINK;

// NetBSD's <sys/stat.h>: the flags the kernel manages.
const NETBSD_SF_SNAPSHOT: u32 = 0x0020_0000; // an FFS snapshot
const NETBSD_SF_LOG: u32 = 0x0040_0000; // the WAPBL journal
const NETBSD_SF_SNAPINVAL: u32 = 0x0080_0000; // an invalid snapshot

/// The flags kept on NetBSD: all that an owner (`UF_SETTABLE`) or root
/// (`SF_SETTABLE`) can set, except those the kernel manages. It refuses
/// `SF_SNAPSHOT` and `SF_SNAPINVAL`, and takes `SF_LOG`, though it marks
/// the journal's inode, which no restored file is.
#[cfg_attr(not(target_os = "netbsd"), allow(dead_code))]
pub(super) const NETBSD_KEPT_FLAGS: u32 =
    !(NETBSD_SF_SNAPSHOT | NETBSD_SF_LOG | NETBSD_SF_SNAPINVAL);

/// The flags kept on DragonFly: all. Root can set every bit, on HAMMER2 and
/// UFS, and none is the kernel's (FreeBSD's snapshot bit is unused there).
#[cfg_attr(not(target_os = "dragonfly"), allow(dead_code))]
pub(super) const DRAGONFLY_KEPT_FLAGS: u32 = 0xffff_ffff;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freebsd_leaves_out_snapshots() {
        assert_eq!(FREEBSD_KEPT_FLAGS, 0xffdf_ffff);
        assert_eq!(freebsd_file_flags(0x0020_0000, false), None);
    }

    #[test]
    fn freebsd_archive_on_zfs() {
        // Archive alone: what ZFS gives every file.
        assert_eq!(freebsd_file_flags(0x0800, true), None);
        // Archive cleared, kept as 0, also when only SF_SNAPSHOT is left.
        assert_eq!(freebsd_file_flags(0, true), Some(0));
        assert_eq!(freebsd_file_flags(0x0020_0000, true), Some(0));
        // hidden (0x8000) with or without archive, nodump.
        assert_eq!(freebsd_file_flags(0x8800, true), Some(0x8800));
        assert_eq!(freebsd_file_flags(0x8000, true), Some(0x8000));
        assert_eq!(freebsd_file_flags(0x0001, true), Some(0x0001));
    }

    #[test]
    fn freebsd_archive_elsewhere() {
        assert_eq!(freebsd_file_flags(0, false), None);
        assert_eq!(freebsd_file_flags(0x0020_0000, false), None);
        // Archive alone, which UFS sets only by chflags(1): kept (it used to
        // be lost, 0x800 restored as 0).
        assert_eq!(freebsd_file_flags(0x0800, false), Some(0x0800));
        assert_eq!(freebsd_file_flags(0x0801, false), Some(0x0801));
        // schg
        assert_eq!(freebsd_file_flags(0x0002_0000, false), Some(0x0002_0000));
    }

    #[test]
    fn netbsd_leaves_out_the_kernels_flags() {
        for bit in [0x0020_0000, 0x0040_0000, 0x0080_0000] {
            assert_eq!(bit & NETBSD_KEPT_FLAGS, 0, "{bit:#x} kept");
        }
        // arch, uchg, nodump
        assert_eq!(0x0001_0003 & NETBSD_KEPT_FLAGS, 0x0001_0003);
        assert_eq!(NETBSD_KEPT_FLAGS, 0xff1f_ffff);
    }

    #[test]
    fn restricting_flags() {
        // chflags(1): uchg uappnd uunlnk urdonly schg sappnd sunlnk.
        assert_eq!(FREEBSD_RESTRICTING_FLAGS, 0x0016_1016);
        assert_eq!(NETBSD_OPENBSD_RESTRICTING_FLAGS, 0x0006_0006);
        assert_eq!(DRAGONFLY_RESTRICTING_FLAGS, 0x0016_0016);
        // nodump, uarch, hidden and the snapshot bit stay.
        for keep in [0x1, 0x800, 0x8000, 0x0020_0000] {
            assert_eq!(keep & FREEBSD_RESTRICTING_FLAGS, 0, "{keep:#x}");
        }
    }

    #[test]
    fn dragonfly_keeps_every_flag() {
        for bit in (0..32).map(|i| 1_u32 << i) {
            assert_eq!(bit & DRAGONFLY_KEPT_FLAGS, bit, "{bit:#x} not kept");
        }
    }
}
