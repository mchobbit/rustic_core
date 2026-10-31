//! The file flags (`st_flags`) kept on NetBSD and DragonFly, where they are
//! the flags of `chflags(1)`, of every type of file. Portable, so that they
//! are tested on any system; the system calls are in `netbsd.rs` and
//! `dragonfly.rs`.

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
    fn netbsd_leaves_out_the_kernels_flags() {
        for bit in [0x0020_0000, 0x0040_0000, 0x0080_0000] {
            assert_eq!(bit & NETBSD_KEPT_FLAGS, 0, "{bit:#x} kept");
        }
        // arch, uchg, nodump
        assert_eq!(0x0001_0003 & NETBSD_KEPT_FLAGS, 0x0001_0003);
        assert_eq!(NETBSD_KEPT_FLAGS, 0xff1f_ffff);
    }

    #[test]
    fn dragonfly_keeps_every_flag() {
        for bit in (0..32).map(|i| 1_u32 << i) {
            assert_eq!(bit & DRAGONFLY_KEPT_FLAGS, bit, "{bit:#x} not kept");
        }
    }
}
