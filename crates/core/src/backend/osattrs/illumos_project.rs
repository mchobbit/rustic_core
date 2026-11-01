//! ZFS project IDs on illumos and FreeBSD (`zfs project`), which ZFS's
//! project quotas count a file's blocks against (`zfs projectspace`), and
//! whether a directory hands its project ID down to the files created in it.
//! Portable, so that it is tested on any system; the ioctls are in
//! `illumos.rs` and `freebsd.rs`.

#![cfg_attr(not(any(target_os = "illumos", target_os = "freebsd")), allow(dead_code))]

use serde::{Deserialize, Serialize};

/// The flag of a directory that hands its project ID down (`zfs project
/// -s`; `ZFS_PROJINHERIT_FL`, Linux's `FS_PROJINHERIT_FL`).
const PROJ_INHERIT: u32 = 0x2000_0000;

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(v: &bool) -> bool {
    !*v
}

/// A file's project ID and inheritance, as `illumos.zfs_project` and
/// `freebsd.zfs_project` keep them.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ZfsProject {
    pub id: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    pub inherit: bool,
}

impl ZfsProject {
    /// The project of a file whose ZFS xattr flags and project ID are
    /// `xflags` and `projid`, if it has one worth keeping: an ID other than
    /// 0, or inheritance.
    pub(super) fn of(xflags: u32, projid: u32) -> Option<Self> {
        let p = Self {
            id: projid,
            inherit: xflags & PROJ_INHERIT != 0,
        };
        (p != Self::default()).then_some(p)
    }

    /// `xflags`, a file's ZFS xattr flags, with inheritance as this project
    /// has it and the other flags as they are.
    pub(super) const fn xflags(self, xflags: u32) -> u32 {
        if self.inherit {
            xflags | PROJ_INHERIT
        } else {
            xflags & !PROJ_INHERIT
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zfs_project() {
        // What ZFS's ioctl gave on OmniOS: zfs project -p 77 -s, -p 79, -s
        // alone.
        for (xflags, projid, json) in [
            (PROJ_INHERIT, 77, r#"{"id":77,"inherit":true}"#),
            (0, 79, r#"{"id":79}"#),
            (PROJ_INHERIT, 0, r#"{"id":0,"inherit":true}"#),
        ] {
            let p = ZfsProject::of(xflags, projid).unwrap();
            assert_eq!(serde_json::to_string(&p).unwrap(), json);
            let back: ZfsProject = serde_json::from_str(json).unwrap();
            assert_eq!(back, p);
            assert_eq!(back.xflags(0), xflags);
        }
        assert_eq!(ZfsProject::of(0, 0), None, "project 0 without inheritance kept");

        // Other flags stay as they are.
        let p = |id, inherit| ZfsProject { id, inherit };
        assert_eq!(p(5, false).xflags(0x2000_0008), 0x8);
        assert_eq!(p(5, true).xflags(0x8), 0x2000_0008);
    }
}
