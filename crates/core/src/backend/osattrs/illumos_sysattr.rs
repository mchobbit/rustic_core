//! illumos system attributes (`chmod(1)`'s `S+v...`, `fgetattr(3C)`) as a
//! bitmask, and the one part of libnvpair needed to read and change them:
//! the booleans in a packed, XDR-encoded nvlist, which is what each file's
//! `SUNWattr_rw` extended attribute holds. Portable, so that it is tested on
//! any system; the file access is in `illumos.rs`.

#![cfg_attr(not(target_os = "illumos"), allow(dead_code))]

use std::{collections::BTreeMap, io};

/// The attributes `SUNWattr_rw` holds as booleans, one bit each in the mask
/// BackOtter keeps.
const BITS: [(&str, u32); 12] = [
    ("hidden", 1 << 0),
    ("system", 1 << 1),
    ("readonly", 1 << 2),
    ("archive", 1 << 3),
    ("nounlink", 1 << 4),
    ("immutable", 1 << 5),
    ("appendonly", 1 << 6),
    ("nodump", 1 << 7),
    ("av_quarantined", 1 << 8),
    ("av_modified", 1 << 9),
    ("offline", 1 << 10),
    ("sparse", 1 << 11),
];

/// ZFS sets these two on every file it writes, as Windows does its archive
/// bit; on their own they're no reason to keep a file's attributes.
pub(super) const AUTOMATIC: u32 = 1 << 3 | 1 << 9; // archive, av_modified

const NV_ENCODE_XDR: u8 = 1;
const DATA_TYPE_BOOLEAN_VALUE: u32 = 21;

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn be32(buf: &[u8], pos: usize) -> u32 {
    u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap())
}

fn usize32(buf: &[u8], pos: usize) -> usize {
    usize::try_from(be32(buf, pos)).unwrap_or(usize::MAX)
}

/// The offset in `buf` of the value of each boolean in an XDR-encoded
/// nvlist: changing those 4 bytes and writing `buf` back changes just that
/// boolean.
fn booleans(buf: &[u8]) -> io::Result<BTreeMap<String, usize>> {
    if buf.len() < 12 || buf[0] != NV_ENCODE_XDR {
        return Err(invalid("not an XDR-encoded nvlist".to_string()));
    }
    // The 4-byte nvs header, then the nvlist's version and flags.
    let mut pos = 12;
    let mut values = BTreeMap::new();
    loop {
        if pos + 8 > buf.len() {
            return Err(invalid(format!("nvlist truncated at {pos}")));
        }
        let start = pos;
        let encoded_size = usize32(buf, pos);
        let decoded_size = be32(buf, pos + 4);
        if encoded_size == 0 && decoded_size == 0 {
            return Ok(values); // the end
        }
        if encoded_size < 8 || start.saturating_add(encoded_size) > buf.len() {
            return Err(invalid(format!("nvpair at {start} has size {encoded_size}")));
        }
        let end = start + encoded_size;
        pos += 8;
        if pos + 4 > end {
            return Err(invalid(format!("nvpair at {start} truncated")));
        }
        let name_len = usize32(buf, pos);
        pos += 4;
        if pos.saturating_add(name_len) > end {
            return Err(invalid(format!("nvpair at {start}: name too long")));
        }
        let name = String::from_utf8_lossy(&buf[pos..pos + name_len]).into_owned();
        pos += (name_len + 3) & !3;
        if pos + 8 > end {
            return Err(invalid(format!("nvpair {name:?} truncated")));
        }
        let (typ, nelem) = (be32(buf, pos), be32(buf, pos + 4));
        pos += 8;
        if typ == DATA_TYPE_BOOLEAN_VALUE && nelem == 1 && pos + 4 <= end {
            _ = values.insert(name, pos);
        }
        pos = end;
    }
}

/// The system attributes in a `SUNWattr_rw` view, as a mask.
///
/// # Errors
///
/// * If the view isn't an XDR-encoded nvlist.
pub(super) fn mask(view: &[u8]) -> io::Result<u32> {
    let offsets = booleans(view)?;
    Ok(BITS
        .iter()
        .filter(|(name, _)| offsets.get(*name).is_some_and(|&off| be32(view, off) != 0))
        .fold(0, |mask, (_, bit)| mask | bit))
}

/// Sets the system attributes in a `SUNWattr_rw` view, in place, to those
/// in `mask`. Attributes the view lacks are left out.
///
/// # Errors
///
/// * If the view isn't an XDR-encoded nvlist.
pub(super) fn set_mask(view: &mut [u8], mask: u32) -> io::Result<()> {
    let offsets = booleans(view)?;
    for (name, bit) in BITS {
        if let Some(&off) = offsets.get(name) {
            view[off..off + 4].copy_from_slice(&u32::from(mask & bit != 0).to_be_bytes());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The start of a real `SUNWattr_rw` view, from OmniOS r151058, of a file
    /// with nodump and immutable set (and archive and av_modified, as ZFS
    /// sets them), up to and including av_modified, then the end of the list.
    const SUNWATTR_RW: &str = "010100000000000000000001000000200000002800000008726561646f6e6c79\
        00000015000000010000000000000020000000200000000668696464656e0000\
        00000015000000010000000000000020000000200000000673797374656d0000\
        0000001500000001000000000000002000000020000000076172636869766500\
        000000150000000100000001000000240000002800000009696d6d757461626c\
        650000000000001500000001000000010000002000000028000000086e6f756e\
        6c696e6b00000015000000010000000000000024000000280000000a61707065\
        6e646f6e6c790000000000150000000100000000000000200000002000000006\
        6e6f64756d70000000000015000000010000000100000028000000280000000e\
        61765f71756172616e74696e6564000000000015000000010000000000000024\
        000000280000000b61765f6d6f64696669656400000000150000000100000001\
        0000000000000000";

    fn bit(name: &str) -> u32 {
        BITS.iter().find(|(n, _)| *n == name).unwrap().1
    }

    #[test]
    fn mask_round_trips() {
        let mut view = hex::decode(SUNWATTR_RW).unwrap();
        let want = bit("nodump") | bit("immutable") | bit("archive") | bit("av_modified");
        assert_eq!(mask(&view).unwrap(), want);

        // Clear immutable, set hidden, and read it back.
        let want = want & !bit("immutable") | bit("hidden");
        set_mask(&mut view, want).unwrap();
        assert_eq!(mask(&view).unwrap(), want);

        assert!(mask(&[0, 1, 0, 0]).is_err(), "a native-encoded nvlist was accepted");
    }
}
