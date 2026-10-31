//! illumos system attributes (`chmod(1)`'s `S+v...`, `fgetattr(3C)`) as a
//! bitmask, the creation time, and the part of libnvpair needed to read and
//! change them: a packed, XDR-encoded nvlist, which is what each file's
//! `SUNWattr_rw` extended attribute holds. A read gives every attribute the
//! file system has; a write sets just those in the nvlist written, so the
//! restore writes a list of those it changes alone. Writing back the whole
//! view would set the creation time too, which an immutable file refuses.
//! Portable, so that it is tested on any system; the file access is in
//! `illumos.rs`.

#![cfg_attr(not(target_os = "illumos"), allow(dead_code))]

use std::{collections::BTreeMap, io};

use jiff::Timestamp;

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

/// ZFS sets these two on every file it creates or writes to, as Windows does
/// its archive bit; on their own they're no reason to keep a file's
/// attributes.
pub(super) const AUTOMATIC: u32 = 1 << 3 | 1 << 9; // archive, av_modified

const NV_ENCODE_XDR: u8 = 1;
const NV_UNIQUE_NAME: u32 = 1;

const DATA_TYPE_UINT32: u32 = 6;
const DATA_TYPE_STRING: u32 = 9;
const DATA_TYPE_UINT64_ARRAY: u32 = 16;
const DATA_TYPE_NVLIST: u32 = 19;
const DATA_TYPE_BOOLEAN_VALUE: u32 = 21;

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn be32(buf: &[u8], pos: usize) -> u32 {
    u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap())
}

fn be64(buf: &[u8], pos: usize) -> u64 {
    u64::from_be_bytes(buf[pos..pos + 8].try_into().unwrap())
}

fn usize32(buf: &[u8], pos: usize) -> usize {
    usize::try_from(be32(buf, pos)).unwrap_or(usize::MAX)
}

/// The type and encoded value of a pair in an XDR-encoded nvlist.
#[derive(Debug)]
struct Pair<'a> {
    typ: u32,
    nelem: u32,
    /// Up to the end of the pair.
    value: &'a [u8],
}

/// The pairs at the top of a `SUNWattr_rw` view, by name.
#[derive(Debug)]
pub(super) struct View<'a>(BTreeMap<String, Pair<'a>>);

impl<'a> View<'a> {
    /// Reads the pairs at the top of the XDR-encoded nvlist `buf`. Nested
    /// nvlists (the owner's and group's SIDs) are skipped, as pairs of every
    /// other type are: each pair starts with its encoded size.
    ///
    /// # Errors
    ///
    /// * If `buf` isn't an XDR-encoded nvlist.
    pub(super) fn parse(buf: &'a [u8]) -> io::Result<Self> {
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
                return Ok(Self(values)); // the end
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
            let pair = Pair {
                typ: be32(buf, pos),
                nelem: be32(buf, pos + 4),
                value: &buf[pos + 8..end],
            };
            _ = values.insert(name, pair);
            pos = end;
        }
    }

    /// Whether the view has the boolean `name`.
    fn has_boolean(&self, name: &str) -> bool {
        self.0
            .get(name)
            .is_some_and(|v| v.typ == DATA_TYPE_BOOLEAN_VALUE && v.nelem == 1 && v.value.len() >= 4)
    }

    /// The system attributes in the view, as a mask.
    pub(super) fn mask(&self) -> u32 {
        BITS.iter()
            .filter(|(name, _)| self.has_boolean(name) && be32(self.0[*name].value, 0) != 0)
            .fold(0, |mask, (_, bit)| mask | bit)
    }

    /// The system attributes in the view, as a mask, if they are worth
    /// keeping: unless they are what a new file gets, the automatic ones the
    /// view has. So a mask of 0 is kept where the view has them, for a file
    /// whose archive and av_modified were cleared, which ZFS would set again.
    pub(super) fn kept_mask(&self) -> Option<u32> {
        let automatic = BITS
            .iter()
            .filter(|(name, bit)| bit & AUTOMATIC != 0 && self.has_boolean(name))
            .fold(0, |mask, (_, bit)| mask | bit);
        let mask = self.mask();
        (mask != automatic).then_some(mask)
    }

    /// The nvlist that sets the system attributes to those in `mask`: a
    /// boolean for each attribute the view has, alone.
    pub(super) fn mask_nvlist(&self, mask: u32) -> Vec<u8> {
        let pairs: Vec<_> = BITS
            .iter()
            .filter(|(name, _)| self.has_boolean(name))
            .map(|&(name, bit)| (name, Nv::Boolean(mask & bit != 0)))
            .collect();
        encode(&pairs)
    }

    /// The creation time in the view, if it has one: `crtime`, two `uint64`s,
    /// the seconds and nanoseconds.
    pub(super) fn crtime(&self) -> Option<Timestamp> {
        let v = self.0.get("crtime")?;
        if v.typ != DATA_TYPE_UINT64_ARRAY || v.nelem != 2 || v.value.len() < 20 || be32(v.value, 0) != 2
        {
            return None;
        }
        // Two's complement, as the kernel's time_t.
        let sec = be64(v.value, 4).cast_signed();
        let nsec = i32::try_from(be64(v.value, 12)).ok()?;
        Timestamp::new(sec, nsec).ok()
    }
}

/// The nvlist that sets the creation time to `t`, alone.
pub(super) fn crtime_nvlist(t: Timestamp) -> Vec<u8> {
    let (sec, nsec) = super::unix_time(t);
    // Two's complement, as the kernel's time_t.
    encode(&[("crtime", Nv::Uint64Array(vec![sec.cast_unsigned(), nsec.into()]))])
}

/// A value to encode in an nvlist.
#[derive(Debug)]
enum Nv<'a> {
    Boolean(bool),
    Uint64Array(Vec<u64>),
    // Only in the tests, which check the encoding of a view's owner SID:
    // the view refuses to set one (EINVAL).
    #[cfg_attr(not(test), allow(dead_code))]
    Uint32(u32),
    #[cfg_attr(not(test), allow(dead_code))]
    String(&'a str),
    #[cfg_attr(not(test), allow(dead_code))]
    Nvlist(Vec<(&'a str, Self)>),
}

/// Packs `pairs`, in their order, as `nvlist_pack(3NVPAIR)` does with
/// `NV_ENCODE_XDR` and `NV_UNIQUE_NAME`.
fn encode(pairs: &[(&str, Nv<'_>)]) -> Vec<u8> {
    // The nvs header: the encoding and the host's byte order (little endian;
    // XDR doesn't use it), then two bytes unused.
    let mut buf = vec![NV_ENCODE_XDR, 1, 0, 0];
    append_nvlist(&mut buf, pairs);
    buf
}

fn append_nvlist(buf: &mut Vec<u8>, pairs: &[(&str, Nv<'_>)]) {
    append32(buf, 0); // nvl_version
    append32(buf, NV_UNIQUE_NAME);
    for (name, value) in pairs {
        // The value's size in memory, for the decoded size.
        let (typ, nelem, native) = match value {
            Nv::Boolean(_) => (DATA_TYPE_BOOLEAN_VALUE, 1, 4),
            Nv::Uint32(_) => (DATA_TYPE_UINT32, 1, 4),
            Nv::String(s) => (DATA_TYPE_STRING, 1, s.len() + 1),
            Nv::Uint64Array(v) => (DATA_TYPE_UINT64_ARRAY, len32(v.len()), 8 * v.len()),
            Nv::Nvlist(_) => (DATA_TYPE_NVLIST, 1, 24), // sizeof (nvlist_t)
        };
        let start = buf.len();
        append32(buf, 0); // the encoded size, below
        // The decoded size: an nvpair_t, then the name and the value, each
        // 8-byte aligned.
        append32(buf, len32(16 + align8(name.len() + 1) + align8(native)));
        append_string(buf, name);
        append32(buf, typ);
        append32(buf, nelem);
        match value {
            Nv::Boolean(b) => append32(buf, u32::from(*b)),
            Nv::Uint32(n) => append32(buf, *n),
            Nv::String(s) => append_string(buf, s),
            Nv::Uint64Array(v) => {
                append32(buf, nelem);
                for x in v {
                    buf.extend_from_slice(&x.to_be_bytes());
                }
            }
            Nv::Nvlist(nested) => append_nvlist(buf, nested),
        }
        let size = len32(buf.len() - start).to_be_bytes();
        buf[start..start + 4].copy_from_slice(&size);
    }
    // The end of the list: a pair with both sizes 0.
    buf.extend_from_slice(&[0; 8]);
}

fn append32(buf: &mut Vec<u8>, n: u32) {
    buf.extend_from_slice(&n.to_be_bytes());
}

/// Appends `s` as XDR does: its length, then its bytes padded to 4, without
/// a NUL.
fn append_string(buf: &mut Vec<u8>, s: &str) {
    append32(buf, len32(s.len()));
    buf.extend_from_slice(s.as_bytes());
    buf.resize(buf.len() + (4 - s.len() % 4) % 4, 0);
}

/// A length as XDR's 32 bits: every nvlist here is small.
fn len32(n: usize) -> u32 {
    u32::try_from(n).expect("nvlist too large")
}

const fn align8(n: usize) -> usize {
    (n + 7) & !7
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

    // Packed by OmniOS r151058's nvlist_pack(NV_ENCODE_XDR), and read with
    // fgetattr(3C)'s view, SUNWattr_rw.
    // {crtime=[1000000000,123456789]}
    const NVLIST_CRTIME: &str = "\
        01010000 00000000 00000001 00000030 00000028 00000006 63727469 6d650000 \
        00000010 00000002 00000002 00000000 3b9aca00 00000000 075bcd15 00000000 \
        00000000";

    // {hidden=true, immutable=false}
    const NVLIST_HIDDEN: &str = "\
        01010000 00000000 00000001 00000020 00000020 00000006 68696464 656e0000 \
        00000015 00000001 00000001 00000024 00000028 00000009 696d6d75 7461626c \
        65000000 00000015 00000001 00000000 00000000 00000000";

    // {ownersid={domain="S-1-5-21-1111-2222-3333", rid=1001}}
    const NVLIST_OWNER_SID: &str = "\
        01010000 00000000 00000001 00000080 00000038 00000008 6f776e65 72736964 \
        00000013 00000001 00000000 00000001 00000038 00000030 00000006 646f6d61 \
        696e0000 00000009 00000001 00000017 532d312d 352d3231 2d313131 312d3232 \
        32322d33 33333300 0000001c 00000020 00000003 72696400 00000006 00000001 \
        000003e9 00000000 00000000 00000000 00000000";

    // A new file's whole view (archive, av_modified and its crtime).
    const SUNWATTR_PLAIN: &str = "\
        01010000 00000000 00000001 00000020 00000028 00000008 72656164 6f6e6c79 \
        00000015 00000001 00000000 00000020 00000020 00000006 68696464 656e0000 \
        00000015 00000001 00000000 00000020 00000020 00000006 73797374 656d0000 \
        00000015 00000001 00000000 00000020 00000020 00000007 61726368 69766500 \
        00000015 00000001 00000001 00000024 00000028 00000009 696d6d75 7461626c \
        65000000 00000015 00000001 00000000 00000020 00000028 00000008 6e6f756e \
        6c696e6b 00000015 00000001 00000000 00000024 00000028 0000000a 61707065 \
        6e646f6e 6c790000 00000015 00000001 00000000 00000020 00000020 00000006 \
        6e6f6475 6d700000 00000015 00000001 00000000 00000028 00000028 0000000e \
        61765f71 75617261 6e74696e 65640000 00000015 00000001 00000000 00000024 \
        00000028 0000000b 61765f6d 6f646966 69656400 00000015 00000001 00000001 \
        00000030 00000028 00000006 63727469 6d650000 00000010 00000002 00000002 \
        00000000 6ae503f8 00000000 007db3d8 00000020 00000020 00000007 6f66666c \
        696e6500 00000015 00000001 00000000 00000020 00000020 00000006 73706172 \
        73650000 00000015 00000001 00000000 00000000 00000000";

    // The whole view of a file owned by a SID: ownersid and groupsid,
    // nested nvlists, after the rest.
    const SUNWATTR_SID: &str = "\
        01010000 00000000 00000001 00000020 00000028 00000008 72656164 6f6e6c79 \
        00000015 00000001 00000000 00000020 00000020 00000006 68696464 656e0000 \
        00000015 00000001 00000000 00000020 00000020 00000006 73797374 656d0000 \
        00000015 00000001 00000000 00000020 00000020 00000007 61726368 69766500 \
        00000015 00000001 00000001 00000024 00000028 00000009 696d6d75 7461626c \
        65000000 00000015 00000001 00000000 00000020 00000028 00000008 6e6f756e \
        6c696e6b 00000015 00000001 00000000 00000024 00000028 0000000a 61707065 \
        6e646f6e 6c790000 00000015 00000001 00000000 00000020 00000020 00000006 \
        6e6f6475 6d700000 00000015 00000001 00000000 00000028 00000028 0000000e \
        61765f71 75617261 6e74696e 65640000 00000015 00000001 00000000 00000024 \
        00000028 0000000b 61765f6d 6f646966 69656400 00000015 00000001 00000001 \
        00000030 00000028 00000006 63727469 6d650000 00000010 00000002 00000002 \
        00000000 6ae503f8 00000000 2759d7f4 00000020 00000020 00000007 6f66666c \
        696e6500 00000015 00000001 00000000 00000020 00000020 00000006 73706172 \
        73650000 00000015 00000001 00000000 00000080 00000038 00000008 6f776e65 \
        72736964 00000013 00000001 00000000 00000001 00000038 00000030 00000006 \
        646f6d61 696e0000 00000009 00000001 00000017 532d312d 352d3231 2d313131 \
        312d3232 32322d33 33333300 0000001c 00000020 00000003 72696400 00000006 \
        00000001 000003e9 00000000 00000000 00000080 00000038 00000008 67726f75 \
        70736964 00000013 00000001 00000000 00000001 00000038 00000030 00000006 \
        646f6d61 696e0000 00000009 00000001 00000017 532d312d 352d3231 2d313131 \
        312d3232 32322d33 33333300 0000001c 00000020 00000003 72696400 00000006 \
        00000001 00000201 00000000 00000000 00000000 00000000";

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }

    fn bit(name: &str) -> u32 {
        BITS.iter().find(|(n, _)| *n == name).unwrap().1
    }

    #[test]
    fn mask_round_trips() {
        let buf = unhex(SUNWATTR_RW);
        let view = View::parse(&buf).unwrap();
        let want = bit("nodump") | bit("immutable") | bit("archive") | bit("av_modified");
        assert_eq!(view.mask(), want);

        // Clear immutable and set hidden: the nvlist written has every
        // boolean the view has, and nothing else, and reads back as the mask.
        let want = want & !bit("immutable") | bit("hidden");
        let buf = view.mask_nvlist(want);
        let written = View::parse(&buf).unwrap();
        assert_eq!(written.mask(), want);
        assert_eq!(written.0.len(), view.0.len());
        assert_eq!(written.crtime(), None);

        assert!(View::parse(&[0, 1, 0, 0]).is_err(), "a native-encoded nvlist was accepted");
    }

    #[test]
    fn kept_masks() {
        let plain = unhex(SUNWATTR_PLAIN);
        let plain = View::parse(&plain).unwrap();
        // The plain view with every attribute cleared, archive and
        // av_modified too (chmod S-varchive,av_modified), and with
        // av_modified alone cleared.
        let cleared = plain.mask_nvlist(0);
        let no_av_modified = plain.mask_nvlist(bit("archive"));
        let immutable = unhex(SUNWATTR_RW);
        let crtime_only = unhex(NVLIST_CRTIME);
        for (what, buf, kept) in [
            ("new file", &plain.mask_nvlist(AUTOMATIC), None),
            (
                "immutable, nodump",
                &immutable,
                Some(bit("immutable") | bit("nodump") | AUTOMATIC),
            ),
            ("archive and av_modified cleared", &cleared, Some(0)),
            ("av_modified cleared", &no_av_modified, Some(bit("archive"))),
            ("no attributes in the view", &crtime_only, None),
        ] {
            assert_eq!(View::parse(buf).unwrap().kept_mask(), kept, "{what}");
        }
        assert_eq!(plain.kept_mask(), None);
    }

    #[test]
    fn encode_as_nvlist_pack() {
        let sid = vec![
            ("domain", Nv::String("S-1-5-21-1111-2222-3333")),
            ("rid", Nv::Uint32(1001)),
        ];
        for (pairs, want) in [
            (
                vec![("crtime", Nv::Uint64Array(vec![1_000_000_000, 123_456_789]))],
                NVLIST_CRTIME,
            ),
            (
                vec![("hidden", Nv::Boolean(true)), ("immutable", Nv::Boolean(false))],
                NVLIST_HIDDEN,
            ),
            (vec![("ownersid", Nv::Nvlist(sid))], NVLIST_OWNER_SID),
        ] {
            assert_eq!(hex::encode(encode(&pairs)), hex::encode(unhex(want)));
        }
        let t = Timestamp::new(1_000_000_000, 123_456_789).unwrap();
        assert_eq!(crtime_nvlist(t), unhex(NVLIST_CRTIME));

        // The system attributes' nvlist for a view with these two booleans.
        let buf = unhex(NVLIST_HIDDEN);
        assert_eq!(View::parse(&buf).unwrap().mask_nvlist(bit("hidden")), buf);
    }

    #[test]
    fn crtime_and_mask_of_views() {
        for (view, sec, nsec, mask) in [
            (NVLIST_CRTIME, 1_000_000_000, 123_456_789, 0),
            (SUNWATTR_PLAIN, 1_793_393_656, 8_238_040, AUTOMATIC),
            (SUNWATTR_SID, 1_793_393_656, 660_199_412, AUTOMATIC),
        ] {
            let buf = unhex(view);
            let view = View::parse(&buf).unwrap();
            assert_eq!(view.crtime(), Some(Timestamp::new(sec, nsec).unwrap()));
            assert_eq!(view.mask(), mask);
        }

        // The nested nvlists are skipped whole: nothing in them is at the top.
        let buf = unhex(SUNWATTR_SID);
        let view = View::parse(&buf).unwrap();
        assert_eq!(view.0["groupsid"].typ, DATA_TYPE_NVLIST);
        assert!(!view.0.contains_key("domain"), "a nested pair was read at the top");
        assert_eq!(view.0.len(), 15);

        let buf = unhex(NVLIST_HIDDEN);
        assert_eq!(View::parse(&buf).unwrap().crtime(), None);

        // Before 1970: seconds in two's complement, nanoseconds positive.
        let t = Timestamp::new(-2, 999_999_999).unwrap();
        let buf = crtime_nvlist(t);
        assert_eq!(buf[44..60], unhex("ffffffff fffffffe 00000000 3b9ac9ff"));
        assert_eq!(View::parse(&buf).unwrap().crtime(), Some(t));
    }
}
