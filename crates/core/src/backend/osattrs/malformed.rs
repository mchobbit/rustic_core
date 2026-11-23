//! BackOtter: malformed input for the tests of the decoders that read bytes
//! another machine wrote (a snapshot's generic attributes) or a system
//! handed over (attribute lists and views): each input cut short at every
//! length, and with each of its bits flipped in turn. A decoder must give an
//! error, or a value it can stand by, and never panic or hang. Under Miri
//! some 200 lengths and bits are tried of each input, spread over all of
//! it (every 13th at least), which keeps the run short.

use std::panic::{AssertUnwindSafe, catch_unwind};

/// How far apart the lengths and bits tried of `n` are.
fn step(n: usize) -> usize {
    if cfg!(miri) { (n / 200).max(13) } else { 1 }
}

/// `buf` cut short at every length from 0 to one short of its own.
pub(crate) fn truncations(buf: &[u8]) -> impl Iterator<Item = &[u8]> {
    (0..buf.len()).step_by(step(buf.len())).map(move |n| &buf[..n])
}

/// `buf` with one of its bits flipped, for each bit in turn.
pub(crate) fn bit_flips(buf: &[u8]) -> impl Iterator<Item = Vec<u8>> + '_ {
    (0..buf.len() * 8).step_by(step(buf.len() * 8)).map(move |bit| {
        let mut b = buf.to_vec();
        b[bit / 8] ^= 1 << (bit % 8);
        b
    })
}

/// What a check of one malformed input found.
pub(crate) enum Found {
    /// Refused, as it should be.
    Refused,
    /// Decoded to a value that is right for the input as it is.
    Decoded,
    /// A wrong answer: an `Ok` for an input that can't be right, or a value
    /// that breaks a rule of the decoder's.
    Wrong(String),
}

/// Every input of [`truncations`] and [`bit_flips`] of `buf`, given to
/// `check` (with whether it was cut short). Panics after all of them if
/// any check panicked (the decoder did) or found a wrong answer, with the
/// first few of each and how many in all; returns how many were decoded and
/// how many refused.
pub(crate) fn every_mutation(
    what: &str,
    buf: &[u8],
    mut check: impl FnMut(&[u8], bool) -> Found,
) -> (usize, usize) {
    let (mut panicked, mut wrong) = (Vec::new(), Vec::new());
    let (mut decoded, mut refused) = (0, 0);
    let mut run = |input: &[u8], cut: bool| {
        let how = if cut { "cut" } else { "flipped" };
        let shown = || format!("{how} {:?}", String::from_utf8_lossy(input));
        match catch_unwind(AssertUnwindSafe(|| check(input, cut))) {
            Ok(Found::Decoded) => decoded += 1,
            Ok(Found::Refused) => refused += 1,
            Ok(Found::Wrong(why)) => wrong.push(format!("{}: {why}", shown())),
            Err(_) => panicked.push(shown()),
        }
    };
    for t in truncations(buf) {
        run(t, true);
    }
    for f in bit_flips(buf) {
        run(&f, false);
    }
    let tried = decoded + refused + wrong.len() + panicked.len();
    eprintln!(
        "{what}: {tried} inputs: {decoded} decoded, {refused} refused, {} wrong, {} panicked",
        wrong.len(),
        panicked.len()
    );
    assert!(
        panicked.is_empty() && wrong.is_empty(),
        "{what}: of {tried} malformed inputs {} panicked, the first {:?}; {} answered wrong, the first {:?}",
        panicked.len(),
        &panicked[..panicked.len().min(3)],
        wrong.len(),
        &wrong[..wrong.len().min(3)],
    );
    (decoded, refused)
}

/// [`every_mutation`] for a JSON document `json` decoded as a `T`, then
/// given to `check` when it decodes. A document cut short is never valid
/// JSON (it ends in a `}` or `]`), so decoding one is a wrong answer.
pub(crate) fn every_json_mutation<T: serde::de::DeserializeOwned>(
    what: &str,
    json: &str,
    mut check: impl FnMut(&T) -> Result<(), String>,
) -> (usize, usize) {
    assert!(
        serde_json::from_str::<T>(json).is_ok(),
        "{what}: the sample doesn't decode"
    );
    every_mutation(
        what,
        json.as_bytes(),
        |input, cut| match serde_json::from_slice::<T>(input) {
            Err(_) => Found::Refused,
            Ok(_) if cut && !input.trim_ascii().is_empty() => {
                Found::Wrong("a document cut short decoded".to_string())
            }
            Ok(v) => match check(&v) {
                Ok(()) => Found::Decoded,
                Err(why) => Found::Wrong(why),
            },
        },
    )
}

/// A regular file's node with every generic attribute the forks know, each
/// in the form one of the tools writes it.
pub(crate) const EVERY_ATTRIBUTE_NODE: &str = concat!(
    r#"{"name":"f","type":"file","mode":420,"mtime":"2026-10-30T12:00:00Z","#,
    r#""atime":"2026-10-30T12:00:00Z","ctime":"2026-10-30T12:00:00Z","uid":1000,"gid":1000,"#,
    r#""user":"u","group":"g","inode":5,"device_id":64769,"size":4096,"links":1,"#,
    r#""extended_attributes":[{"name":"user.a","value":"aGk="},{"name":"security.selinux","value":"c3lzdGVtX3U6b2JqZWN0X3I6dXNlcl9ob21lX3Q6czAA"}],"#,
    r#""generic_attributes":{"#,
    r#""windows.creation_time":"AAAAAAAAAAA=","windows.file_attributes":"IAAAAA==","#,
    r#""linux.inode_flags":16,"linux.project_id":4242,"unix.sparse":true,"#,
    r#""freebsd.file_flags":131072,"freebsd.system_extattrs":{"a":"aGk=","b":null},"#,
    r#""freebsd.acl_access":[{"tag":1,"id":4294967295,"perm":6},{"tag":2,"id":1001,"perm":7},{"tag":4,"id":4294967295,"perm":4},{"tag":16,"id":4294967295,"perm":5},{"tag":32,"id":4294967295,"perm":4}],"#,
    r#""freebsd.acl_nfs4":[{"tag":1,"id":4294967295,"perm":1,"type":256}],"#,
    r#""illumos.acl":[{"who":2147483650,"mask":1,"sid":"S-1-5-21-1111-2222-3333-1004"},{"who":60001,"mask":1}],"#,
    r#""illumos.system_attributes":33,"openbsd.file_flags":4,"netbsd.file_flags":8,"dragonfly.file_flags":2,"#,
    r#""linux.zfs_dos_flags":52978421596160,"unix.birthtime":"2001-09-09T01:46:40.5Z","#,
    r#""illumos.owner_sid":"S-1-5-21-1111-2222-3333-1001","illumos.group_sid":"S-1-5-21-1111-2222-3333-513","#,
    r#""illumos.xattr_meta":{"note":{"uid":1500,"gid":1501,"mode":416,"mtime":"2001-09-09T01:46:40.123456789Z","atime":"2001-09-09T01:46:40Z"}},"#,
    r#""illumos.zfs_project":{"id":5,"inherit":true},"freebsd.zfs_project":{"id":6},"illumos.unread_size":12345,"#,
    r#""haiku.attributes":{"BEOS:TYPE":{"type":1296649555,"value":"dGV4dC9wbGFpbgA="}},"#,
    r#""linux.fat_attrs":7,"linux.xfs_options":{"cowextsize":2097152,"extsize":1048576,"xflags":67584}},"#,
    r#""content":[]}"#
);
