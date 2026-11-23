//! SIDs through idmap(8), on illumos: a file owned by a SID (a Windows user
//! or group, as the SMB server and ZFS keep them) has an ephemeral uid or
//! gid, which idmapd hands out as it is asked for and forgets at a reboot.
//! So a backup keeps the SID, and a restore asks idmapd for the id the SID
//! has now.
//!
//! libidmap is private to illumos (OmniOS installs no `idmap.h`), so this
//! opens `libidmap.so.1` with `dlopen(3C)` the first time it is needed,
//! rather than link with it: the binary doesn't depend on it, and builds
//! and starts without it, where SIDs then are kept as if idmap were
//! offline. The calls are those of illumos' `idmap.h`.

use std::{
    collections::BTreeMap,
    ffi::{CStr, CString, c_char, c_int, c_void},
    fmt, io, ptr,
    sync::{Mutex, OnceLock},
};

/// `idmap_stat`: 0 is `IDMAP_SUCCESS`.
type Stat = i32;
/// `idmap_get_handle_t *`.
type Handle = *mut c_void;

type GetCreate = unsafe extern "C" fn(*mut Handle) -> Stat;
type GetDestroy = unsafe extern "C" fn(Handle);
type GetMappings = unsafe extern "C" fn(Handle) -> Stat;
/// `idmap_get_sidbyuid` and `idmap_get_sidbygid`: the handle, the id, flags,
/// then where the SID's prefix (`malloc(3C)`ed), RID and status go.
type GetSidById =
    unsafe extern "C" fn(Handle, u32, c_int, *mut *mut c_char, *mut u32, *mut Stat) -> Stat;
/// `idmap_get_uidbysid` and `idmap_get_gidbysid`: the handle, the SID's
/// prefix and RID, flags, then where the id and status go.
type GetIdBySid =
    unsafe extern "C" fn(Handle, *mut c_char, u32, c_int, *mut u32, *mut Stat) -> Stat;

/// The functions of libidmap this uses, `idmap_get_*`.
struct Idmap {
    create: GetCreate,
    destroy: GetDestroy,
    mappings: GetMappings,
    sid_by_uid: GetSidById,
    sid_by_gid: GetSidById,
    uid_by_sid: GetIdBySid,
    gid_by_sid: GetIdBySid,
}

impl fmt::Debug for Idmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Function pointers, which say nothing.
        f.debug_struct("Idmap").finish_non_exhaustive()
    }
}

/// libidmap, opened once.
fn idmap() -> io::Result<&'static Idmap> {
    static IDMAP: OnceLock<Result<Idmap, String>> = OnceLock::new();
    IDMAP
        .get_or_init(open)
        .as_ref()
        .map_err(|err| io::Error::other(err.clone()))
}

fn dl_error() -> String {
    // SAFETY: dlerror(3C) returns NULL or a C string.
    let err = unsafe { libc::dlerror() };
    if err.is_null() {
        return "dlopen failed".to_string();
    }
    // SAFETY: err is a C string, valid until the next dl call.
    unsafe { CStr::from_ptr(err) }
        .to_string_lossy()
        .into_owned()
}

fn open() -> Result<Idmap, String> {
    // SAFETY: the name is a C string. The library stays loaded.
    let lib = unsafe { libc::dlopen(c"libidmap.so.1".as_ptr(), libc::RTLD_LAZY) };
    if lib.is_null() {
        return Err(dl_error());
    }
    let sym = |name: &CStr| {
        // SAFETY: lib is open, name a C string.
        let f = unsafe { libc::dlsym(lib, name.as_ptr()) };
        if f.is_null() { Err(dl_error()) } else { Ok(f) }
    };
    /// The function `$name` of libidmap as the type `$as`.
    macro_rules! function {
        ($name:literal as $as:ty) => {{
            let f = sym($name)?;
            // SAFETY: f is the function of that name in libidmap, which
            // has that type in idmap.h.
            unsafe { std::mem::transmute::<*mut c_void, $as>(f) }
        }};
    }
    Ok(Idmap {
        create: function!(c"idmap_get_create" as GetCreate),
        destroy: function!(c"idmap_get_destroy" as GetDestroy),
        mappings: function!(c"idmap_get_mappings" as GetMappings),
        sid_by_uid: function!(c"idmap_get_sidbyuid" as GetSidById),
        sid_by_gid: function!(c"idmap_get_sidbygid" as GetSidById),
        uid_by_sid: function!(c"idmap_get_uidbysid" as GetIdBySid),
        gid_by_sid: function!(c"idmap_get_gidbysid" as GetIdBySid),
    })
}

fn check_stat(stat: Stat) -> io::Result<()> {
    if stat == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!("idmap status {stat}")))
    }
}

/// Makes one request to idmapd: `queue` adds it to the handle it is given
/// (`idmap_get_sidbyuid`, ...), with where its status goes, and returns
/// that call's status. libidmap keeps the pointers `queue` gives it, and
/// fills in the answer in `idmap_get_mappings`, before this returns.
fn request(queue: impl FnOnce(&Idmap, Handle, *mut Stat) -> Stat) -> io::Result<()> {
    let idmap = idmap()?;
    let mut gh = ptr::null_mut();
    // SAFETY: gh is where the new handle goes.
    check_stat(unsafe { (idmap.create)(&raw mut gh) })?;
    let mut stat = 0;
    let mut r = queue(idmap, gh, &raw mut stat);
    if r == 0 {
        // SAFETY: gh is the handle, with a request queued.
        r = unsafe { (idmap.mappings)(gh) };
    }
    // SAFETY: gh is the handle, destroyed once.
    unsafe { (idmap.destroy)(gh) };
    check_stat(r)?;
    check_stat(stat)
}

// What idmapd answered, which it keeps until a reboot: files owned by a SID
// tend to come in numbers, with the same few SIDs.
static SIDS: Mutex<BTreeMap<(u32, bool), String>> = Mutex::new(BTreeMap::new());
static IDS: Mutex<BTreeMap<(String, bool), u32>> = Mutex::new(BTreeMap::new());

/// The SID that the ephemeral uid `id` (gid, if `group`) is for.
pub(super) fn sid_of_id(id: u32, group: bool) -> io::Result<String> {
    let cached = SIDS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&(id, group))
        .cloned();
    if let Some(sid) = cached {
        return Ok(sid);
    }
    let (mut prefix, mut rid) = (ptr::null_mut::<c_char>(), 0);
    let result = request(|idmap, gh, stat| {
        let get = if group {
            idmap.sid_by_gid
        } else {
            idmap.sid_by_uid
        };
        // SAFETY: prefix, rid and stat outlive the request.
        unsafe { get(gh, id, 0, &raw mut prefix, &raw mut rid, stat) }
    });
    let prefix = (!prefix.is_null()).then(|| {
        // SAFETY: libidmap gave a C string.
        let s = unsafe { CStr::from_ptr(prefix) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: it was malloc(3C)ed, and is freed once, here, read.
        unsafe { libc::free(prefix.cast()) };
        s
    });
    result?;
    let sid = format!(
        "{}-{rid}",
        prefix.ok_or_else(|| io::Error::other(format!("idmap gave no SID for {id}")))?
    );
    _ = SIDS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert((id, group), sid.clone());
    Ok(sid)
}

/// The uid (gid, if `group`) that `sid` has here, which idmapd hands out if
/// it hasn't yet.
pub(super) fn id_of_sid(sid: &str, group: bool) -> io::Result<u32> {
    let key = (sid.to_string(), group);
    let cached = IDS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
        .copied();
    if let Some(id) = cached {
        return Ok(id);
    }
    let (prefix, rid) = super::illumos_acl::split_sid(sid).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("malformed SID {sid:?}"))
    })?;
    let prefix = CString::new(prefix)?;
    let mut id = 0;
    request(|idmap, gh, stat| {
        let get = if group {
            idmap.gid_by_sid
        } else {
            idmap.uid_by_sid
        };
        // SAFETY: prefix (which libidmap copies), id and stat outlive the
        // request.
        unsafe { get(gh, prefix.as_ptr().cast_mut(), rid, 0, &raw mut id, stat) }
    })?;
    _ = IDS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key, id);
    Ok(id)
}
