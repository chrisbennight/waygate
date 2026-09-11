//! Reading and writing a file's access-control list on Windows.
//!
//! This is the platform half of the owner-only guarantee: the calls that ask
//! the operating system who may read a path, and the call that restricts one to
//! its owner. What counts as owner-only is decided by [`crate::acl`], which is
//! compiled and tested everywhere; this module only supplies it with facts and
//! carries out its verdict.
//!
//! Everything here is a thin translation of a Win32 call. The unsafety is the
//! calls themselves — each buffer handed out is sized by the same API that
//! fills it, and each pointer the system allocates is released on every path
//! out.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;

use anyhow::{Context, Result};
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_SUCCESS, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, AddAccessAllowedAce, GetAce, GetAclInformation, GetLengthSid,
    GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TokenUser, ACCESS_ALLOWED_ACE,
    ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, CREATE_NEW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::acl::AllowedPrincipal;

/// A path as a null-terminated UTF-16 string, which is what the `W` calls take.
fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Render a SID in the `S-1-…` string form the decision compares.
///
/// # Safety
///
/// `sid` must point at a valid security identifier that outlives the call.
unsafe fn sid_to_string(sid: PSID) -> Result<String> {
    let mut raw: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` is a valid SID per this function's contract, and `raw` is a
    // writable slot for the string the system allocates.
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
        return Err(std::io::Error::last_os_error()).context("render a security identifier");
    }

    // SAFETY: on success the call stored a null-terminated string in `raw`.
    let len = unsafe { (0..).take_while(|&i| *raw.offset(i) != 0).count() };
    // SAFETY: `raw` holds `len` units before its terminator.
    let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(raw, len) });
    // SAFETY: `raw` was allocated by `ConvertSidToStringSidW`, which documents
    // `LocalFree` as its release.
    unsafe { LocalFree(raw as *mut c_void) };
    Ok(text)
}

/// The SID of the account this process runs as.
pub fn current_user_sid() -> Result<String> {
    let buffer = token_user().context("read this process's token user")?;
    // SAFETY: `token_user` returns a buffer holding a `TOKEN_USER`, aligned for
    // it, whose `Sid` points into that same buffer and so lives as long as it
    // does.
    let user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    unsafe { sid_to_string(user.User.Sid) }
}

/// Who owns the file behind `file`, and every access-allowed entry on its
/// discretionary list.
///
/// The owner is read in the same call rather than a second one: a file's owner
/// may rewrite its list at will, so the two facts only mean something together.
///
/// Asked of an open handle rather than of a name. A name is resolved afresh on
/// every call, so checking one and then reading the other asks about two
/// different files — and in a directory where somebody else may rename or
/// delete, those two need not be the same file. The handle is the file, so what
/// is judged here is what the caller has.
///
/// `path` is carried for its error messages only.
pub fn security_of(file: &std::fs::File, path: &Path) -> Result<(String, Vec<AllowedPrincipal>)> {
    use std::os::windows::io::AsRawHandle as _;

    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();

    // SAFETY: the handle is open and owned by the caller for the whole call,
    // and the out-slots are writable. The remaining outputs are declined with
    // nulls, which the call permits.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .with_context(|| format!("read the security descriptor of {}", path.display()));
    }

    let entries = (|| -> Result<(String, Vec<AllowedPrincipal>)> {
        if owner.is_null() {
            anyhow::bail!(
                "{} reports no owner, so there is no account this key can be attributed to",
                path.display()
            );
        }
        // SAFETY: the call returned a non-null owner SID inside `descriptor`,
        // which outlives this closure.
        let owner_sid = unsafe { sid_to_string(owner) }?;
        // A null list is not an empty one: it means the object grants everyone
        // everything. Refusing outright is the only safe reading. There is no
        // offending principal to name here because the answer is "all of them",
        // so the refusal carries the command instead.
        if dacl.is_null() {
            anyhow::bail!(
                "{} has no access-control list, which grants every account full access. \
                 Restrict it to your account with \
                 `icacls \"{}\" /inheritance:r /grant:r \"%USERNAME%\":F`, or delete it and let \
                 a fresh key be created.",
                path.display(),
                path.display()
            );
        }

        let mut info = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        // SAFETY: `dacl` is the non-null list the system just returned, and
        // `info` matches the class being requested.
        if unsafe {
            GetAclInformation(
                dacl,
                &mut info as *mut _ as *mut c_void,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("count the access entries on {}", path.display()));
        }

        let mut found = Vec::with_capacity(info.AceCount as usize);
        for index in 0..info.AceCount {
            let mut ace: *mut c_void = std::ptr::null_mut();
            // SAFETY: `index` is below the count the call above reported.
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("read access entry {index} on {}", path.display()));
            }

            // SAFETY: every ACE begins with a header, so the type is readable
            // before the body is interpreted.
            let header = unsafe { &*(ace as *const ACE_HEADER) };
            match header.AceType as u32 {
                ACCESS_ALLOWED_ACE_TYPE => {
                    // SAFETY: the header says this is an access-allowed entry,
                    // whose layout is `ACCESS_ALLOWED_ACE`.
                    let allowed = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
                    // SAFETY: in an access-allowed entry the SID begins at
                    // `SidStart` and runs to the end of the entry.
                    let sid = unsafe { sid_to_string(&allowed.SidStart as *const u32 as PSID) }?;
                    found.push(AllowedPrincipal {
                        sid,
                        confers_access: crate::acl::mask_confers_access(allowed.Mask),
                    });
                }
                // A deny entry can only take an access away, so passing over it
                // makes the verdict stricter and never weaker.
                ACCESS_DENIED_ACE_TYPE => {}
                // Everything else is refused rather than passed over. The
                // callback and object forms of an allow entry grant access just
                // as the basic form does, but carry a different layout; reading
                // one as though it were basic would be wrong, and skipping it
                // would drop a principal that can read the key. Neither is
                // acceptable for the fact this function exists to establish, and
                // no such entry appears on an ordinary file, so an unrecognised
                // one is reported rather than guessed at.
                // No `icacls` command is offered here, deliberately. This branch
                // is reached without having collected the entries, so there is
                // nothing to name in a `/remove:g`, and the inheritance-and-grant
                // form leaves an explicit entry of this kind exactly where it
                // was — advice that would send someone round the same refusal a
                // second time. Discarding the key is the move that always works.
                other => anyhow::bail!(
                    "{} carries an access-control entry of type {other}, which this check does not \
                     interpret, so it cannot establish who may reach the key. Delete it and let a \
                     fresh key be created, or point --config-dir at a location only you can write.",
                    path.display()
                ),
            }
        }
        Ok((owner_sid, found))
    })();

    // SAFETY: `descriptor` was allocated by `GetSecurityInfo`, which
    // documents `LocalFree` as its release. `dacl` points inside it and must
    // not be released separately, nor used after this.
    unsafe { LocalFree(descriptor) };
    entries
}

/// The `TOKEN_USER` of this process, kept as the buffer that backs it.
///
/// The SID is interior to the buffer, so the buffer is what callers have to
/// hold on to: a returned `PSID` would dangle the moment it dropped.
///
/// Backed by `u64` rather than `u8` because the buffer is read back as a
/// `TOKEN_USER`, which begins with a pointer. A `Vec<u8>` promises only byte
/// alignment, so dereferencing one as that struct would be undefined however
/// well it happened to work.
fn token_user() -> std::io::Result<Vec<u64>> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo-handle from `GetCurrentProcess` needs no release, and
    // `token` is a writable slot for the opened handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let result = (|| -> std::io::Result<Vec<u64>> {
        let mut needed = 0u32;
        // SAFETY: the documented size query; writes only `needed`.
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
        if needed == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        // SAFETY: `buffer` addresses at least `needed` bytes, the size the call
        // just asked for, and is aligned for the struct written into it.
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr() as *mut c_void,
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(buffer)
    })();

    // SAFETY: `token` was opened above and is not used after this point.
    unsafe { CloseHandle(token) };
    result
}

/// An access-control list granting `sid` everything and naming nobody else.
///
/// Returned as `u32` storage so the buffer carries the DWORD alignment an `ACL`
/// requires; a `Vec<u8>` would only be byte-aligned.
///
/// # Safety
///
/// `sid` must point at a valid security identifier that outlives the call.
unsafe fn owner_only_acl(sid: PSID) -> std::io::Result<Vec<u32>> {
    // SAFETY: `sid` is valid per this function's contract.
    let sid_len = unsafe { GetLengthSid(sid) };
    let acl_bytes = std::mem::size_of::<ACL>() + std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        - std::mem::size_of::<u32>()
        + sid_len as usize;
    let mut buffer = vec![0u32; acl_bytes.div_ceil(4)];
    let acl = buffer.as_mut_ptr() as *mut ACL;

    // SAFETY: `acl` addresses `acl_bytes` of correctly aligned storage.
    if unsafe { InitializeAcl(acl, acl_bytes as u32, ACL_REVISION) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `acl` was just initialised with room for exactly this entry.
    if unsafe { AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, sid) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(buffer)
}

/// Create `path` for writing, owner-only from the instant it exists, failing if
/// it is already there.
///
/// The list is supplied to the create call rather than applied afterwards.
/// Creating the file first and restricting it second would leave an interval
/// during which it carries whatever the directory hands down, and a reader
/// admitted by that inherited list keeps the handle it opened — revising a list
/// does not revoke access already granted. In a shared `--config-dir` that
/// interval is enough to watch the key being written.
///
/// The file is opened with no sharing for the same reason: nothing else may
/// hold it open while the key goes in.
pub fn create_private_new(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::io::FromRawHandle as _;

    let user_buffer = token_user()?;
    // SAFETY: `token_user` returns a buffer holding a `TOKEN_USER`, aligned
    // for it.
    let user = unsafe { &*(user_buffer.as_ptr() as *const TOKEN_USER) };
    // SAFETY: the SID is interior to `user_buffer`, which outlives this call.
    let mut acl = unsafe { owner_only_acl(user.User.Sid) }?;

    let mut descriptor = SECURITY_DESCRIPTOR::default();
    let descriptor_ptr = &mut descriptor as *mut _ as PSECURITY_DESCRIPTOR;
    // SAFETY: `descriptor` is owned local storage of the right type.
    if unsafe { InitializeSecurityDescriptor(descriptor_ptr, SECURITY_DESCRIPTOR_REVISION) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the descriptor was just initialised, and `acl` is well-formed and
    // outlives the create call below. `false` for `defaulted` marks the list as
    // deliberate rather than inherited.
    if unsafe { SetSecurityDescriptorDacl(descriptor_ptr, 1, acl.as_mut_ptr() as *mut ACL, 0) } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // Supplying a list is not by itself a refusal of the directory's. Marking it
    // protected is what stops inheritable entries from the parent being merged
    // into it, and a shared `--config-dir` handing entries down is the whole
    // case this exists to survive.
    //
    // SAFETY: the descriptor was initialised above and is owned local storage.
    if unsafe { SetSecurityDescriptorControl(descriptor_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED) }
        == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // Name the owner rather than letting the token choose one. Left unset,
    // Windows assigns the token's default owner, which for a member of the
    // Administrators group may be that group rather than the account itself —
    // and a key owned by a group is a key that group decides the access to.
    // Saying who owns it keeps creation and the check that follows in agreement.
    //
    // SAFETY: the descriptor is owned local storage, and the SID is interior to
    // `user_buffer`, which outlives the create call below.
    if unsafe { SetSecurityDescriptorOwner(descriptor_ptr, user.User.Sid, 0) } == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor_ptr,
        bInheritHandle: 0,
    };

    let wide_path = wide(path);
    // SAFETY: the path is null-terminated and `attributes` points at a valid
    // descriptor that lives across the call. A zero share mode denies any
    // concurrent open; CREATE_NEW fails rather than touching an existing file.
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_WRITE,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `handle` is a fresh, valid file handle this call owns; `File`
    // takes over closing it.
    Ok(unsafe { std::fs::File::from_raw_handle(handle) })
}

/// Replace `path`'s discretionary list with one naming only its owner.
///
/// The list is marked protected so it stops inheriting from the directory
/// above: a `--config-dir` in a shared location is exactly the case where an
/// inherited entry is what would expose what the directory holds.
///
/// This is for a directory, which is created before it can be restricted. A
/// file that is going to hold the key is created through `create_private_new`
/// instead, which leaves no such interval.
pub fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
    let user_buffer = token_user()?;
    // SAFETY: `token_user` returns a buffer holding a `TOKEN_USER`, aligned
    // for it.
    let user = unsafe { &*(user_buffer.as_ptr() as *const TOKEN_USER) };
    // SAFETY: the SID is interior to `user_buffer`, which outlives this call.
    let mut acl = unsafe { owner_only_acl(user.User.Sid) }?;

    let mut wide_path = wide(path);
    // SAFETY: the path is null-terminated and `acl` is a well-formed list.
    // Only the DACL is being set, so the other inputs are declined.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl.as_mut_ptr() as *mut ACL,
            std::ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}
