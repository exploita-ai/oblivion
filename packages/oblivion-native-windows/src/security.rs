//! Private kernel objects are granted only to the actual process user and
//! LocalSystem. Configuration never supplies either an SID or an ACL.
use crate::{Error, Result};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, IsValidSid, PSECURITY_DESCRIPTOR, RevertToSelf, TOKEN_GROUPS, TOKEN_QUERY,
    TOKEN_USER, TokenGroups, TokenUser,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use std::fs::File;
use windows_sys::Win32::Foundation::{GENERIC_EXECUTE, GENERIC_READ};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetLengthSid, INHERIT_ONLY_ACE,
    IsValidAcl, IsValidSecurityDescriptor, OWNER_SECURITY_INFORMATION, PSID, SID,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_CREATE_PIPE_INSTANCE, FILE_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY,
};

pub const PIPE_CLIENT_ACCESS: u32 =
    (FILE_GENERIC_READ | FILE_GENERIC_WRITE) & !FILE_CREATE_PIPE_INSTANCE;

#[derive(Clone)]
pub struct Identity {
    sid: String,
}

pub struct Descriptor(PSECURITY_DESCRIPTOR);

pub(crate) fn file_owner(file: &File) -> Result<Identity> {
    let mut owner = null_mut();
    let mut document = null_mut();
    if unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut document,
        )
    } != 0
    {
        return Err(Error("setup_owner_unavailable"));
    }
    let _document = Security(document);
    Identity::from_sid(&sid_text(owner)?)
}

pub fn elevated() -> Result<bool> {
    use windows_sys::Win32::Security::{TOKEN_ELEVATION, TokenElevation};
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(Error("setup_token_unavailable"));
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut elevation = TOKEN_ELEVATION::default();
    let mut length = 0;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut length,
        )
    } == 0
    {
        return Err(Error("setup_token_unavailable"));
    }
    Ok(elevation.TokenIsElevated != 0)
}

impl Identity {
    pub fn from_sid(value: &str) -> Result<Self> {
        if value.len() > 184
            || !value.starts_with("S-")
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && byte != b'S' && byte != b'-')
        {
            return Err(Error("invalid_principal_sid"));
        }
        let wide = value.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let mut sid = null_mut();
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 || sid.is_null() {
            return Err(Error("invalid_principal_sid"));
        }
        let parsed = sid_text(sid);
        unsafe {
            LocalFree(sid);
        }
        if parsed.as_deref() != Ok(value) {
            return Err(Error("invalid_principal_sid"));
        }
        Ok(Self { sid: value.into() })
    }

    pub fn administrators() -> Result<Self> {
        Self::from_sid("S-1-5-32-544")
    }

    pub fn current() -> Result<Self> {
        Ok(Self {
            sid: process_sid(unsafe { GetCurrentProcess() })?,
        })
    }

    pub fn sid(&self) -> &str {
        &self.sid
    }

    pub fn descriptor(&self) -> Result<Descriptor> {
        descriptor(&self.sddl())
    }

    /// Only privileged pipe servers may create another instance. Ordinary
    /// clients receive data I/O rights, never FILE_CREATE_PIPE_INSTANCE.
    pub fn pipe_descriptor(&self) -> Result<Descriptor> {
        // An unprivileged embedded server needs its own create-instance right.
        // Service servers run as SYSTEM, so their ordinary user never gets it.
        if Self::current()?.sid == self.sid {
            return self.file_descriptor();
        }
        if self.sid == "S-1-5-32-544" {
            return descriptor("O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)");
        }
        let creator = if Self::current()?.sid() == "S-1-5-18" {
            "SY"
        } else {
            "BA"
        };
        descriptor(&format!(
            "O:{creator}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x{PIPE_CLIENT_ACCESS:x};;;{})",
            self.sid
        ))
    }

    pub fn software_for(&self, reader: &Self) -> Result<Descriptor> {
        if self.sid == reader.sid {
            return self.file_descriptor();
        }
        descriptor(&format!(
            "O:{}D:P(A;;GA;;;SY)(A;;GA;;;{})(A;;GRGX;;;{})",
            self.sid, self.sid, reader.sid
        ))
    }

    pub(crate) fn service_descriptor(&self) -> Result<Descriptor> {
        descriptor(&format!(
            "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x20015;;;{})",
            self.sid
        ))
    }

    /// Elevated installation tokens can default to an Administrators owner.
    /// Managed files retain the actual user's identity and a protected DACL.
    pub fn file_descriptor(&self) -> Result<Descriptor> {
        descriptor(&format!("O:{}{}", self.sid, self.sddl()))
    }

    pub fn sddl(&self) -> String {
        if self.sid == "S-1-5-18" {
            "D:P(A;;GA;;;SY)".to_owned()
        } else {
            format!("D:P(A;;GA;;;SY)(A;;GA;;;{})", self.sid)
        }
    }

    pub(crate) fn permits(&self, process_id: u32, allow_system: bool) -> Result<bool> {
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        if process.is_null() {
            return Err(Error("private_peer_check_failed"));
        }
        let process = unsafe { OwnedHandle::from_raw_handle(process) };
        let peer = process_sid(process.as_raw_handle())?;
        if self.sid == "S-1-5-32-544" {
            if peer == "S-1-5-18" {
                return Ok(true);
            }
            return enabled_administrator(process.as_raw_handle());
        }
        Ok(peer == self.sid || allow_system && peer == "S-1-5-18")
    }
}

fn enabled_administrator(process: HANDLE) -> Result<bool> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(Error("private_identity_unavailable"));
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut length = 0;
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenGroups,
            null_mut(),
            0,
            &mut length,
        );
    }
    if length < size_of::<TOKEN_GROUPS>() as u32 || length > 65536 {
        return Err(Error("private_identity_unavailable"));
    }
    let mut bytes = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenGroups,
            bytes.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(Error("private_identity_unavailable"));
    }
    let groups = unsafe { &*bytes.as_ptr().cast::<TOKEN_GROUPS>() };
    let count = groups.GroupCount as usize;
    if count > 4096
        || std::mem::offset_of!(TOKEN_GROUPS, Groups)
            + count * std::mem::size_of_val(&groups.Groups[0])
            > length as usize
    {
        return Err(Error("private_identity_unavailable"));
    }
    for group in unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), count) } {
        if group.Attributes & SE_GROUP_ENABLED as u32 != 0
            && group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY as u32 == 0
            && sid_text(group.Sid)? == "S-1-5-32-544"
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn require_system_process(process: HANDLE) -> Result<()> {
    if process_sid(process)? != "S-1-5-18" {
        return Err(Error("broker_system_process_required"));
    }
    Ok(())
}

/// Authenticate the kernel token of the last message read from this connected
/// pipe. A PID or an owner field in a request is never caller authority.
pub(crate) fn authenticate_pipe(pipe: HANDLE, owner: &Identity) -> Result<()> {
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(Error("broker_client_authentication_failed"));
    }
    let result = (|| {
        let mut token = null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
            return Err(Error("broker_client_authentication_failed"));
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        if token_sid(token.as_raw_handle())? != owner.sid {
            return Err(Error("broker_client_not_authorized"));
        }
        Ok(())
    })();
    if unsafe { RevertToSelf() } == 0 {
        // Continuing as a client would invalidate every subsequent privileged
        // operation on this thread. End the service instead of silently trying.
        std::process::abort();
    }
    result
}

fn descriptor(sddl: &str) -> Result<Descriptor> {
    let wide = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
        || descriptor.is_null()
    {
        return Err(Error("private_security_descriptor_failed"));
    }
    Ok(Descriptor(descriptor))
}

impl Descriptor {
    pub fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn process_sid(process: HANDLE) -> Result<String> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(Error("private_identity_unavailable"));
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    token_sid(token.as_raw_handle())
}

fn token_sid(token: HANDLE) -> Result<String> {
    let mut length = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut length);
    }
    if length < std::mem::size_of::<TOKEN_USER>() as u32 || length > 16384 {
        return Err(Error("private_identity_unavailable"));
    }
    // TOKEN_USER includes a pointer. usize backing preserves the ABI alignment.
    let mut data = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            data.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(Error("private_identity_unavailable"));
    }
    let user = unsafe { &*data.as_ptr().cast::<TOKEN_USER>() };
    if unsafe { IsValidSid(user.User.Sid) } == 0 {
        return Err(Error("private_identity_unavailable"));
    }
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 || text.is_null() {
        return Err(Error("private_identity_unavailable"));
    }
    // ConvertSidToStringSid allocates the complete, NUL-terminated canonical SID.
    let length = (0..256).find(|index| unsafe { *text.add(*index) == 0 });
    let result = length
        .and_then(|length| {
            String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).ok()
        })
        .ok_or(Error("private_identity_unavailable"));
    unsafe {
        LocalFree(text.cast());
    }
    result
}

pub(crate) struct Security(pub(crate) PSECURITY_DESCRIPTOR);
impl Drop for Security {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum FilePolicy {
    Private,
    Immutable,
    ControlledDestination,
}

/// Runtime assets retain their existing policy. Only explicit document export
/// destinations trust the host Administrators group in addition to User/SYSTEM.
pub fn file_permissions(file: &File, owner_sid: &str, policy: FilePolicy) -> Result<()> {
    let mut owner = null_mut();
    let mut acl = null_mut();
    let mut descriptor = null_mut();
    if unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    } != 0
    {
        return Err(Error("runtime_file_permissions_unavailable"));
    }
    let descriptor = Security(descriptor);
    if descriptor.0.is_null()
        || unsafe { IsValidSecurityDescriptor(descriptor.0) } == 0
        || acl.is_null()
        || unsafe { IsValidAcl(acl) } == 0
        || !(if policy == FilePolicy::ControlledDestination {
            sid_text(owner)? == owner_sid
        } else {
            trusted_sid(&sid_text(owner)?, owner_sid)
        })
    {
        return Err(Error("private_runtime_file_required"));
    }
    for (sid, mask) in allowed_masks(acl)? {
        if trusted_sid(&sid, owner_sid)
            || policy == FilePolicy::ControlledDestination && sid == "S-1-5-32-544"
        {
            continue;
        }
        // Standard read/execute rights are sufficient for shared immutable
        // assets. Unknown rights and every mutation/ownership grant fail closed.
        let read_only = FILE_GENERIC_READ | GENERIC_READ | GENERIC_EXECUTE | FILE_EXECUTE;
        if mask != 0 && (policy == FilePolicy::Private || mask & !read_only != 0) {
            return Err(Error("private_runtime_file_required"));
        }
    }
    Ok(())
}

/// Validate the actual connected pipe object; ordinary clients do not query
/// another account's process token or rely on a PID alone for authentication.
pub(crate) fn pipe_permissions(pipe: HANDLE, expected: &Identity) -> Result<()> {
    use windows_sys::Win32::Security::Authorization::SE_KERNEL_OBJECT;
    let mut owner = null_mut();
    let mut acl = null_mut();
    let mut raw = null_mut();
    if unsafe {
        GetSecurityInfo(
            pipe,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut raw,
        )
    } != 0
    {
        return Err(Error("private_pipe_security_unavailable"));
    }
    let descriptor = Security(raw);
    if descriptor.0.is_null()
        || unsafe { IsValidSecurityDescriptor(descriptor.0) } == 0
        || acl.is_null()
        || unsafe { IsValidAcl(acl) } == 0
    {
        return Err(Error("untrusted_runtime_peer"));
    }
    let owner = sid_text(owner)?;
    let same_user = owner == expected.sid && expected.sid != "S-1-5-32-544";
    if !same_user && !matches!(owner.as_str(), "S-1-5-18" | "S-1-5-32-544") {
        return Err(Error("untrusted_runtime_peer"));
    }
    for (sid, mask) in allowed_masks(acl)? {
        if matches!(sid.as_str(), "S-1-5-18" | "S-1-5-32-544") || same_user && sid == expected.sid {
            continue;
        }
        if mask != 0 && (sid != expected.sid || mask & !PIPE_CLIENT_ACCESS != 0) {
            return Err(Error("untrusted_runtime_peer"));
        }
    }
    Ok(())
}

/// Publish only the broker process's query/liveness capability to its owner.
/// The normal CLI obtains neither VM-memory access nor process mutation rights.
pub(crate) fn expose_broker_process(owner: &Identity) -> Result<()> {
    require_system_process(unsafe { GetCurrentProcess() })?;
    expose_process(owner)
}

pub(crate) fn expose_setup_process(owner: &Identity) -> Result<()> {
    if !elevated()? {
        return Err(Error("windows_administrator_required"));
    }
    expose_process(owner)
}

fn expose_process(owner: &Identity) -> Result<()> {
    use windows_sys::Win32::Security::Authorization::{SE_KERNEL_OBJECT, SetSecurityInfo};
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let descriptor = descriptor(&format!(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x101000;;;{})",
        owner.sid
    ))?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(descriptor.as_ptr(), &mut present, &mut acl, &mut defaulted)
    } == 0
        || present == 0
        || acl.is_null()
    {
        return Err(Error("broker_process_permissions_failed"));
    }
    if unsafe {
        SetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl,
            null_mut(),
        )
    } != 0
    {
        return Err(Error("broker_process_permissions_failed"));
    }
    Ok(())
}

/// A per-user broker service must never be owned by that ordinary user: an
/// owner could otherwise grant itself SERVICE_CHANGE_CONFIG through WRITE_DAC.
pub(crate) fn service_permissions(service: HANDLE, expected: &Identity) -> Result<()> {
    use windows_sys::Win32::Security::Authorization::SE_SERVICE;
    let mut owner = null_mut();
    let mut acl = null_mut();
    let mut raw = null_mut();
    if unsafe {
        GetSecurityInfo(
            service,
            SE_SERVICE,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut raw,
        )
    } != 0
    {
        return Err(Error("broker_service_permissions_unavailable"));
    }
    let security = Security(raw);
    if security.0.is_null()
        || unsafe { IsValidSecurityDescriptor(security.0) } == 0
        || acl.is_null()
        || unsafe { IsValidAcl(acl) } == 0
        || !matches!(sid_text(owner)?.as_str(), "S-1-5-18" | "S-1-5-32-544")
    {
        return Err(Error("broker_service_permissions_invalid"));
    }
    for (sid, mask) in allowed_masks(acl)? {
        if matches!(sid.as_str(), "S-1-5-18" | "S-1-5-32-544") {
            continue;
        }
        if mask != 0 && (sid != expected.sid || mask & !0x20015 != 0) {
            return Err(Error("broker_service_permissions_invalid"));
        }
    }
    Ok(())
}

fn allowed_masks(acl: *mut windows_sys::Win32::Security::ACL) -> Result<Vec<(String, u32)>> {
    let mut masks = Vec::new();
    let mut info = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            acl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(Error("runtime_file_permissions_unavailable"));
    }
    for index in 0..info.AceCount {
        let mut raw = null_mut();
        if unsafe { GetAce(acl, index, &mut raw) } == 0 || raw.is_null() {
            return Err(Error("runtime_file_permissions_unavailable"));
        }
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        if header.AceFlags as u32 & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        if header.AceType as u32 == ACCESS_DENIED_ACE_TYPE {
            continue;
        }
        let sid_start = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        let sid_header = std::mem::offset_of!(SID, SubAuthority);
        if header.AceType as u32 != ACCESS_ALLOWED_ACE_TYPE
            || (header.AceSize as usize) < sid_start + sid_header
        {
            return Err(Error("runtime_file_permissions_unsupported"));
        }
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        let sid: PSID = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
        let sid_size = sid_header
            + unsafe { (*sid.cast::<SID>()).SubAuthorityCount } as usize * size_of::<u32>();
        if sid_size > header.AceSize as usize - sid_start
            || unsafe { IsValidSid(sid) } == 0
            || unsafe { GetLengthSid(sid) } as usize != sid_size
        {
            return Err(Error("runtime_file_owner_invalid"));
        }
        masks.push((sid_text(sid)?, ace.Mask));
    }
    Ok(masks)
}

fn trusted_sid(sid: &str, owner_sid: &str) -> bool {
    sid == owner_sid || sid == "S-1-5-18"
}

fn sid_text(sid: PSID) -> Result<String> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(Error("runtime_file_owner_invalid"));
    }
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return Err(Error("runtime_file_owner_invalid"));
    }
    let length = (0..256).find(|index| unsafe { *text.add(*index) == 0 });
    let value = length.and_then(|length| {
        String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).ok()
    });
    unsafe {
        LocalFree(text.cast());
    }
    value.ok_or(Error("runtime_file_owner_invalid"))
}

#[cfg(test)]
mod tests {
    use super::{Identity, PIPE_CLIENT_ACCESS, allowed_masks, sid_text};
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{GENERIC_ALL, GENERIC_WRITE};
    use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, GetSecurityDescriptorOwner};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_CREATE_PIPE_INSTANCE, WRITE_DAC, WRITE_OWNER,
    };
    use windows_sys::Win32::System::Services::{
        SERVICE_CHANGE_CONFIG, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_START,
        SERVICE_STOP,
    };

    #[test]
    fn native_sid_conversion_round_trips_the_actual_token_without_accepting_sddl_or_aliases() {
        let current = Identity::current().unwrap();
        assert_eq!(
            Identity::from_sid(current.sid()).unwrap().sid(),
            current.sid()
        );
        assert_eq!(Identity::administrators().unwrap().sid(), "S-1-5-32-544");
        for invalid in [
            "BA",
            "",
            "S-1-5-21-1-2-3-1001)(A;;GA;;;WD)",
            "S-1-5-21-01",
            "s-1-5-18",
        ] {
            assert!(Identity::from_sid(invalid).is_err());
        }
    }

    #[test]
    fn native_descriptors_keep_service_ownership_admin_only_and_client_permissions_narrow() {
        let storage = Identity::administrators().unwrap();
        let client = Identity::from_sid("S-1-5-21-1-2-3-1001").unwrap();
        for (descriptor, service) in [
            (client.service_descriptor().unwrap(), true),
            (storage.software_for(&client).unwrap(), false),
        ] {
            let mut owner = null_mut();
            let mut defaulted = 0;
            assert_ne!(
                unsafe {
                    GetSecurityDescriptorOwner(descriptor.as_ptr(), &mut owner, &mut defaulted)
                },
                0
            );
            assert_eq!(sid_text(owner).unwrap(), "S-1-5-32-544");
            let mut present = 0;
            let mut acl = null_mut();
            assert_ne!(
                unsafe {
                    GetSecurityDescriptorDacl(
                        descriptor.as_ptr(),
                        &mut present,
                        &mut acl,
                        &mut defaulted,
                    )
                },
                0
            );
            assert_ne!(present, 0);
            let allowed = allowed_masks(acl).unwrap();
            let mask = allowed
                .iter()
                .find(|(sid, _)| sid == client.sid())
                .unwrap()
                .1;
            assert_eq!(
                mask & (GENERIC_ALL | GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER),
                0
            );
            if service {
                assert_eq!(mask & (SERVICE_CHANGE_CONFIG | SERVICE_STOP), 0);
                assert_eq!(
                    mask & (SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG),
                    SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG
                );
            }
        }
        let descriptor = client.pipe_descriptor().unwrap();
        let mut acl = null_mut();
        let mut present = 0;
        let mut defaulted = 0;
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(
                    descriptor.as_ptr(),
                    &mut present,
                    &mut acl,
                    &mut defaulted,
                )
            },
            0
        );
        let allowed = allowed_masks(acl).unwrap();
        let mask = allowed
            .iter()
            .find(|(sid, _)| sid == client.sid())
            .unwrap()
            .1;
        assert_eq!(mask, PIPE_CLIENT_ACCESS);
        assert_eq!(mask & FILE_CREATE_PIPE_INSTANCE, 0);
    }
}
