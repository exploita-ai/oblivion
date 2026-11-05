//! Private kernel objects are granted only to the actual process user and
//! LocalSystem. Configuration never supplies either an SID or an ACL.
use crate::{Error, Result};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, IsValidSid, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use std::fs::File;
use windows_sys::Win32::Foundation::{GENERIC_EXECUTE, GENERIC_READ};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetLengthSid, INHERIT_ONLY_ACE,
    IsValidAcl, IsValidSecurityDescriptor, OWNER_SECURITY_INFORMATION, PSID, SID,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_EXECUTE, FILE_GENERIC_READ};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};

pub struct Identity {
    sid: String,
}

pub struct Descriptor(PSECURITY_DESCRIPTOR);

impl Identity {
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
        Ok(peer == self.sid || allow_system && peer == "S-1-5-18")
    }
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
    let mut length = 0;
    unsafe {
        GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut length);
    }
    if length < std::mem::size_of::<TOKEN_USER>() as u32 || length > 16384 {
        return Err(Error("private_identity_unavailable"));
    }
    // TOKEN_USER includes a pointer. usize backing preserves the ABI alignment.
    let mut data = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
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
        let sid = sid_text(sid)?;
        if trusted_sid(&sid, owner_sid)
            || policy == FilePolicy::ControlledDestination && sid == "S-1-5-32-544"
        {
            continue;
        }
        // Standard read/execute rights are sufficient for shared immutable
        // assets. Unknown rights and every mutation/ownership grant fail closed.
        let read_only = FILE_GENERIC_READ | GENERIC_READ | GENERIC_EXECUTE | FILE_EXECUTE;
        if ace.Mask != 0 && (policy == FilePolicy::Private || ace.Mask & !read_only != 0) {
            return Err(Error("private_runtime_file_required"));
        }
    }
    Ok(())
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
