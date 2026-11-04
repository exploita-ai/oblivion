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
        let wide = self
            .sddl()
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
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
