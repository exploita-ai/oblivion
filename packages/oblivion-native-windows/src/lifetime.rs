//! The supervisor keeps the write end of an inherited private stdin pipe.
//! EOF or any application data revokes this helper's authority over its VM.
use crate::{Error, Result};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};
use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};
use windows_sys::Win32::System::Pipes::PeekNamedPipe;

pub struct Lifetime(OwnedHandle);

impl Lifetime {
    pub fn inherited() -> Result<Self> {
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(Error("supervisor_lifetime_required"));
        }
        // Claim stdin before opening any other resources. It is never used for
        // terminal input, secrets or a guest console on this backend.
        Self::new(unsafe { OwnedHandle::from_raw_handle(handle) })
    }

    pub fn new(handle: OwnedHandle) -> Result<Self> {
        if unsafe { GetFileType(handle.as_raw_handle()) } != FILE_TYPE_PIPE
            || unsafe { SetHandleInformation(handle.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0
        {
            return Err(Error("supervisor_lifetime_required"));
        }
        let lifetime = Self(handle);
        lifetime.check()?;
        Ok(lifetime)
    }

    pub fn check(&self) -> Result<()> {
        let mut available = 0;
        if unsafe {
            PeekNamedPipe(
                self.0.as_raw_handle(),
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            )
        } == 0
            || available != 0
        {
            return Err(Error("supervisor_lifetime_lost"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, Lifetime};
    use std::io::Write;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::GetHandleInformation;
    use windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Pipes::CreatePipe;

    fn pair() -> (Lifetime, std::fs::File) {
        let mut reader = null_mut();
        let mut writer = null_mut();
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        assert_ne!(
            unsafe { CreatePipe(&mut reader, &mut writer, &attributes, 0) },
            0
        );
        (
            Lifetime::new(unsafe { OwnedHandle::from_raw_handle(reader) }).unwrap(),
            unsafe { std::fs::File::from_raw_handle(writer) },
        )
    }

    #[test]
    fn supervisor_eof_and_bytes_revoke_the_vm_lifetime() {
        let (lifetime, parent) = pair();
        assert!(lifetime.check().is_ok());
        let mut flags = 0;
        assert_ne!(
            unsafe { GetHandleInformation(lifetime.0.as_raw_handle(), &mut flags) },
            0
        );
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        drop(parent);
        assert_eq!(lifetime.check(), Err(Error("supervisor_lifetime_lost")));

        let (lifetime, mut parent) = pair();
        parent.write_all(b"x").unwrap();
        assert_eq!(lifetime.check(), Err(Error("supervisor_lifetime_lost")));
    }

    #[test]
    fn a_regular_file_cannot_be_the_supervisor() {
        let file = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
        assert!(matches!(
            Lifetime::new(file.into()),
            Err(Error("supervisor_lifetime_required"))
        ));
    }
}
