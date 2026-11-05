//! These fixtures require an elevated Windows test process. The restricted
//! thread token models the ordinary user's access to protected software.
use crate::bundle::{VerifiedBundle, tests::Fixture};
use crate::files::Directory;
use crate::security::{self, Identity};
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, ImpersonateLoggedOnUser, RevertToSelf,
    SECURITY_ATTRIBUTES, SID_AND_ATTRIBUTES, TOKEN_DUPLICATE, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, DELETE, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

struct Area(PathBuf);

impl Area {
    fn private(storage: &Identity) -> Self {
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).unwrap();
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let temp = temp.to_str().unwrap();
        let area = Self(
            PathBuf::from(temp.strip_prefix(r"\\?\").unwrap_or(temp))
                .join(format!("oblivion-published-source-{suffix}")),
        );
        let descriptor = storage.file_descriptor().unwrap();
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_ptr(),
            bInheritHandle: 0,
        };
        assert_ne!(
            unsafe { CreateDirectoryW(wide(area.text()).as_ptr(), &attributes) },
            0
        );
        area
    }

    fn text(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for Area {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Restricted(OwnedHandle);

impl Restricted {
    fn enter() -> Self {
        let mut token = null_mut();
        assert_ne!(
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_DUPLICATE | TOKEN_QUERY,
                    &mut token,
                )
            },
            0
        );
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut administrator = null_mut();
        assert_ne!(
            unsafe { ConvertStringSidToSidW(wide("S-1-5-32-544").as_ptr(), &mut administrator) },
            0
        );
        let disabled = SID_AND_ATTRIBUTES {
            Sid: administrator,
            Attributes: 0,
        };
        let mut restricted = null_mut();
        // DISABLE_MAX_PRIVILEGE deliberately preserves SeChangeNotifyPrivilege
        // (directory traversal). BA must also be deny-only to remove its ACL
        // grants; deleting privileges alone would not model an ordinary user.
        let created = unsafe {
            CreateRestrictedToken(
                token.as_raw_handle(),
                DISABLE_MAX_PRIVILEGE,
                1,
                &disabled,
                0,
                null(),
                0,
                null(),
                &mut restricted,
            )
        };
        unsafe {
            LocalFree(administrator);
        }
        assert_ne!(created, 0);
        let restricted = Self(unsafe { OwnedHandle::from_raw_handle(restricted) });
        assert_ne!(
            unsafe { ImpersonateLoggedOnUser(restricted.0.as_raw_handle()) },
            0
        );
        restricted
    }
}

impl Drop for Restricted {
    fn drop(&mut self) {
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[test]
fn ordinary_user_can_verify_published_software_without_reading_private_catalog_or_data() {
    assert!(
        security::elevated().unwrap(),
        "this fixture requires elevated Windows"
    );
    let caller = Identity::current().unwrap();
    let storage = Identity::administrators().unwrap();
    let fixture = Fixture::version("restricted-published-source");
    let area = Area::private(&storage);
    let catalog = Directory::open(area.text(), &storage, true).unwrap();
    let mut record = catalog.create_file("installation.json", &storage).unwrap();
    record
        .writer()
        .write_all(b"private catalog fixture")
        .unwrap();
    record.finish().unwrap();
    let data = catalog.create_child("data", &storage).unwrap();
    let mut volume = data.create_file("data.vhdx", &storage).unwrap();
    volume.writer().write_all(b"private data fixture").unwrap();
    volume.finish().unwrap();
    let releases = catalog.create_child("releases", &storage).unwrap();
    let destination = format!(r"{}\release", releases.path());
    let published = fixture
        .open()
        .unwrap()
        .publish(&destination, &storage, &caller)
        .unwrap();
    let launcher = published.cli().to_owned();
    let source = published.source().to_owned();
    let bundle_id = published.id().to_owned();
    drop((published, releases, volume, data, record, catalog));

    let restricted = Restricted::enter();
    assert_eq!(
        File::open(area.0.join("installation.json"))
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        File::open(area.0.join("data").join("data.vhdx"))
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        OpenOptions::new()
            .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS)
            .open(&area.0)
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    assert!(Directory::open(area.text(), &storage, true).is_err());
    let verified = VerifiedBundle::launcher(&launcher, &source, &caller).unwrap();
    assert_eq!(verified.id(), bundle_id);
    assert!(VerifiedBundle::launcher(&launcher, &"0".repeat(64), &caller).is_err());
    assert!(OpenOptions::new().write(true).open(verified.cli()).is_err());
    drop(restricted);

    // Only the new, ordinary-user admission remains alive. Its metadata-only
    // ancestor handles must still deny deletion/rename even to an administrator.
    assert!(
        OpenOptions::new()
            .access_mode(DELETE | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS)
            .open(&area.0)
            .is_err()
    );
    drop(verified);
    assert!(
        OpenOptions::new()
            .access_mode(DELETE | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS)
            .open(&area.0)
            .is_ok()
    );
}
