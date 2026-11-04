//! New-installation VHDX creation. The container is produced only by the SDK;
//! authorization to initialize its virtual blocks stays in a non-serializable
//! capability, never in runtime configuration or the VHDX container header.
#[cfg(any(windows, test))]
use crate::{Error, Result};

#[cfg(any(windows, test))]
const GIB: u64 = 1024 * 1024 * 1024;

#[cfg(any(windows, test))]
struct Specification {
    path: String,
    runtime_id: String,
    bytes: u64,
}

#[cfg(any(windows, test))]
impl Specification {
    fn new(path: &str, runtime_id: &str, bytes: u64) -> Result<Self> {
        if !crate::config::drive_file(path) || !path.to_ascii_lowercase().ends_with(".vhdx") {
            return Err(Error("invalid_runtime_disk_path"));
        }
        if !oblivion_wire::control::valid_id(runtime_id)
            || runtime_id.bytes().all(|byte| byte == b'0')
        {
            return Err(Error("invalid_runtime_disk_identity"));
        }
        if !(4 * GIB..=1024 * GIB).contains(&bytes) || bytes % (1024 * 1024) != 0 {
            return Err(Error("invalid_runtime_disk_capacity"));
        }
        Ok(Self {
            path: path.into(),
            runtime_id: runtime_id.into(),
            bytes,
        })
    }
}

#[cfg(windows)]
mod native {
    use super::Specification;
    use crate::files::{CreatedDiskLeaf, CreationParent};
    use crate::security::Identity;
    use crate::{Error, Result};
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, GetLastError};
    use windows_sys::Win32::Storage::FileSystem::{GetFileAttributesW, INVALID_FILE_ATTRIBUTES};
    use windows_sys::Win32::Storage::Vhd::{
        CREATE_VIRTUAL_DISK_FLAG_NONE, CREATE_VIRTUAL_DISK_PARAMETERS,
        CREATE_VIRTUAL_DISK_PARAMETERS_0, CREATE_VIRTUAL_DISK_PARAMETERS_0_1,
        CREATE_VIRTUAL_DISK_VERSION_2, CreateVirtualDisk, VIRTUAL_DISK_ACCESS_NONE,
        VIRTUAL_STORAGE_TYPE, VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
        VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
    };
    use windows_sys::core::GUID;

    pub struct CreatedDisk {
        specification: Specification,
        parent: CreationParent,
        leaf: CreatedDiskLeaf,
    }

    /// This view cannot be constructed or deserialized by a caller. It is valid
    /// only while the freshly created object and its directory pins remain held.
    pub struct Evidence<'a> {
        disk: &'a CreatedDisk,
    }

    impl CreatedDisk {
        /// Obtain this before HCS loads the VHDX. An already loaded disk cannot
        /// acquire fresh initialization authority, even with the same UUID.
        pub fn evidence(&self) -> Result<Evidence<'_>> {
            self.parent.verify()?;
            self.leaf
                .verify(&self.specification.runtime_id, self.specification.bytes)?;
            Ok(Evidence { disk: self })
        }
    }

    impl Evidence<'_> {
        pub fn path(&self) -> &str {
            &self.disk.specification.path
        }
        pub fn runtime_id(&self) -> &str {
            &self.disk.specification.runtime_id
        }
        pub fn bytes(&self) -> u64 {
            self.disk.specification.bytes
        }
        pub fn file_identity(&self) -> (u64, [u8; 16]) {
            self.disk.leaf.identity()
        }
    }

    pub fn create(
        path: &str,
        runtime_id: &str,
        bytes: u64,
        identity: &Identity,
    ) -> Result<CreatedDisk> {
        let specification = Specification::new(path, runtime_id, bytes)?;
        let parent = CreationParent::open(&specification.path, identity)?;
        let path = specification
            .path
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        // No overwrite flag or deletion rollback is used. A pre-existing leaf
        // (including reparse points) is never adopted as a newly created disk.
        if unsafe { GetFileAttributesW(path.as_ptr()) } != INVALID_FILE_ATTRIBUTES {
            return Err(Error("runtime_disk_already_exists"));
        }
        if unsafe { GetLastError() } != ERROR_FILE_NOT_FOUND {
            return Err(Error("runtime_disk_destination_unavailable"));
        }
        parent.verify()?;
        let descriptor = identity.file_descriptor()?;
        let storage = VIRTUAL_STORAGE_TYPE {
            DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
            VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
        };
        let parameters = CREATE_VIRTUAL_DISK_PARAMETERS {
            Version: CREATE_VIRTUAL_DISK_VERSION_2,
            Anonymous: CREATE_VIRTUAL_DISK_PARAMETERS_0 {
                Version2: CREATE_VIRTUAL_DISK_PARAMETERS_0_1 {
                    UniqueId: GUID::from_u128(
                        u128::from_str_radix(&specification.runtime_id, 16)
                            .map_err(|_| Error("invalid_runtime_disk_identity"))?,
                    ),
                    MaximumSize: specification.bytes,
                    // Microsoft's WSL Linux VHDX creation uses a 1 MiB block.
                    // Sector sizes are explicit; no parent, source or host mount.
                    BlockSizeInBytes: 1024 * 1024,
                    SectorSizeInBytes: 512,
                    PhysicalSectorSizeInBytes: 4096,
                    ParentPath: null(),
                    SourcePath: null(),
                    ..Default::default()
                },
            },
        };
        let mut handle = null_mut();
        if unsafe {
            CreateVirtualDisk(
                &storage,
                path.as_ptr(),
                VIRTUAL_DISK_ACCESS_NONE,
                descriptor.as_ptr(),
                CREATE_VIRTUAL_DISK_FLAG_NONE,
                0,
                &parameters,
                null(),
                &mut handle,
            )
        } != 0
        {
            // On failure the SDK output handle is undefined. A partial file is
            // deliberately retained rather than deleting a path of unknown state.
            return Err(Error("runtime_disk_creation_failed"));
        }
        if handle.is_null() {
            return Err(Error("runtime_disk_creation_failed"));
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        parent.verify()?;
        let leaf = CreatedDiskLeaf::open(&specification.path, identity)?;
        // Retain the ordinary file pin before releasing the SDK creation handle.
        // Get-info reopening then verifies the actual native UUID and capacity.
        drop(handle);
        leaf.verify(&specification.runtime_id, specification.bytes)?;
        Ok(CreatedDisk {
            specification,
            parent,
            leaf,
        })
    }
}

#[cfg(windows)]
pub use native::{CreatedDisk, Evidence, create};

#[cfg(test)]
mod tests {
    use super::{GIB, Specification};

    #[test]
    fn only_new_runtime_vhdx_specifications_with_bounded_aligned_capacity_are_valid() {
        let id = "0123456789abcdef0123456789abcdef";
        let source = Specification::new(r"C:\Oblivion\data.vhdx", id, 8 * GIB).unwrap();
        assert_eq!(source.bytes, 8 * GIB);
        assert_eq!(source.runtime_id, id);
        assert_eq!(source.path, r"C:\Oblivion\data.vhdx");
        for bytes in [
            0,
            4 * GIB - 512,
            4 * GIB + 1,
            4 * GIB + 512,
            1024 * GIB + 512,
        ] {
            assert_eq!(
                Specification::new(r"C:\Oblivion\data.vhdx", id, bytes)
                    .err()
                    .unwrap()
                    .0,
                "invalid_runtime_disk_capacity"
            );
        }
        for invalid in [
            "0".repeat(32),
            "A".repeat(32),
            "x".repeat(32),
            "012345".into(),
        ] {
            assert_eq!(
                Specification::new(r"C:\Oblivion\data.vhdx", &invalid, 8 * GIB)
                    .err()
                    .unwrap()
                    .0,
                "invalid_runtime_disk_identity"
            );
        }
        for path in [
            r"relative.vhdx",
            r"C:\Oblivion\..\foreign.vhdx",
            r"C:\Oblivion\data.raw",
            r"C:\Oblivion\data.vhdx:stream",
            r"\\server\share\data.vhdx",
        ] {
            assert_eq!(
                Specification::new(path, id, 8 * GIB).err().unwrap().0,
                "invalid_runtime_disk_path"
            );
        }
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::{GIB, create};
    use crate::security::Identity;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::PathBuf;
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    use windows_sys::Win32::Storage::Vhd::{
        GET_VIRTUAL_DISK_INFO, GET_VIRTUAL_DISK_INFO_IDENTIFIER, GET_VIRTUAL_DISK_INFO_SIZE,
        GetVirtualDiskInformation, OPEN_VIRTUAL_DISK_FLAG_NO_PARENTS, OPEN_VIRTUAL_DISK_PARAMETERS,
        OPEN_VIRTUAL_DISK_PARAMETERS_0, OPEN_VIRTUAL_DISK_PARAMETERS_0_0,
        OPEN_VIRTUAL_DISK_VERSION_1, OpenVirtualDisk, VIRTUAL_DISK_ACCESS_GET_INFO,
        VIRTUAL_STORAGE_TYPE, VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
        VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
    };

    struct Area(PathBuf);
    impl Area {
        fn new(identity: &Identity) -> Self {
            let mut random = [0; 16];
            getrandom::getrandom(&mut random).unwrap();
            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
            let temp = temp
                .to_str()
                .unwrap()
                .strip_prefix(r"\\?\")
                .unwrap_or(temp.to_str().unwrap());
            let path = PathBuf::from(temp).join(format!("oblivion-vhdx-{suffix}"));
            let descriptor = identity.file_descriptor().unwrap();
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.as_ptr(),
                bInheritHandle: 0,
            };
            let name = wide(path.to_str().unwrap());
            assert_ne!(unsafe { CreateDirectoryW(name.as_ptr(), &attributes) }, 0);
            Self(path)
        }
        fn path(&self, leaf: &str) -> String {
            self.0.join(leaf).to_str().unwrap().to_owned()
        }
    }
    impl Drop for Area {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    #[test]
    fn actual_vhdx_creation_reopens_sdk_uuid_and_capacity_without_mounting() {
        let identity = Identity::current().unwrap();
        let area = Area::new(&identity);
        let path = area.path("data.vhdx");
        let runtime_id = "0123456789abcdef0123456789abcdef";
        let disk = create(&path, runtime_id, 4 * GIB, &identity).unwrap();
        let evidence = disk.evidence().unwrap();
        assert_eq!(evidence.path(), path);
        assert_eq!(evidence.runtime_id(), runtime_id);
        assert_eq!(evidence.bytes(), 4 * GIB);
        assert_ne!(evidence.file_identity().1, [0; 16]);
        let mut signature = [0; 8];
        File::open(&path)
            .unwrap()
            .read_exact(&mut signature)
            .unwrap();
        assert_eq!(&signature, b"vhdxfile");
        // Reopen using the OS provider, independently of container bytes.
        let storage = VIRTUAL_STORAGE_TYPE {
            DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
            VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
        };
        let parameters = OPEN_VIRTUAL_DISK_PARAMETERS {
            Version: OPEN_VIRTUAL_DISK_VERSION_1,
            Anonymous: OPEN_VIRTUAL_DISK_PARAMETERS_0 {
                Version1: OPEN_VIRTUAL_DISK_PARAMETERS_0_0 { RWDepth: 0 },
            },
        };
        let mut handle = null_mut();
        assert_eq!(
            unsafe {
                OpenVirtualDisk(
                    &storage,
                    wide(&path).as_ptr(),
                    VIRTUAL_DISK_ACCESS_GET_INFO,
                    OPEN_VIRTUAL_DISK_FLAG_NO_PARENTS,
                    &parameters,
                    &mut handle,
                )
            },
            0
        );
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        let mut identifier = GET_VIRTUAL_DISK_INFO {
            Version: GET_VIRTUAL_DISK_INFO_IDENTIFIER,
            ..Default::default()
        };
        let mut length = size_of::<GET_VIRTUAL_DISK_INFO>() as u32;
        assert_eq!(
            unsafe {
                GetVirtualDiskInformation(
                    handle.as_raw_handle(),
                    &mut length,
                    &mut identifier,
                    null_mut(),
                )
            },
            0
        );
        let identifier = unsafe { identifier.Anonymous.Identifier };
        assert_eq!(identifier.data1, 0x01234567);
        assert_eq!(identifier.data2, 0x89ab);
        assert_eq!(identifier.data3, 0xcdef);
        assert_eq!(
            identifier.data4,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        let mut size = GET_VIRTUAL_DISK_INFO {
            Version: GET_VIRTUAL_DISK_INFO_SIZE,
            ..Default::default()
        };
        length = size_of::<GET_VIRTUAL_DISK_INFO>() as u32;
        assert_eq!(
            unsafe {
                GetVirtualDiskInformation(
                    handle.as_raw_handle(),
                    &mut length,
                    &mut size,
                    null_mut(),
                )
            },
            0
        );
        assert_eq!(unsafe { size.Anonymous.Size.VirtualSize }, 4 * GIB);
        assert!(std::fs::rename(&path, area.path("replacement.vhdx")).is_err());
        assert!(std::fs::rename(&area.0, area.0.with_extension("moved")).is_err());
        assert_eq!(
            create(&path, runtime_id, 4 * GIB, &identity)
                .err()
                .unwrap()
                .0,
            "runtime_disk_already_exists"
        );
        disk.evidence().unwrap();
        drop(handle);
        drop(disk);
    }

    #[test]
    fn preexisting_file_is_never_replaced_or_turned_into_creation_authority() {
        let identity = Identity::current().unwrap();
        let area = Area::new(&identity);
        let path = area.path("foreign.vhdx");
        File::create(&path)
            .unwrap()
            .write_all(b"DO_NOT_REPLACE_CANARY")
            .unwrap();
        assert_eq!(
            create(
                &path,
                "aabbccddeeff00112233445566778899",
                4 * GIB,
                &identity
            )
            .err()
            .unwrap()
            .0,
            "runtime_disk_already_exists"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"DO_NOT_REPLACE_CANARY");
    }
}
