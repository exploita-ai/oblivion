//! Pinned Windows assets for one owned HCS VM. The new 1.0 installation contract
//! sets the VHDX Identifier to UUID(runtime_id), matching the guest marker/UUID.
//! This module never creates, repairs, mounts or adopts an unrelated disk.
use crate::config::{CONFIG_LIMIT, RuntimeConfig};
use crate::resources::FileEvidence;
use crate::security::Identity;
use crate::{Error, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::sync::Arc;
use windows_sys::Wdk::Storage::FileSystem::NtFlushBuffersFileEx;
use windows_sys::Win32::Foundation::GENERIC_WRITE;
use windows_sys::Win32::Foundation::{
    ERROR_SHARING_VIOLATION, GENERIC_READ, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE,
    FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_READ_ATTRIBUTES,
    FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK,
    FileDispositionInfo, FileIdInfo, FileRenameInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetFileType, GetFinalPathNameByHandleW, OPEN_EXISTING,
    READ_CONTROL, SetFileInformationByHandle, WRITE_DAC,
};
use windows_sys::Win32::Storage::Vhd::{
    GET_VIRTUAL_DISK_INFO, GET_VIRTUAL_DISK_INFO_IDENTIFIER, GET_VIRTUAL_DISK_INFO_IS_LOADED,
    GET_VIRTUAL_DISK_INFO_PROVIDER_SUBTYPE, GET_VIRTUAL_DISK_INFO_SIZE, GetVirtualDiskInformation,
    OPEN_VIRTUAL_DISK_FLAG_NO_PARENTS, OPEN_VIRTUAL_DISK_PARAMETERS,
    OPEN_VIRTUAL_DISK_PARAMETERS_0, OPEN_VIRTUAL_DISK_PARAMETERS_0_0, OPEN_VIRTUAL_DISK_VERSION_1,
    OpenVirtualDisk, VIRTUAL_DISK_ACCESS_GET_INFO, VIRTUAL_STORAGE_TYPE,
    VIRTUAL_STORAGE_TYPE_DEVICE_VHDX, VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
};
use windows_sys::Win32::System::HostComputeSystem::{HcsGrantVmAccess, HcsRevokeVmAccess};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

const GIB: u64 = 1024 * 1024 * 1024;
const MAX_DISK: u64 = 1024 * GIB;

pub fn read_config(path: &str, identity: &Identity) -> Result<RuntimeConfig> {
    let pinned = Pinned::open(path, Role::Configuration, identity)?;
    if pinned.size == 0 || pinned.size > CONFIG_LIMIT as u64 {
        return Err(Error("invalid_runtime_configuration"));
    }
    let mut bytes = Vec::new();
    pinned
        .file
        .take((CONFIG_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("runtime_configuration_unavailable"))?;
    RuntimeConfig::decode(&bytes)
}

pub struct Lease {
    files: Vec<Pinned>,
    vm_id: String,
    granted: Vec<usize>,
    owner: String,
    data_bytes: u64,
}

impl Lease {
    pub fn acquire(config: &RuntimeConfig, identity: &Identity) -> Result<Self> {
        config.validate()?;
        let mut files = Vec::new();
        for (path, role) in [
            (&config.kernel, Role::Asset),
            (&config.initrd, Role::Asset),
            (&config.disks[0].path, Role::Asset),
            (&config.disks[1].path, Role::Data),
        ] {
            let pinned = Pinned::open(path, role, identity)?;
            if pinned.size == 0 || files.iter().any(|other: &Pinned| other.id == pinned.id) {
                return Err(Error("runtime_asset_identity_invalid"));
            }
            files.push(pinned);
        }
        let data_bytes = validate_runtime_files(&files, config)?;
        Ok(Self {
            files,
            vm_id: config.vm_id(),
            granted: Vec::new(),
            owner: identity.sid().to_owned(),
            data_bytes,
        })
    }

    /// The private recovery receipt stores these original admission identities
    /// before any grant. Asset lengths are immutable; VHDX capacity is stable
    /// while its physical file may grow as the guest writes.
    pub fn evidence(&self) -> Vec<FileEvidence> {
        self.files
            .iter()
            .map(|file| FileEvidence {
                volume: file.id.volume,
                file: file.id.file,
                bytes: if file.role == Role::Data {
                    self.data_bytes
                } else {
                    file.size
                },
            })
            .collect()
    }

    /// These APIs take paths, not handles. Leaf and ancestor handles keep those
    /// exact objects non-deletable throughout grant, HCS use and explicit revoke.
    /// https://learn.microsoft.com/virtualization/api/hcs/reference/hcsgrantvmaccess
    pub fn grant_vm_access(&mut self, vm_id: &str) -> Result<()> {
        if vm_id != self.vm_id || !self.granted.is_empty() {
            return Err(Error("runtime_vm_access_identity_invalid"));
        }
        let id = wide(&self.vm_id);
        let result = (|| {
            for index in 0..self.files.len() {
                self.files[index].verify()?;
                // Include a failed grant in rollback: failure must not be
                // interpreted as proof that the file ACL was unchanged.
                self.granted.push(index);
                if unsafe { HcsGrantVmAccess(id.as_ptr(), wide(&self.files[index].path).as_ptr()) }
                    < 0
                {
                    return Err(Error("runtime_vm_access_grant_failed"));
                }
                self.files[index].verify()?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.revoke_vm_access()?;
        }
        result
    }

    /// Call only after confirmed HCS stop, before releasing this lease. A failed
    /// revoke remains tracked and must not become a successful cleanup report.
    /// https://learn.microsoft.com/virtualization/api/hcs/reference/hcsrevokevmaccess
    pub fn revoke_vm_access(&mut self) -> Result<()> {
        let id = wide(&self.vm_id);
        let mut pending = Vec::new();
        for index in self.granted.iter().copied() {
            let result = self.files[index].verify().and_then(|()| {
                if unsafe { HcsRevokeVmAccess(id.as_ptr(), wide(&self.files[index].path).as_ptr()) }
                    < 0
                {
                    return Err(Error("runtime_vm_access_revoke_failed"));
                }
                permissions(
                    &self.files[index].file,
                    &self.owner,
                    self.files[index].role != Role::Asset,
                )
            });
            if result.is_err() {
                pending.push(index);
            }
        }
        self.granted = pending;
        if !self.granted.is_empty() {
            return Err(Error("runtime_vm_access_revoke_failed"));
        }
        Ok(())
    }

    /// The one-shot backend could not confirm VM stop. Do not revoke a live
    /// VM's access or release its pinned paths while cleanup is uncertain. The
    /// process exit closes handles; the caller must report the failed shutdown.
    pub fn retain_until_exit(self) {
        std::mem::forget(self);
    }
}

/// Only the caller's observed HCS Stopped/absent boundary authorizes this
/// operation. A protected receipt binds these exact original file objects; no
/// path, role or replacement file is adopted from a client request.
pub fn reconcile(
    config: &RuntimeConfig,
    identity: &Identity,
    expected: &[FileEvidence],
) -> Result<()> {
    config.validate()?;
    if expected.len() != 4 {
        return Err(Error("invalid_runtime_file_evidence"));
    }
    let mut files = Vec::new();
    for ((path, role), evidence) in [
        (&config.kernel, Role::Asset),
        (&config.initrd, Role::Asset),
        (&config.disks[0].path, Role::Asset),
        (&config.disks[1].path, Role::Data),
    ]
    .into_iter()
    .zip(expected)
    {
        let pinned = Pinned::pin(path, role)?;
        if pinned.id
            != (FileId {
                volume: evidence.volume,
                file: evidence.file,
            })
            || pinned.size == 0
            || role == Role::Asset && pinned.size != evidence.bytes
            || files.iter().any(|other: &Pinned| other.id == pinned.id)
        {
            return Err(Error("runtime_file_evidence_changed"));
        }
        // ACL admission is intentionally deferred only after the protected
        // receipt matched this original object. The VM's own grant can be the
        // reason strict pre-grant policy currently fails.
        files.push(pinned);
    }
    let data_bytes = validate_runtime_files(&files, config)?;
    if data_bytes != expected[3].bytes {
        return Err(Error("runtime_file_evidence_changed"));
    }
    for file in &files {
        file.verify()?;
    }
    Lease {
        files,
        vm_id: config.vm_id(),
        granted: (0..4).collect(),
        owner: identity.sid().into(),
        data_bytes,
    }
    .revoke_vm_access()
}

fn validate_runtime_files(files: &[Pinned], config: &RuntimeConfig) -> Result<u64> {
    let mut signature = [0; 8];
    read_at(&files[2], 32768, &mut signature)?;
    if files[2].size < 34816
        || files[2].size % 2048 != 0
        || signature[1..6] != *b"CD001"
        || signature[6] != 1
    {
        return Err(Error("runtime_iso_required"));
    }
    read_at(&files[3], 0, &mut signature)?;
    if signature != *b"vhdxfile" || files[3].size < 1024 * 1024 {
        return Err(Error("runtime_vhdx_required"));
    }
    virtual_disk(&files[3], &config.runtime_id)
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileId {
    volume: u64,
    file: [u8; 16],
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Role {
    Configuration,
    Asset,
    Data,
}

struct Pinned {
    path: String,
    file: File,
    id: FileId,
    size: u64,
    role: Role,
    parents: Vec<(String, File, FileId)>,
}

/// The path-taking SDK must keep the reviewed directory objects in place.
/// This guard grants no authority to an existing leaf and never creates one.
pub(crate) struct CreationParent {
    path: String,
    parents: Vec<(String, File, FileId)>,
}

impl CreationParent {
    pub(crate) fn open(path: &str, identity: &Identity) -> Result<Self> {
        let parent = Self::ancestors(path)?;
        permissions(
            &parent
                .parents
                .last()
                .ok_or(Error("runtime_parent_required"))?
                .1,
            identity.sid(),
            true,
        )?;
        Ok(parent)
    }

    /// Only for creating a NEW protected app directory. This does not claim
    /// the existing parent is private; callers must seal and verify the child.
    pub(crate) fn ancestors(path: &str) -> Result<Self> {
        Ok(Self {
            path: path.to_owned(),
            parents: pin_parents(path)?,
        })
    }

    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn verify(&self) -> Result<()> {
        verify_parents(&self.parents)
    }

    pub(crate) fn sync(&self, identity: &Identity) -> Result<()> {
        self.verify()?;
        let parent = self
            .parents
            .last()
            .ok_or(Error("invalid_runtime_asset_path"))?;
        Directory::open(&parent.0, identity, true)?.sync()?;
        self.verify()
    }
}

pub(crate) struct Executable(Pinned);

impl Executable {
    pub(crate) fn open(path: &str, identity: &Identity) -> Result<Self> {
        if !path.to_ascii_lowercase().ends_with(".exe") {
            return Err(Error("runtime_executable_required"));
        }
        Ok(Self(Pinned::open(path, Role::Asset, identity)?))
    }
    pub(crate) fn path(&self) -> &str {
        &self.0.path
    }
    pub(crate) fn verify(&self) -> Result<()> {
        self.0.verify()
    }
}

pub(crate) struct CreatedDiskLeaf(Pinned);

impl CreatedDiskLeaf {
    pub(crate) fn open(path: &str, identity: &Identity) -> Result<Self> {
        Ok(Self(Pinned::open(path, Role::Data, identity)?))
    }

    pub(crate) fn verify(&self, runtime_id: &str, bytes: u64) -> Result<()> {
        if virtual_disk(&self.0, runtime_id)? != bytes {
            return Err(Error("runtime_disk_capacity_mismatch"));
        }
        Ok(())
    }

    pub(crate) fn identity(&self) -> (u64, [u8; 16]) {
        (self.0.id.volume, self.0.id.file)
    }

    pub(crate) fn sync(&self, identity: &Identity) -> Result<()> {
        self.0.verify()?;
        let file = open_raw(&self.0.path, GENERIC_WRITE | READ_CONTROL, true, false)?;
        if inspect(&file, &self.0.path, false)?.0 != self.0.id {
            return Err(Error("runtime_asset_changed"));
        }
        permissions(&file, identity.sid(), true)?;
        file.sync_all()
            .map_err(|_| Error("runtime_disk_sync_failed"))?;
        self.0.verify()
    }

    pub(crate) fn publish(self, destination: &str, identity: &Identity) -> Result<Self> {
        self.0.verify()?;
        let parent = CreationParent::open(destination, identity)?;
        let expected = self.0.id;
        let Pinned {
            path,
            file,
            parents,
            ..
        } = self.0;
        let mutation = Mutation::open(file, &path, expected, false, true, identity)?;
        mutation.rename(destination, false)?;
        drop(mutation);
        let published = Self::open(destination, identity)?;
        if published.0.id != expected {
            return Err(Error("runtime_asset_changed"));
        }
        parent.verify()?;
        verify_parents(&parents)?;
        Ok(published)
    }
}

pub(crate) fn verify_private(file: &File, path: &str, identity: &Identity) -> Result<()> {
    inspect(file, path, false)?;
    permissions(file, identity.sid(), true)
}

/// Identity observation for an already admitted runtime disk. This conveys no
/// initialization, write, ACL or adoption authority (a running VM has its own ACE).
pub(crate) fn data_file_identity(path: &str) -> Result<(u64, [u8; 16])> {
    let parents = pin_parents(path)?;
    let file = open_raw(path, FILE_READ_ATTRIBUTES, true, false)?;
    let (id, _) = inspect(&file, path, false)?;
    verify_parents(&parents)?;
    Ok((id.volume, id.file))
}

/// A pinned tree shares ancestor handles rather than opening the entire parent
/// chain once for every bundle file. Leaf names are checked before path APIs.
#[derive(Clone)]
pub(crate) struct Directory(Arc<DirectoryPin>);

struct DirectoryPin {
    path: String,
    file: File,
    id: FileId,
    ancestors: Vec<(String, File, FileId)>,
    parent: Option<Directory>,
}

pub(crate) struct Asset {
    path: String,
    file: File,
    id: FileId,
    bytes: u64,
    parent: Directory,
}

impl Directory {
    /// Published software, unlike the private catalog, is readable by its user.
    /// Ancestors need only metadata handles to prevent deletion/renaming; their
    /// private ACLs are not software authority. Root and every leaf still pass
    /// the ordinary immutable owner/DACL and file-identity boundary below.
    pub(crate) fn open_published(path: &str, caller: &Identity) -> Result<(Self, Identity)> {
        let ancestors = pin_parents_access(path, 0)?;
        let file = open_raw(path, READ_CONTROL | FILE_READ_ATTRIBUTES, true, true)?;
        let (id, _) = inspect(&file, path, true)?;
        let owner = crate::security::file_owner(&file)?;
        let expected = if matches!(owner.sid(), "S-1-5-18" | "S-1-5-32-544") {
            Identity::administrators()?
        } else if owner.sid() == caller.sid() {
            caller.clone()
        } else {
            return Err(Error("untrusted_published_software_owner"));
        };
        permissions(&file, expected.sid(), false)?;
        Ok((
            Self(Arc::new(DirectoryPin {
                path: path.into(),
                file,
                id,
                ancestors,
                parent: None,
            })),
            expected,
        ))
    }

    /// Setup may create a fresh private software staging tree under the
    /// standard shared ProgramData parent. No existing leaf is adopted.
    pub(crate) fn create_setup(path: &str, identity: &Identity) -> Result<Self> {
        let parent = CreationParent::ancestors(path)?;
        parent.verify()?;
        create_directory(path, identity)?;
        let directory = Self::open(path, identity, true)?;
        parent.verify()?;
        Ok(directory)
    }

    /// This identity is only a candidate restriction until the setup pipe's
    /// actual caller token matches it. It never authorizes a target user alone.
    pub(crate) fn setup_owner(path: &str) -> Result<(Self, Identity)> {
        let ancestors = pin_parents(path)?;
        let file = open_raw(path, READ_CONTROL | FILE_READ_ATTRIBUTES, true, true)?;
        let (id, _) = inspect(&file, path, true)?;
        let owner = crate::security::file_owner(&file)?;
        if matches!(owner.sid(), "S-1-5-18" | "S-1-5-32-544") {
            return Err(Error("setup_user_owner_required"));
        }
        permissions(&file, owner.sid(), false)?;
        Ok((
            Self(Arc::new(DirectoryPin {
                path: path.into(),
                file,
                id,
                ancestors,
                parent: None,
            })),
            owner,
        ))
    }

    pub(crate) fn open(path: &str, identity: &Identity, private: bool) -> Result<Self> {
        let ancestors = pin_parents(path)?;
        let file = open_raw(path, READ_CONTROL | FILE_READ_ATTRIBUTES, true, true)?;
        let (id, _) = inspect(&file, path, true)?;
        permissions(&file, identity.sid(), private)?;
        Ok(Self(Arc::new(DirectoryPin {
            path: path.into(),
            file,
            id,
            ancestors,
            parent: None,
        })))
    }

    pub(crate) fn create(path: &str, identity: &Identity) -> Result<Self> {
        let parent = CreationParent::open(path, identity)?;
        parent.verify()?;
        create_directory(path, identity)?;
        let directory = Self::open(path, identity, true)?;
        parent.verify()?;
        Ok(directory)
    }

    pub(crate) fn path(&self) -> &str {
        &self.0.path
    }

    pub(crate) fn verify(&self) -> Result<()> {
        if let Some(parent) = &self.0.parent {
            parent.verify()?;
        }
        verify_parents(&self.0.ancestors)?;
        if inspect(&self.0.file, &self.0.path, true)?.0 != self.0.id {
            return Err(Error("runtime_asset_changed"));
        }
        Ok(())
    }

    fn child_path(&self, name: &str) -> Result<String> {
        if name.contains(['/', '\\']) {
            return Err(Error("invalid_runtime_asset_path"));
        }
        let path = format!("{}\\{name}", self.0.path);
        if !crate::config::drive_file(&path) {
            return Err(Error("invalid_runtime_asset_path"));
        }
        Ok(path)
    }

    /// Only an empty, reviewed directory can be removed. An extra child causes
    /// the kernel operation to fail; no recursive deletion is performed.
    pub(crate) fn remove(self, identity: &Identity) -> Result<()> {
        self.verify()?;
        let pin = Arc::try_unwrap(self.0).map_err(|_| Error("runtime_software_in_use"))?;
        Mutation::open(pin.file, &pin.path, pin.id, true, false, identity)?.remove()
    }

    pub(crate) fn move_to(
        self,
        destination: &Directory,
        name: &str,
        identity: &Identity,
    ) -> Result<Self> {
        self.verify()?;
        destination.verify()?;
        let path = destination.child_path(name)?;
        let pin = Arc::try_unwrap(self.0).map_err(|_| Error("runtime_software_in_use"))?;
        let mutation = Mutation::open(pin.file, &pin.path, pin.id, true, false, identity)?;
        mutation.rename(&path, false)?;
        drop(mutation);
        destination.child(name, identity, false)
    }

    pub(crate) fn software_for(&self, storage: &Identity, client: &Identity) -> Result<()> {
        self.verify()?;
        software_acl(&self.0.file, &self.0.path, self.0.id, true, storage, client)
    }

    pub(crate) fn child(&self, name: &str, identity: &Identity, private: bool) -> Result<Self> {
        let path = self.child_path(name)?;
        self.verify()?;
        let file = open_raw(&path, READ_CONTROL | FILE_READ_ATTRIBUTES, true, true)?;
        let (id, _) = inspect(&file, &path, true)?;
        permissions(&file, identity.sid(), private)?;
        Ok(Self(Arc::new(DirectoryPin {
            path,
            file,
            id,
            ancestors: vec![],
            parent: Some(self.clone()),
        })))
    }

    pub(crate) fn create_child(&self, name: &str, identity: &Identity) -> Result<Self> {
        let path = self.child_path(name)?;
        self.verify()?;
        permissions(&self.0.file, identity.sid(), true)?;
        create_directory(&path, identity)?;
        self.child(name, identity, true)
    }

    pub(crate) fn names(&self, limit: usize) -> Result<Vec<String>> {
        self.verify()?;
        let mut names = Vec::new();
        for entry in
            std::fs::read_dir(&self.0.path).map_err(|_| Error("runtime_inventory_unavailable"))?
        {
            let entry = entry.map_err(|_| Error("runtime_inventory_unavailable"))?;
            names.push(
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| Error("invalid_runtime_asset_path"))?,
            );
            if names.len() > limit {
                return Err(Error("runtime_inventory_limit"));
            }
        }
        self.verify()?;
        names.sort();
        Ok(names)
    }

    pub(crate) fn sync(&self) -> Result<()> {
        self.verify()?;
        let file = open_raw(&self.0.path, GENERIC_READ | GENERIC_WRITE, true, true)?;
        if inspect(&file, &self.0.path, true)?.0 != self.0.id {
            return Err(Error("runtime_asset_changed"));
        }
        let mut status = IO_STATUS_BLOCK::default();
        if unsafe { NtFlushBuffersFileEx(file.as_raw_handle(), 0, null(), 0, &mut status) } != 0 {
            return Err(Error("runtime_directory_sync_failed"));
        }
        Ok(())
    }

    pub(crate) fn asset(&self, name: &str, identity: &Identity, private: bool) -> Result<Asset> {
        let path = self.child_path(name)?;
        self.verify()?;
        let file = open_raw(&path, GENERIC_READ | READ_CONTROL, false, false)?;
        let (id, bytes) = inspect(&file, &path, false)?;
        permissions(&file, identity.sid(), private)?;
        Ok(Asset {
            path,
            file,
            id,
            bytes,
            parent: self.clone(),
        })
    }

    pub(crate) fn create_file(&self, name: &str, identity: &Identity) -> Result<Asset> {
        let path = self.child_path(name)?;
        self.verify()?;
        permissions(&self.0.file, identity.sid(), true)?;
        let descriptor = identity.file_descriptor()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_ptr(),
            bInheritHandle: 0,
        };
        let handle = unsafe {
            CreateFileW(
                wide(&path).as_ptr(),
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                FILE_SHARE_READ,
                &attributes,
                CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(Error("runtime_file_creation_failed"));
        }
        let file = unsafe { File::from_raw_handle(handle) };
        let (id, bytes) = inspect(&file, &path, false)?;
        permissions(&file, identity.sid(), true)?;
        Ok(Asset {
            path,
            file,
            id,
            bytes,
            parent: self.clone(),
        })
    }
}

impl Asset {
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }
    pub(crate) fn identity(&self) -> (u64, [u8; 16]) {
        (self.id.volume, self.id.file)
    }
    pub(crate) fn verify(&self) -> Result<()> {
        self.parent.verify()?;
        if inspect(&self.file, &self.path, false)?.0 != self.id {
            return Err(Error("runtime_asset_changed"));
        }
        Ok(())
    }
    pub(crate) fn reader(&self) -> Result<File> {
        self.verify()?;
        let mut file = self
            .file
            .try_clone()
            .map_err(|_| Error("runtime_asset_unavailable"))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| Error("runtime_asset_read_failed"))?;
        Ok(file)
    }
    pub(crate) fn writer(&mut self) -> &mut File {
        &mut self.file
    }
    pub(crate) fn finish(&mut self) -> Result<()> {
        self.file
            .sync_all()
            .map_err(|_| Error("runtime_asset_sync_failed"))?;
        self.bytes = inspect(&self.file, &self.path, false)?.1;
        self.verify()?;
        // A retained write handle would prevent the helper's own read-only
        // pin from opening. Keep a metadata/no-delete guard throughout this
        // downgrade, then retain only a read handle for the published asset.
        let guard = open_raw(&self.path, READ_CONTROL | FILE_READ_ATTRIBUTES, true, false)?;
        if inspect(&guard, &self.path, false)?.0 != self.id {
            return Err(Error("runtime_asset_changed"));
        }
        self.file = guard;
        let read = open_raw(&self.path, GENERIC_READ | READ_CONTROL, false, false)?;
        if inspect(&read, &self.path, false)?.0 != self.id {
            return Err(Error("runtime_asset_changed"));
        }
        self.file = read;
        self.verify()
    }

    pub(crate) fn removal(self, identity: &Identity) -> Result<Removal> {
        self.verify()?;
        Ok(Removal {
            mutation: Mutation::open(self.file, &self.path, self.id, false, false, identity)?,
            _parent: self.parent,
        })
    }

    pub(crate) fn software_for(&self, storage: &Identity, client: &Identity) -> Result<()> {
        self.verify()?;
        software_acl(&self.file, &self.path, self.id, false, storage, client)
    }

    pub(crate) fn move_to(
        self,
        destination: &Directory,
        name: &str,
        identity: &Identity,
    ) -> Result<Self> {
        self.rename(destination, name, None, identity)
    }

    pub(crate) fn replace(self, previous: Asset, identity: &Identity) -> Result<Self> {
        let parent = previous.parent.clone();
        let name = previous
            .path
            .rsplit('\\')
            .next()
            .ok_or(Error("invalid_runtime_asset_path"))?
            .to_owned();
        self.rename(&parent, &name, Some(previous), identity)
    }

    fn rename(
        self,
        destination: &Directory,
        name: &str,
        previous: Option<Asset>,
        identity: &Identity,
    ) -> Result<Self> {
        self.verify()?;
        destination.verify()?;
        let path = destination.child_path(name)?;
        let replace = previous.is_some();
        let _previous = previous
            .map(|asset| {
                asset.verify()?;
                if asset.path != path {
                    return Err(Error("runtime_asset_changed"));
                }
                Mutation::open(asset.file, &asset.path, asset.id, false, true, identity)
            })
            .transpose()?;
        let mutation = Mutation::open(self.file, &self.path, self.id, false, true, identity)?;
        mutation.rename(&path, replace)?;
        drop(mutation);
        drop(_previous);
        destination.asset(
            path.rsplit('\\')
                .next()
                .ok_or(Error("invalid_runtime_asset_path"))?,
            identity,
            true,
        )
    }
}

pub(crate) struct Removal {
    mutation: Mutation,
    _parent: Directory,
}
impl Removal {
    pub(crate) fn remove(self) -> Result<()> {
        self.mutation.remove()
    }
}

struct Mutation {
    file: File,
}
impl Mutation {
    fn open(
        original: File,
        path: &str,
        expected: FileId,
        directory: bool,
        private: bool,
        identity: &Identity,
    ) -> Result<Self> {
        // Downgrade the immutable read pin before requesting DELETE, while a
        // metadata handle retains the selected object throughout the handoff.
        let open = |access| -> Result<File> {
            let handle = unsafe {
                CreateFileW(
                    wide(path).as_ptr(),
                    access,
                    FILE_SHARE_READ | FILE_SHARE_DELETE,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT
                        | if directory {
                            FILE_FLAG_BACKUP_SEMANTICS
                        } else {
                            0
                        },
                    null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(Error(
                    if unsafe { GetLastError() } == ERROR_SHARING_VIOLATION {
                        "runtime_software_in_use"
                    } else {
                        "runtime_software_mutation_failed"
                    },
                ));
            }
            let file = unsafe { File::from_raw_handle(handle) };
            if inspect(&file, path, directory)?.0 != expected {
                return Err(Error("runtime_asset_changed"));
            }
            permissions(&file, identity.sid(), private)?;
            Ok(file)
        };
        let guard = open(READ_CONTROL | FILE_READ_ATTRIBUTES)?;
        drop(original);
        let file = open(READ_CONTROL | FILE_READ_ATTRIBUTES | DELETE)?;
        drop(guard);
        Ok(Self { file })
    }
    fn rename(&self, path: &str, replace: bool) -> Result<()> {
        let name = path.encode_utf16().collect::<Vec<_>>();
        let size = size_of::<FILE_RENAME_INFO>() + name.len() * 2;
        let mut storage = vec![0usize; size.div_ceil(size_of::<usize>())];
        let rename = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        unsafe {
            (*rename).Anonymous.ReplaceIfExists = replace;
            (*rename).RootDirectory = null_mut();
            (*rename).FileNameLength = (name.len() * 2) as u32;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                (*rename).FileName.as_mut_ptr(),
                name.len(),
            );
        }
        if unsafe {
            SetFileInformationByHandle(
                self.file.as_raw_handle(),
                FileRenameInfo,
                rename.cast(),
                size as u32,
            )
        } == 0
        {
            return Err(Error("runtime_software_rename_failed"));
        }
        Ok(())
    }
    fn remove(self) -> Result<()> {
        let mut info = FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe {
            SetFileInformationByHandle(
                self.file.as_raw_handle(),
                FileDispositionInfo,
                (&mut info as *mut FILE_DISPOSITION_INFO).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        } == 0
        {
            return Err(Error("runtime_software_remove_failed"));
        }
        Ok(())
    }
}

fn software_acl(
    original: &File,
    path: &str,
    expected: FileId,
    directory: bool,
    storage: &Identity,
    client: &Identity,
) -> Result<()> {
    // Only an already private, storage-owned object can become published code.
    // The owner is retained; the descriptor grants the client read/execute only.
    permissions(original, storage.sid(), true)?;
    let file = open_raw(
        path,
        READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
        false,
        directory,
    )?;
    if inspect(&file, path, directory)?.0 != expected {
        return Err(Error("runtime_asset_changed"));
    }
    let descriptor = storage.software_for(client)?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(descriptor.as_ptr(), &mut present, &mut acl, &mut defaulted)
    } == 0
        || present == 0
        || acl.is_null()
        || unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl,
                null_mut(),
            )
        } != 0
    {
        return Err(Error("runtime_software_permissions_failed"));
    }
    permissions(&file, storage.sid(), false)
}

fn create_directory(path: &str, identity: &Identity) -> Result<()> {
    let descriptor = identity.file_descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    if unsafe { CreateDirectoryW(wide(path).as_ptr(), &attributes) } == 0 {
        return Err(Error("runtime_directory_creation_failed"));
    }
    Ok(())
}

fn pin_parents(path: &str) -> Result<Vec<(String, File, FileId)>> {
    pin_parents_access(path, READ_CONTROL | FILE_READ_ATTRIBUTES)
}

fn pin_parents_access(path: &str, access: u32) -> Result<Vec<(String, File, FileId)>> {
    if !crate::config::drive_file(path) {
        return Err(Error("invalid_runtime_asset_path"));
    }
    let mut parents = Vec::new();
    let mut paths = vec![path[..3].to_owned()];
    for (index, _) in path[3..].match_indices('\\') {
        paths.push(path[..index + 3].to_owned());
    }
    for parent in paths {
        let file = open_raw(&parent, access, true, true)?;
        let (id, _) = inspect(&file, &parent, true)?;
        parents.push((parent, file, id));
    }
    Ok(parents)
}

pub(crate) fn published_file_identity(path: &str) -> Result<(u64, [u8; 16])> {
    let file = open_raw(path, READ_CONTROL | FILE_READ_ATTRIBUTES, false, false)?;
    let (id, _) = inspect(&file, path, false)?;
    Ok((id.volume, id.file))
}

fn verify_parents(parents: &[(String, File, FileId)]) -> Result<()> {
    for (path, file, id) in parents {
        if inspect(file, path, true)?.0 != *id {
            return Err(Error("runtime_asset_changed"));
        }
    }
    Ok(())
}

impl Pinned {
    fn open(path: &str, role: Role, identity: &Identity) -> Result<Self> {
        let pinned = Self::pin(path, role)?;
        permissions(&pinned.file, identity.sid(), role != Role::Asset)?;
        Ok(pinned)
    }

    fn pin(path: &str, role: Role) -> Result<Self> {
        let parents = pin_parents(path)?;
        // Metadata-only data-file access lets HCS choose its own VHDX sharing
        // mode. Signature reads are short-lived, identity-checked handles.
        let access = if role == Role::Data {
            READ_CONTROL | FILE_READ_ATTRIBUTES
        } else {
            GENERIC_READ | READ_CONTROL
        };
        let file = open_raw(path, access, role == Role::Data, false)?;
        let (id, size) = inspect(&file, path, false)?;
        let pinned = Self {
            path: path.to_owned(),
            file,
            id,
            size,
            role,
            parents,
        };
        pinned.verify()?;
        Ok(pinned)
    }

    fn verify(&self) -> Result<()> {
        verify_parents(&self.parents)?;
        if inspect(&self.file, &self.path, false)?.0 != self.id {
            return Err(Error("runtime_asset_changed"));
        }
        Ok(())
    }
}

fn open_raw(path: &str, access: u32, share_write: bool, directory: bool) -> Result<File> {
    let handle = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            access,
            FILE_SHARE_READ | if share_write { FILE_SHARE_WRITE } else { 0 },
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(Error("runtime_file_unavailable"));
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn inspect(file: &File, path: &str, directory: bool) -> Result<(FileId, u64)> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    let mut id = FILE_ID_INFO::default();
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
        || unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
        || unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (&mut id as *mut FILE_ID_INFO).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        } == 0
        || info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE) != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || !directory && info.nNumberOfLinks != 1
    {
        return Err(Error("regular_runtime_asset_required"));
    }
    let mut resolved = vec![0u16; 32768];
    let count = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            resolved.as_mut_ptr(),
            resolved.len() as u32,
            0,
        )
    } as usize;
    if count == 0 || count >= resolved.len() {
        return Err(Error("runtime_asset_path_unavailable"));
    }
    let resolved = String::from_utf16(&resolved[..count])
        .map_err(|_| Error("runtime_asset_path_unavailable"))?;
    if !resolved
        .strip_prefix(r"\\?\")
        .is_some_and(|resolved| resolved.eq_ignore_ascii_case(path))
    {
        return Err(Error("runtime_asset_path_alias"));
    }
    Ok((
        FileId {
            volume: id.VolumeSerialNumber,
            file: id.FileId.Identifier,
        },
        ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
    ))
}

fn read_at(pinned: &Pinned, offset: u64, bytes: &mut [u8]) -> Result<()> {
    let mut file = open_raw(
        &pinned.path,
        GENERIC_READ | READ_CONTROL,
        pinned.role == Role::Data,
        false,
    )?;
    if inspect(&file, &pinned.path, false)?.0 != pinned.id {
        return Err(Error("runtime_asset_changed"));
    }
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(bytes))
        .map_err(|_| Error("runtime_asset_read_failed"))
}

fn permissions(file: &File, owner_sid: &str, private: bool) -> Result<()> {
    crate::security::file_permissions(
        file,
        owner_sid,
        if private {
            crate::security::FilePolicy::Private
        } else {
            crate::security::FilePolicy::Immutable
        },
    )
}

fn virtual_disk(pinned: &Pinned, runtime_id: &str) -> Result<u64> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(pinned.file.as_raw_handle(), &mut info) } == 0
        || info.dwFileAttributes & (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ENCRYPTED) != 0
    {
        return Err(Error("runtime_vhdx_required"));
    }
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
    if unsafe {
        OpenVirtualDisk(
            &storage,
            wide(&pinned.path).as_ptr(),
            VIRTUAL_DISK_ACCESS_GET_INFO,
            OPEN_VIRTUAL_DISK_FLAG_NO_PARENTS,
            &parameters,
            &mut handle,
        )
    } != 0
        || handle.is_null()
    {
        return Err(Error("runtime_vhdx_information_unavailable"));
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    let size = disk_info(handle.as_raw_handle(), GET_VIRTUAL_DISK_INFO_SIZE)?;
    let identifier = disk_info(handle.as_raw_handle(), GET_VIRTUAL_DISK_INFO_IDENTIFIER)?;
    let subtype = disk_info(
        handle.as_raw_handle(),
        GET_VIRTUAL_DISK_INFO_PROVIDER_SUBTYPE,
    )?;
    let loaded = disk_info(handle.as_raw_handle(), GET_VIRTUAL_DISK_INFO_IS_LOADED)?;
    let size = unsafe { size.Anonymous.Size };
    let identifier = unsafe { identifier.Anonymous.Identifier };
    let expected = u128::from_str_radix(runtime_id, 16)
        .map_err(|_| Error("runtime_disk_identity_mismatch"))?;
    let expected = windows_sys::core::GUID::from_u128(expected);
    if identifier.data1 != expected.data1
        || identifier.data2 != expected.data2
        || identifier.data3 != expected.data3
        || identifier.data4 != expected.data4
    {
        return Err(Error("runtime_disk_identity_mismatch"));
    }
    if !(4 * GIB..=MAX_DISK).contains(&size.VirtualSize)
        || !matches!(size.SectorSize, 512 | 4096)
        || size.VirtualSize % size.SectorSize as u64 != 0
        || size.PhysicalSize < 1024 * 1024
        || size.PhysicalSize > size.VirtualSize + GIB
        || !matches!(unsafe { subtype.Anonymous.ProviderSubtype }, 2 | 3)
        || unsafe { loaded.Anonymous.IsLoaded } != 0
    {
        return Err(Error("invalid_runtime_disk"));
    }
    pinned.verify()?;
    Ok(size.VirtualSize)
}

fn disk_info(handle: HANDLE, version: i32) -> Result<GET_VIRTUAL_DISK_INFO> {
    let mut info = GET_VIRTUAL_DISK_INFO {
        Version: version,
        ..Default::default()
    };
    let mut size = size_of::<GET_VIRTUAL_DISK_INFO>() as u32;
    if unsafe { GetVirtualDiskInformation(handle, &mut size, &mut info, null_mut()) } != 0 {
        return Err(Error("runtime_vhdx_information_unavailable"));
    }
    Ok(info)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        CONFIG_LIMIT, File, GIB, Identity, Lease, Pinned, Role, open_raw, read_config, reconcile,
        wide,
    };
    use crate::config::{Disk, RuntimeConfig};
    use crate::security::Security;
    use serde_json::json;
    use std::io::Write;
    use std::os::windows::io::AsRawHandle;
    use std::path::PathBuf;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT, SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC, WRITE_OWNER};

    struct Area(PathBuf);
    impl Area {
        fn new() -> Self {
            let mut bytes = [0; 16];
            getrandom::getrandom(&mut bytes).unwrap();
            let name: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = std::env::temp_dir().join(format!("oblivion-files-{name}"));
            super::create_directory(path.to_str().unwrap(), &Identity::current().unwrap()).unwrap();
            Self(path)
        }
        fn path(&self, name: &str) -> String {
            self.0.join(name).to_str().unwrap().to_owned()
        }
        fn file(&self, name: &str, bytes: &[u8], identity: &Identity, extra: &str) -> String {
            let path = self.path(name);
            File::create(&path).unwrap().write_all(bytes).unwrap();
            acl(&path, identity, extra);
            path
        }

        fn runtime(&self, identity: &Identity) -> RuntimeConfig {
            let id = "0123456789abcdef0123456789abcdef";
            let kernel = self.file("kernel", b"kernel", identity, "");
            let initrd = self.file("initrd", b"initrd", identity, "");
            let mut iso = vec![0; 34816];
            iso[32769..32774].copy_from_slice(b"CD001");
            iso[32774] = 1;
            let image = self.file("controller.iso", &iso, identity, "");
            let data = self.path("data.vhdx");
            drop(crate::disk::create(&data, id, 4 * GIB, identity).unwrap());
            RuntimeConfig {
                version: 1,
                backend: "hcs-hyperv".into(),
                runtime_id: id.into(),
                kernel,
                initrd,
                command_line: format!(
                    "oblivion.runtime=1 oblivion.runtime-backend=hcs-hyperv oblivion.runtime-id={id}"
                ),
                disks: vec![
                    Disk {
                        path: image,
                        read_only: true,
                    },
                    Disk {
                        path: data,
                        read_only: false,
                    },
                ],
                cpu_count: 2,
                memory_mi_b: 2048,
                control_pipe: format!(r"\\.\pipe\oblivion.{id}.control"),
                control_port: 4050,
                network: false,
                serial_stdio: false,
            }
        }
    }
    impl Drop for Area {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn acl(path: &str, identity: &Identity, extra: &str) {
        let file = open_raw(path, READ_CONTROL | WRITE_DAC | WRITE_OWNER, false, false).unwrap();
        let text = format!("O:{}{}{}", identity.sid(), identity.sddl(), extra);
        let mut descriptor = null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide(&text).as_ptr(),
                    1,
                    &mut descriptor,
                    null_mut(),
                )
            },
            0
        );
        let descriptor = Security(descriptor);
        let mut owner = null_mut();
        let mut acl = null_mut();
        let mut present = 0;
        let mut defaulted = 0;
        assert_ne!(
            unsafe { GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut defaulted) },
            0
        );
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted)
            },
            0
        );
        assert_ne!(present, 0);
        assert_eq!(
            unsafe {
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION
                        | PROTECTED_DACL_SECURITY_INFORMATION,
                    owner,
                    null_mut(),
                    acl,
                    null(),
                )
            },
            0
        );
    }

    #[test]
    fn actual_acl_distinguishes_private_configuration_from_public_read_only_assets() {
        let area = Area::new();
        let identity = Identity::current().unwrap();
        let path = area.file("PRIVATE_CANARY.json", b"{}", &identity, "(A;;GR;;;WD)");
        assert!(Pinned::open(&path, Role::Asset, &identity).is_ok());
        assert_eq!(
            Pinned::open(&path, Role::Configuration, &identity)
                .err()
                .unwrap()
                .0,
            "private_runtime_file_required"
        );
        assert_eq!(
            read_config(&path, &identity).err().unwrap().0,
            "private_runtime_file_required"
        );
        acl(&path, &identity, "(A;;GW;;;WD)");
        let error = Pinned::open(&path, Role::Asset, &identity).err().unwrap();
        assert_eq!(error.0, "private_runtime_file_required");
        assert!(!error.to_string().contains("PRIVATE_CANARY"));
    }

    #[test]
    fn document_destination_admin_rights_never_relax_private_runtime_data() {
        let area = Area::new();
        let identity = Identity::current().unwrap();
        let path = area.file("document", b"data", &identity, "(A;;GA;;;BA)");
        let file = open_raw(&path, READ_CONTROL, false, false).unwrap();
        assert!(
            crate::security::file_permissions(
                &file,
                identity.sid(),
                crate::security::FilePolicy::ControlledDestination
            )
            .is_ok()
        );
        assert!(
            crate::security::file_permissions(
                &file,
                identity.sid(),
                crate::security::FilePolicy::Private
            )
            .is_err()
        );
        assert!(
            crate::security::file_permissions(
                &file,
                identity.sid(),
                crate::security::FilePolicy::Immutable
            )
            .is_err()
        );
        drop(file);
        acl(&path, &identity, "(A;;GW;;;WD)");
        let file = open_raw(&path, READ_CONTROL, false, false).unwrap();
        assert!(
            crate::security::file_permissions(
                &file,
                identity.sid(),
                crate::security::FilePolicy::ControlledDestination
            )
            .is_err()
        );
    }

    #[test]
    fn config_reader_uses_private_file_and_bounded_actual_content() {
        let area = Area::new();
        let identity = Identity::current().unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        let bytes = serde_json::to_vec(&json!({"version":1,"backend":"hcs-hyperv","runtimeId":id,
            "kernel":area.path("vmlinuz"),"initrd":area.path("initrd.img"),
            "commandLine":format!("oblivion.runtime=1 oblivion.runtime-backend=hcs-hyperv oblivion.runtime-id={id}"),
            "disks":[{"path":area.path("live.iso"),"readOnly":true},{"path":area.path("data.vhdx"),"readOnly":false}],
            "cpuCount":2,"memoryMiB":2048,"controlPipe":format!(r"\\.\pipe\oblivion.{id}.control"),
            "controlPort":4050,"network":false,"serialStdio":false})).unwrap();
        let path = area.file("config.json", &bytes, &identity, "");
        assert_eq!(read_config(&path, &identity).unwrap().runtime_id, id);
        let large = area.file("large.json", &vec![b' '; CONFIG_LIMIT + 1], &identity, "");
        assert_eq!(
            read_config(&large, &identity).err().unwrap().0,
            "invalid_runtime_configuration"
        );
    }

    #[test]
    fn pinned_asset_denies_writes_and_replacement_and_rejects_hard_link_aliases() {
        let area = Area::new();
        let identity = Identity::current().unwrap();
        let path = area.file("kernel", b"kernel", &identity, "");
        {
            let pinned = Pinned::open(&path, Role::Asset, &identity).unwrap();
            assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
            assert!(std::fs::rename(&path, area.path("renamed")).is_err());
            assert!(std::fs::rename(&area.0, area.0.with_extension("moved")).is_err());
            pinned.verify().unwrap();
        }
        std::fs::hard_link(&path, area.path("alias")).unwrap();
        assert_eq!(
            Pinned::open(&path, Role::Asset, &identity).err().unwrap().0,
            "regular_runtime_asset_required"
        );
    }

    #[test]
    fn file_evidence_uses_original_ordered_file_ids_and_stable_virtual_disk_capacity() {
        let area = Area::new();
        let identity = Identity::current().unwrap();
        let config = area.runtime(&identity);
        let lease = Lease::acquire(&config, &identity).unwrap();
        let evidence = lease.evidence();
        assert_eq!(evidence.len(), 4);
        for (path, observed) in [
            &config.kernel,
            &config.initrd,
            &config.disks[0].path,
            &config.disks[1].path,
        ]
        .into_iter()
        .zip(&evidence)
        {
            let expected = super::data_file_identity(path).unwrap();
            assert_eq!(observed.volume, expected.0);
            assert_eq!(observed.file, expected.1);
        }
        assert_eq!(evidence[0].bytes, 6);
        assert_eq!(evidence[2].bytes, 34816);
        assert_eq!(evidence[3].bytes, 4 * GIB);
        assert!(std::fs::metadata(&config.disks[1].path).unwrap().len() < evidence[3].bytes);
    }

    #[test]
    fn reconciliation_refuses_replacements_and_preserves_unknown_acl_before_any_revoke() {
        let area = Area::new();
        let identity = Identity::current().unwrap();
        let config = area.runtime(&identity);
        let lease = Lease::acquire(&config, &identity).unwrap();
        let evidence = lease.evidence();
        drop(lease);
        std::fs::rename(&config.kernel, area.path("original-kernel")).unwrap();
        area.file("kernel", b"kernel", &identity, "");
        assert_eq!(
            reconcile(&config, &identity, &evidence).unwrap_err().0,
            "runtime_file_evidence_changed"
        );
        assert!(std::path::Path::new(&area.path("original-kernel")).exists());

        let lease = Lease::acquire(&config, &identity).unwrap();
        let mut evidence = lease.evidence();
        drop(lease);
        // The same original kernel can carry an unexpected permission. A
        // rejected capacity receipt must not silently repair or adopt its ACL.
        acl(&config.kernel, &identity, "(A;;GW;;;WD)");
        evidence[3].bytes += 1024 * 1024;
        assert_eq!(
            reconcile(&config, &identity, &evidence).unwrap_err().0,
            "runtime_file_evidence_changed"
        );
        assert_eq!(
            Lease::acquire(&config, &identity).err().unwrap().0,
            "private_runtime_file_required"
        );
        assert_eq!(
            reconcile(&config, &identity, &[]).unwrap_err().0,
            "invalid_runtime_file_evidence"
        );
        assert_eq!(
            Pinned::open(&config.kernel, Role::Asset, &identity)
                .err()
                .unwrap()
                .0,
            "private_runtime_file_required"
        );
    }

    #[test]
    #[ignore = "Requires Windows Developer Mode or symlink privilege; no VM is started"]
    fn real_leaf_and_parent_symlinks_are_rejected() {
        let area = Area::new();
        let identity = Identity::current().unwrap();
        let path = area.file("kernel", b"kernel", &identity, "");
        let link = area.path("link");
        std::os::windows::fs::symlink_file(&path, &link).unwrap();
        assert_eq!(
            Pinned::open(&link, Role::Asset, &identity).err().unwrap().0,
            "regular_runtime_asset_required"
        );
        std::fs::create_dir(area.path("actual")).unwrap();
        let nested = area.file(r"actual\initrd", b"initrd", &identity, "");
        std::os::windows::fs::symlink_dir(area.path("actual"), area.path("directory-link"))
            .unwrap();
        let _ = nested;
        assert_eq!(
            Pinned::open(&area.path(r"directory-link\initrd"), Role::Asset, &identity)
                .err()
                .unwrap()
                .0,
            "regular_runtime_asset_required"
        );
    }
}
