//! Native Windows filesystem capabilities. Every child is opened relative to a
//! pinned handle; no device namespace, remote drive or reparse traversal exists.
pub(crate) use crate::file_identity::FileIdentity;
use crate::{MAX_ENTRIES, invalid, require};
use oblivion_native_windows::security::{FilePolicy, Identity, file_permissions};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_THROUGH, FileDispositionInformation,
    FileRenameInformation, NtCreateFile, NtFlushBuffersFileEx, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ATTRIBUTE_DEVICE,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_ID_BOTH_DIR_INFO, FILE_ID_INFO,
    FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_TRAVERSE, FILE_TYPE_DISK, FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo,
    FileIdInfo, GetDriveTypeW, GetFileInformationByHandle, GetFileInformationByHandleEx,
    GetFileType, GetFinalPathNameByHandleW, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    LockFileEx, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE, VOLUME_NAME_GUID,
};
use windows_sys::Win32::System::IO::{IO_STATUS_BLOCK, OVERLAPPED};

struct Node {
    file: File,
    _parent: Option<Arc<Node>>,
    identity: Arc<Identity>,
    lock: Mutex<Option<File>>,
}

pub(crate) struct Directory(Arc<Node>);

impl Directory {
    pub fn open(path: &Path) -> io::Result<Self> {
        let path = path
            .to_str()
            .ok_or_else(|| invalid("invalid_native_path"))?;
        require(
            path.len() >= 3
                && path.as_bytes()[0].is_ascii_alphabetic()
                && path.as_bytes()[1..3] == *b":\\"
                && !path.contains('/')
                && path.encode_utf16().count() <= 32700,
            "local_drive_path_required",
        )?;
        let identity = Arc::new(Identity::current().map_err(native_error)?);
        let root = &path[..3];
        // DRIVE_FIXED=3 / DRIVE_REMOVABLE=2. In particular a mapped SMB drive
        // is remote even though its input spelling starts with a drive letter.
        require(
            matches!(unsafe { GetDriveTypeW(wide(root).as_ptr()) }, 2 | 3),
            "local_drive_path_required",
        )?;
        let handle = unsafe {
            CreateFileW(
                wide(root).as_ptr(),
                FILE_GENERIC_READ | READ_CONTROL | FILE_TRAVERSE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(os_error());
        }
        let mut directory = Self::new(unsafe { File::from_raw_handle(handle) }, None, identity)?;
        for name in path[3..].split('\\').filter(|name| !name.is_empty()) {
            component(name)?;
            directory = directory.directory(name)?;
        }
        // Empty repeated components are not an alternative authority spelling.
        require(
            !path[3..].contains("\\\\") && (path.len() == 3 || !path.ends_with('\\')),
            "invalid_native_path",
        )?;
        Ok(directory)
    }

    fn new(file: File, parent: Option<Arc<Node>>, identity: Arc<Identity>) -> io::Result<Self> {
        let info = information(&file)?;
        require(
            info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
            "not_directory",
        )?;
        Ok(Self(Arc::new(Node {
            file,
            _parent: parent,
            identity,
            lock: Mutex::new(None),
        })))
    }

    pub fn from_file(file: File) -> io::Result<Self> {
        let directory = Self::open(&canonical_path(&file)?)?;
        require(
            directory.identity()?.matches(&file)?,
            "native_directory_changed",
        )?;
        Ok(directory)
    }

    pub fn clone(&self) -> io::Result<Self> {
        Ok(Self(self.0.clone()))
    }
    pub fn identity(&self) -> io::Result<FileIdentity> {
        file_identity(&self.0.file)
    }
    pub fn same_device(&self, file: &File) -> io::Result<bool> {
        let FileIdentity::Windows {
            volume_guid,
            volume_serial,
            ..
        } = self.identity()?
        else {
            return Err(invalid("invalid_file_identity"));
        };
        let FileIdentity::Windows {
            volume_guid: other_guid,
            volume_serial: other_serial,
            ..
        } = file_identity(file)?
        else {
            return Err(invalid("invalid_file_identity"));
        };
        Ok(volume_guid == other_guid && volume_serial == other_serial)
    }

    pub fn require_private(&self) -> io::Result<()> {
        file_permissions(&self.0.file, self.0.identity.sid(), FilePolicy::Private)
            .map_err(native_error)
    }
    pub fn require_controlled(&self) -> io::Result<()> {
        file_permissions(
            &self.0.file,
            self.0.identity.sid(),
            FilePolicy::ControlledDestination,
        )
        .map_err(native_error)
    }
    pub fn source(&self, name: &str) -> io::Result<File> {
        let file = self.child(
            name,
            FILE_GENERIC_READ | READ_CONTROL,
            FILE_OPEN,
            0,
            FILE_SHARE_READ,
            false,
        )?;
        verify_source(&file)?;
        Ok(file)
    }
    pub fn directory(&self, name: &str) -> io::Result<Self> {
        let file = self.child(
            name,
            FILE_GENERIC_READ | READ_CONTROL,
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            false,
        )?;
        Self::new(file, Some(self.0.clone()), self.0.identity.clone())
    }
    pub fn create_file(&self, name: &str) -> io::Result<File> {
        self.child(
            name,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            true,
        )
    }
    pub fn create_directory(&self, name: &str) -> io::Result<Self> {
        let file = self.child(
            name,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_WRITE_THROUGH,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            true,
        )?;
        Self::new(file, Some(self.0.clone()), self.0.identity.clone())
    }
    fn child(
        &self,
        name: &str,
        access: u32,
        disposition: u32,
        options: u32,
        share: u32,
        private: bool,
    ) -> io::Result<File> {
        component(name)?;
        self.relative(name, access, disposition, options, share, private)
    }
    fn relative(
        &self,
        name: &str,
        access: u32,
        disposition: u32,
        options: u32,
        share: u32,
        private: bool,
    ) -> io::Result<File> {
        let mut name = name.encode_utf16().collect::<Vec<_>>();
        let mut name = UNICODE_STRING {
            Length: (name.len() * 2) as u16,
            MaximumLength: (name.len() * 2) as u16,
            Buffer: name.as_mut_ptr(),
        };
        let descriptor = private
            .then(|| self.0.identity.file_descriptor())
            .transpose()
            .map_err(native_error)?;
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: self.0.file.as_raw_handle(),
            ObjectName: &mut name,
            Attributes: 0x40,
            SecurityDescriptor: descriptor
                .as_ref()
                .map_or(null_mut(), |value| value.as_ptr().cast()),
            SecurityQualityOfService: null_mut(),
        };
        let mut handle = null_mut();
        let mut status = IO_STATUS_BLOCK::default();
        let result = unsafe {
            NtCreateFile(
                &mut handle,
                access
                    | SYNCHRONIZE
                    | if options & FILE_DIRECTORY_FILE != 0 {
                        FILE_TRAVERSE
                    } else {
                        0
                    },
                &attributes,
                &mut status,
                null(),
                FILE_ATTRIBUTE_NORMAL,
                share,
                disposition,
                options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                null(),
                0,
            )
        };
        if result < 0 {
            return Err(nt_error(result));
        }
        require(!handle.is_null(), "native_file_open_failed")?;
        let file = unsafe { File::from_raw_handle(handle) };
        information(&file)?;
        if private {
            file_permissions(&file, self.0.identity.sid(), FilePolicy::Private)
                .map_err(native_error)?;
        }
        Ok(file)
    }

    pub fn record(&self, name: &str, limit: u64) -> io::Result<File> {
        let file = self.source(name)?;
        require(
            file.metadata()?.is_file() && file.metadata()?.len() <= limit,
            "unsafe_file_operation_record",
        )?;
        file_permissions(&file, self.0.identity.sid(), FilePolicy::Private)
            .map_err(native_error)?;
        Ok(file)
    }

    /// Called only for a newly created, approved receiver inbox. Read-only
    /// status/listing never manufactures a missing lock or adopts another root.
    pub fn initialize_lock(&self) -> io::Result<()> {
        self.require_private()?;
        let file = self.create_file(".lock")?;
        file.sync_all()?;
        self.sync()
    }

    pub fn lock(&self) -> io::Result<()> {
        let mut held = self
            .0
            .lock
            .lock()
            .map_err(|_| invalid("native_lock_unavailable"))?;
        if held.is_some() {
            return Ok(());
        }
        let file = self.child(
            ".lock",
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            false,
        )?;
        verify_source(&file)?;
        file_permissions(&file, self.0.identity.sid(), FilePolicy::Private)
            .map_err(native_error)?;
        require(file.metadata()?.len() == 0, "unsafe_receive_lock")?;
        let mut overlapped = OVERLAPPED::default();
        if unsafe {
            LockFileEx(
                file.as_raw_handle(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        } == 0
        {
            return Err(os_error());
        }
        *held = Some(file);
        Ok(())
    }

    pub fn sync(&self) -> io::Result<()> {
        let file = self.relative(
            ".",
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            false,
        )?;
        require(self.identity()?.matches(&file)?, "native_directory_changed")?;
        let mut status = IO_STATUS_BLOCK::default();
        // A directory flush is mandatory. Unsupported filesystems fail closed;
        // this is never replaced by a no-op or a flush of an unrelated marker.
        let result =
            unsafe { NtFlushBuffersFileEx(file.as_raw_handle(), 0, null(), 0, &mut status) };
        if result != 0 {
            return Err(io::Error::new(
                nt_error(result).kind(),
                "native_directory_sync_failed",
            ));
        }
        Ok(())
    }

    pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.move_into(from, self, to)
    }
    pub fn move_into(&self, from: &str, destination: &Self, to: &str) -> io::Result<()> {
        // Private metadata writers can still hold the just-synced pending file.
        // A metadata-only handle shares that writer; source() deliberately does
        // not, because reviewed input files must exclude existing writers.
        let file = self.child(
            from,
            FILE_READ_ATTRIBUTES,
            FILE_OPEN,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            false,
        )?;
        let expected = file_identity(&file)?;
        drop(file);
        self.move_exclusive(from, destination, to, &expected)
    }
    pub fn move_exclusive(
        &self,
        from: &str,
        destination: &Self,
        to: &str,
        expected: &FileIdentity,
    ) -> io::Result<()> {
        component(to)?;
        let file = self.child(
            from,
            FILE_READ_ATTRIBUTES | DELETE,
            FILE_OPEN,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            false,
        )?;
        require(
            expected.matches(&file)? && destination.same_device(&file)?,
            "publication_changed",
        )?;
        self.rename_file_exclusive(&file, destination, to)
    }

    pub fn move_file_exclusive(
        &self,
        from: &str,
        destination: &Self,
        to: &str,
        expected: &File,
    ) -> io::Result<()> {
        component(to)?;
        let file = self.child(
            from,
            FILE_READ_ATTRIBUTES | DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            false,
        )?;
        require(same_file(&file, expected)?, "publication_changed")?;
        self.rename_file_exclusive(&file, destination, to)
    }

    fn rename_file_exclusive(&self, file: &File, destination: &Self, to: &str) -> io::Result<()> {
        let name = to.encode_utf16().collect::<Vec<_>>();
        let bytes = size_of::<FILE_RENAME_INFO>() + name.len() * 2;
        let mut buffer = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        let rename = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        unsafe {
            (*rename).Anonymous.ReplaceIfExists = false;
            (*rename).RootDirectory = destination.0.file.as_raw_handle();
            (*rename).FileNameLength = (name.len() * 2) as u32;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                (*rename).FileName.as_mut_ptr(),
                name.len(),
            );
        }
        let mut status = IO_STATUS_BLOCK::default();
        let result = unsafe {
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut status,
                rename.cast(),
                bytes as u32,
                FileRenameInformation,
            )
        };
        if result != 0 {
            return Err(nt_error(result));
        }
        Ok(())
    }

    pub fn names(&self, limit: usize) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        self.visit(|name| {
            require(names.len() < limit, "entry_limit")?;
            names.push(
                name.to_str()
                    .map_err(|_| invalid("invalid_path"))?
                    .to_owned(),
            );
            Ok(())
        })?;
        names.sort();
        Ok(names)
    }
    pub fn visit(&self, mut visitor: impl FnMut(&CStr) -> io::Result<()>) -> io::Result<()> {
        let file = self.relative(
            ".",
            FILE_GENERIC_READ,
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            false,
        )?;
        let mut buffer = vec![0u64; 8192];
        let mut class = FileIdBothDirectoryRestartInfo;
        loop {
            if unsafe {
                GetFileInformationByHandleEx(
                    file.as_raw_handle(),
                    class,
                    buffer.as_mut_ptr().cast(),
                    (buffer.len() * 8) as u32,
                )
            } == 0
            {
                if io::Error::last_os_error().raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                    return Ok(());
                }
                return Err(os_error());
            }
            class = FileIdBothDirectoryInfo;
            let mut offset = 0;
            loop {
                let header = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
                require(
                    offset + header <= buffer.len() * 8,
                    "invalid_directory_reply",
                )?;
                let entry = unsafe {
                    &*buffer
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset)
                        .cast::<FILE_ID_BOTH_DIR_INFO>()
                };
                let length = entry.FileNameLength as usize;
                require(
                    length % 2 == 0 && offset + header + length <= buffer.len() * 8,
                    "invalid_directory_reply",
                )?;
                let name = String::from_utf16(unsafe {
                    std::slice::from_raw_parts(entry.FileName.as_ptr(), length / 2)
                })
                .map_err(|_| invalid("invalid_path"))?;
                if name != "." && name != ".." {
                    visitor(&CString::new(name).map_err(|_| invalid("invalid_path"))?)?;
                }
                if entry.NextEntryOffset == 0 {
                    break;
                }
                require(
                    entry.NextEntryOffset as usize >= header + length
                        && entry.NextEntryOffset % 8 == 0,
                    "invalid_directory_reply",
                )?;
                offset += entry.NextEntryOffset as usize;
            }
        }
    }

    pub fn remove_directory(&self, name: &str) -> io::Result<()> {
        let file = self.child(
            name,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | READ_CONTROL,
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            false,
        )?;
        file_permissions(&file, self.0.identity.sid(), FilePolicy::Private)
            .map_err(native_error)?;
        let child = Self::new(file, Some(self.0.clone()), self.0.identity.clone())?;
        for name in child.names(MAX_ENTRIES)? {
            let file = child.child(
                &name,
                FILE_GENERIC_READ | DELETE,
                FILE_OPEN,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                false,
            )?;
            let directory = file.metadata()?.is_dir();
            drop(file);
            if directory {
                child.remove_directory(&name)?;
                continue;
            }
            child.delete(&name)?;
        }
        mark_delete(&child.0.file)
    }
    fn delete(&self, name: &str) -> io::Result<()> {
        let file = self.child(
            name,
            FILE_READ_ATTRIBUTES | DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            false,
        )?;
        mark_delete(&file)
    }

    pub fn remove_file(&self, name: &str, expected: &File) -> io::Result<()> {
        let file = self.child(
            name,
            FILE_READ_ATTRIBUTES | DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            false,
        )?;
        require(same_file(&file, expected)?, "publication_changed")?;
        mark_delete(&file)
    }
}

fn same_file(left: &File, right: &File) -> io::Result<bool> {
    let mut identities = [FILE_ID_INFO::default(); 2];
    for (file, identity) in [left, right].into_iter().zip(&mut identities) {
        information(file)?;
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (identity as *mut FILE_ID_INFO).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        } == 0
        {
            return Err(os_error());
        }
    }
    Ok(
        identities[0].VolumeSerialNumber == identities[1].VolumeSerialNumber
            && identities[0].FileId.Identifier == identities[1].FileId.Identifier,
    )
}

fn mark_delete(file: &File) -> io::Result<()> {
    let mut status = IO_STATUS_BLOCK::default();
    let information = FILE_DISPOSITION_INFO { DeleteFile: true };
    let result = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status,
            (&information as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
            FileDispositionInformation,
        )
    };
    if result != 0 {
        return Err(nt_error(result));
    }
    Ok(())
}

pub(crate) fn verify_source(file: &File) -> io::Result<()> {
    let info = information(file)?;
    require(
        info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 || info.nNumberOfLinks == 1,
        "unsupported_source",
    )
}
fn information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    require(
        unsafe { GetFileType(file.as_raw_handle()) } == FILE_TYPE_DISK,
        "unsupported_source",
    )?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(os_error());
    }
    require(
        info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE) == 0,
        "unsupported_source",
    )?;
    Ok(info)
}

pub(crate) fn canonical_path(file: &File) -> io::Result<PathBuf> {
    information(file)?;
    let path = final_path(file, 0)?;
    let path = path
        .strip_prefix(r"\\?\")
        .ok_or_else(|| invalid("local_drive_path_required"))?;
    require(
        path.len() >= 3
            && path.as_bytes()[0].is_ascii_alphabetic()
            && path.as_bytes()[1..3] == *b":\\",
        "local_drive_path_required",
    )?;
    require(
        matches!(unsafe { GetDriveTypeW(wide(&path[..3]).as_ptr()) }, 2 | 3),
        "local_drive_path_required",
    )?;
    Ok(PathBuf::from(path))
}
fn final_path(file: &File, flags: u32) -> io::Result<String> {
    let mut path = vec![0u16; 32768];
    let count = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            flags,
        )
    } as usize;
    require(
        count > 0 && count < path.len(),
        "native_file_path_unavailable",
    )?;
    String::from_utf16(&path[..count]).map_err(|_| invalid("invalid_native_path"))
}
pub(crate) fn file_identity(file: &File) -> io::Result<FileIdentity> {
    information(file)?;
    let path = final_path(file, VOLUME_NAME_GUID)?;
    let guid = path
        .strip_prefix(r"\\?\Volume{")
        .and_then(|path| path.split_once("}\\"))
        .map(|(guid, _)| guid)
        .ok_or_else(|| invalid("filesystem_identity_unavailable"))?;
    require(
        guid.len() == 36
            && [8, 13, 18, 23]
                .iter()
                .all(|index| guid.as_bytes()[*index] == b'-'),
        "filesystem_identity_unavailable",
    )?;
    let guid = guid
        .chars()
        .filter(|character| *character != '-')
        .collect::<String>();
    let guid = u128::from_str_radix(&guid, 16)
        .map_err(|_| invalid("filesystem_identity_unavailable"))?
        .to_be_bytes();
    let mut info = FILE_ID_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(os_error());
    }
    require(
        guid != [0; 16] && info.FileId.Identifier != [0; 16],
        "filesystem_identity_unavailable",
    )?;
    Ok(FileIdentity::Windows {
        volume_guid: guid,
        volume_serial: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    })
}

pub(crate) fn validate_name(name: &str) -> io::Result<()> {
    component(name)
}

fn component(name: &str) -> io::Result<()> {
    crate::native_files::validate_name(name)?;
    require(
        crate::selection::portable_name(name),
        "unsupported_windows_name",
    )
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn native_error(_: oblivion_native_windows::Error) -> io::Error {
    invalid("native_file_permissions_unavailable")
}
fn os_error() -> io::Error {
    io::Error::new(
        io::Error::last_os_error().kind(),
        "native_filesystem_operation_failed",
    )
}
fn nt_error(status: i32) -> io::Error {
    io::Error::new(
        io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32).kind(),
        "native_filesystem_operation_failed",
    )
}
