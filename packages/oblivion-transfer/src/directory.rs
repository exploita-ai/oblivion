use crate::{MAX_ENTRIES, invalid, require};
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// All peer paths are resolved one component at a time from pinned descriptors.
pub(crate) struct Directory(File);

/// A volume UUID identifies the filesystem across device-number reassignment.
/// It is not authentication against a cloned or attacker-controlled volume.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "platform", rename_all = "kebab-case", deny_unknown_fields)]
enum FilesystemIdentity {
    Linux { kind: i64, uuid: Vec<u8> },
    MacOs { kind: String, uuid: [u8; 16] },
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileIdentity {
    filesystem: FilesystemIdentity,
    pub inode: u64,
}

impl FileIdentity {
    pub fn of(file: &File) -> io::Result<Self> {
        Ok(Self {
            filesystem: filesystem_identity(file)?,
            inode: file.metadata()?.ino(),
        })
    }

    pub fn matches(&self, file: &File) -> io::Result<bool> {
        Ok(*self == Self::of(file)?)
    }
}

impl Directory {
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::from_file(
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?,
        )
    }

    pub fn from_file(file: File) -> io::Result<Self> {
        require(file.metadata()?.is_dir(), "not_directory")?;
        Ok(Self(file))
    }

    pub fn require_private(&self) -> io::Result<()> {
        let metadata = self.0.metadata()?;
        // The receiver runs as a dedicated service identity, distinct from the agent.
        require(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0,
            "unsafe_receive_root",
        )
    }

    pub fn require_controlled(&self) -> io::Result<()> {
        let metadata = self.0.metadata()?;
        require(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o022 == 0,
            "unsafe_publish_root",
        )
    }

    pub fn mode(&self, mode: u32) -> io::Result<()> {
        self.0
            .set_permissions(std::fs::Permissions::from_mode(mode))
    }

    pub fn metadata(&self) -> io::Result<std::fs::Metadata> {
        self.0.metadata()
    }

    pub fn identity(&self) -> io::Result<FileIdentity> {
        FileIdentity::of(&self.0)
    }

    pub fn lock(&self) -> io::Result<()> {
        if unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn clone(&self) -> io::Result<Self> {
        Ok(Self(self.0.try_clone()?))
    }
    pub fn sync(&self) -> io::Result<()> {
        self.0.sync_all()
    }

    pub fn source(&self, name: &str) -> io::Result<File> {
        let component = component(name)?;
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                self.0.as_raw_fd(),
                component.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let metadata = unsafe { metadata.assume_init() };
        require(
            matches!(
                metadata.st_mode & libc::S_IFMT,
                libc::S_IFREG | libc::S_IFDIR
            ),
            "unsupported_source",
        )?;
        // NONBLOCK avoids hanging on a FIFO before fstat rejects special files.
        self.open_child(name, libc::O_RDONLY | libc::O_NONBLOCK)
    }

    pub fn directory(&self, name: &str) -> io::Result<Self> {
        Self::from_file(self.open_child(name, libc::O_RDONLY | libc::O_DIRECTORY)?)
    }

    pub fn create_file(&self, name: &str) -> io::Result<File> {
        self.open_child(name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)
    }

    fn open_child(&self, name: &str, flags: i32) -> io::Result<File> {
        let name = component(name)?;
        // SAFETY: descriptor stays owned by self; the C string is live, NUL terminated.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a fresh descriptor, now owned only by File.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub fn create_directory(&self, name: &str) -> io::Result<Self> {
        let name = component(name)?;
        if unsafe { libc::mkdirat(self.0.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        self.directory(name.to_str().map_err(|_| invalid("invalid_path"))?)
    }

    pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.move_into(from, self, to)
    }

    pub fn move_into(&self, from: &str, destination: &Self, to: &str) -> io::Result<()> {
        let from = component(from)?;
        let to = component(to)?;
        if unsafe {
            libc::renameat(
                self.0.as_raw_fd(),
                from.as_ptr(),
                destination.0.as_raw_fd(),
                to.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Publish a verified entry without replacing an existing destination,
    /// including an empty directory created concurrently by the agent.
    pub fn move_exclusive(&self, from: &str, destination: &Self, to: &str) -> io::Result<()> {
        let from = component(from)?;
        let to = component(to)?;
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::renameat2(
                self.0.as_raw_fd(),
                from.as_ptr(),
                destination.0.as_raw_fd(),
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::renameatx_np(
                self.0.as_raw_fd(),
                from.as_ptr(),
                destination.0.as_raw_fd(),
                to.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let result = return Err(io::Error::from(io::ErrorKind::Unsupported));
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn names(&self, limit: usize) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        self.visit(|name| {
            let name = name.to_str().map_err(|_| invalid("invalid_path"))?;
            require(names.len() < limit, "entry_limit")?;
            names.push(name.to_owned());
            Ok(())
        })?;
        names.sort();
        Ok(names)
    }

    pub fn visit(&self, mut visitor: impl FnMut(&CStr) -> io::Result<()>) -> io::Result<()> {
        // A fresh open description avoids sharing the directory cursor with other walks.
        let dot = c".";
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                dot.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let directory = unsafe { libc::fdopendir(file.as_raw_fd()) };
        if directory.is_null() {
            return Err(io::Error::last_os_error());
        }
        // fdopendir owns the descriptor only on success; DirectoryStream closes it.
        let _ = file.into_raw_fd();
        let directory = DirectoryStream(directory);
        loop {
            unsafe {
                *errno() = 0;
            }
            let entry = unsafe { libc::readdir(directory.0) };
            if entry.is_null() {
                if unsafe { *errno() } != 0 {
                    return Err(io::Error::last_os_error());
                }
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name == c"." || name == c".." {
                continue;
            }
            visitor(name)?;
        }
        Ok(())
    }

    pub fn remove_directory(&self, name: &str) -> io::Result<()> {
        let directory = self.directory(name)?;
        // This tree is receiver-created in a private root, never an arbitrary source.
        for child in directory.names(MAX_ENTRIES)? {
            if directory.source(&child)?.metadata()?.is_dir() {
                directory.remove_directory(&child)?;
                continue;
            }
            directory.unlink(&child, 0)?;
        }
        self.unlink(name, libc::AT_REMOVEDIR)
    }

    fn unlink(&self, name: &str, flags: i32) -> io::Result<()> {
        let name = component(name)?;
        if unsafe { libc::unlinkat(self.0.as_raw_fd(), name.as_ptr(), flags) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn filesystem_identity(file: &File) -> io::Result<FilesystemIdentity> {
    // Linux 6.9+ FS_IOC_GETFSUUID returns the filesystem's complete external
    // UUID from this descriptor. f_fsid folds ext4's UUID to only 64 bits.
    #[repr(C)]
    struct FsUuid {
        len: u8,
        uuid: [u8; 16],
    }
    let mut uuid = FsUuid {
        len: 0,
        uuid: [0; 16],
    };
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::_IOR::<FsUuid>(0x15, 0), &mut uuid) } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "filesystem_identity_unavailable",
        ));
    }
    require((1..=16).contains(&uuid.len), "invalid_filesystem_identity")?;
    let uuid = uuid.uuid[..usize::from(uuid.len)].to_vec();
    require(
        uuid.iter().any(|byte| *byte != 0),
        "invalid_filesystem_identity",
    )?;
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(file.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FilesystemIdentity::Linux {
        kind: unsafe { stats.assume_init() }.f_type as i64,
        uuid,
    })
}

#[cfg(target_os = "macos")]
fn filesystem_identity(file: &File) -> io::Result<FilesystemIdentity> {
    #[repr(C)]
    struct Attributes {
        length: u32,
        returned: libc::attribute_set_t,
        uuid: [u8; 16],
    }
    let mut request: libc::attrlist = unsafe { std::mem::zeroed() };
    request.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
    request.commonattr = libc::ATTR_CMN_RETURNED_ATTRS;
    request.volattr = libc::ATTR_VOL_INFO | libc::ATTR_VOL_UUID;
    let mut value: Attributes = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fgetattrlist(
            file.as_raw_fd(),
            (&mut request as *mut libc::attrlist).cast(),
            (&mut value as *mut Attributes).cast(),
            std::mem::size_of::<Attributes>(),
            0,
        )
    } != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "filesystem_identity_unavailable",
        ));
    }
    require(
        value.length as usize == std::mem::size_of::<Attributes>()
            && value.returned.volattr & libc::ATTR_VOL_UUID != 0
            && value.uuid.iter().any(|byte| *byte != 0),
        "invalid_filesystem_identity",
    )?;
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(file.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let stats = unsafe { stats.assume_init() };
    let kind = unsafe { CStr::from_ptr(stats.f_fstypename.as_ptr()) }
        .to_str()
        .map_err(|_| invalid("invalid_filesystem_identity"))?
        .to_owned();
    Ok(FilesystemIdentity::MacOs {
        kind,
        uuid: value.uuid,
    })
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}

#[cfg(target_os = "linux")]
unsafe fn errno() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

#[cfg(target_os = "macos")]
unsafe fn errno() -> *mut libc::c_int {
    unsafe { libc::__error() }
}

fn component(name: &str) -> io::Result<CString> {
    require(
        !name.is_empty() && name != "." && name != ".." && !name.contains('/'),
        "invalid_component",
    )?;
    CString::new(name).map_err(|_| invalid("invalid_component"))
}

#[cfg(test)]
mod tests {
    use super::Directory;

    #[test]
    fn private_cleanup_supports_every_valid_transfer_directory() {
        let root = std::env::temp_dir().join(format!(
            "oblivion-cleanup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let directory = Directory::open(&root).unwrap();
        let pending = directory.create_directory("pending").unwrap();
        for index in 0..4097 {
            pending.create_file(&format!("file-{index}")).unwrap();
        }
        directory.create_file("keep").unwrap();
        directory.remove_directory("pending").unwrap();
        assert!(!root.join("pending").exists());
        assert!(root.join("keep").is_file());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exclusive_move_cannot_replace_an_existing_empty_directory() {
        let root = std::env::temp_dir().join(format!(
            "oblivion-exclusive-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let directory = Directory::open(&root).unwrap();
        directory.create_directory("source").unwrap();
        directory.create_directory("destination").unwrap();
        assert_eq!(
            directory
                .move_exclusive("source", &directory, "destination")
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert!(root.join("source").is_dir());
        assert!(root.join("destination").is_dir());
        directory
            .move_exclusive("source", &directory, "unused")
            .unwrap();
        assert!(!root.join("source").exists());
        assert!(root.join("unused").is_dir());
        std::fs::remove_dir_all(root).unwrap();
    }
}
