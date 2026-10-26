use crate::{invalid, require};
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// All peer paths are resolved one component at a time from pinned descriptors.
pub(crate) struct Directory(File);

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
        for child in directory.names(4096)? {
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
