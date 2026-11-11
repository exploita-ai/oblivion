use crate::{Error, Result};
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

pub struct Endpoint {
    listener: Option<UnixListener>,
    path: PathBuf,
    _lock: File,
    inode: u64,
}

impl Endpoint {
    pub fn bind(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .ok_or(Error("private_control_directory_required"))?;
        let info = fs::symlink_metadata(parent)
            .map_err(|_| Error("private_control_directory_required"))?;
        if !info.is_dir() || info.uid() != unsafe { libc::getuid() } || info.mode() & 0o077 != 0 {
            return Err(Error("private_control_directory_required"));
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(sidecar(path, ".lock"))
            .map_err(|_| Error("runtime_lock_failed"))?;
        let info = lock.metadata().map_err(|_| Error("runtime_lock_failed"))?;
        if !info.is_file()
            || info.uid() != unsafe { libc::getuid() }
            || info.mode() & 0o077 != 0
            || info.nlink() != 1
            || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
        {
            return Err(Error("runtime_already_running"));
        }
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err(Error("runtime_socket_recovery_required")),
            Err(_) => return Err(Error("control_socket_failed")),
        }
        let listener = UnixListener::bind(path).map_err(|_| Error("control_socket_failed"))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| Error("control_socket_failed"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| Error("control_socket_failed"))?;
        let inode = fs::symlink_metadata(path)
            .map_err(|_| Error("control_socket_failed"))?
            .ino();
        Ok(Self {
            listener: Some(listener),
            path: path.to_owned(),
            _lock: lock,
            inode,
        })
    }

    pub fn accept(&self) -> Result<Option<UnixStream>> {
        let Some(listener) = &self.listener else {
            return Ok(None);
        };
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(_) => return Err(Error("control_socket_failed")),
        };
        if peer_uid(&stream)? != unsafe { libc::getuid() } {
            return Err(Error("untrusted_control_peer"));
        }
        Ok(Some(stream))
    }

    pub fn stop_admission(&mut self) {
        self.listener.take();
    }
}

pub fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|info| info.file_type().is_socket() && info.ino() == self.inode)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn peer_uid(stream: &UnixStream) -> Result<u32> {
    #[cfg(target_os = "linux")]
    unsafe {
        let mut peer = std::mem::MaybeUninit::<libc::ucred>::uninit();
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            peer.as_mut_ptr().cast(),
            &mut length,
        ) != 0
        {
            return Err(Error("control_peer_check_failed"));
        }
        Ok(peer.assume_init().uid)
    }
    #[cfg(target_os = "macos")]
    unsafe {
        let mut uid = 0;
        let mut gid = 0;
        if libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) != 0 {
            return Err(Error("control_peer_check_failed"));
        }
        Ok(uid)
    }
}
