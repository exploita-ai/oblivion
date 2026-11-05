//! Private terminal ownership handshake with the native manager.
use oblivion_host::control;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub(super) struct ManagerTerminal(UnixStream);

impl ManagerTerminal {
    pub(super) fn open() -> control::Result<Option<Self>> {
        if std::env::var("OBLIVION_MANAGER_HANDOFF").as_deref() != Ok("1")
            || std::env::args_os().nth(1).as_deref() != Some(std::ffi::OsStr::new("run"))
        {
            return Ok(None);
        }
        // The private descriptor belongs to this launcher, not its children.
        unsafe { std::env::remove_var("OBLIVION_MANAGER_HANDOFF"); }
        const FD: libc::c_int = 3;
        let flags = unsafe { libc::fcntl(FD, libc::F_GETFD) };
        if flags == -1 || unsafe { libc::fcntl(FD, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
            return Err("Manager terminal channel unavailable".into());
        }
        let socket = unsafe { UnixStream::from_raw_fd(FD) };
        socket.peer_addr()?;
        socket.set_nonblocking(false)?;
        socket.set_read_timeout(Some(Duration::from_secs(15)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        Ok(Some(Self(socket)))
    }

    pub(super) fn event(&self, event: u8) -> control::Result<()> {
        let mut socket = &self.0;
        socket.write_all(&[event])?;
        let mut ack = [0];
        socket.read_exact(&mut ack)?;
        if ack != [b'K'] {
            return Err("Manager terminal handoff was not acknowledged".into());
        }
        Ok(())
    }

    pub(super) fn prompt<T>(&self, read: impl FnOnce() -> control::Result<T>) -> control::Result<T> {
        self.event(b'P')?;
        let result = read();
        self.event(b'W')?;
        result
    }
}
