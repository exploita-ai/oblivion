//! An inherited private socket binds this helper to its owning supervisor.
use crate::{Error, Result};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;

pub struct Lifetime(UnixStream);

impl Lifetime {
    /// The CLI accepts only descriptor 3. Claim it before opening configuration
    /// files, and prevent all later execs from inheriting this endpoint.
    pub fn inherited() -> Result<Self> {
        if unsafe { libc::fcntl(3, libc::F_GETFD) } < 0 {
            return Err(Error("supervisor_lifetime_required"));
        }
        Self::new(unsafe { UnixStream::from_raw_fd(3) })
    }

    pub fn new(stream: UnixStream) -> Result<Self> {
        let fd = stream.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0 {
            return Err(Error("supervisor_lifetime_required"));
        }
        let mut kind = 0_i32;
        let mut length = std::mem::size_of_val(&kind) as libc::socklen_t;
        let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut address_length = std::mem::size_of_val(&address) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut kind as *mut i32).cast(),
                &mut length,
            )
        } != 0
            || kind != libc::SOCK_STREAM
            || unsafe {
                libc::getsockname(
                    fd,
                    (&mut address as *mut libc::sockaddr_storage).cast(),
                    &mut address_length,
                )
            } != 0
            || address.ss_family as i32 != libc::AF_UNIX
        {
            return Err(Error("supervisor_lifetime_required"));
        }
        let value = Self(stream);
        value.check()?;
        Ok(value)
    }

    pub fn check(&self) -> Result<()> {
        let mut byte = 0_u8;
        loop {
            let received = unsafe {
                libc::recv(
                    self.0.as_raw_fd(),
                    (&mut byte as *mut u8).cast(),
                    1,
                    libc::MSG_PEEK | libc::MSG_DONTWAIT,
                )
            };
            if received >= 0 {
                // No application data is valid on this socket: EOF and a byte
                // both revoke the supervisor's lifetime capability.
                return Err(Error("supervisor_lifetime_lost"));
            }
            match std::io::Error::last_os_error().kind() {
                std::io::ErrorKind::WouldBlock => return Ok(()),
                std::io::ErrorKind::Interrupted => continue,
                _ => return Err(Error("supervisor_lifetime_lost")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Lifetime;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
    use std::os::unix::net::{UnixDatagram, UnixStream};

    #[test]
    fn supervisor_eof_and_data_revoke_the_owned_endpoint() {
        let (supervisor, child) = UnixStream::pair().unwrap();
        let lifetime = Lifetime::new(child).unwrap();
        assert!(lifetime.check().is_ok());
        drop(supervisor);
        // A concurrent test's fork can retain the peer until exec closes its
        // CLOEXEC descriptors. Wait for actual EOF readiness, not drop timing.
        let mut ready = libc::pollfd {
            fd: lifetime.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut ready, 1, 2000) },
            1,
            "supervisor endpoint did not become ready after its owner closed"
        );
        assert_ne!(ready.revents & (libc::POLLIN | libc::POLLHUP), 0);
        assert_eq!(
            lifetime.check().err().unwrap().0,
            "supervisor_lifetime_lost"
        );
        let (mut supervisor, child) = UnixStream::pair().unwrap();
        let lifetime = Lifetime::new(child).unwrap();
        supervisor.write_all(b"x").unwrap();
        assert_eq!(
            lifetime.check().err().unwrap().0,
            "supervisor_lifetime_lost"
        );
    }

    #[test]
    fn child_exec_cannot_inherit_the_lifetime_endpoint() {
        let (_supervisor, child) = UnixStream::pair().unwrap();
        let fd = child.as_raw_fd();
        unsafe {
            libc::fcntl(fd, libc::F_SETFD, 0);
        }
        let lifetime = Lifetime::new(child).unwrap();
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        assert!(lifetime.check().is_ok());
    }
    #[test]
    fn inherited_capability_must_be_a_stream_socket() {
        let (_parent, child) = UnixDatagram::pair().unwrap();
        let stream = unsafe { UnixStream::from_raw_fd(child.into_raw_fd()) };
        assert_eq!(
            Lifetime::new(stream).err().unwrap().0,
            "supervisor_lifetime_required"
        );
    }
}
