use crate::{Error, Result};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

const BUFFER: usize = 65536;

struct Pending {
    bytes: Zeroizing<Vec<u8>>,
    start: usize,
    end: usize,
}
impl Pending {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(vec![0; BUFFER]),
            start: 0,
            end: 0,
        }
    }
    fn readable(&self) -> &[u8] {
        &self.bytes[self.start..self.end]
    }
    fn writable(&mut self) -> &mut [u8] {
        if self.end == BUFFER && self.start != 0 {
            self.bytes.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        &mut self.bytes[self.end..]
    }
    fn consume(&mut self, length: usize) {
        self.start += length;
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
    }
}

/// Transport EOF closes both directions, releasing the controller lease.
/// Native stdin EOF is a framed message and never a transport half-close.
pub fn duplex(local: UnixStream, guest: UnixStream, stop: Arc<AtomicBool>) -> Result<()> {
    let result = transfer(&local, &guest, &stop, None);
    let _ = local.shutdown(Shutdown::Both);
    let _ = guest.shutdown(Shutdown::Both);
    result
}

/// A media caller uses write EOF to end its source stream and awaits a
/// teardown receipt on the same local socket. Keep that socket writable.
#[cfg(target_os = "linux")]
pub(crate) fn media_source(
    local: &UnixStream,
    source: UnixStream,
    reservation: &UnixStream,
    stop: &AtomicBool,
) -> Result<()> {
    let result = transfer(local, &source, stop, Some(reservation));
    let _ = source.shutdown(Shutdown::Both);
    result
}

fn transfer(
    local: &UnixStream,
    guest: &UnixStream,
    stop: &AtomicBool,
    reservation: Option<&UnixStream>,
) -> Result<()> {
    local
        .set_nonblocking(true)
        .map_err(|_| Error("bridge_setup_failed"))?;
    guest
        .set_nonblocking(true)
        .map_err(|_| Error("bridge_setup_failed"))?;
    let mut to_guest = Pending::new();
    let mut to_local = Pending::new();
    let mut guest_closed = false;
    while !stop.load(Ordering::Relaxed) {
        if guest_closed && to_local.readable().is_empty() {
            return Ok(());
        }
        let mut polls = [
            libc::pollfd {
                fd: local.as_raw_fd(),
                events: (if guest_closed || to_guest.writable().is_empty() {
                    0
                } else {
                    libc::POLLIN
                }) | (if to_local.readable().is_empty() {
                    0
                } else {
                    libc::POLLOUT
                }),
                revents: 0,
            },
            libc::pollfd {
                fd: if guest_closed
                    || to_local.writable().is_empty() && to_guest.readable().is_empty()
                {
                    -1
                } else {
                    guest.as_raw_fd()
                },
                events: (if to_local.writable().is_empty() {
                    0
                } else {
                    libc::POLLIN
                }) | (if to_guest.readable().is_empty() {
                    0
                } else {
                    libc::POLLOUT
                }),
                revents: 0,
            },
            libc::pollfd {
                fd: reservation.map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as _, 100) } < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error("bridge_failed"));
        }
        if polls[2].revents != 0 {
            return Err(Error("live_media_reservation_lost"));
        }
        for (index, mut source, destination) in
            [(0, local, &mut to_guest), (1, guest, &mut to_local)]
        {
            if polls[index].revents & (libc::POLLERR | libc::POLLNVAL) != 0
                || index == 0 && polls[index].revents & libc::POLLHUP != 0
            {
                return Ok(());
            }
            if polls[index].revents & (libc::POLLIN | libc::POLLHUP) == 0 {
                continue;
            }
            // POLLHUP is reported even without POLLIN. Reading into a full
            // buffer returns zero without observing EOF and loses the tail.
            if destination.writable().is_empty() {
                continue;
            }
            match source.read(destination.writable()) {
                Ok(0) if index == 1 => guest_closed = true,
                Ok(0) => return Ok(()),
                Ok(length) => destination.end += length,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(Error("bridge_failed")),
            }
        }
        for (index, mut destination, source) in
            [(0, local, &mut to_local), (1, guest, &mut to_guest)]
        {
            if polls[index].revents & libc::POLLOUT == 0 {
                continue;
            }
            match destination.write(source.readable()) {
                Ok(0) => return Ok(()),
                Ok(length) => source.consume(length),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(Error("bridge_failed")),
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn connect_guest(cid: u32, port: u32) -> Result<UnixStream> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let socket = unsafe {
        libc::socket(
            libc::AF_VSOCK,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if socket < 0 {
        return Err(Error("vsock_unavailable"));
    }
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };
    let address = libc::sockaddr_vm {
        svm_family: libc::AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: cid,
        svm_zero: [0; 4],
    };
    let connected = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_vm).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if connected != 0 {
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(Error("guest_control_unavailable"));
        }
        let mut poll = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 3000) } <= 0 {
            return Err(Error("guest_control_unavailable"));
        }
        let mut error = 0;
        let mut size = std::mem::size_of::<i32>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut error as *mut i32).cast(),
                &mut size,
            )
        } != 0
            || error != 0
        {
            return Err(Error("guest_control_unavailable"));
        }
    }
    // UnixStream is used only as an owned read/write stream, never for Unix
    // addressing APIs. The descriptor remains an AF_VSOCK socket.
    Ok(unsafe { UnixStream::from_raw_fd(std::os::fd::IntoRawFd::into_raw_fd(socket)) })
}

#[cfg(not(target_os = "linux"))]
pub fn connect_guest(_: u32, _: u32) -> Result<UnixStream> {
    Err(Error("linux_required"))
}
