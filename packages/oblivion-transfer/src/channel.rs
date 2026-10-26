use crate::require;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::time::{Duration, Instant};

/// A dedicated socket, pipe or virtio-serial file with one monotonic deadline.
/// Takes ownership and enables nonblocking I/O on its open file description.
/// Use a new descriptor/exchange after failure; never retry a partial transfer.
pub struct Channel {
    file: File,
    deadline: Instant,
    watches: Vec<OwnedFd>,
}

impl Channel {
    pub fn new(file: File, budget: Duration) -> io::Result<Self> {
        let deadline = Instant::now()
            .checked_add(budget)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        Self::until(file, deadline)
    }

    /// Several channels in one exchange share this absolute deadline.
    pub fn until(file: File, deadline: Instant) -> io::Result<Self> {
        let kind = file.metadata()?.file_type();
        require(
            kind.is_socket() || kind.is_fifo() || kind.is_char_device(),
            "invalid_channel",
        )?;
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            file,
            deadline,
            watches: Vec::new(),
        })
    }

    /// Any readable data, closure or error revokes the channel. Used for pidfds
    /// and for the trusted controller's cancellation connection; never drained.
    pub fn watch(&mut self, descriptor: OwnedFd) {
        self.watches.push(descriptor);
    }

    pub fn check(&self) -> io::Result<()> {
        self.remaining()?;
        let mut watches: Vec<_> = self
            .watches
            .iter()
            .map(|fd| libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        loop {
            let result = unsafe { libc::poll(watches.as_mut_ptr(), watches.len() as _, 0) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    self.remaining()?;
                    continue;
                }
                return Err(error);
            }
            return not_revoked(&watches);
        }
    }

    pub fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    }

    fn ready(&self, events: libc::c_short) -> io::Result<()> {
        loop {
            let timeout = self
                .remaining()?
                .as_millis()
                .saturating_add(1)
                .min(i32::MAX as u128) as i32;
            let mut descriptors = vec![libc::pollfd {
                fd: self.file.as_raw_fd(),
                events,
                revents: 0,
            }];
            descriptors.extend(self.watches.iter().map(|fd| libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }));
            let result =
                unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, timeout) };
            self.remaining()?;
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if result == 0 {
                continue;
            }
            // Revocation wins even when data and cancellation become ready
            // together, including a dead owner with buffered transport data.
            not_revoked(&descriptors[1..])?;
            let descriptor = &descriptors[0];
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            // HUP/ERR still need a read/write: buffered data, EOF and a permanent
            // transport error must not be confused with a deadline expiration.
            if descriptor.revents & (events | libc::POLLHUP | libc::POLLERR) != 0 {
                return Ok(());
            }
        }
    }
}

impl Read for Channel {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.ready(libc::POLLIN)?;
            let result = self.file.read(bytes);
            self.check()?;
            match result {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }
}

impl Write for Channel {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.ready(libc::POLLOUT)?;
            let result = self.file.write(bytes);
            self.check()?;
            match result {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check()
    }
}

fn not_revoked(watches: &[libc::pollfd]) -> io::Result<()> {
    if watches.iter().any(|fd| fd.revents != 0) {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "transfer_revoked",
        ));
    }
    Ok(())
}
