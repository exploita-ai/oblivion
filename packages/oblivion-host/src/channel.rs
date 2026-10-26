use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// QMP can stop accepting while its VM is suspended. A read deadline cannot
/// bound connect() itself once that Unix listener's backlog is full.
#[cfg(target_os = "linux")]
pub fn connect(path: &std::path::Path, budget: Duration) -> io::Result<UnixStream> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    address.sun_family = libc::AF_UNIX as _;
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = *byte as _;
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    // Linux applies SO_SNDTIMEO to connect as well as writes. On timeout the
    // unfinished socket is dropped; it is never handed to a QMP exchange.
    stream.set_write_timeout(Some(budget))?;
    if unsafe {
        libc::connect(
            stream.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            size_of::<libc::sockaddr_un>() as _,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    stream.set_write_timeout(None)?;
    Ok(stream)
}

/// One deadline for a complete exchange, including fragmented reads and writes.
/// A new exchange must construct a new Channel, never derive its budget from
/// the socket timeout left by the previous operation.
pub struct Channel<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
}

impl<'a> Channel<'a> {
    pub fn new(stream: &'a UnixStream, budget: Duration) -> Self {
        Self {
            stream,
            deadline: Instant::now() + budget,
        }
    }

    pub fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    }

    // Also used around the single-byte SCM_RIGHTS transfer. Its following
    // metadata response shares this Channel's deadline.
    pub fn prepare_read(&self) -> io::Result<()> {
        self.stream.set_read_timeout(Some(self.remaining()?))
    }

    pub fn prepare_write(&self) -> io::Result<()> {
        self.stream.set_write_timeout(Some(self.remaining()?))
    }
}

impl Read for Channel<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            self.prepare_read()?;
            let result = self.stream.read(bytes);
            self.remaining()?;
            match result {
                Err(error) if retry(&error) => continue,
                result => return result,
            }
        }
    }
}

impl Write for Channel<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            self.prepare_write()?;
            let result = self.stream.write(bytes);
            self.remaining()?;
            match result {
                Err(error) if retry(&error) => continue,
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.remaining().map(|_| ())
    }
}

fn retry(error: &io::Error) -> bool {
    // Socket timeout resolution differs across kernels. Retry an early kernel
    // timeout against the same monotonic deadline, never a fresh budget.
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}
