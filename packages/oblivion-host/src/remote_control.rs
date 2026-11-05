//! Length-framed native launcher transport over the private VZ Unix socket.
//! The Debian relay preserves descriptor ownership without exposing the host's
//! network or a filesystem share to a Safe.

use crate::channel::Channel;
use crate::control::Result;
use oblivion_wire::control::{Operation, Request};
use oblivion_wire::control_client::{self, Framing};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

pub fn request(
    path: &Path,
    operation: &str,
    session: Option<&str>,
    secret: &[u8],
    expected: Option<&str>,
) -> Result<String> {
    request_operation(
        path,
        Operation::parse(operation)?,
        session,
        secret,
        expected,
    )
}

pub(crate) fn request_operation(
    path: &Path,
    operation: Operation,
    session: Option<&str>,
    secret: &[u8],
    expected: Option<&str>,
) -> Result<String> {
    let stream = connect(
        path,
        operation,
        session,
        secret,
        expected,
        Duration::from_secs(10),
    )?;
    read_response(&stream, operation)
}

/// One total budget across connection, request transmission and response.
/// The supervisor uses this after releasing its lifecycle registry lock.
pub fn request_with_budget(
    path: &Path,
    operation: &str,
    session: Option<&str>,
    secret: &[u8],
    expected: Option<&str>,
    budget: Duration,
) -> Result<String> {
    let deadline = Instant::now() + budget;
    let stream = connect(
        path,
        Operation::parse(operation)?,
        session,
        secret,
        expected,
        budget,
    )?;
    read_response_with_budget(&stream, remaining(deadline)?)
}

/// A startup probe shares one short deadline across connection and response.
/// Normal control operations retain their full operation-specific budgets.
pub fn probe(path: &Path, budget: Duration) -> Result<String> {
    request_with_budget(path, "status", None, &[], None, budget)
}

pub fn attach(path: &Path, operation: &str, expected: &str) -> Result<(UnixStream, String)> {
    attach_scoped(path, operation, None, Some(expected))
}

pub fn attach_scoped(
    path: &Path,
    operation: &str,
    session: Option<&str>,
    expected: Option<&str>,
) -> Result<(UnixStream, String)> {
    attach_scoped_with_secret(path, operation, session, expected, &[])
}

pub fn attach_scoped_with_secret(
    path: &Path,
    operation: &str,
    session: Option<&str>,
    expected: Option<&str>,
    secret: &[u8],
) -> Result<(UnixStream, String)> {
    let operation = Operation::parse(operation).map_err(|_| "invalid_attachment")?;
    if !operation.is_attachment() {
        return Err("invalid_attachment".into());
    }
    let stream = connect(
        path,
        operation,
        session,
        secret,
        expected,
        Duration::from_secs(10),
    )?;
    let client = read_response(&stream, operation)?;
    if client.len() != 32 || !client.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid_client_id".into());
    }
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    // Transport close releases the relay's local controller lease. stdin EOF is
    // an agent-channel frame, never a half-close of this ownership connection.
    Ok((stream, client))
}

fn connect(
    path: &Path,
    operation: Operation,
    session: Option<&str>,
    secret: &[u8],
    expected: Option<&str>,
    budget: Duration,
) -> Result<UnixStream> {
    let deadline = Instant::now() + budget;
    if secret.len() > operation.native_secret_limit() {
        return Err("secret_too_large".into());
    }
    let stream = connect_peer(path, remaining(deadline)?)?;
    let request = Request {
        operation,
        session: session.map(str::to_owned),
        secret_len: secret.len() as u32,
        slot: crate::scope::current(),
        expected_session: expected.map(str::to_owned),
    };
    let mut channel = Channel::new(&stream, remaining(deadline)?);
    control_client::write_request(&mut channel, &request, secret, Framing::Native)
        .map_err(control_client::Error::into_boxed)?;
    Ok(stream)
}

/// Authenticate the local runtime socket before a caller sends any data.
pub fn connect_peer(path: &Path, budget: Duration) -> Result<UnixStream> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("untrusted_runtime_socket".into());
    }
    let stream = connect_socket(path, budget)?;
    #[cfg(target_os = "macos")]
    unsafe {
        let mut uid = 0;
        let mut gid = 0;
        if libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) != 0 || uid != libc::getuid() {
            return Err("untrusted_runtime_peer".into());
        }
    }
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
            || peer.assume_init().uid != libc::getuid()
        {
            return Err("untrusted_runtime_peer".into());
        }
    }
    Ok(stream)
}

fn read_response(stream: &UnixStream, operation: Operation) -> Result<String> {
    read_response_with_budget(
        stream,
        operation.response_budget(),
    )
}

fn read_response_with_budget(stream: &UnixStream, budget: Duration) -> Result<String> {
    control_client::read_response(&mut Channel::new(stream, budget), Framing::Native)
        .map_err(control_client::Error::into_boxed)
}

fn remaining(deadline: Instant) -> std::io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or_else(|| std::io::ErrorKind::TimedOut.into())
}

fn connect_socket(path: &Path, budget: Duration) -> std::io::Result<UnixStream> {
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    address.sun_family = libc::AF_UNIX as _;
    #[cfg(target_os = "macos")]
    {
        address.sun_len = std::mem::size_of::<libc::sockaddr_un>() as _;
    }
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = *byte as _;
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    stream.set_nonblocking(true)?;
    let deadline = Instant::now() + budget;
    if unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of_val(&address) as _,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::EINPROGRESS) | Some(libc::EWOULDBLOCK)
        ) {
            return Err(error);
        }
        loop {
            let mut event = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            let millis = remaining(deadline)?
                .as_millis()
                .max(1)
                .min(i32::MAX as u128) as i32;
            let ready = unsafe { libc::poll(&mut event, 1, millis) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            if let Some(error) = stream.take_error()? {
                return Err(error);
            }
            break;
        }
    }
    stream.set_nonblocking(false)?;
    Ok(stream)
}
