use crate::channel::Channel;
use oblivion_cli::controller::{Call, Controller};
use oblivion_wire::control::{Operation, Request};
use oblivion_wire::control_client::{self, Framing};
#[cfg(target_os = "linux")]
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn protect() -> Result<()> {
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
            return Err("dump_protection_failed".into());
        }
    }
    #[cfg(target_os = "linux")]
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
        return Err("dump_protection_failed".into());
    }
    Ok(())
}

fn connect_expected(
    operation: Operation,
    session: Option<&str>,
    secret: &[u8],
    expected: Option<&str>,
) -> Result<UnixStream> {
    if secret.len()
        > if operation == Operation::FamilyPasswordChange {
            crate::family_rotation::CHANGE_LIMIT
        } else if operation == Operation::ShareImportBegin {
            oblivion_share::manifest::MAX_METADATA + 4096
        } else if matches!(
            operation,
            Operation::SessionStorage
                | Operation::FamilyPasswordRecover
                | Operation::Egress
                | Operation::ProxyProfiles
                | Operation::NetworkPolicy
                | Operation::Transfers
                | Operation::Onion
                | Operation::SafeAccess
                | Operation::Browse
                | Operation::ShareExportSourceOpen
                | Operation::ShareImportOpen
                | Operation::ShareImportFinish
                | Operation::BackupImportFinish
        ) {
            4096
        } else {
            1024
        }
    {
        return Err("secret_too_large".into());
    }
    let stream = UnixStream::connect("/run/oblivion-control.sock")?;
    #[cfg(target_os = "linux")]
    unsafe {
        use std::os::fd::AsRawFd;
        let mut peer = std::mem::MaybeUninit::<libc::ucred>::uninit();
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            peer.as_mut_ptr().cast(),
            &mut length,
        ) != 0
            || peer.assume_init().uid != 0
        {
            return Err("untrusted_controller".into());
        }
    }
    let mut channel = Channel::new(&stream, Duration::from_secs(10));
    let request = Request {
        operation,
        session: session.map(str::to_owned),
        secret_len: secret.len() as u32,
        slot: crate::scope::current(),
        expected_session: expected.map(str::to_owned),
    };
    control_client::write_request(&mut channel, &request, secret, Framing::Local)
        .map_err(control_client::Error::into_boxed)?;
    if !matches!(
        operation,
        Operation::AgentAttach
            | Operation::FileAttach
            | Operation::ShareAttach
            | Operation::ShareImportAttach
            | Operation::ShareExportLease
            | Operation::BackupAttach
    ) {
        stream.shutdown(std::net::Shutdown::Write)?;
    }
    Ok(stream)
}

/// Real Unix controller adapter used by the shared frontend and existing CLI
/// boundaries. Explicit remote construction also avoids global environment in
/// integrations which already own the authenticated runtime endpoint.
pub struct Client {
    remote: Option<std::path::PathBuf>,
}

impl Client {
    pub fn new() -> Self {
        match std::env::var_os("OBLIVION_CONTROL_SOCKET") {
            Some(path) => Self::remote(std::path::PathBuf::from(path)),
            None => Self { remote: None },
        }
    }

    pub fn remote(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            remote: Some(path.into()),
        }
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Controller for Client {
    type Slot = crate::scope::Slot;

    fn request(&mut self, call: Call<'_, Self::Slot>) -> Result<String> {
        let request = || match self.remote.as_deref() {
            Some(path) => crate::remote_control::request_operation(
                path,
                call.operation,
                call.session,
                call.secret,
                call.expected_session,
            ),
            None => request_local(
                call.operation,
                call.session,
                call.secret,
                call.expected_session,
            ),
        };
        match call.slot {
            Some(slot) => crate::scope::within(slot, request),
            None => request(),
        }
    }
}

pub fn request(operation: &str, session: Option<&str>, secret: &[u8]) -> Result<String> {
    Client::new().request(Call {
        operation: Operation::parse(operation)?,
        slot: None,
        session,
        expected_session: None,
        secret,
    })
}

pub fn request_for(
    expected: &str,
    operation: &str,
    session: Option<&str>,
    secret: &[u8],
) -> Result<String> {
    Client::new().request(Call {
        operation: Operation::parse(operation)?,
        slot: None,
        session,
        expected_session: Some(expected),
        secret,
    })
}

fn request_local(
    operation: Operation,
    session: Option<&str>,
    secret: &[u8],
    expected: Option<&str>,
) -> Result<String> {
    let stream = connect_expected(operation, session, secret, expected)?;
    control_client::read_response(
        &mut Channel::new(
            &stream,
            Duration::from_secs(if operation == Operation::SessionStorage {
                1800
            } else if matches!(
                operation,
                Operation::Egress
                    | Operation::ProxyProfiles
                    | Operation::StartAgent
                    | Operation::OpenChildDocuments
                    | Operation::BackupExportBegin
                    | Operation::BackupImportFinish
                    | Operation::FamilyPasswordChange
                    | Operation::FamilyPasswordRecover
            ) {
                210
            } else {
                120
            }),
        ),
        Framing::Local,
    )
    .map_err(control_client::Error::into_boxed)
}

#[cfg(target_os = "linux")]
pub fn attach_client(operation: &str, expected: &str) -> Result<(UnixStream, UnixStream, String)> {
    attach_scoped(operation, None, Some(expected), &[])
}

pub fn attach_export(id: &str) -> Result<(UnixStream, UnixStream, String)> {
    attach_scoped("share-export-lease", Some(id), None, &[])
}

pub fn attach_file(opening: &crate::autolock::Opening) -> Result<(UnixStream, UnixStream, String)> {
    attach_scoped(
        "file-attach",
        None,
        Some(&opening.safe_id),
        &serde_json::to_vec(opening)?,
    )
}

pub fn attach_backup(transaction: &str) -> Result<(UnixStream, UnixStream, String)> {
    attach_scoped("backup-attach", Some(transaction), None, &[])
}

#[cfg(target_os = "linux")]
fn attach_scoped(
    operation: &str,
    session: Option<&str>,
    expected: Option<&str>,
    secret: &[u8],
) -> Result<(UnixStream, UnixStream, String)> {
    if let Some(path) = std::env::var_os("OBLIVION_CONTROL_SOCKET") {
        let (stream, client) = crate::remote_control::attach_scoped_with_secret(
            std::path::Path::new(&path),
            operation,
            session,
            expected,
            secret,
        )?;
        return Ok((stream.try_clone()?, stream, client));
    }
    let stream = connect_expected(Operation::parse(operation)?, session, secret, expected)?;
    let channel = Channel::new(&stream, Duration::from_secs(120));
    let console = receive_descriptor(&stream, &channel)?;
    // The control connection owns the attachment until EOF, independently of
    // the passed stream. A vanished launcher releases only this client.
    let mut client = [0; 32];
    Channel::new(&stream, Duration::from_secs(10)).read_exact(&mut client)?;
    if !client
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err("invalid_client_identifier".into());
    }
    Ok((console, stream, String::from_utf8(client.to_vec())?))
}

#[cfg(target_os = "linux")]
fn receive_descriptor(stream: &UnixStream, channel: &Channel<'_>) -> Result<UnixStream> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let mut byte = 0u8;
    let mut data = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut data;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control);
    channel.prepare_read()?;
    unsafe {
        if libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) != 1 {
            return Err("console_transfer_failed".into());
        }
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null()
            || (*header).cmsg_level != libc::SOL_SOCKET
            || (*header).cmsg_type != libc::SCM_RIGHTS
            || (*header).cmsg_len != libc::CMSG_LEN(4) as usize
        {
            return Err("console_transfer_failed".into());
        }
        let fd = OwnedFd::from_raw_fd(std::ptr::read_unaligned(
            libc::CMSG_DATA(header).cast::<i32>(),
        ));
        if byte != b'F' || message.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err("console_transfer_failed".into());
        }
        Ok(UnixStream::from(fd))
    }
}

#[cfg(not(target_os = "linux"))]
pub fn attach_client(operation: &str, expected: &str) -> Result<(UnixStream, UnixStream, String)> {
    attach_scoped(operation, None, Some(expected), &[])
}

#[cfg(not(target_os = "linux"))]
fn attach_scoped(
    operation: &str,
    session: Option<&str>,
    expected: Option<&str>,
    secret: &[u8],
) -> Result<(UnixStream, UnixStream, String)> {
    let path = std::env::var_os("OBLIVION_CONTROL_SOCKET").ok_or("native_runtime_required")?;
    let (stream, client) = crate::remote_control::attach_scoped_with_secret(
        std::path::Path::new(&path),
        operation,
        session,
        expected,
        secret,
    )?;
    Ok((stream.try_clone()?, stream, client))
}

pub fn release_agent(client: &str, expected: &str) -> Result<()> {
    request_for(expected, "agent-release", Some(client), &[]).map(|_| ())
}
