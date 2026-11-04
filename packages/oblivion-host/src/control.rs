use crate::channel::Channel;
use serde::Deserialize;
use serde_json::json;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    ok: bool,
    output: String,
    error: Option<String>,
}

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
    operation: &str,
    session: Option<&str>,
    secret: &[u8],
    expected: Option<&str>,
) -> Result<UnixStream> {
    if secret.len()
        > if operation == "share-import-begin" { oblivion_share::manifest::MAX_METADATA + 4096 } else if matches!(
            operation,
            "session-storage"
                | "egress"
                | "proxy-profiles"
                | "network-policy"
                | "transfers"
                | "onion"
                | "prepare-usb"
                | "safe-access"
                | "browse"
                | "share-export-source-open"
                | "share-import-open"
                | "share-import-finish"
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
    let header = serde_json::to_vec(
        &json!({"operation": operation, "session": session, "secret_len": secret.len(), "slot": crate::scope::current(), "expected_session": expected}),
    )?;
    channel.write_all(&(header.len() as u32).to_be_bytes())?;
    channel.write_all(&header)?;
    channel.write_all(secret)?;
    if !matches!(operation, "agent-attach" | "file-attach" | "share-attach" | "share-import-attach" | "share-export-lease") {
        stream.shutdown(std::net::Shutdown::Write)?;
    }
    Ok(stream)
}

pub fn request(operation: &str, session: Option<&str>, secret: &[u8]) -> Result<String> {
    request_expected(operation, session, secret, None)
}

pub fn request_for(
    expected: &str,
    operation: &str,
    session: Option<&str>,
    secret: &[u8],
) -> Result<String> {
    request_expected(operation, session, secret, Some(expected))
}

fn request_expected(
    operation: &str,
    session: Option<&str>,
    secret: &[u8],
    expected: Option<&str>,
) -> Result<String> {
    if let Some(path) = std::env::var_os("OBLIVION_CONTROL_SOCKET") {
        return crate::remote_control::request(
            std::path::Path::new(&path),
            operation,
            session,
            secret,
            expected,
        );
    }
    let stream = connect_expected(operation, session, secret, expected)?;
    response(Channel::new(
        &stream,
        Duration::from_secs(if operation == "session-storage" {
            1800
        } else if matches!(operation, "egress" | "proxy-profiles" | "start-agent" | "open-child-documents") {
            210
        } else {
            120
        }),
    ))
}

fn response(channel: Channel<'_>) -> Result<String> {
    let mut bytes = Vec::new();
    channel.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err("response_too_large".into());
    }
    let response: Response = serde_json::from_slice(&bytes)?;
    if !response.ok {
        // Protocol errors are static identifiers, never arbitrary guest text.
        let error = response.error.filter(|value| {
            value.len() <= 80 && value.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
        });
        return Err(error
            .unwrap_or_else(|| "operation_rejected".to_owned())
            .into());
    }
    Ok(response.output)
}

#[cfg(target_os = "linux")]
pub fn attach_client(operation: &str, expected: &str) -> Result<(UnixStream, UnixStream, String)> {
    attach_scoped(operation, None, Some(expected))
}

pub fn attach_export(id: &str) -> Result<(UnixStream, UnixStream, String)> {
    attach_scoped("share-export-lease", Some(id), None)
}

#[cfg(target_os = "linux")]
fn attach_scoped(operation: &str, session: Option<&str>, expected: Option<&str>) -> Result<(UnixStream, UnixStream, String)> {
    if let Some(path) = std::env::var_os("OBLIVION_CONTROL_SOCKET") {
        let (stream, client) = crate::remote_control::attach_scoped(std::path::Path::new(&path), operation, session, expected)?;
        return Ok((stream.try_clone()?, stream, client));
    }
    let stream = connect_expected(operation, session, &[], expected)?;
    let channel = Channel::new(&stream, Duration::from_secs(120));
    let console = receive_descriptor(&stream, &channel)?;
    // The control connection owns the attachment until EOF, independently of
    // the passed stream. A vanished launcher releases only this client.
    let mut client = [0; 32];
    Channel::new(&stream, Duration::from_secs(10)).read_exact(&mut client)?;
    if !client.iter().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)) {
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
    attach_scoped(operation, None, Some(expected))
}

#[cfg(not(target_os = "linux"))]
fn attach_scoped(operation: &str, session: Option<&str>, expected: Option<&str>) -> Result<(UnixStream, UnixStream, String)> {
    let path = std::env::var_os("OBLIVION_CONTROL_SOCKET").ok_or("native_runtime_required")?;
    let (stream, client) =
        crate::remote_control::attach_scoped(std::path::Path::new(&path), operation, session, expected)?;
    Ok((stream.try_clone()?, stream, client))
}

pub fn release_agent(client: &str, expected: &str) -> Result<()> {
    if let Some(path) = std::env::var_os("OBLIVION_CONTROL_SOCKET") {
        crate::remote_control::request(
            std::path::Path::new(&path),
            "agent-release",
            Some(client),
            &[],
            Some(expected),
        )?;
        return Ok(());
    }
    let stream = connect_expected("agent-release", Some(client), &[], Some(expected))?;
    response(Channel::new(&stream, Duration::from_secs(120)))?;
    Ok(())
}
