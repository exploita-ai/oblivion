//! Length-framed native launcher transport over the private VZ Unix socket.
//! The Debian relay preserves descriptor ownership without exposing the host's
//! network or a filesystem share to a Safe.

use crate::channel::Channel;
use crate::control::Result;
use serde::Deserialize;
use serde_json::json;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    ok: bool,
    output: String,
    error: Option<String>,
}

pub fn request(
    path: &Path,
    operation: &str,
    session: Option<&str>,
    secret: &[u8],
    expected: Option<&str>,
) -> Result<String> {
    let stream = connect(path, operation, session, secret, expected)?;
    read_response(&stream, operation)
}

pub fn attach_agent(path: &Path, expected: &str) -> Result<(UnixStream, String)> {
    let stream = connect(path, "agent-attach", None, &[], Some(expected))?;
    let client = read_response(&stream, "agent-attach")?;
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
    operation: &str,
    session: Option<&str>,
    secret: &[u8],
    expected: Option<&str>,
) -> Result<UnixStream> {
    if secret.len() > 4096 {
        return Err("secret_too_large".into());
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("untrusted_runtime_socket".into());
    }
    let stream = UnixStream::connect(path)?;
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
    let header = serde_json::to_vec(&json!({
        "version": 1,
        "operation": operation,
        "session": session,
        "secret_len": secret.len(),
        "slot": crate::scope::current(),
        "expected_session": expected,
    }))?;
    if header.len() > 1024 {
        return Err("header_too_large".into());
    }
    let mut channel = Channel::new(&stream, Duration::from_secs(10));
    channel.write_all(&(header.len() as u32).to_be_bytes())?;
    channel.write_all(&header)?;
    channel.write_all(secret)?;
    Ok(stream)
}

fn read_response(stream: &UnixStream, operation: &str) -> Result<String> {
    let mut channel = Channel::new(
        stream,
        Duration::from_secs(if operation == "session-storage" {
            1800
        } else {
            120
        }),
    );
    let mut length = [0; 4];
    channel.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if !(1..=1024 * 1024).contains(&length) {
        return Err("invalid_response_length".into());
    }
    let mut bytes = vec![0; length];
    channel.read_exact(&mut bytes)?;
    let response: Response = serde_json::from_slice(&bytes)?;
    if !response.ok {
        let error = response.error.filter(|value| {
            value.len() <= 80
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        });
        return Err(error
            .unwrap_or_else(|| "operation_rejected".to_owned())
            .into());
    }
    Ok(response.output)
}
