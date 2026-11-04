//! AF_VSOCK host CID2 is not a Unix-user identity. Every connection proves
//! a per-boot token provisioned over a private, ready-gated virtio serial port.

use crate::{Error, Result};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const READY: &[u8; 8] = b"OBLVPRV1";
pub const SET: &[u8; 8] = b"OBLVSET1";
pub const HELLO: &[u8; 8] = b"OBLVCTL1";
pub const ACK: &[u8; 8] = b"OBLVAUT1";

pub struct Token(Zeroizing<[u8; 32]>);
impl Token {
    pub fn random() -> Result<Self> {
        let mut bytes = Zeroizing::new([0; 32]);
        std::fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(bytes.as_mut_slice()))
            .map_err(|_| Error("runtime_entropy_unavailable"))?;
        Ok(Self(bytes))
    }
}

pub fn provision(
    stream: &mut UnixStream,
    token: &Token,
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<()> {
    prepare(stream)?;
    let mut ready = [0; 8];
    receive(stream, &mut ready, stop, deadline)?;
    if &ready != READY {
        return Err(Error("runtime_auth_provision_failed"));
    }
    stream
        .write_all(token.0.as_slice())
        .map_err(|_| Error("runtime_auth_provision_failed"))?;
    let mut acknowledged = [0; 8];
    receive(stream, &mut acknowledged, stop, deadline)?;
    if &acknowledged != SET {
        return Err(Error("runtime_auth_provision_failed"));
    }
    Ok(())
}

pub fn authenticate(stream: &mut UnixStream, token: &Token, stop: &AtomicBool) -> Result<()> {
    prepare(stream)?;
    stream
        .write_all(HELLO)
        .and_then(|_| stream.write_all(token.0.as_slice()))
        .map_err(|_| Error("guest_control_unavailable"))?;
    let mut acknowledged = [0; 8];
    receive(
        stream,
        &mut acknowledged,
        stop,
        Instant::now() + Duration::from_secs(3),
    )?;
    if &acknowledged != ACK {
        return Err(Error("runtime_control_authentication_failed"));
    }
    stream
        .set_nonblocking(true)
        .map_err(|_| Error("guest_control_unavailable"))?;
    Ok(())
}

fn prepare(stream: &UnixStream) -> Result<()> {
    stream
        .set_nonblocking(false)
        .and_then(|_| stream.set_read_timeout(Some(Duration::from_millis(100))))
        .and_then(|_| stream.set_write_timeout(Some(Duration::from_millis(100))))
        .map_err(|_| Error("runtime_auth_setup_failed"))
}

fn receive(
    stream: &mut UnixStream,
    mut output: &mut [u8],
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<()> {
    while !output.is_empty() {
        if stop.load(Ordering::Relaxed) {
            return Err(Error("runtime_auth_cancelled"));
        }
        if Instant::now() >= deadline {
            return Err(Error("runtime_auth_timeout"));
        }
        match stream.read(output) {
            Ok(0) => return Err(Error("guest_control_unavailable")),
            Ok(length) => output = &mut output[length..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return Err(Error("guest_control_unavailable")),
        }
    }
    Ok(())
}
