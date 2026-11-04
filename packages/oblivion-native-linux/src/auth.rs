//! Unix stream setup and OS entropy for the shared private runtime handshake.
use crate::{Error, Result};
use oblivion_wire::runtime_auth::{self, Token};
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub fn token() -> Result<Token> {
    let mut bytes = Zeroizing::new([0; 32]);
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(bytes.as_mut_slice()))
        .map_err(|_| Error("runtime_entropy_unavailable"))?;
    Ok(Token::from_entropy(bytes))
}

pub fn provision(
    stream: &mut UnixStream,
    token: &Token,
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<()> {
    prepare(stream)?;
    runtime_auth::provision(stream, token, stop, deadline).map_err(|error| Error(error.0))
}

pub fn authenticate(stream: &mut UnixStream, token: &Token, stop: &AtomicBool) -> Result<()> {
    prepare(stream)?;
    runtime_auth::authenticate(stream, token, stop, Instant::now() + Duration::from_secs(3))
        .map_err(|error| Error(error.0))?;
    stream
        .set_nonblocking(true)
        .map_err(|_| Error("guest_control_unavailable"))
}

fn prepare(stream: &UnixStream) -> Result<()> {
    stream
        .set_nonblocking(false)
        .and_then(|_| stream.set_read_timeout(Some(Duration::from_millis(100))))
        .and_then(|_| stream.set_write_timeout(Some(Duration::from_millis(100))))
        .map_err(|_| Error("runtime_auth_setup_failed"))
}
