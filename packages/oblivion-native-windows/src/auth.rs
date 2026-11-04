//! Windows entropy and error mapping for the shared private runtime handshake.
use crate::{Error, Result};
use oblivion_wire::runtime_auth::{self, Token};
use std::io::{Read, Write};
use std::sync::atomic::AtomicBool;
use std::time::Instant;
use zeroize::Zeroizing;

pub fn token() -> Result<Token> {
    let mut bytes = Zeroizing::new([0; 32]);
    getrandom::getrandom(bytes.as_mut_slice()).map_err(|_| Error("runtime_entropy_unavailable"))?;
    Ok(Token::from_entropy(bytes))
}

pub fn provision(
    stream: &mut (impl Read + Write),
    token: &Token,
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<()> {
    runtime_auth::provision(stream, token, stop, deadline).map_err(|error| Error(error.0))
}

pub fn authenticate(
    stream: &mut (impl Read + Write),
    token: &Token,
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<()> {
    runtime_auth::authenticate(stream, token, stop, deadline).map_err(|error| Error(error.0))
}
