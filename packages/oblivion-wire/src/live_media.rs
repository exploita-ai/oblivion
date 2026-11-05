use crate::idle::Opening;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    Import,
    Export,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reserve<S> {
    pub opening: Opening<S>,
    pub device_id: String,
    pub direction: Direction,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source<S> {
    pub lease_id: String,
    pub opening: Opening<S>,
    pub device_id: String,
    pub direction: Direction,
}

pub const STOP: u8 = b'X';
pub const REVOKED: &[u8; 8] = b"revoked\n";
pub const DETACHED: &[u8; 9] = b"detached\n";

pub fn valid_device_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Only the local .media ACK carries this nonce. The raw guest source cannot
/// forge the runtime's proof of controller cleanup and physical eject.
pub fn detach_proof(nonce: &str) -> Option<[u8; 42]> {
    if !crate::control::valid_id(nonce) {
        return None;
    }
    let mut proof = *b"detached 00000000000000000000000000000000\n";
    proof[9..41].copy_from_slice(nonce.as_bytes());
    Some(proof)
}
