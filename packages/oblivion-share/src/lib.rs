//! Portable, passphrase-encrypted Share streams. Filesystem access belongs to
//! the guest endpoints: this crate never discovers profiles or opens a path.

pub mod container;
pub mod control;
pub mod manifest;

pub use age::secrecy::SecretString;
pub use container::{Import, Source, Verified, decrypt, encrypt};
pub use manifest::{Agent, Package, Policy, Provenance, Safe, Settings};
pub use oblivion_transfer::{Entry, Manifest};

use std::io;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn require(condition: bool, message: &'static str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}
