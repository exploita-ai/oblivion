//! Headless Windows HCS backend. Platform I/O is separate from the secret-free
//! configuration model; ordinary control keeps the existing private wire.
use std::fmt;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Error(pub &'static str);

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(self.0)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

pub mod auth;
#[cfg(windows)]
pub mod bridge;
pub mod config;
#[cfg(windows)]
pub mod client;
#[cfg(windows)]
pub mod files;
#[cfg(windows)]
pub mod hcs;
pub mod hcs_model;
pub mod network_model;
#[cfg(windows)]
pub mod network;
#[cfg(windows)]
pub mod lifetime;
#[cfg(windows)]
pub mod private;
#[cfg(windows)]
pub mod runtime;
#[cfg(windows)]
pub mod security;
