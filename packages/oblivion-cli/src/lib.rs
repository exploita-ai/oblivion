//! Portable frontend syntax, consumed by the native launcher.
//!
//! Parsing performs no I/O, login, prompts, runtime discovery or authorization.
//! Names are validated by their domain owner before using the parsed request.
pub mod proxy;
pub mod run;
