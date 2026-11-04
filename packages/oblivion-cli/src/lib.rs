//! Shared frontend syntax and controller commands, consumed by the launcher.
//!
//! Parsers perform no I/O. Controller commands use an injected authenticated
//! platform adapter; runtime discovery, terminals and authorization stay there.
pub mod proxy;
pub mod run;
pub mod shell;

pub mod controller;
