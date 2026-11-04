//! Shared frontend syntax and controller commands, consumed by the launcher.
//!
//! Parsers perform no I/O. Controller commands use an injected authenticated
//! platform adapter; runtime discovery, terminals and authorization stay there.
pub mod proxy;
pub mod run;
pub mod shell;
pub mod storage;

pub mod activity;
pub mod backup;
pub mod child_task;
pub mod command;
pub mod controller;
pub mod family_password;
pub mod files;
pub mod network;
pub mod proxy_profiles;
pub mod safe;
pub mod settings;
#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub mod windows_entrypoint;
#[cfg(windows)]
pub mod windows_files;
#[cfg(windows)]
pub mod windows_terminal;
