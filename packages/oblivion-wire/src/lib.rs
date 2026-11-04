//! Private Oblivion wire data and framing shared by desktop frontends and Debian.
//!
//! No filesystem, sockets, runtime discovery, authorization or OS policy lives
//! here. Callers authenticate peers and apply operation-specific secret budgets.
pub mod agent;
pub mod control;
pub mod control_client;
pub mod frame;
