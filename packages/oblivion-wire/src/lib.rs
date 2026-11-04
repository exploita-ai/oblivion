//! Private Oblivion wire data and framing shared by desktop frontends and Debian.
//!
//! No filesystem, sockets, runtime discovery, authorization or OS policy lives
//! here. Callers authenticate peers and apply operation-specific secret budgets.
pub mod agent;
pub mod child_task;
pub mod control;
pub mod control_client;
pub mod frame;
pub mod family_rotation;
pub mod idle;
pub mod managed;
pub mod runtime_auth;
pub mod session_title;
pub mod slot;
pub mod volume;
