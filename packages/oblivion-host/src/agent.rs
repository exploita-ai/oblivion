//! The launcher sends arguments as data, never as a shell command.
use crate::control::Result;
pub use oblivion_wire::agent::{Size, LIMIT};
use oblivion_wire::frame;
use serde::Serialize;
use std::io::{Read, Write};

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Command<'a> {
    Agent(&'a Launch),
    Workspace { terminal: Size },
}

#[derive(Serialize)]
pub struct Launch {
    pub agent: String,
    pub argv: Vec<String>,
    pub terminal: Option<Size>,
    pub managed: Option<crate::managed::Command>,
}

impl Launch {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.agent.as_str(), "codex" | "claude" | "opencode2") {
            return Err("unsupported_agent".into());
        }
        if self
            .managed
            .as_ref()
            .is_some_and(|value| !value.valid() || !self.argv.is_empty() || self.terminal.is_some())
        {
            return Err("invalid_managed_job".into());
        }
        if self.argv.len() > 1024 || self.argv.iter().any(|arg| arg.contains('\0')) {
            return Err("invalid_agent_arguments".into());
        }
        if self.terminal.is_some_and(|size| !size.valid()) {
            return Err("invalid_terminal_size".into());
        }
        Ok(())
    }

    pub fn write(&self, stream: &mut impl Write) -> Result<()> {
        Command::Agent(self).write(stream)
    }
}

impl Command<'_> {
    pub fn write(&self, stream: &mut impl Write) -> Result<()> {
        match self {
            Self::Agent(launch) => launch.validate()?,
            Self::Workspace { terminal } if !terminal.valid() => {
                return Err("invalid_terminal_size".into());
            }
            Self::Workspace { .. } => {}
        }
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(self)?);
        if bytes.len() > LIMIT {
            return Err("agent_request_too_large".into());
        }
        frame::write(stream, &bytes, 1..=LIMIT)?;
        Ok(())
    }
}

pub fn write_frame(stream: &mut impl Write, kind: u8, payload: &[u8]) -> Result<()> {
    oblivion_wire::agent::write_frame(stream, kind, payload).map_err(frame_error)
}

pub fn read_frame(stream: &mut impl Read) -> Result<(u8, Vec<u8>)> {
    oblivion_wire::agent::read_frame(stream).map_err(frame_error)
}

fn frame_error(error: frame::Error) -> Box<dyn std::error::Error> {
    match error {
        frame::Error::InvalidLength => "agent_frame_too_large".into(),
        frame::Error::Io(error) => error.into(),
    }
}
