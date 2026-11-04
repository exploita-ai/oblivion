//! The launcher sends arguments as data, never as a shell command.
use crate::control::Result;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

pub const LIMIT: usize = 65536;

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

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Size {
    pub rows: u16,
    pub cols: u16,
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
        if self.terminal.is_some_and(|size| {
            size.rows == 0 || size.cols == 0 || size.rows > 1000 || size.cols > 1000
        }) {
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
            Self::Workspace { terminal }
                if terminal.rows == 0
                    || terminal.cols == 0
                    || terminal.rows > 1000
                    || terminal.cols > 1000 =>
            {
                return Err("invalid_terminal_size".into());
            }
            Self::Workspace { .. } => {}
        }
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(self)?);
        if bytes.len() > LIMIT {
            return Err("agent_request_too_large".into());
        }
        stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
        stream.write_all(&bytes)?;
        Ok(())
    }
}

pub fn write_frame(stream: &mut impl Write, kind: u8, payload: &[u8]) -> Result<()> {
    if payload.len() > LIMIT {
        return Err("agent_frame_too_large".into());
    }
    stream.write_all(&[kind])?;
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(payload)?;
    Ok(())
}

pub fn read_frame(stream: &mut impl Read) -> Result<(u8, Vec<u8>)> {
    let mut header = [0; 5];
    stream.read_exact(&mut header)?;
    let size = u32::from_be_bytes(header[1..].try_into()?) as usize;
    if size > LIMIT {
        return Err("agent_frame_too_large".into());
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes)?;
    Ok((header[0], bytes))
}
