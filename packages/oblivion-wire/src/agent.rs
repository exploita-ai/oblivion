//! Existing agent stream: one kind byte, u32-BE payload length, then raw bytes.
//! Linux signal numbers carried by kind 6 belong to the guest protocol, never
//! to the desktop OS. Agent argv remains data, not shell source.
//! Empty stderr followed by exit 125 is a relay failure. Older readers
//! ignore the empty frame and see the legacy status.
use crate::frame;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub const LIMIT: usize = 65536;
pub const RELAY_FAILURE_STATUS: i32 = 125;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Size {
    pub rows: u16,
    pub cols: u16,
}

impl Size {
    pub fn valid(self) -> bool {
        (1..=1000).contains(&self.rows) && (1..=1000).contains(&self.cols)
    }
}

pub fn write_frame(
    writer: &mut impl Write,
    kind: u8,
    payload: &[u8],
) -> std::result::Result<(), frame::Error> {
    // Validate before emitting the kind so a rejected write emits no prefix.
    if payload.len() > LIMIT {
        return Err(frame::Error::InvalidLength);
    }
    writer.write_all(&[kind])?;
    frame::write(writer, payload, 0..=LIMIT)
}

pub fn read_frame(reader: &mut impl Read) -> std::result::Result<(u8, Vec<u8>), frame::Error> {
    Decoder::default()
        .read(reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "agent_frame_incomplete").into())
}

/// Partial frame state for a duplex terminal pump. The same decoder serves
/// blocking readers; a WouldBlock never loses a prefix or consumes another frame.
#[derive(Default)]
pub struct Decoder {
    header: [u8; 5],
    header_read: usize,
    payload: Vec<u8>,
    payload_read: usize,
}

impl Decoder {
    pub fn read(
        &mut self,
        reader: &mut impl Read,
    ) -> std::result::Result<Option<(u8, Vec<u8>)>, frame::Error> {
        while self.header_read < self.header.len() {
            match reader.read(&mut self.header[self.header_read..]) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
                Ok(count) => self.header_read += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        let length = u32::from_be_bytes(self.header[1..].try_into().unwrap()) as usize;
        if length > LIMIT {
            return Err(frame::Error::InvalidLength);
        }
        self.payload.resize(length, 0);
        while self.payload_read < length {
            match reader.read(&mut self.payload[self.payload_read..]) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
                Ok(count) => self.payload_read += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        let kind = self.header[0];
        self.header_read = 0;
        self.payload_read = 0;
        Ok(Some((kind, std::mem::take(&mut self.payload))))
    }
}

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
