//! Neutral, bounded administration inside one unlocked Safe. No agent process.
use crate::control::Result;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

pub const READY: &[u8; 6] = b"OBSA1\n";
pub const REQUEST_LIMIT: usize = 32768;
pub const RESPONSE_LIMIT: usize = 65536;
pub const PAGE_SIZE: usize = 50;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u8,
    pub command: Command,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    Usage {},
    Diagnostics { report: crate::diagnostics::Report },
    Checkpoint { metadata: Metadata },
    Inspect {},
    ArchiveState { cursor: Option<String> },
    Job { job_id: String },
}

impl Request {
    pub fn new(command: Command) -> Self {
        Self {
            version: 1,
            command,
        }
    }
    pub fn valid(&self) -> bool {
        self.version == 1
            && match &self.command {
                Command::Diagnostics { report } => report.valid(),
                Command::Checkpoint { metadata } => metadata.valid(),
                Command::ArchiveState { cursor } => {
                    cursor.as_ref().is_none_or(|id| valid_chat_id(id))
                }
                Command::Job { job_id } => crate::managed::id(job_id),
                Command::Usage {} | Command::Inspect {} => true,
            }
    }
}

/// Only the current 1.0 Safe format; no agent-specific or beta database reader.
#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub format: String,
    pub version: u8,
    pub safe_id: String,
    pub title: Option<String>,
    pub history_version: u8,
    pub origin: crate::safe_origin::Origin,
}
impl Metadata {
    pub fn valid(&self) -> bool {
        self.format == "oblivion-safe"
            && self.version == 1
            && self.history_version == 1
            && valid_safe_id(&self.safe_id)
            && self.origin.valid(&self.safe_id)
            && self
                .title
                .as_ref()
                .is_none_or(|title| crate::session_title::validate(title).is_ok())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub version: u8,
    pub response: Response,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Response {
    Storage { usage: crate::volume::Usage },
    Exported { path: String, bytes: u64 },
    Metadata { metadata: Metadata },
    ArchiveState { state: ArchiveState },
    Job { info: Option<crate::managed::Info> },
    Rejected { error: Rejection },
    Unavailable {},
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Rejection {
    UnsupportedVersion,
    InvalidMetadata,
    InvalidCatalog,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Agent {
    Codex,
    Claude,
    Opencode2,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub chat_id: String,
    pub title: String,
    pub updated: u64,
    pub agents: Vec<Agent>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Consistency {
    CatalogSqliteOk,
    CatalogEmpty,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveState {
    pub history_version: u8,
    pub consistency: Consistency,
    pub entries: Vec<Entry>,
    pub next: Option<String>,
    pub pending: Vec<Agent>,
}

impl Response {
    pub fn valid(&self, request: &Request) -> bool {
        match (self, &request.command) {
            (Self::Storage { usage }, Command::Usage {}) => usage.valid(),
            (Self::Exported { path, bytes }, Command::Diagnostics { .. }) => {
                (1..=4096).contains(bytes)
                    && path
                        .strip_prefix("workspace/diagnostics/")
                        .and_then(|name| name.strip_suffix(".json"))
                        .is_some_and(valid_safe_id)
            }
            (Self::Metadata { metadata }, Command::Checkpoint { metadata: expected }) => {
                metadata.valid() && metadata == expected
            }
            (Self::Metadata { metadata }, Command::Inspect {}) => metadata.valid(),
            (Self::Job { info }, Command::Job { job_id }) => info.as_ref().is_none_or(|info| info.valid() && info.job_id == *job_id),
            (Self::ArchiveState { state }, Command::ArchiveState { cursor }) => {
                state.history_version == 1
                    && (!matches!(state.consistency, Consistency::CatalogEmpty)
                        || (state.entries.is_empty()
                            && state.next.is_none()
                            && state.pending.is_empty()))
                    && state.entries.len() <= PAGE_SIZE
                    && valid_agents(&state.pending)
                    && state.entries.iter().all(|entry| {
                        valid_chat_id(&entry.chat_id)
                            && entry.title.chars().count() <= 240
                            && safe_text(&entry.title)
                            && valid_agents(&entry.agents)
                    })
                    && state
                        .entries
                        .windows(2)
                        .all(|rows| rows[0].chat_id < rows[1].chat_id)
                    && cursor.as_ref().is_none_or(|cursor| {
                        state
                            .entries
                            .first()
                            .is_none_or(|entry| &entry.chat_id > cursor)
                    })
                    && state.next.as_ref().is_none_or(|next| {
                        state.entries.len() == PAGE_SIZE
                            && state
                                .entries
                                .last()
                                .is_some_and(|entry| &entry.chat_id == next)
                    })
            }
            (
                Self::Rejected { .. },
                Command::Checkpoint { .. } | Command::Inspect {} | Command::ArchiveState { .. } | Command::Job { .. },
            ) => true,
            (Self::Unavailable {}, _) => true,
            _ => false,
        }
    }
}

pub fn exchange(channel: &mut (impl Read + Write), request: &Request) -> Result<Response> {
    if !request.valid() {
        return Err("invalid_safe_admin_request".into());
    }
    let request_bytes = serde_json::to_vec(request)?;
    if request_bytes.len() > if matches!(request.command, Command::Checkpoint { .. }) { REQUEST_LIMIT } else { 4096 } {
        return Err("safe_admin_request_too_large".into());
    }
    let mut ready = [0; 6];
    channel.read_exact(&mut ready)?;
    if &ready != READY {
        return Err("invalid_safe_admin_guest".into());
    }
    channel.write_all(b"G")?;
    channel.write_all(&(request_bytes.len() as u32).to_be_bytes())?;
    channel.write_all(&request_bytes)?;
    let mut prefix = [0; 4];
    channel.read_exact(&mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if !(1..=RESPONSE_LIMIT).contains(&length) {
        return Err("invalid_safe_admin_frame".into());
    }
    let mut payload = vec![0; length];
    channel.read_exact(&mut payload)?;
    let reply: Reply = serde_json::from_slice(&payload)?;
    if reply.version != 1 || !reply.response.valid(request) {
        return Err("invalid_safe_admin_response".into());
    }
    if matches!(reply.response, Response::Unavailable {}) {
        return Err("safe_admin_unavailable".into());
    }
    Ok(reply.response)
}

fn valid_safe_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn valid_chat_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}
fn safe_text(value: &str) -> bool {
    !value.chars().any(|character| {
        character.is_control()
            || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    })
}
fn valid_agents(value: &[Agent]) -> bool {
    value.len() <= 3
        && value
            .iter()
            .enumerate()
            .all(|(index, agent)| !value[..index].contains(agent))
}
