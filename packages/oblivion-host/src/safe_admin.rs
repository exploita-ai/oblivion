//! Bounded administration inside one unlocked Safe. Credential bodies are
//! private: they never belong to public status or diagnostics responses.
use crate::control::Result;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use zeroize::Zeroizing;

pub const READY: &[u8; 6] = b"OBSA1\n";
pub const REQUEST_LIMIT: usize = 32768;
pub const RESPONSE_LIMIT: usize = 65536;

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
    Job { job_id: String },
    CredentialExport { agent: Agent },
    CredentialInstall { credential: crate::delegation::Credential },
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
                Command::Job { job_id } => crate::managed::id(job_id),
                Command::CredentialExport { .. } => true,
                Command::CredentialInstall { credential } => credential.valid(),
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
    pub origin: crate::safe_origin::Origin,
}
impl Metadata {
    pub fn valid(&self) -> bool {
        self.format == "oblivion-safe"
            && self.version == 1
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
    Job { info: Option<crate::managed::Info> },
    Credential { credential: Option<crate::delegation::Credential>, reason: Option<CredentialReason> },
    CredentialInstalled {},
    CredentialNotInstalled { reason: CredentialReason },
    Rejected { error: Rejection },
    Unavailable {},
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Rejection {
    UnsupportedVersion,
    InvalidMetadata,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialReason {
    NeedsAuth,
    UnsupportedOauth,
    UnsupportedRouting,
    AmbiguousAuth,
    ModelRequired,
    AuthConflict,
    InstallFailed,
    InstallTimeout,
    InvalidCredential,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Agent {
    Codex,
    Claude,
    Opencode2,
}

impl Agent {
    pub fn as_str(self) -> &'static str {
        match self { Self::Codex => "codex", Self::Claude => "claude", Self::Opencode2 => "opencode2" }
    }
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
            (Self::Credential { credential, reason }, Command::CredentialExport { agent }) => match (credential, reason) {
                (Some(credential), None) => credential.valid() && credential.agent() == agent.as_str(),
                (None, Some(_)) => true,
                _ => false,
            },
            (Self::CredentialInstalled {}, Command::CredentialInstall { .. }) => true,
            (Self::CredentialNotInstalled { .. }, Command::CredentialInstall { .. }) => true,
            (
                Self::Rejected { .. },
                Command::Checkpoint { .. } | Command::Inspect {} | Command::Job { .. } | Command::CredentialInstall { .. },
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
    let request_bytes = Zeroizing::new(serde_json::to_vec(request)?);
    if request_bytes.len() > if matches!(request.command, Command::Checkpoint { .. } | Command::CredentialInstall { .. }) { REQUEST_LIMIT } else { 4096 } {
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
    let mut payload = Zeroizing::new(vec![0; length]);
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
