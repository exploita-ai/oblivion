//! Managed jobs use the existing guest agent stream; only these facts leave it.
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const TASK_LIMIT: usize = 16384;
pub const OUTPUT_LIMIT: u64 = 4 * 1024 * 1024;
pub const RECORD_LIMIT: usize = 16;

#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    Start {
        job_id: String,
        request_id: String,
        task: Zeroizing<String>,
    },
    Inspect {
        job_id: String,
    },
}
impl Command {
    pub fn valid(&self) -> bool {
        match self {
            Self::Start {
                job_id,
                request_id,
                task,
            } => {
                id(job_id)
                    && id(request_id)
                    && !task.trim().is_empty()
                    && task.len() <= TASK_LIMIT
                    && !task.contains('\0')
            }
            Self::Inspect { job_id } => id(job_id),
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}
impl State {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    NeedsAuth,
    NeedsInput,
    Timeout,
    OutputLimit,
    Interrupted,
    AgentExit,
    StartupFailed,
    CleanupRequired,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Info {
    pub job_id: String,
    pub request_id: String,
    pub agent: String,
    pub state: State,
    pub native_chat_id: Option<String>,
    pub reason: Option<Reason>,
}
impl Info {
    pub fn valid(&self) -> bool {
        id(&self.job_id)
            && id(&self.request_id)
            && matches!(self.agent.as_str(), "codex" | "claude" | "opencode2")
            && self
                .native_chat_id
                .as_ref()
                .is_none_or(|value| native_id(&self.agent, value))
            && (self.state == State::Failed) == self.reason.is_some()
    }
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Event {
    Status { info: Info },
    Rejected { error: Rejection },
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Rejection {
    NotFound,
    Busy,
    Quota,
    RecoveryRequired,
    StorageFailed,
}

pub fn id(value: &str) -> bool {
    oblivion_wire::control::valid_id(value)
}

fn native_id(agent: &str, value: &str) -> bool {
    if matches!(agent, "codex" | "claude") {
        return value.len() == 36
            && value.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                }
            });
    }
    value.strip_prefix("ses_").is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix.len() <= 128
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    })
}
