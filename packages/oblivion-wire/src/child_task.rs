//! Focused child-task administration. Plaintext is returned only by an explicit
//! review of an already opened Safe, never by global status or process argv.
use crate::managed;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const ATTEMPT_LIMIT: usize = 16;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub request_id: String,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    NotStarted,
    Submitted,
    Unknown,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub version: u8,
    pub safe_id: String,
    pub agent: String,
    pub request_id: String,
    pub attempt_request_id: Option<String>,
    pub attempts: usize,
    pub attempt_limit: usize,
    pub phase: Phase,
    pub job: Option<managed::Info>,
    pub can_start: bool,
    pub can_retry: bool,
    pub can_cancel: bool,
    pub blocked: Option<String>,
}

impl Status {
    pub fn valid(&self) -> bool {
        self.version == 1
            && managed::id(&self.safe_id)
            && managed::id(&self.request_id)
            && matches!(self.agent.as_str(), "codex" | "claude" | "opencode2")
            && self.attempt_limit == ATTEMPT_LIMIT
            && self.attempts <= self.attempt_limit
            && (self.attempts == 0) == self.attempt_request_id.is_none()
            && self
                .attempt_request_id
                .as_ref()
                .is_none_or(|id| managed::id(id))
            && match self.phase {
                Phase::NotStarted => {
                    self.attempts == 0 && self.job.is_none() && !self.can_cancel && !self.can_retry
                }
                Phase::Unknown => {
                    self.attempts > 0 && self.job.is_none() && !self.can_cancel && !self.can_retry
                }
                Phase::Submitted => {
                    self.attempts > 0
                        && self.job.as_ref().is_some_and(|job| {
                            job.valid()
                                && job.agent == self.agent
                                && Some(&job.request_id) == self.attempt_request_id.as_ref()
                                && self.can_cancel == !job.state.terminal()
                                && (!self.can_retry
                                    || matches!(
                                        job.state,
                                        managed::State::Failed | managed::State::Cancelled
                                    ))
                        })
                }
            }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub status: Status,
    pub task: Zeroizing<String>,
}

impl Review {
    pub fn valid(&self) -> bool {
        self.status.valid()
            && !self.task.trim().is_empty()
            && self.task.len() <= managed::TASK_LIMIT
            && !self.task.contains('\0')
    }
}
