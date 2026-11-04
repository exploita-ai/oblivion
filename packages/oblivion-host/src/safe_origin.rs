//! Current origin and queued-task snapshot for personal recovery. Creator chat
//! identifiers are reported metadata; they are not an attested agent identity.
use crate::family::{SealedTask, TaskContext};
use serde::{Deserialize, Serialize};

pub use oblivion_wire::child_task::ATTEMPT_LIMIT;

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCreated {
    pub safe_id: String,
    pub parent_id: String,
    pub request_id: String,
    pub agent: String,
    pub creator_chat_id: Option<String>,
    pub sealed_task: SealedTask,
    pub attempts: Vec<String>,
}

impl AgentCreated {
    pub fn valid(&self) -> bool {
        crate::managed::id(&self.safe_id) && crate::managed::id(&self.parent_id)
            && self.safe_id != self.parent_id && crate::managed::id(&self.request_id)
            && matches!(self.agent.as_str(), "codex" | "claude" | "opencode2")
            && self.creator_chat_id.as_ref().is_none_or(|id| !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control))
            && attempts_valid(&self.request_id, &self.attempts)
    }

    pub fn context(&self) -> TaskContext<'_> {
        TaskContext { safe_id: &self.safe_id, parent_id: &self.parent_id, request_id: &self.request_id, agent: &self.agent }
    }
}

pub fn attempts_valid(creation: &str, attempts: &[String]) -> bool {
    attempts.len() <= ATTEMPT_LIMIT && attempts.first().is_none_or(|first| first == creation)
        && attempts.iter().enumerate().all(|(index, id)| crate::managed::id(id) && !attempts[..index].contains(id))
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Origin {
    Local {},
    AgentCreated { record: AgentCreated },
    Shared {
        parent_id: Option<String>,
        provenance: Option<oblivion_share::Provenance>,
        source_policy: oblivion_share::Policy,
        required_proxy: Option<String>,
    },
}

impl Origin {
    pub fn valid(&self, safe_id: &str) -> bool {
        match self {
            Self::Local {} => true,
            Self::AgentCreated { record } => record.safe_id == safe_id && record.valid(),
            Self::Shared { parent_id, provenance, required_proxy, .. } => {
                parent_id.as_ref().is_none_or(|parent| crate::managed::id(parent) && parent != safe_id)
                    && provenance.as_ref().is_none_or(|origin| origin.created_by_agent || origin.requested_agent.is_none())
                    && required_proxy.as_ref().is_none_or(|label| !label.trim().is_empty() && label.len() <= 240 && !label.chars().any(char::is_control))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempt_history_has_one_creation_admission_and_bounded_unique_retries() {
        let creation = "1".repeat(32);
        assert!(attempts_valid(&creation, &[]));
        assert!(attempts_valid(&creation, &[creation.clone(), "2".repeat(32)]));
        assert!(!attempts_valid(&creation, &["2".repeat(32)]));
        assert!(!attempts_valid(&creation, &[creation.clone(), creation.clone()]));
        let mut over = vec![creation.clone()];
        over.extend((2..=17).map(|id| format!("{id:032x}")));
        assert!(!attempts_valid(&creation, &over));
    }
}
