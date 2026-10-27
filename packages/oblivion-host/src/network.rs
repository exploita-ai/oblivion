use oblivion_transport::policy::{Policy, Rule};
use serde::{Deserialize, Serialize};

pub const LIMIT: usize = 64 * 1024;

#[derive(Deserialize, Serialize)]
pub struct Observation {
    pub label: String,
    pub host_link: String,
    pub direct_blocked: bool,
    pub age_ms: u64,
    pub tor_progress: Option<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    Put { rule: Rule, save: bool },
    Remove { rule: Rule, save: bool },
    Saved {},
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub policy: Policy,
    pub enabled: bool,
    pub temporary: bool,
}

impl Status {
    pub fn new(saved: Option<Policy>, selected: Option<Policy>) -> Self {
        Self {
            enabled: selected.is_some() || saved.is_some(),
            temporary: selected.is_some(),
            policy: selected.or(saved).unwrap_or_default(),
        }
    }
}
