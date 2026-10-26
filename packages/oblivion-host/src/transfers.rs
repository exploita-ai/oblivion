use serde::{Deserialize, Serialize};

pub const SOCKET: &str = "/run/oblivion-transfer-host/control.sock";
pub const MAX_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 1024;
pub const BUDGET_SECONDS: u64 = 300;

#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    List,
    Import { source: String },
    Export { target: String },
    Recover,
    Cancel,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: String,
    pub name: String,
    pub bytes: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub configured: bool,
    pub export_configured: bool,
    pub active: bool,
    pub sources: Vec<Source>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Started {
    pub id: String,
}

pub fn limits() -> oblivion_transfer::Limits {
    oblivion_transfer::Limits {
        entries: MAX_ENTRIES,
        bytes: MAX_BYTES,
    }
}
