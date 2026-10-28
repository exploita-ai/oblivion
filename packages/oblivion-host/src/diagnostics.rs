use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "lowercase", deny_unknown_fields)]
pub enum Request {
    Preview,
    Export,
}

/// No arbitrary strings from configuration, errors or transcripts belong here.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub version: u8,
    pub controller_version: String,
    pub architecture: Architecture,
    pub cpu_cores: usize,
    pub memory_mib: u64,
    pub ephemeral: bool,
    pub general_open: bool,
    pub session: Session,
    pub transport: Transport,
    pub direct_access_blocked: bool,
    pub observation_age_ms: u64,
    pub tor_bootstrap: Option<u8>,
    pub laboratory: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    Aarch64,
    X86_64,
    Unknown,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Session {
    Locked,
    Documents,
    Chat,
    Starting,
    Recovery,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    NotStarted,
    Connecting,
    Tor,
    Socks5,
    Offline,
    Unknown,
}

impl Report {
    pub fn valid(&self) -> bool {
        self.version == 1
            && self.controller_version == env!("CARGO_PKG_VERSION")
            && (1..=4096).contains(&self.cpu_cores)
            && self.memory_mib <= 1024 * 1024 * 1024
            && self.tor_bootstrap.is_none_or(|value| value <= 100)
    }
}
