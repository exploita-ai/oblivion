use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Only the recipient's public X25519 key crosses the host/guest boundary.
#[derive(Deserialize, Serialize)]
#[serde(try_from = "String")]
pub struct ClientAuth(String);

impl TryFrom<String> for ClientAuth {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != 52
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
            || !matches!(value.as_bytes().last(), Some(b'A' | b'Q'))
        {
            return Err("invalid_client_auth");
        }
        Ok(Self(value))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    Prepare {
        ttl_seconds: u16,
    },
    PrepareBackup {
        id: String,
        password: Zeroizing<String>,
        ttl_seconds: u16,
    },
    Receive {
        client_auth: ClientAuth,
    },
    Stage {},
    Share {
        client_auth: ClientAuth,
    },
    Freeze {},
    Import {},
    Access {},
    Status {},
    Cancel {},
}

impl Command {
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Self::Prepare { ttl_seconds } | Self::PrepareBackup { ttl_seconds, .. } = self {
            if !(1..=3600).contains(ttl_seconds) {
                return Err("invalid_onion_deadline");
            }
        }
        if let Self::PrepareBackup { id, password, .. } = self {
            if id.len() != 32
                || !id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || !(1..=1024).contains(&password.len())
            {
                return Err("invalid_backup_request");
            }
        }
        Ok(())
    }
}

/// Root-to-root control only; this is not a raw guest/Tor command channel.
#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OwnerRequest {
    Observe {},
    Receive { client_auth: ClientAuth },
    Stage {},
    Share { client_auth: ClientAuth },
    Freeze {},
    Import {},
    Access {},
    Stop {},
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    Closed,
    Connecting,
    Ready,
    Starting,
    PreparingShare,
    Staging,
    Staged,
    Sharing,
    Receiving,
    Freezing,
    Review,
    PreparingImport,
    Copying,
    Imported,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Progress {
    pub files: usize,
    pub bytes: u64,
    pub transferred_bytes: u64,
    pub rejected: u64,
}

/// Separate explicit response, excluded from job files and status polling.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Access {
    pub url: Zeroizing<String>,
}

impl Access {
    pub fn published(id: String) -> Result<Self, &'static str> {
        if id.len() != 56
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
        {
            return Err("invalid_onion_address");
        }
        Ok(Self {
            url: Zeroizing::new(format!("http://{id}.onion/")),
        })
    }
}

/// Addresses, authorization secrets, paths and file data are absent.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub configured: bool,
    pub active: bool,
    pub id: Option<String>,
    pub tor_progress: Option<u8>,
    pub tor_ready: bool,
    pub age_ms: u64,
    pub phase: Phase,
    pub progress: Option<Progress>,
    pub receipt: Option<oblivion_transfer::Receipt>,
}

impl Status {
    pub fn closed(configured: bool) -> Self {
        Self {
            configured,
            active: false,
            id: None,
            tor_progress: None,
            tor_ready: false,
            age_ms: 0,
            phase: Phase::Closed,
            progress: None,
            receipt: None,
        }
    }

    pub fn observed(id: String, progress: Option<u8>, ready: bool, age_ms: u64) -> Self {
        let fresh = age_ms <= 10_000;
        Self {
            configured: true,
            active: true,
            id: Some(id),
            tor_progress: progress.filter(|value| fresh && *value <= 100),
            tor_ready: fresh && ready && progress == Some(100),
            age_ms,
            phase: if fresh && ready && progress == Some(100) {
                Phase::Ready
            } else {
                Phase::Connecting
            },
            progress: None,
            receipt: None,
        }
    }
}
