//! Automatic-lock preferences and public opening/deadline projections. Runtime
//! clocks and activity authority belong to the controller, not this wire model.
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub const MAX_MINUTES: u16 = 1440;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Preferences {
    pub version: u8,
    pub safe_minutes: u16,
    pub host_minutes: u16,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            version: 1,
            safe_minutes: 15,
            host_minutes: 30,
        }
    }
}

impl Preferences {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1 || self.safe_minutes > MAX_MINUTES || self.host_minutes > MAX_MINUTES {
            return Err("invalid_idle_preferences");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Opening<S> {
    pub slot: S,
    pub safe_id: String,
    pub nonce: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Activity<S> {
    pub host: String,
    pub safe: Option<Opening<S>>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Status<S> {
    pub preferences: Preferences,
    pub host: Option<HostStatus>,
    pub safes: Vec<SafeStatus<S>>,
    pub last_error: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct HostStatus {
    pub nonce: String,
    pub remaining_seconds: Option<u64>,
    pub closing: bool,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SafeStatus<S> {
    pub opening: Opening<S>,
    pub remaining_seconds: Option<u64>,
    pub closing: bool,
}

#[derive(Deserialize, Serialize)]
pub struct View<S> {
    #[serde(flatten)]
    pub state: Status<S>,
    pub storage: Storage,
    pub writable: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Storage {
    Defaults,
    SavedEncrypted,
    RamOnly,
}

impl<S: DeserializeOwned> View<S> {
    pub fn decode_status(bytes: &[u8]) -> Result<Self, &'static str> {
        #[derive(Deserialize)]
        struct Current<S> {
            idle_lock: View<S>,
        }
        let current: Current<S> =
            serde_json::from_slice(bytes).map_err(|_| "invalid_idle_status")?;
        current
            .idle_lock
            .state
            .preferences
            .validate()
            .map_err(|_| "invalid_idle_status")?;
        Ok(current.idle_lock)
    }
}
