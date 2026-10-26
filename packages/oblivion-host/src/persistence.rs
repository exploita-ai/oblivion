use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The manager confirms this complete plan; the controller discovers it again
/// before writing. Device paths are never accepted from a client.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub device: String,
    pub identity: String,
    pub table: String,
    pub disk_bytes: u64,
    pub start: u64,
    pub sectors: u64,
    pub partition: u32,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub plan: Option<Plan>,
    pub present: bool,
    pub incomplete: bool,
    pub unavailable: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Prepare {
    pub plan: Plan,
    pub password: Zeroizing<String>,
}
