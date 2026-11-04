//! Personal full-volume recovery, separate from sanitized portable Share.
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Exported {
    pub transaction: String,
    pub safe_id: String,
    pub bytes: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Imported {
    pub transaction: String,
    pub maximum: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finish {
    pub transaction: String,
    pub password: zeroize::Zeroizing<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finished {
    pub transaction: String,
    pub safe_id: String,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind { Export, Import }

#[derive(Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome { Prepared, Copying, Copied, Committed, RecoveryRequired, Cancelled }

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub transaction: String,
    pub slot: crate::scope::Slot,
    pub kind: Kind,
    pub safe_id: Option<String>,
    pub bytes: Option<u64>,
    pub outcome: Outcome,
    pub active: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status { pub transactions: Vec<Entry> }
