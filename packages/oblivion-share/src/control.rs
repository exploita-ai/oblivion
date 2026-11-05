//! Current portable Share RPC values. Guest payload bytes use a separate
//! private stream; these controller messages contain only reviewed metadata.
use crate::Package;
use oblivion_transfer::Receipt;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Parent {
    pub id: String,
    pub parent: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Begin {
    pub package: Package,
    pub metadata_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Begun {
    pub transaction: String,
    pub nonce: String,
    pub destinations: Vec<Destination>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub package_id: String,
    pub safe_id: String,
    pub title: String,
    pub parent: Option<String>,
    pub mib: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Open {
    pub transaction: String,
    pub nonce: String,
    pub package_id: String,
    pub request_id: String,
    pub password: Zeroizing<String>,
}

pub type Opened<S> = oblivion_wire::idle::Opening<S>;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finish {
    pub transaction: String,
    pub nonce: String,
    pub package_id: String,
    pub receipt: Receipt,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub transaction: String,
    pub nonce: String,
    pub metadata_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Committed {
    pub transaction: String,
    pub metadata_sha256: String,
    pub destinations: Vec<Destination>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Abort {
    pub transaction: String,
    pub nonce: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Discard {
    pub transaction: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Pending,
    Committed,
    RecoveryRequired,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status<S> {
    pub transaction: String,
    pub package_id: Option<String>,
    pub metadata_sha256: Option<String>,
    pub outcome: Outcome,
    pub safes: usize,
    pub ready: usize,
    pub openings: Vec<Opened<S>>,
}

/// Export authorization is scoped to one controller-owned batch.
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ExportSelection {
    Safe { safe_id: String },
    Branch { safe_id: String },
    All,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportSource {
    pub id: String,
    pub parent: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportStarted {
    pub export_id: String,
    pub sources: Vec<ExportSource>,
    pub settings: Option<crate::Settings>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportIdentity {
    pub export_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportOpen {
    pub export_id: String,
    pub password: Option<Zeroizing<String>>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMetadata<S> {
    pub opening: Opened<S>,
    pub title: String,
    pub created_by_agent: bool,
    pub requested_agent: Option<crate::Agent>,
    pub parent_not_included: bool,
    pub policy: crate::Policy,
    pub required_proxy: Option<String>,
}
