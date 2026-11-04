use crate::require;
use oblivion_transfer::Manifest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io;

pub const MAX_SAFES: usize = 1024;
pub const MAX_METADATA: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub format: String,
    pub version: u8,
    pub id: String,
    pub safes: Vec<Safe>,
    pub settings: Option<Settings>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Safe {
    /// Package-local identity, never an output filesystem path.
    pub id: String,
    pub title: String,
    pub parent: Option<String>,
    pub provenance: Option<Provenance>,
    pub policy: Policy,
    /// A label can travel; a proxy endpoint or credential cannot.
    pub required_proxy: Option<String>,
    pub contents_sha256: String,
    pub entries: usize,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub created_by_agent: bool,
    pub requested_agent: Option<Agent>,
    pub parent_not_included: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Agent {
    Codex,
    Claude,
    Opencode2,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Policy {
    Offline,
    Strict,
    OpenInternet,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub safe_idle_minutes: u16,
    pub host_idle_minutes: u16,
}

impl Package {
    pub fn validate(&self) -> io::Result<()> {
        require(
            self.format == "oblivion-share" && self.version == 1,
            "unsupported_share_format",
        )?;
        validate_id(&self.id)?;
        require(
            !self.safes.is_empty() && self.safes.len() <= MAX_SAFES,
            "share_safe_limit",
        )?;
        let mut ids = BTreeMap::new();
        for safe in &self.safes {
            validate_id(&safe.id)?;
            validate_label(&safe.title)?;
            require(
                safe.entries > 0
                    && safe.entries <= oblivion_transfer::MAX_ENTRIES
                    && safe.bytes <= oblivion_transfer::MAX_DOCUMENT_BYTES,
                "share_content_limit",
            )?;
            require(valid_hash(&safe.contents_sha256), "invalid_share_hash")?;
            require(
                ids.insert(safe.id.as_str(), safe).is_none(),
                "duplicate_share_safe",
            )?;
            if let Some(label) = &safe.required_proxy {
                validate_label(label)?;
            }
            if let Some(provenance) = &safe.provenance {
                require(
                    provenance.created_by_agent || provenance.requested_agent.is_none(),
                    "invalid_share_provenance",
                )?;
                require(
                    !provenance.parent_not_included || safe.parent.is_none(),
                    "invalid_share_provenance",
                )?;
            }
        }
        for safe in &self.safes {
            let mut visited = BTreeSet::new();
            let mut current = Some(safe.id.as_str());
            while let Some(id) = current {
                require(visited.insert(id), "share_parent_cycle")?;
                current = ids
                    .get(id)
                    .ok_or_else(|| crate::invalid("share_parent_missing"))?
                    .parent
                    .as_deref();
            }
        }
        if let Some(settings) = &self.settings {
            require(
                settings.safe_idle_minutes <= 1440 && settings.host_idle_minutes <= 1440,
                "invalid_share_settings",
            )?;
        }
        Ok(())
    }
}

pub fn validate_contents(manifest: &Manifest, safe: &Safe) -> io::Result<()> {
    require(
        manifest.sha256() == safe.contents_sha256
            && manifest.entries().len() == safe.entries
            && manifest.bytes() == safe.bytes,
        "share_contents_changed",
    )?;
    oblivion_transfer::share::validate_manifest(manifest)
}

pub fn validate_id(value: &str) -> io::Result<()> {
    require(
        value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid_share_id",
    )
}

fn validate_label(value: &str) -> io::Result<()> {
    require(
        !value.trim().is_empty() && value.len() <= 240 && !value.chars().any(|character| character.is_control() || matches!(character, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')),
        "invalid_share_label",
    )
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
