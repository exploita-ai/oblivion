//! The current guest plan, validated once before review or approval.
use super::command::{validate_chat, validate_path};
use crate::controller::Result;
use oblivion_share::Manifest;
pub use oblivion_share::control::SourceMetadata;
use oblivion_transfer::Entry;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub version: u8,
    pub request_id: String,
    pub manifest: Vec<Entry>,
    pub manifest_sha256: String,
    pub plan_sha256: String,
    pub bytes: u64,
    pub chats: Vec<String>,
    pub omitted: BTreeMap<String, u64>,
    pub warnings: Vec<Warning>,
    pub warning_count: u64,
    pub scan: Scan,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Warning {
    pub reason: String,
    pub path: Option<String>,
    pub chat_id: Option<String>,
    pub included: bool,
    pub default_excluded: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scan {
    pub files_bytes: u64,
    pub history_bytes: u64,
    pub limit_per_kind: u64,
    pub best_effort: bool,
}

pub fn show_review(
    output: &mut impl Write,
    title: &str,
    review: &Review,
    manifest: &Manifest,
) -> Result<()> {
    writeln!(
        output,
        "{title:?} · {} entries · {} bytes · {} conversations",
        manifest.entries().len(),
        review.bytes,
        review.chats.len()
    )?;
    for entry in manifest.entries() {
        writeln!(
            output,
            "  {:?}{}",
            entry.path(),
            if matches!(entry, Entry::Directory { .. }) {
                "/"
            } else {
                ""
            }
        )?;
    }
    for (kind, count) in &review.omitted {
        writeln!(output, "  Omitted {kind}: {count}")?;
    }
    for warning in &review.warnings {
        writeln!(
            output,
            "  {}: {:?} · {}",
            if warning.reason == "native_history_dependency_included" {
                "Required saved context from a parent conversation"
            } else {
                warning.reason.as_str()
            },
            warning
                .path
                .as_deref()
                .or(warning.chat_id.as_deref())
                .unwrap_or("selection"),
            if warning.included {
                "included"
            } else {
                "excluded"
            }
        )?;
    }
    if review.warning_count > review.warnings.len() as u64 {
        return Err("Too many Share warnings to review; narrow the selection".into());
    }
    Ok(())
}

pub fn validate_review(review: &mut Review, request: &str) -> io::Result<Manifest> {
    let hash = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if review.version != 1
        || review.request_id != request
        || !hash(&review.plan_sha256)
        || review.chats.len() > 2048
        || review.chats.iter().collect::<BTreeSet<_>>().len() != review.chats.len()
        || review.warnings.len() > 512
        || review.warning_count < review.warnings.len() as u64
        || review.omitted.len() > 64
        || !review.scan.best_effort
        || review.scan.limit_per_kind != 16 * 1024 * 1024
        || review.scan.files_bytes > review.scan.limit_per_kind
        || review.scan.history_bytes > review.scan.limit_per_kind
    {
        return Err(io::Error::other("invalid_share_review"));
    }
    for chat in &review.chats {
        validate_chat(chat)?;
    }
    for kind in review.omitted.keys() {
        if kind.len() > 64
            || kind.is_empty()
            || !kind
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        {
            return Err(io::Error::other("invalid_share_review"));
        }
    }
    for warning in &review.warnings {
        if !matches!(
            warning.reason.as_str(),
            "credential_store_excluded"
                | "invalid_name_excluded"
                | "unsupported_entry_excluded"
                | "potential_secret"
                | "partial_content_scan"
                | "native_history_dependency_included"
        ) || warning.path.is_some() == warning.chat_id.is_some()
            || warning.default_excluded.is_some_and(|value| !value)
            || warning.reason == "native_history_dependency_included"
                && (warning.chat_id.is_none()
                    || !warning.included
                    || warning.default_excluded.is_some())
        {
            return Err(io::Error::other("invalid_share_warning"));
        }
        if let Some(path) = &warning.path {
            validate_path(path)?;
        }
        if let Some(chat) = &warning.chat_id {
            validate_chat(chat)?;
        }
    }
    let manifest = Manifest::new(
        std::mem::take(&mut review.manifest),
        oblivion_transfer::share::LIMITS,
    )?;
    oblivion_transfer::share::validate_manifest(&manifest)?;
    if manifest.sha256() != review.manifest_sha256 || manifest.bytes() != review.bytes {
        return Err(io::Error::other("share_review_changed"));
    }
    Ok(manifest)
}
