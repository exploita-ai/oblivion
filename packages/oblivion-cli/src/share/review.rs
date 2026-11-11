//! The current guest plan, validated once before review or approval.
use super::command::{Selection, validate_chat, validate_path};
use crate::controller::Result;
use oblivion_share::Manifest;
pub use oblivion_share::control::SourceMetadata;
use oblivion_transfer::Entry;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum Reply {
    Reviewed(Review),
    Rejected(Rejection),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Rejection {
    version: u8,
    request_id: Option<String>,
    ok: bool,
    error: String,
}

#[derive(Debug)]
pub(super) enum Conflict {
    RequiredFile,
    RequiredConversation,
}

impl std::fmt::Display for Conflict {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str(match self {
            Self::RequiredFile => {
                "A selected conversation requires a file omitted by this selection."
            }
            Self::RequiredConversation => {
                "A selected conversation requires saved context from an excluded conversation."
            }
        })
    }
}

impl std::error::Error for Conflict {}

pub(super) fn validate_reply(reply: Reply, request: &str) -> Result<(Review, Manifest)> {
    match reply {
        Reply::Reviewed(mut review) => {
            let manifest = validate_review(&mut review, request)?;
            Ok((review, manifest))
        }
        Reply::Rejected(reply) => {
            if reply.version == 1 && !reply.ok && reply.request_id.as_deref() == Some(request) {
                let conflict = match reply.error.as_str() {
                    "share_native_dependency_not_selected" => Some(Conflict::RequiredFile),
                    "share_excluded_chat_required" => Some(Conflict::RequiredConversation),
                    _ => None,
                };
                if let Some(conflict) = conflict {
                    return Err(conflict.into());
                }
            }
            Err("The Safe could not prepare this Share selection".into())
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub version: u8,
    pub request_id: String,
    pub manifest: Vec<Entry>,
    pub manifest_sha256: String,
    pub plan_sha256: String,
    pub bytes: u64,
    pub chats: Vec<Chat>,
    pub omitted: BTreeMap<String, u64>,
    pub warnings: Vec<Warning>,
    pub warning_count: u64,
    pub scan: Scan,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chat {
    pub id: String,
    pub agent: Agent,
    pub title: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Agent {
    Codex,
    Claude,
    #[serde(rename = "opencode2")]
    OpenCode,
}

impl Agent {
    fn label(&self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::Claude => "Claude Code",
            Self::OpenCode => "OpenCode 2",
        }
    }
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
    for (index, entry) in manifest.entries().iter().enumerate() {
        let number = if selectable_path(entry.path()) {
            format!("F {}", index + 1)
        } else {
            "   ".into()
        };
        writeln!(
            output,
            "  {number} · {:?}{}",
            entry.path(),
            if matches!(entry, Entry::Directory { .. }) {
                "/"
            } else {
                ""
            }
        )?;
    }
    for (index, chat) in review.chats.iter().enumerate() {
        writeln!(
            output,
            "  C {} · {} · {:?} ({})",
            index + 1,
            chat.agent.label(),
            chat.title.as_deref().unwrap_or("Untitled conversation"),
            chat.id,
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

fn selectable_path(path: &str) -> bool {
    matches!(path.split('/').next(), Some("workspace" | "imports"))
}

pub(super) fn exclude(
    value: &str,
    selection: &mut Selection,
    manifest: &Manifest,
    review: &Review,
) -> Option<usize> {
    let mut words = value.split_ascii_whitespace();
    let (target, paths) = match words.next()? {
        "F" | "f" => (&mut selection.exclude_paths, true),
        "C" | "c" => (&mut selection.exclude_chats, false),
        _ => return None,
    };
    let requested = words
        .map(|word| {
            let index = word.parse::<usize>().ok()?.checked_sub(1)?;
            if paths {
                let path = manifest.entries().get(index)?.path();
                return selectable_path(path).then_some(path);
            }
            review.chats.get(index).map(|chat| chat.id.as_str())
        })
        .collect::<Option<BTreeSet<_>>>()?;
    if requested.is_empty() {
        return None;
    }
    let added = requested
        .into_iter()
        .filter(|value| !target.iter().any(|entry| entry == value))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let count = added.len();
    target.extend(added);
    Some(count)
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
        || review
            .chats
            .iter()
            .map(|chat| &chat.id)
            .collect::<BTreeSet<_>>()
            .len()
            != review.chats.len()
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
        validate_chat(&chat.id)?;
        if chat.title.as_ref().is_some_and(|title| {
            title.trim().is_empty() || title.len() > 256 || title.chars().any(|character|
                character.is_control() || matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
        }) {
            return Err(io::Error::other("invalid_share_chat_title"));
        }
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
