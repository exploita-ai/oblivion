use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    List { cursor: Option<String> },
    Export { id: String, format: Format },
    Diagnostics { report: crate::diagnostics::Report },
    Checkpoint { metadata: crate::backup::Metadata },
    Inspect,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Markdown,
    Json,
}

impl Request {
    pub fn is_chat_export(&self) -> bool {
        matches!(self, Self::List { .. } | Self::Export { .. })
    }

    pub fn valid(&self) -> bool {
        match self {
            Self::List { cursor } => cursor
                .as_ref()
                .is_none_or(|value| value.len() <= 1024 && !value.chars().any(char::is_control)),
            Self::Export { id, .. } => valid_id(id),
            Self::Diagnostics { report } => report.valid(),
            Self::Checkpoint { metadata } => metadata.valid(),
            Self::Inspect => true,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: String,
    pub title: String,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "lowercase", deny_unknown_fields)]
pub enum Response {
    Chats {
        entries: Vec<Entry>,
        next: Option<String>,
    },
    Exported {
        path: String,
        bytes: u64,
    },
    Metadata {
        metadata: crate::backup::Metadata,
    },
    Rejected {
        error: crate::backup::Rejection,
    },
    Unavailable,
}

impl Response {
    pub fn valid(&self, request: &Request) -> bool {
        match (self, request) {
            (Self::Metadata { metadata }, Request::Checkpoint { metadata: expected }) => {
                metadata.valid() && metadata == expected
            }
            (Self::Metadata { metadata }, Request::Inspect) => metadata.valid(),
            (Self::Rejected { .. }, Request::Checkpoint { .. } | Request::Inspect) => true,
            (Self::Chats { entries, next }, Request::List { .. }) => {
                entries.len() <= 50
                    && entries.iter().all(|entry| {
                        valid_id(&entry.id)
                            && entry.title.chars().count() <= 200
                            && !entry.title.chars().any(char::is_control)
                    })
                    && next.as_ref().is_none_or(|value| {
                        value.len() <= 1024 && !value.chars().any(char::is_control)
                    })
            }
            (Self::Exported { path, bytes }, Request::Export { format, .. }) => {
                let extension = match format {
                    Format::Markdown => ".md",
                    Format::Json => ".json",
                };
                *bytes > 0
                    && *bytes <= 64 * 1024 * 1024
                    && path
                        .strip_prefix("workspace/chat-exports/")
                        .and_then(|name| name.strip_suffix(extension))
                        .is_some_and(|name| {
                            name.len() == 32
                                && name.bytes().all(|byte| {
                                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                                })
                        })
            }
            (Self::Exported { path, bytes }, Request::Diagnostics { .. }) => {
                *bytes > 0
                    && *bytes <= 4096
                    && path
                        .strip_prefix("workspace/diagnostics/")
                        .and_then(|name| name.strip_suffix(".json"))
                        .is_some_and(|name| {
                            name.len() == 32
                                && name.bytes().all(|byte| {
                                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                                })
                        })
            }
            (Self::Unavailable, _) => true,
            _ => false,
        }
    }
}

fn valid_id(id: &str) -> bool {
    id.strip_prefix("ses_").is_some_and(|suffix| {
        (1..=128).contains(&suffix.len())
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    })
}
