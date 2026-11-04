//! Portable native Files requests and authoritative receiver outcomes.
use crate::{Receipt, require, validate_id};
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub id: String,
    pub safe_id: String,
    pub opening: String,
    pub direction: Direction,
    pub name: String,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    Import,
    Export,
}

impl Context {
    pub fn validate(&self) -> io::Result<()> {
        validate_id(&self.id)?;
        validate_id(&self.safe_id)?;
        validate_id(&self.opening)?;
        validate_name(&self.name)
    }
}

/// A publication name preserves native spelling; only logical selection
/// aliases use NFC normalization and case-folded collision detection.
pub fn validate_name(name: &str) -> io::Result<()> {
    crate::validate_path(name)?;
    require(!name.contains('/'), "invalid_destination_name")
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    Unknown,
    Incomplete,
    Ready,
    Published,
    Discarded,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub operation_id: String,
    pub safe_id: String,
    pub opening: String,
    pub source_opening: Option<String>,
    pub state: State,
    pub receipt: Option<Receipt>,
    pub can_recover: bool,
    pub can_discard: bool,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Status,
    Recover,
    Discard,
}

impl Status {
    pub fn validate(&self, id: &str, safe: &str, opening: &str) -> io::Result<()> {
        require(
            self.operation_id == id && self.safe_id == safe && self.opening == opening,
            "file_operation_changed",
        )?;
        if let Some(source) = &self.source_opening {
            validate_id(source)?;
        }
        if let Some(receipt) = &self.receipt {
            validate_id(&receipt.id)?;
            require(
                receipt.id == id
                    && receipt.manifest_sha256.len() == 64
                    && receipt
                        .manifest_sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    && (1..=crate::MAX_ENTRIES).contains(&receipt.entries)
                    && receipt.bytes <= crate::MAX_DOCUMENT_BYTES,
                "invalid_file_receipt",
            )?;
        }
        require(
            match self.state {
                State::Unknown => {
                    self.source_opening.is_none()
                        && self.receipt.is_none()
                        && !self.can_recover
                        && !self.can_discard
                }
                State::Incomplete => {
                    self.source_opening.is_some() && self.receipt.is_none() && !self.can_recover
                }
                State::Ready => {
                    self.source_opening.is_some() && self.receipt.is_some() && self.can_recover
                }
                State::Published => {
                    self.source_opening.is_some()
                        && self.receipt.is_some()
                        && !self.can_recover
                        && !self.can_discard
                }
                State::Discarded => {
                    self.source_opening.is_some()
                        && self.receipt.is_none()
                        && !self.can_recover
                        && !self.can_discard
                }
            },
            "invalid_file_operation_status",
        )
    }
}

/// Current launchers use this fixed-root endpoint inside the selected Safe.
#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    Import {
        id: String,
        safe_id: String,
        opening: String,
        name: String,
    },
    Status {
        id: String,
        safe_id: String,
        opening: String,
    },
    Recover {
        id: String,
        safe_id: String,
        opening: String,
    },
    Discard {
        id: String,
        safe_id: String,
        opening: String,
    },
}
