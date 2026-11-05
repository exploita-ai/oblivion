//! Bounded operation references and current-content evidence on a selected USB.
pub use crate::native_files::State;
use crate::{Receipt, require, validate_id};
use serde::{Deserialize, Serialize};
use std::io;

#[cfg(unix)]
#[path = "media_export_unix.rs"]
mod unix;
#[cfg(unix)]
pub use unix::{Authority, execute, serve};
#[cfg(unix)]
pub(crate) use unix::{operation_names, write_operation, write_receipt};

pub const PAGE_LIMIT: usize = 8;

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    Inventory { after: Option<String>, limit: usize },
    Status { id: String },
    Recover { id: String, review_sha256: String },
    Discard { id: String, review_sha256: String },
}

impl Request {
    pub fn validate(&self) -> io::Result<()> {
        match self {
            Self::Inventory { after, limit } => {
                require((1..=PAGE_LIMIT).contains(limit), "invalid_usb_page_limit")?;
                if let Some(after) = after {
                    validate_id(after)?;
                }
                Ok(())
            }
            Self::Status { id } => validate_id(id),
            Self::Recover { id, review_sha256 } | Self::Discard { id, review_sha256 } => {
                validate_id(id)?;
                validate_digest(review_sha256)
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Response {
    Inventory {
        operations: Vec<String>,
        next_cursor: Option<String>,
    },
    Status {
        status: Status,
    },
    Rejected {
        reason: Rejection,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Rejection {
    Unavailable,
    ReviewChanged,
    NotAuthorized,
}

impl Response {
    pub fn validate(&self, request: &Request) -> io::Result<()> {
        request.validate()?;
        match (self, request) {
            (
                Self::Inventory {
                    operations,
                    next_cursor,
                },
                Request::Inventory { after, limit },
            ) => {
                require(operations.len() <= *limit, "invalid_usb_inventory")?;
                let mut previous = after.as_deref();
                for id in operations {
                    validate_id(id)?;
                    require(
                        previous.is_none_or(|previous| previous < id.as_str()),
                        "invalid_usb_inventory",
                    )?;
                    previous = Some(id);
                }
                require(
                    next_cursor.is_none()
                        || operations.len() == *limit && next_cursor.as_deref() == previous,
                    "invalid_usb_inventory",
                )
            }
            (Self::Status { status }, Request::Status { id }) => {
                status.validate(id)?;
                require(
                    status.state != State::Discarded,
                    "invalid_usb_operation_response",
                )
            }
            (Self::Status { status }, Request::Recover { id, .. }) => {
                status.validate(id)?;
                require(
                    status.state == State::Published,
                    "invalid_usb_operation_response",
                )
            }
            (Self::Status { status }, Request::Discard { id, .. }) => {
                status.validate(id)?;
                require(
                    status.state == State::Discarded,
                    "invalid_usb_operation_response",
                )
            }
            (Self::Rejected { reason }, _) => Err(crate::invalid(match reason {
                Rejection::Unavailable => "usb_operation_unavailable",
                Rejection::ReviewChanged => "usb_review_changed",
                Rejection::NotAuthorized => "usb_operation_not_authorized",
            })),
            _ => Err(crate::invalid("invalid_usb_operation_response")),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub operation_id: String,
    pub state: State,
    pub receipt: Option<Receipt>,
    pub review_sha256: Option<String>,
}

impl Status {
    pub fn validate(&self, id: &str) -> io::Result<()> {
        validate_id(id)?;
        require(self.operation_id == id, "usb_operation_changed")?;
        if let Some(receipt) = &self.receipt {
            validate_digest(&receipt.manifest_sha256)?;
            require(
                receipt.id == id
                    && (1..=crate::MAX_ENTRIES).contains(&receipt.entries)
                    && receipt.bytes <= crate::MAX_DOCUMENT_BYTES,
                "invalid_usb_receipt",
            )?;
        }
        if let Some(digest) = &self.review_sha256 {
            validate_digest(digest)?;
        }
        let expected = match self.state {
            State::Unknown | State::Discarded => (false, false),
            State::Incomplete => (false, true),
            State::Ready => (true, true),
            State::Published => (true, false),
        };
        require(
            (self.receipt.is_some(), self.review_sha256.is_some()) == expected,
            "invalid_usb_operation_status",
        )
    }
}

fn validate_digest(value: &str) -> io::Result<()> {
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid_usb_operation_digest",
    )
}
