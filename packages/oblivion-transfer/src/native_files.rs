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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

pub const TRANSFERS_PAGE_LIMIT: usize = 8;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransfersQuery {
    pub safe_id: String,
    pub opening: String,
    pub direction: Direction,
    pub after: Option<String>,
    pub limit: usize,
}

impl TransfersQuery {
    pub fn validate(&self) -> io::Result<()> {
        validate_id(&self.safe_id)?;
        validate_id(&self.opening)?;
        require(
            (1..=TRANSFERS_PAGE_LIMIT).contains(&self.limit),
            "invalid_transfer_page_limit",
        )?;
        if let Some(after) = &self.after {
            validate_id(after)?;
        }
        Ok(())
    }
}

/// A receiver-owned operation reference, not a verified outcome or grant to
/// recover/discard. The caller must inspect fresh status before acting.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferEntry {
    pub operation_id: String,
    pub source_opening: String,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransfersPage {
    pub safe_id: String,
    pub opening: String,
    pub direction: Direction,
    pub entries: Vec<TransferEntry>,
    pub next_cursor: Option<String>,
    pub skipped: usize,
}

impl TransfersPage {
    pub fn validate(&self, query: &TransfersQuery) -> io::Result<()> {
        query.validate()?;
        require(
            self.safe_id == query.safe_id
                && self.opening == query.opening
                && self.direction == query.direction,
            "file_transfer_inventory_changed",
        )?;
        require(
            self.entries.len() <= query.limit && self.skipped <= crate::MAX_ENTRIES,
            "invalid_transfer_page",
        )?;
        let mut previous = query.after.as_deref();
        for entry in &self.entries {
            validate_id(&entry.operation_id)?;
            validate_id(&entry.source_opening)?;
            validate_name(&entry.name)?;
            require(
                previous.is_none_or(|previous| previous < entry.operation_id.as_str()),
                "invalid_transfer_page_order",
            )?;
            previous = Some(&entry.operation_id);
        }
        if let Some(cursor) = &self.next_cursor {
            validate_id(cursor)?;
            require(
                query.after.as_ref().is_none_or(|after| after < cursor)
                    && previous.is_none_or(|previous| previous <= cursor.as_str()),
                "invalid_transfer_cursor",
            )?;
            // A scan can advance across invalid or unrelated records without
            // exposing them. It cannot invent such a gap with no skipped item.
            require(
                previous == Some(cursor.as_str()) || self.skipped > 0,
                "invalid_transfer_cursor",
            )?;
        }
        Ok(())
    }
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
    Transfers {
        safe_id: String,
        opening: String,
        after: Option<String>,
        limit: usize,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> TransfersQuery {
        TransfersQuery {
            safe_id: "a".repeat(32),
            opening: "b".repeat(32),
            direction: Direction::Import,
            after: Some("1".repeat(32)),
            limit: TRANSFERS_PAGE_LIMIT,
        }
    }

    fn page(query: &TransfersQuery) -> TransfersPage {
        TransfersPage {
            safe_id: query.safe_id.clone(),
            opening: query.opening.clone(),
            direction: query.direction,
            entries: vec![TransferEntry {
                operation_id: "2".repeat(32),
                source_opening: "c".repeat(32),
                name: "cafe\u{301}".into(),
            }],
            next_cursor: Some("2".repeat(32)),
            skipped: 0,
        }
    }

    #[test]
    fn inventory_queries_and_pages_are_bound_and_bounded_without_normalizing_names() {
        let query = query();
        let valid = page(&query);
        valid.validate(&query).unwrap();
        assert_eq!(valid.entries[0].name.as_bytes(), "cafe\u{301}".as_bytes());
        for changed in [
            TransfersQuery {
                limit: 0,
                ..query.clone()
            },
            TransfersQuery {
                limit: 9,
                ..query.clone()
            },
            TransfersQuery {
                safe_id: "../outside".into(),
                ..query.clone()
            },
            TransfersQuery {
                opening: "A".repeat(32),
                ..query.clone()
            },
            TransfersQuery {
                after: Some("short".into()),
                ..query.clone()
            },
        ] {
            assert!(changed.validate().is_err());
        }
        for changed in [
            TransfersPage {
                safe_id: "d".repeat(32),
                ..valid.clone()
            },
            TransfersPage {
                opening: "d".repeat(32),
                ..valid.clone()
            },
            TransfersPage {
                direction: Direction::Export,
                ..valid.clone()
            },
            TransfersPage {
                entries: vec![valid.entries[0].clone(); 9],
                ..valid.clone()
            },
            TransfersPage {
                skipped: crate::MAX_ENTRIES + 1,
                ..valid.clone()
            },
        ] {
            assert!(changed.validate(&query).is_err());
        }
    }

    #[test]
    fn invalid_records_can_advance_the_cursor_without_fabricating_an_entry() {
        let query = query();
        let valid = TransfersPage {
            entries: Vec::new(),
            next_cursor: Some("4".repeat(32)),
            skipped: 3,
            ..page(&query)
        };
        valid.validate(&query).unwrap();
        assert!(
            TransfersPage {
                skipped: 0,
                ..valid.clone()
            }
            .validate(&query)
            .is_err()
        );
        assert!(
            TransfersPage {
                next_cursor: query.after.clone(),
                ..valid.clone()
            }
            .validate(&query)
            .is_err()
        );
        let with_entry = page(&query);
        TransfersPage {
            next_cursor: Some("4".repeat(32)),
            skipped: 2,
            ..with_entry.clone()
        }
        .validate(&query)
        .unwrap();
        assert!(
            TransfersPage {
                next_cursor: Some("4".repeat(32)),
                ..with_entry.clone()
            }
            .validate(&query)
            .is_err()
        );
        assert!(
            TransfersPage {
                next_cursor: Some("0".repeat(32)),
                ..with_entry
            }
            .validate(&query)
            .is_err()
        );
    }

    #[test]
    fn operation_references_reject_bad_ids_names_duplicates_and_stale_ordering() {
        let query = query();
        let valid = page(&query);
        for name in [
            "",
            "../outside",
            "a/b",
            "a\\b",
            "bad\nname",
            "bad\u{061c}name",
            "bad\u{2028}name",
            "bad\u{2029}name",
        ] {
            let mut changed = valid.clone();
            changed.entries[0].name = name.into();
            assert!(changed.validate(&query).is_err(), "{name:?}");
        }
        for id in ["bad".into(), "F".repeat(32), "1".repeat(32)] {
            let mut changed = valid.clone();
            changed.entries[0].operation_id = id;
            assert!(changed.validate(&query).is_err());
        }
        let mut changed = valid.clone();
        changed.entries[0].source_opening = "bad".into();
        assert!(changed.validate(&query).is_err());
        let mut changed = valid.clone();
        changed.entries.push(valid.entries[0].clone());
        assert!(changed.validate(&query).is_err());
        let mut changed = valid;
        changed.entries.push(TransferEntry {
            operation_id: "0".repeat(32),
            source_opening: "c".repeat(32),
            name: "other".into(),
        });
        assert!(changed.validate(&query).is_err());
    }

    #[test]
    fn inventory_wire_has_no_outcome_or_mutation_authority() {
        let query = query();
        let request = Request::Transfers {
            safe_id: query.safe_id.clone(),
            opening: query.opening.clone(),
            after: None,
            limit: 8,
        };
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"operation":"transfers","safe_id":"a".repeat(32),"opening":"b".repeat(32),"after":null,"limit":8})
        );
        serde_json::from_value::<Request>(value.clone()).unwrap();
        for field in ["direction", "root", "id", "path"] {
            let mut invalid = value.clone();
            invalid[field] = serde_json::json!("export");
            assert!(serde_json::from_value::<Request>(invalid).is_err());
        }
        let serialized = serde_json::to_value(page(&query)).unwrap();
        assert_eq!(serialized["entries"][0].as_object().unwrap().len(), 3);
        for field in ["state", "receipt", "can_recover", "can_discard"] {
            let mut invalid = serialized.clone();
            invalid["entries"][0][field] = serde_json::json!(true);
            assert!(serde_json::from_value::<TransfersPage>(invalid).is_err());
        }
    }
}
