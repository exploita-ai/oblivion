//! Bounded, path-free NDJSON for one explicitly reviewed native Files copy.
use crate::selection::{Mapping, Plan};
use crate::{Entry, Manifest, Receipt, invalid, native_files::Direction, require, validate_id};
use serde::{Deserialize, Serialize};
use std::io;

pub const LINE_LIMIT: usize = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub operation_id: String,
    pub safe_id: String,
    pub opening: String,
}

impl Identity {
    pub fn validate(&self) -> io::Result<()> {
        validate_id(&self.operation_id)?;
        validate_id(&self.safe_id)?;
        validate_id(&self.opening)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub manifest_sha256: String,
    pub mapping_sha256: String,
    pub entries: usize,
    pub files: usize,
    pub directories: usize,
    pub bytes: u64,
}

impl Summary {
    pub fn from_manifest(manifest: &Manifest, plan: &Plan) -> io::Result<Self> {
        plan.validate()?;
        let selected = plan.selected.as_str();
        let mut files = 0;
        let mut directories = 0;
        for entry in manifest.entries() {
            if entry.path() == selected
                || entry
                    .path()
                    .strip_prefix(selected)
                    .is_some_and(|suffix| suffix.starts_with('/'))
            {
                if plan.mappings.len() > 1 && entry.path() == selected {
                    continue;
                }
                match entry {
                    Entry::File { .. } => files += 1,
                    Entry::Directory { .. } => directories += 1,
                }
                continue;
            }
            return Err(invalid("invalid_file_review"));
        }
        let summary = Self {
            manifest_sha256: manifest.sha256(),
            mapping_sha256: plan.sha256()?,
            entries: manifest.entries().len(),
            files,
            directories,
            bytes: manifest.bytes(),
        };
        summary.validate()?;
        require(
            summary.entries - files - directories == usize::from(plan.mappings.len() > 1),
            "invalid_file_review",
        )?;
        Ok(summary)
    }

    pub fn validate(&self) -> io::Result<()> {
        let selected = self
            .files
            .checked_add(self.directories)
            .ok_or_else(|| invalid("invalid_file_review"))?;
        require(
            hash(&self.manifest_sha256)
                && hash(&self.mapping_sha256)
                && (1..=crate::MAX_ENTRIES).contains(&self.entries)
                && (1..=self.entries).contains(&selected)
                && self.entries - selected <= 1
                && self.bytes <= crate::MAX_DOCUMENT_BYTES,
            "invalid_file_review",
        )
    }

    pub fn matches(&self, receipt: &Receipt, identity: &Identity) -> bool {
        receipt.id == identity.operation_id
            && receipt.manifest_sha256 == self.manifest_sha256
            && receipt.entries == self.entries
            && receipt.bytes == self.bytes
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    Copying,
    Finalizing,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Completed,
    Interrupted,
    CancelledBeforeCopy,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Event {
    Mapping {
        identity: Identity,
        start: usize,
        total: usize,
        selected: String,
        entries: Vec<Mapping>,
        mapping_sha256: String,
    },
    Review {
        identity: Identity,
        direction: Direction,
        name: String,
        summary: Summary,
    },
    Progress {
        identity: Identity,
        phase: Phase,
        bytes: u64,
        total_bytes: u64,
    },
    Finished {
        identity: Identity,
        outcome: Outcome,
        receipt: Option<Receipt>,
    },
}

impl Event {
    pub fn validate(&self) -> io::Result<()> {
        match self {
            Self::Mapping {
                identity,
                start,
                total,
                selected,
                entries,
                mapping_sha256,
            } => {
                identity.validate()?;
                crate::selection::validate_alias(selected)?;
                require(
                    (1..=crate::selection::MAX_SELECTIONS).contains(total)
                        && *start < *total
                        && start % crate::selection::MAPPING_PAGE == 0
                        && entries.len() == crate::selection::MAPPING_PAGE.min(total - start)
                        && hash(mapping_sha256),
                    "invalid_file_mapping",
                )?;
                for (offset, entry) in entries.iter().enumerate() {
                    require(entry.input_index == start + offset, "invalid_file_mapping")?;
                    match (&entry.alias, entry.covered_by) {
                        (Some(alias), None) => crate::selection::validate_alias(alias)?,
                        (None, Some(owner)) => require(
                            owner < *total && owner != entry.input_index,
                            "invalid_file_mapping",
                        )?,
                        _ => return Err(invalid("invalid_file_mapping")),
                    }
                }
                Ok(())
            }
            Self::Review {
                identity,
                name,
                summary,
                ..
            } => {
                identity.validate()?;
                crate::native_files::validate_name(name)?;
                summary.validate()?;
                Ok(())
            }
            Self::Progress {
                identity,
                phase,
                bytes,
                total_bytes,
            } => {
                identity.validate()?;
                require(
                    *bytes <= *total_bytes
                        && *total_bytes <= crate::MAX_DOCUMENT_BYTES
                        && (*phase != Phase::Finalizing || bytes == total_bytes),
                    "invalid_file_progress",
                )
            }
            Self::Finished {
                identity,
                outcome,
                receipt,
            } => {
                identity.validate()?;
                require(
                    (*outcome == Outcome::Completed) == receipt.is_some(),
                    "invalid_file_completion",
                )?;
                if let Some(receipt) = receipt {
                    require(
                        receipt.id == identity.operation_id
                            && hash(&receipt.manifest_sha256)
                            && (1..=crate::MAX_ENTRIES).contains(&receipt.entries)
                            && receipt.bytes <= crate::MAX_DOCUMENT_BYTES,
                        "invalid_file_completion",
                    )?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Input {
    Approve {
        operation_id: String,
        manifest_sha256: String,
    },
    Cancel {
        operation_id: String,
    },
}

impl Input {
    pub fn validate(&self, expected: &str) -> io::Result<()> {
        let operation = match self {
            Self::Approve { operation_id, .. } | Self::Cancel { operation_id } => operation_id,
        };
        validate_id(operation)?;
        require(operation == expected, "file_operation_changed")?;
        if let Self::Approve {
            manifest_sha256, ..
        } = self
        {
            require(hash(manifest_sha256), "invalid_file_approval")?;
        }
        Ok(())
    }
}

pub fn encode(event: &Event) -> io::Result<Vec<u8>> {
    event.validate()?;
    let mut bytes = serde_json::to_vec(event).map_err(|_| invalid("invalid_file_event"))?;
    bytes.push(b'\n');
    require(bytes.len() <= LINE_LIMIT, "file_event_too_large")?;
    Ok(bytes)
}

pub fn input(line: &[u8], expected: &str) -> io::Result<Input> {
    require(
        !line.is_empty()
            && line.len() <= LINE_LIMIT
            && line.last() == Some(&b'\n')
            && !line[..line.len() - 1].contains(&b'\n'),
        "invalid_file_input",
    )?;
    let input: Input = serde_json::from_slice(line).map_err(|_| invalid("invalid_file_input"))?;
    input.validate(expected)?;
    Ok(input)
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity {
            operation_id: "a".repeat(32),
            safe_id: "b".repeat(32),
            opening: "c".repeat(32),
        }
    }

    #[test]
    fn selected_counts_exclude_only_the_generated_collection_wrapper() {
        let manifest = Manifest::new(
            vec![
                Entry::Directory {
                    path: "selection".into(),
                },
                Entry::Directory {
                    path: "selection/project".into(),
                },
                Entry::File {
                    path: "selection/project/note".into(),
                    size: 2,
                    sha256: "d".repeat(64),
                },
                Entry::File {
                    path: "selection/readme".into(),
                    size: 1,
                    sha256: "e".repeat(64),
                },
            ],
            crate::Limits {
                entries: 10,
                bytes: 10,
            },
        )
        .unwrap();
        let plan = Plan::new(&[
            crate::selection::Input {
                path: "workspace/project".into(),
                directory: true,
            },
            crate::selection::Input {
                path: "imports/readme".into(),
                directory: false,
            },
        ])
        .unwrap();
        let summary = Summary::from_manifest(&manifest, &plan).unwrap();
        assert_eq!(
            (
                summary.entries,
                summary.files,
                summary.directories,
                summary.bytes
            ),
            (4, 2, 1, 3)
        );
        assert!(
            encode(&Event::Review {
                identity: identity(),
                direction: Direction::Export,
                name: "project".into(),
                summary: summary.clone()
            })
            .is_ok()
        );
        assert!(
            encode(&Event::Review {
                identity: identity(),
                direction: Direction::Import,
                name: "project".into(),
                summary
            })
            .is_ok()
        );
        let other = Plan::new(&[crate::selection::Input {
            path: "workspace/other".into(),
            directory: true,
        }])
        .unwrap();
        assert!(Summary::from_manifest(&manifest, &other).is_err());
        let single = Plan::new(&[crate::selection::Input {
            path: "workspace/selection".into(),
            directory: true,
        }])
        .unwrap();
        let summary = Summary::from_manifest(&manifest, &single).unwrap();
        assert_eq!(summary.directories, 2);
    }

    #[test]
    fn input_is_one_bounded_strict_line_bound_to_the_operation() {
        let line = format!(
            "{{\"action\":\"approve\",\"operation_id\":\"{}\",\"manifest_sha256\":\"{}\"}}\n",
            "a".repeat(32),
            "d".repeat(64)
        );
        assert!(matches!(
            input(line.as_bytes(), &identity().operation_id),
            Ok(Input::Approve { .. })
        ));
        assert!(input(line.as_bytes(), &"e".repeat(32)).is_err());
        assert!(input(line.trim_end().as_bytes(), &identity().operation_id).is_err());
        assert!(input(format!("{line}{line}").as_bytes(), &identity().operation_id).is_err());
        assert!(input(&vec![b'x'; LINE_LIMIT + 1], &identity().operation_id).is_err());
        assert!(
            input(
                format!(
                    "{{\"action\":\"cancel\",\"operation_id\":\"{}\",\"path\":\"/etc/passwd\"}}\n",
                    "a".repeat(32)
                )
                .as_bytes(),
                &identity().operation_id
            )
            .is_err()
        );
    }

    #[test]
    fn maximum_selection_mapping_is_paged_within_the_ndjson_bound() {
        let plan = Plan::new(
            &(0..crate::selection::MAX_SELECTIONS)
                .map(|index| crate::selection::Input {
                    path: format!("/source{index}/{}{index:03}", "\"".repeat(252)),
                    directory: false,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        for (page, mappings) in plan
            .mappings
            .chunks(crate::selection::MAPPING_PAGE)
            .enumerate()
        {
            let event = Event::Mapping {
                identity: identity(),
                start: page * crate::selection::MAPPING_PAGE,
                total: plan.mappings.len(),
                selected: plan.selected.clone(),
                entries: mappings.to_vec(),
                mapping_sha256: plan.sha256().unwrap(),
            };
            let line = encode(&event).unwrap();
            assert!(line.len() <= LINE_LIMIT);
            assert!(!String::from_utf8(line).unwrap().contains("/source"));
        }
        let mut entries = plan.mappings[..crate::selection::MAPPING_PAGE].to_vec();
        entries[0].input_index = 1;
        assert!(
            encode(&Event::Mapping {
                identity: identity(),
                start: 0,
                total: plan.mappings.len(),
                selected: plan.selected.clone(),
                entries,
                mapping_sha256: plan.sha256().unwrap(),
            })
            .is_err()
        );
    }

    #[test]
    fn finalizing_and_completion_cannot_be_faked_from_a_progress_total() {
        assert!(
            encode(&Event::Progress {
                identity: identity(),
                phase: Phase::Finalizing,
                bytes: 1,
                total_bytes: 2
            })
            .is_err()
        );
        assert!(
            encode(&Event::Progress {
                identity: identity(),
                phase: Phase::Copying,
                bytes: 2,
                total_bytes: 2
            })
            .is_ok()
        );
        assert!(
            encode(&Event::Finished {
                identity: identity(),
                outcome: Outcome::Completed,
                receipt: None
            })
            .is_err()
        );
        let receipt = Receipt {
            id: "a".repeat(32),
            manifest_sha256: "d".repeat(64),
            entries: 1,
            bytes: 2,
        };
        assert!(
            encode(&Event::Finished {
                identity: identity(),
                outcome: Outcome::Interrupted,
                receipt: Some(receipt)
            })
            .is_err()
        );
    }
}
