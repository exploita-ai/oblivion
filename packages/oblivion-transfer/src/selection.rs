//! Pure selection planning. Source paths remain private; only aliases leave the
//! source process. Physical objects are opened and pinned by the OS endpoint.
use crate::{invalid, require};
use icu_casemap::CaseMapper;
use icu_normalizer::ComposingNormalizer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io;

pub const MAX_SELECTIONS: usize = 128;
pub const MAX_SELECTION_BYTES: usize = 64 * 1024;
pub const MAPPING_PAGE: usize = 4;

pub struct Input {
    pub path: String,
    pub directory: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    pub input_index: usize,
    pub alias: Option<String>,
    pub covered_by: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub selected: String,
    pub mappings: Vec<Mapping>,
}

pub fn validate_paths(paths: &[String]) -> io::Result<()> {
    validate_path_budget(paths)?;
    for path in paths {
        require(
            !path.is_empty() && path.len() <= 4096 && !path.chars().any(unsafe_character),
            "invalid_selection_path",
        )?;
        let drive = path.as_bytes().get(..3).is_some_and(|prefix| {
            prefix[0].is_ascii_uppercase() && prefix[1] == b':' && prefix[2] == b'/'
        });
        let logical = if drive { &path[3..] } else { path.strip_prefix('/').unwrap_or(path) };
        let components = logical.split('/').collect::<Vec<_>>();
        require(
            !components.is_empty()
                && components.iter().all(|part| {
                    !part.is_empty() && part.len() <= 255 && *part != "." && *part != ".."
                }),
            "invalid_selection_path",
        )?;
        require(
            components[..components.len() - 1]
                .iter()
                .all(|part| !part.contains('\\')),
            "invalid_selection_path",
        )?;
        if drive {
            require(
                components.iter().all(|part| {
                    !part.ends_with(['.', ' ']) && !part.contains([':', '\\', '<', '>', '"', '|', '?', '*'])
                }),
                "invalid_selection_path",
            )?;
        }
        require(
            drive || path.starts_with('/') || matches!(components[0], "workspace" | "imports"),
            "invalid_selection_root",
        )?;
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn validate_rooted_paths(paths: &[String]) -> io::Result<()> {
    validate_path_budget(paths)?;
    for path in paths {
        crate::validate_path(path)?;
    }
    Ok(())
}

fn validate_path_budget(paths: &[String]) -> io::Result<()> {
    require(
        (1..=MAX_SELECTIONS).contains(&paths.len()),
        "selection_limit",
    )?;
    let bytes = paths.iter().try_fold(0usize, |total, path| {
        total
            .checked_add(path.len())
            .ok_or_else(|| invalid("selection_byte_limit"))
    })?;
    require(bytes <= MAX_SELECTION_BYTES, "selection_byte_limit")
}

impl Plan {
    pub fn new(inputs: &[Input]) -> io::Result<Self> {
        Self::with_path_validation(inputs, validate_paths)
    }

    #[cfg(unix)]
    pub(crate) fn rooted(inputs: &[Input]) -> io::Result<Self> {
        Self::with_path_validation(inputs, validate_rooted_paths)
    }

    fn with_path_validation(
        inputs: &[Input],
        validate: fn(&[String]) -> io::Result<()>,
    ) -> io::Result<Self> {
        validate(&inputs.iter().map(|input| input.path.clone()).collect::<Vec<_>>())?;
        for input in inputs {
            require(
                inputs
                    .iter()
                    .all(|other| other.path != input.path || other.directory == input.directory),
                "selection_changed",
            )?;
        }
        let owners = inputs
            .iter()
            .map(|input| {
                inputs
                    .iter()
                    .enumerate()
                    .filter(|(_, candidate)| {
                        candidate.path == input.path
                            || candidate.directory && descendant(&input.path, &candidate.path)
                    })
                    .min_by_key(|(index, candidate)| {
                        (
                            candidate.path.bytes().filter(|byte| *byte == b'/').count(),
                            *index,
                        )
                    })
                    .map(|(index, _)| index)
                    .ok_or_else(|| invalid("invalid_selection"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        let mut aliases = BTreeSet::new();
        let mut mappings = Vec::with_capacity(inputs.len());
        for (index, input) in inputs.iter().enumerate() {
            if owners[index] != index {
                mappings.push(Mapping {
                    input_index: index,
                    alias: None,
                    covered_by: Some(owners[index]),
                });
                continue;
            }
            let leaf = input
                .path
                .rsplit('/')
                .next()
                .ok_or_else(|| invalid("invalid_selection_path"))?
                .replace('\\', "_");
            let original = ComposingNormalizer::new_nfc().normalize(&leaf).into_owned();
            let mut alias = original.clone();
            let mut ordinal = 2;
            while !aliases.insert(collision_key(&alias)) {
                let (stem, extension) = original
                    .rsplit_once('.')
                    .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
                    .map_or((original.as_str(), String::new()), |(stem, extension)| {
                        (stem, format!(".{extension}"))
                    });
                alias = format!("{stem} ({ordinal}){extension}");
                ordinal += 1;
            }
            validate_alias(&alias)?;
            mappings.push(Mapping {
                input_index: index,
                alias: Some(alias),
                covered_by: None,
            });
        }
        let selected = if inputs.len() == 1 {
            mappings[0]
                .alias
                .clone()
                .ok_or_else(|| invalid("invalid_selection"))?
        } else {
            "selection".into()
        };
        let plan = Self { selected, mappings };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> io::Result<()> {
        require(
            (1..=MAX_SELECTIONS).contains(&self.mappings.len()),
            "selection_limit",
        )?;
        validate_alias(&self.selected)?;
        let mut aliases = BTreeSet::new();
        for (index, mapping) in self.mappings.iter().enumerate() {
            require(mapping.input_index == index, "invalid_selection_mapping")?;
            match (&mapping.alias, mapping.covered_by) {
                (Some(alias), None) => {
                    validate_alias(alias)?;
                    require(
                        aliases.insert(collision_key(alias)),
                        "invalid_selection_alias",
                    )?;
                }
                (None, Some(owner)) => {
                    let root = self
                        .mappings
                        .get(owner)
                        .filter(|_| owner != index)
                        .ok_or_else(|| invalid("invalid_selection_mapping"))?;
                    require(
                        root.alias.is_some() && root.covered_by.is_none(),
                        "invalid_selection_mapping",
                    )?;
                }
                _ => return Err(invalid("invalid_selection_mapping")),
            }
        }
        require(
            if self.mappings.len() == 1 {
                self.mappings[0].alias.as_deref() == Some(self.selected.as_str())
            } else {
                self.selected == "selection"
            },
            "invalid_selection_mapping",
        )
    }

    pub fn manifest_path(&self, index: usize) -> Option<String> {
        let alias = self.mappings.get(index)?.alias.as_ref()?;
        Some(if self.mappings.len() == 1 {
            alias.clone()
        } else {
            format!("{}/{alias}", self.selected)
        })
    }

    /// Compact JSON arrays have identical UTF-8 encoding in serde_json and
    /// JSON.stringify. No object-key order or source pathname enters the hash.
    pub fn sha256(&self) -> io::Result<String> {
        self.validate()?;
        let entries = self
            .mappings
            .iter()
            .map(|mapping| {
                (
                    mapping.input_index,
                    mapping.alias.as_deref(),
                    mapping.covered_by,
                )
            })
            .collect::<Vec<_>>();
        let bytes = serde_json::to_vec(&(self.selected.as_str(), entries))
            .map_err(|_| invalid("invalid_selection_mapping"))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

pub fn validate_alias(alias: &str) -> io::Result<()> {
    require(
        !alias.is_empty()
            && alias.len() <= 255
            && alias != "."
            && alias != ".."
            && !alias.contains(['/', '\\'])
            && !alias.chars().any(unsafe_character)
            && ComposingNormalizer::new_nfc().is_normalized(alias),
        "invalid_selection_alias",
    )
}

fn unsafe_character(character: char) -> bool {
    character.is_control()
        || matches!(character, '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

fn descendant(path: &str, parent: &str) -> bool {
    path.strip_prefix(parent)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn collision_key(alias: &str) -> String {
    ComposingNormalizer::new_nfc()
        .normalize(&CaseMapper::new().fold_string(alias))
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::{Input, Plan, validate_paths};
    use sha2::{Digest, Sha256};
    fn file(path: &str) -> Input {
        Input {
            path: path.into(),
            directory: false,
        }
    }
    fn directory(path: &str) -> Input {
        Input {
            path: path.into(),
            directory: true,
        }
    }

    #[test]
    fn later_directory_covers_descendants_and_duplicates_but_not_sibling_prefixes() {
        let plan = Plan::new(&[
            file("/a/project/note"),
            directory("/a/project"),
            file("/a/project-two/note"),
            directory("/a/project"),
        ])
        .unwrap();
        assert_eq!(plan.mappings[0].covered_by, Some(1));
        assert_eq!(plan.mappings[3].covered_by, Some(1));
        assert_eq!(plan.manifest_path(1).as_deref(), Some("selection/project"));
        assert_eq!(plan.manifest_path(2).as_deref(), Some("selection/note"));
        assert!(plan.manifest_path(0).is_none());
    }

    #[test]
    fn aliases_use_full_unicode_casefold_and_nfc_without_normalizing_sources() {
        let plan = Plan::new(&[
            file("/first/Straße.txt"),
            file("/second/STRASSE.TXT"),
            file("/third/e\u{301}.txt"),
            file("/fourth/é.txt"),
            file("/fifth/a\\b.txt"),
        ])
        .unwrap();
        let names = plan
            .mappings
            .iter()
            .map(|mapping| mapping.alias.as_deref().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "Straße.txt",
                "STRASSE (2).TXT",
                "é.txt",
                "é (2).txt",
                "a_b.txt"
            ]
        );
    }

    #[test]
    fn canonical_windows_drives_share_the_same_collection_and_alias_rules() {
        let plan = Plan::new(&[
            file("C:/Users/alice/project/note.txt"),
            directory("C:/Users/alice/project"),
            file("D:/Documents/project"),
        ]).unwrap();
        assert_eq!(plan.mappings[0].covered_by, Some(1));
        assert_eq!(plan.manifest_path(1).as_deref(), Some("selection/project"));
        assert_eq!(plan.manifest_path(2).as_deref(), Some("selection/project (2)"));
        assert!(!serde_json::to_string(&plan).unwrap().contains("Users"));
        for path in ["C:/", "c:/lower", "C:relative", "C:/file:stream", "C:/trailing.", "C:/trailing ", "C:/a/../b", "C:/bad?name", "C:/a\\b", "//server/share/file", r"\\?\C:\file", r"\\server\share\file"] {
            assert!(Plan::new(&[file(path)]).is_err(), "{path:?}");
        }
    }

    #[test]
    fn ambiguous_roots_dots_parent_backslashes_and_bad_text_are_rejected() {
        for path in [
            "/",
            "relative/file",
            "/a/../b",
            "/a/./b",
            "/a//b",
            "/a/",
            "/a\\b/file",
            "/a/b\n",
            "/a/\u{202e}file",
        ] {
            assert!(Plan::new(&[file(path)]).is_err(), "{path:?}");
        }
        assert!(Plan::new(&[directory("workspace/project")]).is_ok());
        assert!(Plan::new(&[file("/a"), directory("/a")]).is_err());
    }

    #[test]
    fn limits_and_unrepresentable_collision_suffix_fail_before_review() {
        assert!(
            Plan::new(
                &(0..129)
                    .map(|index| file(&format!("/a/{index}")))
                    .collect::<Vec<_>>()
            )
            .is_err()
        );
        assert!(validate_paths(&vec![format!("/{}", "a".repeat(4090)); 17]).is_err());
        let name = "é".repeat(127) + "a";
        assert!(Plan::new(&[file(&format!("/a/{name}")), file(&format!("/b/{name}"))]).is_err());
    }

    #[test]
    fn hash_has_one_language_independent_array_grammar_and_no_paths() {
        let plan = Plan::new(&[file("/private/path/note")]).unwrap();
        let expected = format!("{:x}", Sha256::digest(br#"["note",[[0,"note",null]]]"#));
        assert_eq!(plan.sha256().unwrap(), expected);
        assert!(!serde_json::to_string(&plan).unwrap().contains("private"));
        let mut changed = plan.clone();
        changed.mappings[0].covered_by = Some(0);
        assert!(changed.validate().is_err());
    }
}
