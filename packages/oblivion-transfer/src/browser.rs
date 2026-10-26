use crate::{directory::Directory, require, validate_path};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io;
use std::path::Path;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub path: String,
    pub after: Option<String>,
    pub limit: usize,
}

impl Request {
    pub fn validate(&self) -> io::Result<()> {
        require((1..=100).contains(&self.limit), "invalid_page_limit")?;
        if !self.path.is_empty() {
            validate_path(&self.path)?;
        }
        if let Some(after) = &self.after {
            validate_path(after)?;
            require(!after.contains('/'), "invalid_cursor")?;
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub name: String,
    pub directory: bool,
    pub bytes: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub path: String,
    pub entries: Vec<Entry>,
    pub next: Option<String>,
    pub skipped: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Response {
    Page(Page),
    Unavailable { error: Unavailable },
}

#[derive(Deserialize, Serialize)]
pub enum Unavailable {
    #[serde(rename = "directory_unavailable")]
    Directory,
}

impl Page {
    pub fn validate(&self, request: &Request) -> io::Result<()> {
        require(
            self.path == request.path && self.entries.len() <= request.limit,
            "invalid_directory_page",
        )?;
        let mut previous = request.after.as_deref();
        for entry in &self.entries {
            validate_path(&entry.name)?;
            require(
                !entry.name.contains('/') && previous.is_none_or(|name| name < entry.name.as_str()),
                "invalid_directory_entry",
            )?;
            previous = Some(&entry.name);
        }
        if let Some(next) = &self.next {
            validate_path(next)?;
            require(
                !next.contains('/')
                    && request.after.as_ref().is_none_or(|after| after < next)
                    && previous.is_none_or(|name| name <= next),
                "invalid_cursor",
            )?;
        }
        Ok(())
    }
}

/// Runs in the guest. Directory descriptors pin each component; symlinks and
/// special files are never followed. Only a bounded page of names is retained.
pub fn list(root: &Path, request: &Request, documents: bool) -> io::Result<Page> {
    request.validate()?;
    if documents && request.path.is_empty() {
        let entries = ["imports", "workspace"]
            .into_iter()
            .filter(|name| {
                request
                    .after
                    .as_ref()
                    .is_none_or(|after| *name > after.as_str())
            })
            .map(|name| Entry {
                name: name.into(),
                directory: true,
                bytes: 0,
            })
            .collect::<Vec<_>>();
        let next = (entries.len() > request.limit).then(|| entries[request.limit - 1].name.clone());
        return Ok(Page {
            path: String::new(),
            entries: entries.into_iter().take(request.limit).collect(),
            next,
            skipped: 0,
        });
    }
    if documents {
        require(
            matches!(
                request.path.split('/').next(),
                Some("imports" | "workspace")
            ),
            "invalid_document_selection",
        )?;
    }
    let mut directory = Directory::open(root)?;
    for component in request.path.split('/').filter(|name| !name.is_empty()) {
        directory = directory.directory(component)?;
    }
    let mut names = BTreeSet::new();
    let mut skipped = 0;
    let mut visited = 0;
    directory.visit(|name| {
        visited += 1;
        require(visited <= 1_000_000, "directory_entry_limit")?;
        let Some(name) = name
            .to_str()
            .ok()
            .filter(|name| validate_path(name).is_ok())
        else {
            skipped += 1;
            return Ok(());
        };
        if request
            .after
            .as_ref()
            .is_some_and(|after| name <= after.as_str())
        {
            return Ok(());
        }
        names.insert(name.to_owned());
        if names.len() > request.limit + 1 {
            names.pop_last();
        }
        Ok(())
    })?;
    let next =
        (names.len() > request.limit).then(|| names.iter().nth(request.limit - 1).unwrap().clone());
    let mut entries = Vec::new();
    for name in names.into_iter().take(request.limit) {
        let Ok(metadata) = directory.source(&name).and_then(|file| file.metadata()) else {
            skipped += 1;
            continue;
        };
        if !metadata.is_file() && !metadata.is_dir() {
            skipped += 1;
            continue;
        }
        entries.push(Entry {
            name,
            directory: metadata.is_dir(),
            bytes: if metadata.is_file() {
                metadata.len()
            } else {
                0
            },
        });
    }
    Ok(Page {
        path: request.path.clone(),
        entries,
        next,
        skipped,
    })
}
