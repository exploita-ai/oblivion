use crate::directory::Directory;
use crate::{Receipt, invalid, require, validate_id};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const PAGE: usize = 64;

#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    List { after: Option<String> },
    Discard { id: String },
}

impl Request {
    pub fn validate(&self) -> io::Result<()> {
        match self {
            Self::List { after: Some(id) } | Self::Discard { id } => validate_id(id),
            Self::List { after: None } => Ok(()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    Private,
    Available,
    Published,
    Missing,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub id: String,
    pub state: State,
    pub receipt: Option<Receipt>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Response {
    Inventory {
        records: Vec<Record>,
        next: Option<String>,
    },
    Discarded {
        id: String,
    },
}

impl Response {
    pub fn validate(&self, request: &Request) -> io::Result<()> {
        match (self, request) {
            (Self::Discarded { id }, Request::Discard { id: requested }) => {
                require(id == requested, "invalid_recovery_response")
            }
            (Self::Inventory { records, next }, Request::List { after }) => {
                require(records.len() <= PAGE, "invalid_recovery_response")?;
                let mut previous = after.as_deref();
                for record in records {
                    validate_id(&record.id)?;
                    require(
                        previous.is_none_or(|id| id < record.id.as_str()),
                        "invalid_recovery_response",
                    )?;
                    if let Some(receipt) = &record.receipt {
                        validate_receipt(receipt, &record.id)?;
                    }
                    require(
                        record.state != State::Published || record.receipt.is_some(),
                        "invalid_recovery_response",
                    )?;
                    previous = Some(&record.id);
                }
                require(
                    next.is_none() || (records.len() == PAGE && next.as_deref() == previous),
                    "invalid_recovery_response",
                )
            }
            _ => Err(invalid("invalid_recovery_response")),
        }
    }
}

/// Runs only in the session guest as the receiver identity. It never rehashes
/// or removes published documents: those are intentionally editable by chat.
pub fn execute(root: &Path, target: &Path, request: Request) -> io::Result<Response> {
    request.validate()?;
    let root = Directory::open(root)?;
    root.require_private()?;
    root.lock()?;
    let target = Directory::open(target)?;
    target.require_controlled()?;
    match request {
        Request::List { after } => {
            let names: BTreeSet<_> = root
                .names(4096)?
                .into_iter()
                .chain(target.names(4096)?)
                .collect();
            let mut records = Vec::new();
            let mut next = None;
            for id in names {
                validate_id(&id)?;
                if after.as_ref().is_some_and(|after| id <= *after) {
                    continue;
                }
                if records.len() == PAGE {
                    next = records.last().map(|record: &Record| record.id.clone());
                    break;
                }
                records.push(inspect(&root, &target, &id)?);
            }
            Ok(Response::Inventory { records, next })
        }
        Request::Discard { id } => {
            require(
                inspect(&root, &target, &id)?.state == State::Private,
                "copy_not_private",
            )?;
            // Neither tree is accessible to the chat. Re-check while holding
            // the same inbox lock used by import, then remove only this ID.
            if let Some(directory) = optional_directory(&target, &id)? {
                directory.require_private()?;
                target.remove_directory(&id)?;
                target.sync()?;
            }
            if optional_directory(&root, &id)?.is_some() {
                root.remove_directory(&id)?;
                root.sync()?;
            }
            Ok(Response::Discarded { id })
        }
    }
}

fn inspect(root: &Directory, target: &Directory, id: &str) -> io::Result<Record> {
    let transaction = optional_directory(root, id)?;
    let publication = optional_directory(target, id)?;
    require(
        transaction.is_some() || publication.is_some(),
        "copy_not_found",
    )?;
    let mut receipt = None;
    let mut committed = false;
    if let Some(transaction) = transaction {
        transaction.require_private()?;
        if let Some(file) = private_file(&transaction, "receipt.json", 1024)? {
            let saved: Receipt =
                serde_json::from_reader(file).map_err(|_| invalid("invalid_receipt"))?;
            validate_receipt(&saved, id)?;
            receipt = Some(saved);
        }
        committed = private_file(&transaction, "published", 0)?.is_some();
        require(
            !committed || receipt.is_some(),
            "invalid_publication_record",
        )?;
    }
    let state = match publication {
        Some(publication) => {
            let metadata = publication.metadata()?;
            require(
                metadata.uid() == unsafe { libc::geteuid() },
                "invalid_publication_owner",
            )?;
            if metadata.mode() & 0o077 == 0 {
                // A publication marker contradicting private permissions is
                // preserved for diagnosis, never offered for deletion.
                if committed {
                    State::Missing
                } else {
                    State::Private
                }
            } else if committed {
                State::Published
            } else {
                // Legacy imports or interruption after exposure, before the
                // durable marker. Do not infer success from names or hashes.
                State::Available
            }
        }
        None if committed => State::Missing,
        None => State::Private,
    };
    Ok(Record {
        id: id.to_owned(),
        state,
        receipt,
    })
}

fn validate_receipt(receipt: &Receipt, id: &str) -> io::Result<()> {
    require(
        receipt.id == id
            && receipt.entries > 0
            && receipt.entries <= 4096
            && receipt.manifest_sha256.len() == 64
            && receipt
                .manifest_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid_receipt",
    )
}

fn optional_directory(root: &Directory, id: &str) -> io::Result<Option<Directory>> {
    match root.directory(id) {
        Ok(directory) => Ok(Some(directory)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn private_file(root: &Directory, name: &str, limit: u64) -> io::Result<Option<File>> {
    let file = match root.source(name) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    require(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && metadata.len() <= limit,
        "invalid_recovery_file",
    )?;
    Ok(Some(file))
}
