//! Recovery metadata stays beside the receiver's explicitly approved staging.
//! A pathname is never evidence of a completed copy, and publication is never
//! undone by recovery or discard.
use super::{Publication, validate_name, verify_receipt};
use crate::channel::Channel;
use crate::directory::{Directory, FileIdentity};
use crate::{Limits, Manifest, Receipt, invalid, require, validate_id};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::native_files::{
    Action, Context, Direction, Request, State, Status, TransferEntry, TransfersPage,
    TransfersQuery,
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    context: Context,
    target: FileIdentity,
}

pub fn begin(inbox: &Path, target: &Path, context: &Context) -> io::Result<()> {
    let root = Directory::open(inbox)?;
    root.require_private()?;
    root.lock()?;
    begin_at(&root, &Directory::open(target)?, context)
}

pub(super) fn begin_at(root: &Directory, target: &Directory, context: &Context) -> io::Result<()> {
    context.validate()?;
    root.require_private()?;
    target.require_controlled()?;
    let target = target.identity()?;
    let operations = match root.create_directory("operations") {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            root.directory("operations")?
        }
        Err(error) => return Err(error),
    };
    operations.require_private()?;
    let operation = operations.create_directory(&context.id)?;
    let record = Record {
        version: 1,
        context: context.clone(),
        target,
    };
    let mut file = operation.create_file("context.pending")?;
    serde_json::to_writer(&mut file, &record).map_err(|_| invalid("invalid_file_operation"))?;
    file.sync_all()?;
    operation.rename("context.pending", "context.json")?;
    operation.sync()?;
    operations.sync()?;
    root.sync()
}

fn read<T: serde::de::DeserializeOwned>(
    directory: &Directory,
    name: &str,
    limit: u64,
) -> io::Result<T> {
    let file = record_file(directory, name, limit)?;
    serde_json::from_reader(file.take(limit + 1))
        .map_err(|_| invalid("invalid_file_operation_record"))
}

fn record_file(directory: &Directory, name: &str, limit: u64) -> io::Result<std::fs::File> {
    let file = directory.source(name)?;
    let metadata = file.metadata()?;
    require(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.nlink() == 1
            && metadata.mode() & 0o077 == 0
            && metadata.len() <= limit,
        "unsafe_file_operation_record",
    )?;
    Ok(file)
}

fn optional<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn operation(
    root: &Directory,
    target: &Directory,
    id: &str,
    safe: &str,
    direction: Direction,
) -> io::Result<Option<(Directory, Record)>> {
    validate_id(id)?;
    validate_id(safe)?;
    let Some(operations) = optional(root.directory("operations"))? else {
        return Ok(None);
    };
    operations.require_private()?;
    read_operation(&operations, &target.identity()?, id, safe, direction)
}

fn read_operation(
    operations: &Directory,
    target: &FileIdentity,
    id: &str,
    safe: &str,
    direction: Direction,
) -> io::Result<Option<(Directory, Record)>> {
    let Some(operation) = optional(operations.directory(id))? else {
        return Ok(None);
    };
    operation.require_private()?;
    let Some(record) = optional(read::<Record>(&operation, "context.json", 8192))? else {
        return Ok(None);
    };
    record.context.validate()?;
    require(
        record.version == 1
            && record.context.id == id
            && record.context.safe_id == safe
            && record.context.direction == direction
            && record.target == *target,
        "file_operation_changed",
    )?;
    Ok(Some((operation, record)))
}

fn inspect(
    root: &Directory,
    target: &Directory,
    id: &str,
    safe: &str,
    opening: &str,
    direction: Direction,
) -> io::Result<Status> {
    validate_id(opening)?;
    let mut status = Status {
        operation_id: id.into(),
        safe_id: safe.into(),
        opening: opening.into(),
        source_opening: None,
        state: State::Unknown,
        receipt: None,
        can_recover: false,
        can_discard: false,
    };
    let Some((operation, record)) = operation(root, target, id, safe, direction)? else {
        return Ok(status);
    };
    status.source_opening = Some(record.context.opening.clone());
    if optional(record_file(&operation, "discarded", 0))?.is_some() {
        status.state = State::Discarded;
        return Ok(status);
    }
    status.state = State::Incomplete;
    status.can_discard = true;
    let Some(transaction) = optional(root.directory(id))? else {
        return Ok(status);
    };
    transaction.require_private()?;
    let publication = optional(read::<Publication>(&transaction, "publication.json", 8192))?;
    let published = optional(record_file(&transaction, "published", 0))?.is_some();
    // No publication can occur before its durable identity record. An
    // incomplete private receive is safely discardable under this same lock.
    if publication.is_none() {
        require(!published, "invalid_file_publication")?;
        return Ok(status);
    }
    let publication = publication.ok_or_else(|| invalid("invalid_file_publication"))?;
    validate_name(&publication.name)?;
    crate::validate_path(&publication.selected)?;
    require(
        publication.name == record.context.name,
        "file_operation_changed",
    )?;
    let receipt: Receipt = read(&transaction, "receipt.json", 1024)?;
    let mut manifest = record_file(&transaction, "manifest.bin", 8 * 1024 * 1024 + 12)?;
    let manifest = Manifest::read(
        &mut manifest,
        Limits {
            entries: crate::MAX_ENTRIES,
            bytes: crate::MAX_DOCUMENT_BYTES,
        },
    )?;
    verify_receipt(&receipt, id, &manifest)?;
    super::require_selection(&manifest, &publication.selected)?;
    status.can_discard = false;
    if published {
        status.state = State::Published;
        status.receipt = Some(receipt);
        return Ok(status);
    }
    // If the move happened before the completion marker, only recovery can
    // finish syncing it. Never discard that user's published output.
    let output = optional(target.source(&publication.name))?;
    let moved = output
        .as_ref()
        .map(|file| publication.source.matches(file))
        .transpose()?
        .unwrap_or(false);
    if !moved {
        if let Ok(parent) = super::selected_parent(&transaction, &publication.selected) {
            if let Some(file) = optional(
                parent.source(
                    publication
                        .selected
                        .rsplit('/')
                        .next()
                        .ok_or_else(|| invalid("invalid_file_publication"))?,
                ),
            )? {
                status.can_discard = publication.source.matches(&file)?;
            }
        }
    }
    status.state = State::Ready;
    status.can_recover = true;
    status.receipt = Some(receipt);
    Ok(status)
}

pub fn manage(
    inbox: &Path,
    target: &Path,
    id: &str,
    safe: &str,
    opening: &str,
    direction: Direction,
    action: Action,
) -> io::Result<Status> {
    let root = match Directory::open(inbox) {
        Ok(root) => root,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound && matches!(action, Action::Status) =>
        {
            validate_id(id)?;
            validate_id(safe)?;
            validate_id(opening)?;
            return Ok(Status {
                operation_id: id.into(),
                safe_id: safe.into(),
                opening: opening.into(),
                source_opening: None,
                state: State::Unknown,
                receipt: None,
                can_recover: false,
                can_discard: false,
            });
        }
        Err(error) => return Err(error),
    };
    root.require_private()?;
    root.lock()?;
    let target_directory = Directory::open(target)?;
    target_directory.require_controlled()?;
    let status = inspect(&root, &target_directory, id, safe, opening, direction)?;
    match action {
        Action::Status => Ok(status),
        Action::Recover => {
            require(status.can_recover, "file_operation_not_recoverable")?;
            super::recover_directory_locked(&root, &target_directory, id)?;
            inspect(&root, &target_directory, id, safe, opening, direction)
        }
        Action::Discard => {
            require(status.can_discard, "file_operation_not_private")?;
            if optional(root.directory(id))?.is_some() {
                root.remove_directory(id)?;
                root.sync()?;
            }
            let (operation, _) = operation(&root, &target_directory, id, safe, direction)?
                .ok_or_else(|| invalid("file_operation_changed"))?;
            let file = operation.create_file("discarded")?;
            file.sync_all()?;
            operation.sync()?;
            inspect(&root, &target_directory, id, safe, opening, direction)
        }
    }
}

/// Inventory is a bounded set of receiver references, never permission to
/// publish or discard. Those actions still inspect fresh state under this lock.
pub fn inventory(inbox: &Path, target: &Path, query: &TransfersQuery) -> io::Result<TransfersPage> {
    query.validate()?;
    let mut page = TransfersPage {
        safe_id: query.safe_id.clone(),
        opening: query.opening.clone(),
        direction: query.direction,
        entries: Vec::new(),
        next_cursor: None,
        skipped: 0,
    };
    let target = Directory::open(target)?;
    target.require_controlled()?;
    let target_identity = target.identity()?;
    let Some(root) = optional(Directory::open(inbox))? else {
        return Ok(page);
    };
    root.require_private()?;
    root.lock()?;
    let Some(operations) = optional(root.directory("operations"))? else {
        return Ok(page);
    };
    operations.require_private()?;
    let mut ids = BTreeSet::new();
    operations.visit(|name| {
        let Ok(name) = name.to_str() else {
            return Ok(());
        };
        if validate_id(name).is_ok() && query.after.as_deref().is_none_or(|after| name > after) {
            ids.insert(name.to_owned());
            if ids.len() > query.limit + 1 {
                ids.pop_last();
            }
        }
        Ok(())
    })?;
    let more = ids.len() > query.limit;
    for id in ids.into_iter().take(query.limit) {
        if more {
            page.next_cursor = Some(id.clone());
        }
        match read_operation(
            &operations,
            &target_identity,
            &id,
            &query.safe_id,
            query.direction,
        ) {
            Ok(Some((_, record))) => page.entries.push(TransferEntry {
                operation_id: id,
                source_opening: record.context.opening,
                name: record.context.name,
            }),
            Ok(None) | Err(_) => page.skipped += 1,
        }
    }
    page.validate(query)?;
    Ok(page)
}

pub fn serve(
    channel: &mut Channel,
    inbox: &Path,
    target: &Path,
    request: Request,
) -> io::Result<()> {
    match request {
        Request::Transfers {
            safe_id,
            opening,
            after,
            limit,
        } => crate::endpoint::write_message(
            channel,
            &inventory(
                inbox,
                target,
                &TransfersQuery {
                    safe_id,
                    opening,
                    direction: Direction::Import,
                    after,
                    limit,
                },
            )?,
        ),
        Request::Import {
            id,
            safe_id,
            opening,
            name,
        } => {
            let context = Context {
                id,
                safe_id,
                opening,
                direction: Direction::Import,
                name,
            };
            begin(inbox, target, &context)?;
            super::receive_directory(channel, inbox, target, &context)?;
            Ok(())
        }
        Request::Status {
            id,
            safe_id,
            opening,
        } => crate::endpoint::write_message(
            channel,
            &manage(
                inbox,
                target,
                &id,
                &safe_id,
                &opening,
                Direction::Import,
                Action::Status,
            )?,
        ),
        Request::Recover {
            id,
            safe_id,
            opening,
        } => crate::endpoint::write_message(
            channel,
            &manage(
                inbox,
                target,
                &id,
                &safe_id,
                &opening,
                Direction::Import,
                Action::Recover,
            )?,
        ),
        Request::Discard {
            id,
            safe_id,
            opening,
        } => crate::endpoint::write_message(
            channel,
            &manage(
                inbox,
                target,
                &id,
                &safe_id,
                &opening,
                Direction::Import,
                Action::Discard,
            )?,
        ),
    }
}

pub(super) fn require_active(
    inbox: &Directory,
    target: &Directory,
    context: &Context,
) -> io::Result<()> {
    let (operation, record) = operation(
        inbox,
        target,
        &context.id,
        &context.safe_id,
        context.direction,
    )?
    .ok_or_else(|| invalid("file_operation_missing"))?;
    require(
        record.context.opening == context.opening
            && record.context.name == context.name
            && optional(record_file(&operation, "discarded", 0))?.is_none(),
        "file_operation_changed",
    )
}
