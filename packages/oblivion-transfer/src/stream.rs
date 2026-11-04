//! Explicit desktop copies over an already authorized private stream.
//! Manifest, file hashes, limits and receipts use the existing copy protocol.
use crate::channel::Channel;
use crate::directory::Directory;
use crate::endpoint::{Approval, OfferRequest, ReceiveRequest, read_message, write_message};
use crate::{Limits, Manifest, Receipt, Selection, invalid, require, validate_id, validate_path};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// A locally selected file or directory. Peers cannot choose another host path.
pub fn send_path(channel: &mut Channel, source: &Path, limits: Limits, id: &str) -> io::Result<Receipt> {
    require(source.is_absolute(), "absolute_source_required")?;
    let name = source.file_name().and_then(|name| name.to_str()).ok_or_else(|| invalid("invalid_source_name"))?;
    let root = source.parent().ok_or_else(|| invalid("invalid_source_root"))?;
    let mut selection = Selection::prepare(root, &[name.to_owned()], limits)?;
    send(channel, &mut selection, id)
}

/// Talks directly to a destination using endpoint::import/accept framing.
pub fn send(channel: &mut Channel, selection: &mut Selection, id: &str) -> io::Result<Receipt> {
    validate_id(id)?;
    let approval = Approval { id: id.to_owned(), manifest_sha256: selection.manifest().sha256() };
    write_message(channel, &ReceiveRequest {
        approval,
        limits: Limits { entries: selection.manifest().entries().len(), bytes: selection.manifest().bytes() },
    })?;
    selection.manifest().write(channel)?;
    let mut accepted = [0; 8];
    channel.read_exact(&mut accepted)?;
    require(&accepted == b"receive\n", "offer_rejected")?;
    selection.send_data(channel)?;
    let receipt: Receipt = read_message(channel, 1024)?;
    verify_receipt(&receipt, id, selection.manifest())?;
    Ok(receipt)
}

/// The local launcher chooses both roots, name and ceiling. The peer supplies
/// only one declared top-level file/directory, never an archive to extract.
pub fn receive_directory(channel: &mut Channel, inbox: &Path, target: &Path, name: &str, limits: Limits) -> io::Result<Receipt> {
    validate_name(name)?;
    let guard = Directory::open(inbox)?;
    guard.require_private()?;
    guard.lock()?;
    Directory::open(target)?.require_controlled()?;
    let request: ReceiveRequest = read_message(channel, 1024)?;
    validate_id(&request.approval.id)?;
    require(request.limits.entries <= limits.entries && request.limits.bytes <= limits.bytes, "transfer_limit")?;
    let manifest = Manifest::read(channel, request.limits)?;
    require(manifest.sha256() == request.approval.manifest_sha256, "offer_not_approved")?;
    let selected = manifest.entries()[0].path().to_owned();
    require(!selected.contains('/'), "invalid_source_selection")?;
    require_selection(&manifest, &selected)?;
    channel.write_all(b"receive\n")?;
    let receipt = crate::receive(channel, &manifest, inbox, &request.approval.id)?;
    channel.check()?;
    publish(inbox, target, name, &selected, &receipt, &manifest)?;
    write_message(channel, &receipt)?;
    Ok(receipt)
}

/// A requested guest file is copied into the explicit desktop directory. This
/// speaks to endpoint::send/documents, retaining its offer/approval/receipt flow.
pub fn download(channel: &mut Channel, selected: &str, inbox: &Path, target: &Path, name: &str, limits: Limits, id: &str) -> io::Result<Receipt> {
    validate_id(id)?;
    validate_name(name)?;
    validate_path(selected)?;
    let guard = Directory::open(inbox)?;
    guard.require_private()?;
    guard.lock()?;
    Directory::open(target)?.require_controlled()?;
    write_message(channel, &OfferRequest { id: id.to_owned(), limits, paths: vec![selected.to_owned()] })?;
    let manifest = Manifest::read(channel, limits)?;
    require_selection(&manifest, selected)?;
    write_message(channel, &Approval { id: id.to_owned(), manifest_sha256: manifest.sha256() })?;
    let receipt = crate::receive(channel, &manifest, inbox, id)?;
    channel.check()?;
    publish(inbox, target, name, selected, &receipt, &manifest)?;
    write_message(channel, &receipt)?;
    let mut completed = [0; 7];
    channel.read_exact(&mut completed)?;
    require(&completed == b"copied\n", "source_not_completed")?;
    Ok(receipt)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    name: String,
    selected: String,
    device: u64,
    inode: u64,
}

/// Retry only the publication of a completed private transaction. File content
/// is never recopied and an unrelated existing destination is never replaced.
pub fn recover_directory(inbox: &Path, target: &Path, id: &str) -> io::Result<Receipt> {
    validate_id(id)?;
    let guard = Directory::open(inbox)?;
    guard.require_private()?;
    guard.lock()?;
    let transaction = guard.directory(id)?;
    let publication: Publication = serde_json::from_reader(transaction.source("publication.json")?.take(8192))
        .map_err(|_| invalid("invalid_publication"))?;
    validate_name(&publication.name)?;
    validate_path(&publication.selected)?;
    let receipt: Receipt = serde_json::from_reader(transaction.source("receipt.json")?.take(1024))
        .map_err(|_| invalid("invalid_receipt"))?;
    require(receipt.id == id, "invalid_receipt")?;
    finish_publication(&transaction, &Directory::open(target)?, &publication)?;
    Ok(receipt)
}

fn publish(inbox: &Path, target: &Path, name: &str, selected: &str, receipt: &Receipt, manifest: &Manifest) -> io::Result<()> {
    let transaction = Directory::open(inbox)?.directory(&receipt.id)?;
    let mut offer = transaction.create_file("manifest.pending")?;
    manifest.write(&mut offer)?;
    offer.sync_all()?;
    transaction.rename("manifest.pending", "manifest.bin")?;
    transaction.sync()?;
    let parent = selected_parent(&transaction, selected)?;
    let file = parent.source(selected.rsplit('/').next().ok_or_else(|| invalid("invalid_selection"))?)?;
    let metadata = file.metadata()?;
    let publication = Publication { name: name.to_owned(), selected: selected.to_owned(), device: metadata.dev(), inode: metadata.ino() };
    let mut record = transaction.create_file("publication.pending")?;
    serde_json::to_writer(&mut record, &publication).map_err(|_| invalid("invalid_publication"))?;
    record.sync_all()?;
    transaction.rename("publication.pending", "publication.json")?;
    transaction.sync()?;
    finish_publication(&transaction, &Directory::open(target)?, &publication)
}

fn finish_publication(transaction: &Directory, target: &Directory, publication: &Publication) -> io::Result<()> {
    target.require_controlled()?;
    let current = target.source(&publication.name);
    match current {
        Ok(file) => {
            let metadata = file.metadata()?;
            require(metadata.dev() == publication.device && metadata.ino() == publication.inode, "destination_exists")?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = selected_parent(transaction, &publication.selected)?;
            let selected = publication.selected.rsplit('/').next().ok_or_else(|| invalid("invalid_selection"))?;
            let metadata = parent.source(selected)?.metadata()?;
            require(metadata.dev() == publication.device && metadata.ino() == publication.inode, "publication_changed")?;
            parent.move_exclusive(selected, target, &publication.name)?;
            parent.sync()?;
        }
        Err(error) => return Err(error),
    }
    target.sync()?;
    match transaction.create_file("published") {
        Ok(file) => file.sync_all()?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    transaction.sync()
}

fn selected_parent(transaction: &Directory, selected: &str) -> io::Result<Directory> {
    let mut components = selected.split('/').collect::<Vec<_>>();
    components.pop().ok_or_else(|| invalid("invalid_selection"))?;
    components.into_iter().try_fold(transaction.directory("files")?, |parent, component| parent.directory(component))
}

fn require_selection(manifest: &Manifest, selected: &str) -> io::Result<()> {
    require(manifest.entries().iter().any(|entry| entry.path() == selected), "selection_missing")?;
    for entry in manifest.entries() {
        let ancestor = selected.strip_prefix(entry.path()).is_some_and(|tail| tail.starts_with('/'));
        let descendant = entry.path().strip_prefix(selected).is_some_and(|tail| tail.starts_with('/'));
        require(entry.path() == selected || ancestor || descendant, "selection_expanded")?;
    }
    Ok(())
}

fn validate_name(name: &str) -> io::Result<()> {
    validate_path(name)?;
    require(!name.contains('/'), "invalid_destination_name")
}

fn verify_receipt(receipt: &Receipt, id: &str, manifest: &Manifest) -> io::Result<()> {
    require(receipt.id == id && receipt.manifest_sha256 == manifest.sha256()
        && receipt.entries == manifest.entries().len() && receipt.bytes == manifest.bytes(), "invalid_receipt")
}
