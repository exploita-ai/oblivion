use crate::channel::Channel;
use crate::{Limits, Manifest, Receipt, Selection, invalid, receive, require, validate_id};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OfferRequest {
    pub id: String,
    pub limits: Limits,
    pub paths: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum SourceRequest {
    Browse { browse: crate::browser::Request },
    Offer(OfferRequest),
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub id: String,
    pub manifest_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiveRequest {
    pub approval: Approval,
    pub limits: Limits,
}

/// One selection, one approval and one receipt. No listener or retry loop.
/// The controller supplies a private channel and owns the user's decision.
pub fn send(channel: &mut Channel, root: &Path) -> io::Result<()> {
    send_from(channel, root, false)
}

pub fn documents(channel: &mut Channel, root: &Path) -> io::Result<()> {
    send_from(channel, root, true)
}

/// Ciphertext-only backup source. The parent selects the descriptor and byte
/// ceiling; its peer can neither browse nor request another file. This checks
/// the LUKS2 signature, not the authenticity or integrity of its filesystem.
pub fn send_open_file(channel: &mut Channel, file: File, maximum: u64) -> io::Result<()> {
    require(
        (32 * 1024 * 1024..=crate::MAX_ENCRYPTED_VOLUME_BYTES).contains(&maximum),
        "invalid_backup_limit",
    )?;
    let request: OfferRequest = read_message(channel, 4096)?;
    validate_id(&request.id)?;
    require(
        request.paths == [crate::ENCRYPTED_VOLUME_NAME],
        "invalid_backup_selection",
    )?;
    require(
        request.limits.entries == 1 && request.limits.bytes <= maximum,
        "invalid_backup_limit",
    )?;
    let mut selection = Selection::encrypted_volume(file, request.limits.bytes)?;
    send_selection(channel, &mut selection, &request.id)
}

/// A media source keeps its existing paginated browser, but a backup offer
/// selects exactly one regular LUKS2 file. Parent directories are not copied.
pub fn send_encrypted(channel: &mut Channel, root: &Path) -> io::Result<()> {
    let request = source_request(channel, root, false)?;
    validate_id(&request.id)?;
    require(
        request.paths.len() == 1
            && request.limits.entries == 1
            && request.limits.bytes <= crate::MAX_ENCRYPTED_VOLUME_BYTES,
        "invalid_backup_selection",
    )?;
    let mut selection = Selection::encrypted_path(root, &request.paths[0], request.limits.bytes)?;
    send_selection(channel, &mut selection, &request.id)
}

/// The controller supplies an empty writable file descriptor, never a root or
/// destination name from the peer. A receipt means the ciphertext is copied
/// and synced; the controller must still unlock and validate the new archive.
pub fn receive_open_file(channel: &mut Channel, mut file: File, maximum: u64) -> io::Result<()> {
    require(
        (32 * 1024 * 1024..=crate::MAX_ENCRYPTED_VOLUME_BYTES).contains(&maximum),
        "invalid_backup_limit",
    )?;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    let metadata = file.metadata()?;
    require(
        flags >= 0 && flags & libc::O_ACCMODE != libc::O_RDONLY && flags & libc::O_APPEND == 0,
        "destination_not_writable",
    )?;
    require(
        metadata.is_file() && metadata.nlink() == 1 && metadata.len() == 0,
        "unsafe_backup_destination",
    )?;
    file.rewind()?;
    let request: ReceiveRequest = read_message(channel, 1024)?;
    validate_id(&request.approval.id)?;
    require(
        request.limits.entries == 1 && request.limits.bytes <= maximum,
        "invalid_backup_limit",
    )?;
    let manifest = Manifest::read(channel, request.limits)?;
    let [crate::Entry::File { path, size, sha256 }] = manifest.entries() else {
        return Err(invalid("invalid_backup_selection"));
    };
    require(
        path == crate::ENCRYPTED_VOLUME_NAME && *size >= 32 * 1024 * 1024,
        "invalid_backup_selection",
    )?;
    require(
        manifest.sha256() == request.approval.manifest_sha256,
        "offer_not_approved",
    )?;
    channel.write_all(b"receive\n")?;
    let mut magic = [0; 8];
    channel.read_exact(&mut magic)?;
    require(
        &magic == b"LUKS\xba\xbe\x00\x02",
        "invalid_encrypted_volume",
    )?;
    let mut content = io::Cursor::new(magic).chain((&mut *channel).take(*size - 8));
    require(
        crate::copy_hash(&mut content, &mut file, *size)? == *sha256,
        "content_changed",
    )?;
    let mut end = [0; 8];
    channel.read_exact(&mut end)?;
    require(&end == crate::END, "invalid_transfer_end")?;
    file.sync_all()?;
    channel.check()?;
    write_message(
        channel,
        &crate::Receipt {
            id: request.approval.id,
            manifest_sha256: manifest.sha256(),
            entries: 1,
            bytes: *size,
        },
    )
}

fn source_request(channel: &mut Channel, root: &Path, documents: bool) -> io::Result<OfferRequest> {
    loop {
        match read_message::<SourceRequest>(channel, 64 * 1024)? {
            SourceRequest::Offer(request) => return Ok(request),
            SourceRequest::Browse { browse } => {
                let response = match crate::browser::list(root, &browse, documents) {
                    Ok(page) => crate::browser::Response::Page(page),
                    Err(_) => crate::browser::Response::Unavailable {
                        error: crate::browser::Unavailable::Directory,
                    },
                };
                // A virtio port stays connected after an endpoint exits. Send an
                // explicit failure so a missing directory does not wait for expiry.
                write_message(channel, &response)?;
            }
        }
    }
}

fn send_from(channel: &mut Channel, root: &Path, documents: bool) -> io::Result<()> {
    let request = source_request(channel, root, documents)?;
    validate_id(&request.id)?;
    if documents {
        require(
            request
                .paths
                .iter()
                .all(|path| matches!(path.split('/').next(), Some("workspace" | "imports"))),
            "invalid_document_selection",
        )?;
    }
    let mut selection = Selection::prepare(root, &request.paths, request.limits)?;
    send_selection(channel, &mut selection, &request.id)
}

fn send_selection(channel: &mut Channel, selection: &mut Selection, id: &str) -> io::Result<()> {
    selection.manifest().write(channel)?;
    let approval: Approval = read_message(channel, 1024)?;
    require(
        approval.id == id && approval.manifest_sha256 == selection.manifest().sha256(),
        "offer_not_approved",
    )?;
    selection.send_data(channel)?;
    let receipt: Receipt = read_message(channel, 1024)?;
    require(
        receipt.id == id
            && receipt.manifest_sha256 == approval.manifest_sha256
            && receipt.entries == selection.manifest().entries().len()
            && receipt.bytes == selection.manifest().bytes(),
        "invalid_receipt",
    )?;
    channel.write_all(b"copied\n")
}

/// The destination root is chosen locally, never from the peer's request.
pub fn accept(channel: &mut Channel, root: &Path) -> io::Result<()> {
    accept_into(channel, root, None)
}

/// Import mode is selected only by the local trusted launcher. The manager's
/// approval explicitly covers copying and making the selected files usable by
/// the chat; the peer cannot supply the publication root or filesystem paths.
pub fn import(channel: &mut Channel, root: &Path, published: &Path) -> io::Result<()> {
    let guard = crate::directory::Directory::open(root)?;
    guard.require_private()?;
    guard.lock()?;
    accept_into(channel, root, Some(published))
}

pub fn recover(channel: &mut Channel, root: &Path, published: &Path) -> io::Result<()> {
    let request = read_message(channel, 1024)?;
    let response = crate::recovery::execute(root, published, request)?;
    write_message(channel, &response)
}

pub fn export(channel: &mut Channel, root: &Path, mode: crate::ExportMode) -> io::Result<()> {
    let request: ReceiveRequest = read_message(channel, 1024)?;
    validate_id(&request.approval.id)?;
    let manifest = Manifest::read(channel, request.limits)?;
    require(
        manifest.sha256() == request.approval.manifest_sha256,
        "offer_not_approved",
    )?;
    channel.write_all(b"receive\n")?;
    let receipt = crate::receive_external(channel, &manifest, root, &request.approval.id, mode)?;
    write_message(channel, &receipt)
}

fn accept_into(channel: &mut Channel, root: &Path, published: Option<&Path>) -> io::Result<()> {
    let request: ReceiveRequest = read_message(channel, 1024)?;
    validate_id(&request.approval.id)?;
    let manifest = Manifest::read(channel, request.limits)?;
    require(
        manifest.sha256() == request.approval.manifest_sha256,
        "offer_not_approved",
    )?;
    channel.write_all(b"receive\n")?;
    let receipt = receive(channel, &manifest, root, &request.approval.id)?;
    if let Some(published) = published {
        channel.check()?;
        crate::publish(root, published, &receipt.id, &manifest)?;
    }
    write_message(channel, &receipt)
}

pub fn read_message<T: for<'de> Deserialize<'de>>(
    reader: &mut impl Read,
    limit: usize,
) -> io::Result<T> {
    let mut size = [0; 4];
    reader.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    require(size > 0 && size <= limit, "message_limit")?;
    let mut bytes = vec![0; size];
    reader.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(|_| invalid("invalid_message"))
}

pub fn write_message(writer: &mut impl Write, message: &impl Serialize) -> io::Result<()> {
    let bytes = serde_json::to_vec(message).map_err(|_| invalid("invalid_message"))?;
    require(bytes.len() <= 64 * 1024, "message_limit")?;
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)
}
