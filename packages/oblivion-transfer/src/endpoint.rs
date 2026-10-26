use crate::channel::Channel;
use crate::{Limits, Manifest, Receipt, Selection, invalid, receive, require, validate_id};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
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

fn send_from(channel: &mut Channel, root: &Path, documents: bool) -> io::Result<()> {
    let request = loop {
        match read_message::<SourceRequest>(channel, 64 * 1024)? {
            SourceRequest::Offer(request) => break request,
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
    };
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
    selection.manifest().write(channel)?;
    let approval: Approval = read_message(channel, 1024)?;
    require(
        approval.id == request.id && approval.manifest_sha256 == selection.manifest().sha256(),
        "offer_not_approved",
    )?;
    selection.send_data(channel)?;
    let receipt: Receipt = read_message(channel, 1024)?;
    require(
        receipt.id == request.id
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
