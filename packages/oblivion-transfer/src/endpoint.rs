//! Portable copy requests and length-delimited JSON, with Unix endpoints.
use crate::{Limits, invalid, require};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

#[cfg(unix)]
#[path = "endpoint_unix.rs"]
mod unix;
#[cfg(unix)]
pub use unix::{
    accept, documents, export, export_live_media, import, media_source, receive_open_file,
    receive_open_file_completed, receive_open_file_receipt, recover, send, send_encrypted,
    send_open_file, send_open_file_completed, send_open_file_receipt,
};

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

/// Documents offers describe the selected inputs without exposing source paths.
/// Payload framing and content manifests remain the common copy protocol.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionOffer {
    pub directories: Vec<bool>,
    pub plan: crate::selection::Plan,
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
