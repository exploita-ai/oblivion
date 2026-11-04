//! Shared copy manifests, bounded wire messages and payload verification.
//! Filesystem and channel authority are supplied only by platform endpoints.
pub mod browser;
#[cfg(unix)]
pub mod channel;
#[cfg(unix)]
mod directory;
pub mod endpoint;
pub mod native_files;
pub mod native_file_events;
pub mod selection;
#[cfg(unix)]
mod filesystem;
#[cfg(target_os = "linux")]
pub mod onion_file;
#[cfg(unix)]
pub mod recovery;
#[cfg(unix)]
pub mod relay;
#[cfg(unix)]
pub mod stream;
pub mod share;

#[cfg(unix)]
pub use filesystem::{ExportMode, Selection, publish, receive, receive_external};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};

const MAGIC: &[u8; 8] = b"OBLVCP01";
const END: &[u8; 8] = b"OBLVEND1";
const HEADER_LIMIT: usize = 8 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 16384;
pub const MAX_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const ENCRYPTED_VOLUME_NAME: &str = "session.oblivion";
pub const MAX_ENCRYPTED_VOLUME_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub entries: usize,
    pub bytes: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Entry {
    Directory {
        path: String,
    },
    File {
        path: String,
        size: u64,
        sha256: String,
    },
}

impl Entry {
    pub fn path(&self) -> &str {
        match self {
            Self::Directory { path } | Self::File { path, .. } => path,
        }
    }
}

/// Validated once at the offer boundary, before allocating destination files.
pub struct Manifest {
    entries: Vec<Entry>,
    bytes: u64,
    encoded: Vec<u8>,
}

impl Manifest {
    pub fn new(entries: Vec<Entry>, limits: Limits) -> io::Result<Self> {
        require(
            limits.entries > 0 && limits.entries <= MAX_ENTRIES,
            "invalid_entry_limit",
        )?;
        require(
            !entries.is_empty() && entries.len() <= limits.entries,
            "entry_limit",
        )?;
        let mut seen = BTreeMap::new();
        let mut bytes = 0u64;
        for entry in &entries {
            validate_path(entry.path())?;
            require(!seen.contains_key(entry.path()), "duplicate_path")?;
            if let Some((parent, _)) = entry.path().rsplit_once('/') {
                require(seen.get(parent) == Some(&true), "parent_not_declared")?;
            }
            if let Entry::File { size, sha256, .. } = entry {
                bytes = bytes
                    .checked_add(*size)
                    .ok_or_else(|| invalid("byte_limit"))?;
                require(bytes <= limits.bytes, "byte_limit")?;
                require(
                    sha256.len() == 64
                        && sha256
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                    "invalid_digest",
                )?;
            }
            seen.insert(entry.path(), matches!(entry, Entry::Directory { .. }));
        }
        let encoded = serde_json::to_vec(&entries).map_err(|_| invalid("invalid_manifest"))?;
        require(encoded.len() <= HEADER_LIMIT, "header_limit")?;
        Ok(Self {
            entries,
            bytes,
            encoded,
        })
    }

    pub fn read(reader: &mut impl Read, limits: Limits) -> io::Result<Self> {
        let mut magic = [0; 8];
        reader.read_exact(&mut magic)?;
        require(&magic == MAGIC, "invalid_transfer_version")?;
        let mut length = [0; 4];
        reader.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        require(length > 0 && length <= HEADER_LIMIT, "header_limit")?;
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes)?;
        Self::new(
            serde_json::from_slice(&bytes).map_err(|_| invalid("invalid_manifest"))?,
            limits,
        )
    }

    pub fn write(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(MAGIC)?;
        writer.write_all(&(self.encoded.len() as u32).to_be_bytes())?;
        writer.write_all(&self.encoded)
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn sha256(&self) -> String {
        format!("{:x}", Sha256::digest(&self.encoded))
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub id: String,
    pub manifest_sha256: String,
    pub entries: usize,
    pub bytes: u64,
}

/// Forward an already approved payload without opening or publishing a file.
/// Encrypted Share containers use the same hashes and terminator as the guest
/// copy endpoints; a corrupt source never produces a completed payload.
pub fn relay_payload(reader: &mut impl Read, writer: &mut impl Write, manifest: &Manifest) -> io::Result<()> {
    for entry in manifest.entries() {
        if let Entry::File { size, sha256, .. } = entry {
            require(copy_hash(reader, writer, *size)? == *sha256, "source_changed")?;
        }
    }
    let mut end = [0; 8];
    reader.read_exact(&mut end)?;
    require(&end == END, "incomplete_transfer")?;
    writer.write_all(END)
}

fn validate_id(id: &str) -> io::Result<()> {
    require(
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid_transfer_id",
    )
}

fn copy_hash(reader: &mut impl Read, writer: &mut impl Write, mut size: u64) -> io::Result<String> {
    let mut buffer = [0; 64 * 1024];
    let mut hash = Sha256::new();
    while size > 0 {
        let length = size.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..length])?;
        writer.write_all(&buffer[..length])?;
        hash.update(&buffer[..length]);
        size -= length as u64;
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn validate_path(path: &str) -> io::Result<()> {
    require(!path.is_empty() && path.len() <= 4096, "invalid_path")?;
    require(!path.chars().any(|c| c.is_control() || c == '\\' || matches!(c, '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')), "invalid_path")?;
    let components: Vec<_> = path.split('/').collect();
    require(
        components.len() <= 32
            && components
                .iter()
                .all(|part| !part.is_empty() && part.len() <= 255 && *part != "." && *part != ".."),
        "invalid_path",
    )
}

fn require(condition: bool, message: &'static str) -> io::Result<()> {
    if condition {
        return Ok(());
    }
    Err(invalid(message))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests;
