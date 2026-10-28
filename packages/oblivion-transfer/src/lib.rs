pub mod browser;
pub mod channel;
mod directory;
pub mod endpoint;
#[cfg(target_os = "linux")]
pub mod onion_file;
pub mod recovery;
pub mod relay;

use directory::Directory;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

const MAGIC: &[u8; 8] = b"OBLVCP01";
const END: &[u8; 8] = b"OBLVEND1";
const HEADER_LIMIT: usize = 1024 * 1024;
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
            limits.entries > 0 && limits.entries <= 4096,
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

/// Holds opened source files, so path replacement cannot change the selection.
/// The source environment must be isolated; this object is not a host authority.
pub struct Selection {
    manifest: Manifest,
    files: Vec<File>,
}

impl Selection {
    /// Resolve a selected backup inside an isolated media guest, retaining the
    /// opened file and emitting only the fixed public ciphertext filename.
    pub fn encrypted_path(root: &Path, path: &str, maximum: u64) -> io::Result<Self> {
        validate_path(path)?;
        let mut components = path.split('/').collect::<Vec<_>>();
        let name = components.pop().ok_or_else(|| invalid("invalid_path"))?;
        let parent = components
            .into_iter()
            .try_fold(Directory::open(root)?, |parent, name| {
                parent.directory(name)
            })?;
        Self::encrypted_volume(parent.source(name)?, maximum)
    }

    /// A trusted controller delegates one closed, read-only LUKS2 file. The
    /// signature is not authentication or a check of its encrypted filesystem.
    /// No directory or peer-selected filesystem path is accepted here.
    pub fn encrypted_volume(mut file: File, maximum: u64) -> io::Result<Self> {
        let metadata = file.metadata()?;
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        require(
            flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
            "source_not_read_only",
        )?;
        require(
            metadata.is_file() && metadata.nlink() == 1,
            "unsupported_source",
        )?;
        require(
            metadata.len() >= 32 * 1024 * 1024 && metadata.len() <= maximum,
            "byte_limit",
        )?;
        file.rewind()?;
        let mut magic = [0; 8];
        file.read_exact(&mut magic)?;
        require(
            &magic == b"LUKS\xba\xbe\x00\x02",
            "invalid_encrypted_volume",
        )?;
        file.rewind()?;
        let sha256 = copy_hash(&mut file, &mut io::sink(), metadata.len())?;
        require(file.metadata()?.len() == metadata.len(), "source_changed")?;
        Ok(Self {
            manifest: Manifest::new(
                vec![Entry::File {
                    path: ENCRYPTED_VOLUME_NAME.into(),
                    size: metadata.len(),
                    sha256,
                }],
                Limits {
                    entries: 1,
                    bytes: maximum,
                },
            )?,
            files: vec![file],
        })
    }

    pub fn prepare(root: &Path, paths: &[String], limits: Limits) -> io::Result<Self> {
        require(
            limits.entries > 0 && limits.entries <= 4096,
            "invalid_entry_limit",
        )?;
        let root = Directory::open(root)?;
        let mut entries = Vec::new();
        let mut files = Vec::new();
        let mut bytes = 0;
        for path in paths {
            validate_path(path)?;
            // Explicit parents are part of the offer; no implicit filesystem traversal.
            let mut components = path.split('/').peekable();
            let mut parent = root.clone()?;
            let mut prefix = String::new();
            while let Some(component) = components.next() {
                if components.peek().is_none() {
                    collect(
                        &parent,
                        component,
                        path,
                        limits,
                        &mut entries,
                        &mut files,
                        &mut bytes,
                    )?;
                    break;
                }
                parent = parent.directory(component)?;
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(component);
                if !entries.iter().any(|entry| entry.path() == prefix) {
                    require(entries.len() < limits.entries, "entry_limit")?;
                    entries.push(Entry::Directory {
                        path: prefix.clone(),
                    });
                }
            }
        }
        Ok(Self {
            manifest: Manifest::new(entries, limits)?,
            files,
        })
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Writes the already offered files; a changed source aborts before END.
    /// The caller owns transport deadlines, cancellation and the final receipt.
    pub fn send_data(&mut self, writer: &mut impl Write) -> io::Result<()> {
        let mut files = self.files.iter_mut();
        for entry in &self.manifest.entries {
            if let Entry::File { size, sha256, .. } = entry {
                let file = files.next().ok_or_else(|| invalid("source_missing"))?;
                file.rewind()?;
                require(file.metadata()?.len() == *size, "source_changed")?;
                require(&copy_hash(file, writer, *size)? == sha256, "source_changed")?;
            }
        }
        writer.write_all(END)?;
        writer.flush()
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

/// Copy into a new private transaction under a receiver-owned root. On success
/// only `id/files` is complete. The caller must explicitly release it to the chat.
/// This function neither approves an offer nor grants access to a USB device.
pub fn receive(
    reader: &mut impl Read,
    manifest: &Manifest,
    root: &Path,
    id: &str,
) -> io::Result<Receipt> {
    validate_id(id)?;
    let root = Directory::open(root)?;
    root.require_private()?;
    let transaction = root.create_directory(id)?;
    let result = receive_transaction(reader, manifest, &transaction);
    if let Err(error) = result {
        root.remove_directory(id)?;
        root.sync()?;
        return Err(error);
    }
    root.sync()?;
    let receipt = Receipt {
        id: id.to_owned(),
        manifest_sha256: manifest.sha256(),
        entries: manifest.entries.len(),
        bytes: manifest.bytes,
    };
    // Keep the proof in the receiver's private inbox, on the same encrypted
    // volume. A killed write leaves only receipt.pending, never a valid receipt.
    let mut file = transaction.create_file("receipt.pending")?;
    serde_json::to_writer(&mut file, &receipt).map_err(|_| invalid("invalid_receipt"))?;
    file.sync_all()?;
    transaction.rename("receipt.pending", "receipt.json")?;
    transaction.sync()?;
    Ok(receipt)
}

/// Permission policy selected by the trusted writer launcher, never the peer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExportMode {
    Posix,
    /// FAT/exFAT permissions come from the isolated guest's mount options.
    Portable,
}

/// Plaintext export into a new, exclusive directory on the authorized medium.
pub fn receive_external(
    reader: &mut impl Read,
    manifest: &Manifest,
    root: &Path,
    id: &str,
    mode: ExportMode,
) -> io::Result<Receipt> {
    validate_id(id)?;
    if mode == ExportMode::Portable {
        for entry in manifest.entries() {
            for name in entry.path().split('/') {
                require(
                    !name.ends_with(['.', ' '])
                        && !name
                            .chars()
                            .any(|c| matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')),
                    "unsupported_export_name",
                )?;
            }
        }
    }
    let root = Directory::open(root)?;
    let name = format!("Oblivion-{id}");
    let transaction = root.create_directory(&name)?;
    if let Err(error) = receive_transaction(reader, manifest, &transaction) {
        root.remove_directory(&name)?;
        root.sync()?;
        return Err(error);
    }
    let files = transaction.directory("files")?;
    // FAT/exFAT synthesize permissions at mount; chmod is not a portable
    // operation there. POSIX media must be readable by users outside Oblivion.
    if mode == ExportMode::Posix {
        for entry in manifest.entries() {
            let mut parent = files.clone()?;
            let mut components = entry.path().split('/').peekable();
            while let Some(component) = components.next() {
                if components.peek().is_some() {
                    parent = parent.directory(component)?;
                    continue;
                }
                let file = parent.source(component)?;
                file.set_permissions(std::fs::Permissions::from_mode(
                    if matches!(entry, Entry::Directory { .. }) {
                        0o755
                    } else {
                        0o644
                    },
                ))?;
                file.sync_all()?;
            }
        }
        files.mode(0o755)?;
        transaction.mode(0o755)?;
    }
    files.sync()?;
    transaction.sync()?;
    root.sync()?;
    Ok(Receipt {
        id: id.to_owned(),
        manifest_sha256: manifest.sha256(),
        entries: manifest.entries().len(),
        bytes: manifest.bytes(),
    })
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

/// Explicit local release after receive has verified and synced the whole
/// transaction. The service owns both roots; the chat shares its primary group
/// but cannot traverse the private inbox or modify the publication root.
pub fn publish(root: &Path, target: &Path, id: &str, manifest: &Manifest) -> io::Result<()> {
    validate_id(id)?;
    let root = Directory::open(root)?;
    root.require_private()?;
    let transaction = root.directory(id)?;
    transaction.require_private()?;
    let files = transaction.directory("files")?;
    files.require_private()?;
    let target = Directory::open(target)?;
    target.require_controlled()?;
    // Reserve the name while inaccessible to the chat. No existing publication
    // is ever replaced, even if it is empty or only partially prepared.
    let reserved = target.create_directory(id)?;
    for entry in manifest.entries() {
        let mut components = entry.path().split('/').peekable();
        let mut parent = files.clone()?;
        while let Some(name) = components.next() {
            if components.peek().is_some() {
                parent = parent.directory(name)?;
                continue;
            }
            let file = parent.source(name)?;
            let metadata = file.metadata()?;
            require(
                metadata.uid() == unsafe { libc::geteuid() }
                    && metadata.gid() == unsafe { libc::getegid() },
                "invalid_publication_owner",
            )?;
            require(
                match entry {
                    Entry::Directory { .. } => metadata.is_dir(),
                    Entry::File { size, .. } => {
                        metadata.is_file() && metadata.nlink() == 1 && metadata.len() == *size
                    }
                },
                "invalid_publication_entry",
            )?;
            file.set_permissions(std::fs::Permissions::from_mode(if metadata.is_dir() {
                0o770
            } else {
                0o660
            }))?;
            file.sync_all()?;
        }
    }
    files.mode(0o770)?;
    files.sync()?;
    // Both roots must be in the same session filesystem. EXDEV fails; there is
    // deliberately no plaintext staging or host-filesystem fallback.
    transaction.move_into("files", &reserved, "files")?;
    reserved.sync()?;
    transaction.sync()?;
    // Chat may edit the document tree, but cannot replace its top-level name.
    reserved.mode(0o750)?;
    reserved.sync()?;
    target.sync()?;
    transaction.create_file("published")?.sync_all()?;
    transaction.sync()
}

fn receive_transaction(
    reader: &mut impl Read,
    manifest: &Manifest,
    transaction: &Directory,
) -> io::Result<()> {
    let pending = transaction.create_directory("pending")?;
    for entry in &manifest.entries {
        let mut components = entry.path().split('/').peekable();
        let mut parent = pending.clone()?;
        while let Some(name) = components.next() {
            if components.peek().is_some() {
                parent = parent.directory(name)?;
                continue;
            }
            match entry {
                Entry::Directory { .. } => {
                    parent.create_directory(name)?.sync()?;
                }
                Entry::File { size, sha256, .. } => {
                    let mut file = parent.create_file(name)?;
                    require(
                        &copy_hash(reader, &mut file, *size)? == sha256,
                        "digest_mismatch",
                    )?;
                    file.sync_all()?;
                }
            }
            parent.sync()?;
        }
    }
    let mut end = [0; 8];
    reader.read_exact(&mut end)?;
    require(&end == END, "transfer_incomplete")?;
    pending.sync()?;
    transaction.rename("pending", "files")?;
    transaction.sync()
}

fn collect(
    parent: &Directory,
    name: &str,
    path: &str,
    limits: Limits,
    entries: &mut Vec<Entry>,
    files: &mut Vec<File>,
    bytes: &mut u64,
) -> io::Result<()> {
    validate_path(path)?;
    require(entries.len() < limits.entries, "entry_limit")?;
    let mut file = parent.source(name)?;
    let metadata = file.metadata()?;
    if metadata.is_dir() {
        entries.push(Entry::Directory {
            path: path.to_owned(),
        });
        let directory = Directory::from_file(file)?;
        for child in directory.names(limits.entries - entries.len())? {
            collect(
                &directory,
                &child,
                &format!("{path}/{child}"),
                limits,
                entries,
                files,
                bytes,
            )?;
        }
        return Ok(());
    }
    require(
        metadata.is_file() && metadata.nlink() == 1,
        "unsupported_source",
    )?;
    *bytes = bytes
        .checked_add(metadata.len())
        .ok_or_else(|| invalid("byte_limit"))?;
    require(*bytes <= limits.bytes, "byte_limit")?;
    let sha256 = copy_hash(&mut file, &mut io::sink(), metadata.len())?;
    require(file.metadata()?.len() == metadata.len(), "source_changed")?;
    entries.push(Entry::File {
        path: path.to_owned(),
        size: metadata.len(),
        sha256,
    });
    files.push(file);
    Ok(())
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
    require(!path.chars().any(|c| c.is_control() || c == '\\' || matches!(c, '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')), "invalid_path")?;
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
