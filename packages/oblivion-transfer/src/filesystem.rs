//! Unix filesystem authority for explicitly reviewed copies.
use crate::{Entry, Limits, Manifest, Receipt, END, ENCRYPTED_VOLUME_NAME, MAX_ENTRIES, copy_hash, invalid, require, validate_id, validate_path};
use crate::directory::Directory;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// Pins the root and source identities; files are reopened without following links.
/// The source environment must be isolated; this object is not a host authority.
pub struct Selection {
    manifest: Manifest,
    files: Sources,
}

enum Sources {
    Volume(File),
    Tree {
        root: Directory,
        identities: Vec<(u64, u64)>,
    },
    Approved {
        root: Directory,
        sources: Vec<(String, u64, u64)>,
    },
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
            files: Sources::Volume(file),
        })
    }

    pub fn prepare(root: &Path, paths: &[String], limits: Limits) -> io::Result<Self> {
        require(
            limits.entries > 0 && limits.entries <= MAX_ENTRIES,
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
            files: Sources::Tree {
                root,
                identities: files,
            },
        })
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The isolated source supplies an already reviewed manifest and one
    /// relative source alias per file. Generated portable metadata can have a
    /// public destination name without copying the workspace into staging.
    pub fn approved(root: &Path, manifest: Manifest, aliases: &[String]) -> io::Result<Self> {
        let root = Directory::open(root)?;
        let mut sources = Vec::new();
        for entry in manifest.entries() {
            if let Entry::File { size, sha256, .. } = entry {
                let alias = aliases.get(sources.len()).ok_or_else(|| invalid("source_alias_missing"))?;
                validate_path(alias)?;
                let mut components = alias.split('/').collect::<Vec<_>>();
                let name = components.pop().ok_or_else(|| invalid("invalid_path"))?;
                let parent = components.into_iter().try_fold(root.clone()?, |parent, name| parent.directory(name))?;
                let mut file = parent.source(name)?;
                let metadata = file.metadata()?;
                require(metadata.is_file() && metadata.nlink() == 1 && metadata.len() == *size, "source_changed")?;
                require(copy_hash(&mut file, &mut io::sink(), *size)? == *sha256, "source_changed")?;
                sources.push((alias.clone(), metadata.dev(), metadata.ino()));
            }
        }
        require(sources.len() == aliases.len(), "source_alias_expanded")?;
        Ok(Self { manifest, files: Sources::Approved { root, sources } })
    }

    /// Writes the already offered files; a changed source aborts before END.
    /// The caller owns transport deadlines, cancellation and the final receipt.
    pub fn send_data(&mut self, writer: &mut impl Write) -> io::Result<()> {
        let mut index = 0;
        for entry in self.manifest.entries() {
            if let Entry::File { path, size, sha256 } = entry {
                let mut file = match &self.files {
                    Sources::Volume(file) => file.try_clone()?,
                    Sources::Tree { root, identities } => {
                        let mut components = path.split('/').collect::<Vec<_>>();
                        let name = components.pop().ok_or_else(|| invalid("invalid_path"))?;
                        let parent = components
                            .into_iter()
                            .try_fold(root.clone()?, |parent, name| parent.directory(name))?;
                        let file = parent.source(name)?;
                        let meta = file.metadata()?;
                        require(
                            meta.is_file()
                                && meta.nlink() == 1
                                && identities.get(index) == Some(&(meta.dev(), meta.ino())),
                            "source_changed",
                        )?;
                        file
                    }
                    Sources::Approved { root, sources } => {
                        let (alias, device, inode) = sources.get(index).ok_or_else(|| invalid("source_changed"))?;
                        let mut components = alias.split('/').collect::<Vec<_>>();
                        let name = components.pop().ok_or_else(|| invalid("invalid_path"))?;
                        let parent = components.into_iter().try_fold(root.clone()?, |parent, name| parent.directory(name))?;
                        let file = parent.source(name)?;
                        let metadata = file.metadata()?;
                        require(metadata.is_file() && metadata.nlink() == 1
                            && metadata.dev() == *device && metadata.ino() == *inode, "source_changed")?;
                        file
                    }
                };
                file.rewind()?;
                require(file.metadata()?.len() == *size, "source_changed")?;
                require(
                    &copy_hash(&mut file, writer, *size)? == sha256,
                    "source_changed",
                )?;
                index += 1;
            }
        }
        writer.write_all(END)?;
        writer.flush()
    }
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
        entries: manifest.entries().len(),
        bytes: manifest.bytes(),
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
    for entry in manifest.entries() {
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
    files: &mut Vec<(u64, u64)>,
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
    files.push((metadata.dev(), metadata.ino()));
    Ok(())
}

