//! Unix filesystem authority for explicitly reviewed copies.
use crate::directory::Directory;
use crate::selection::{self, Input, Plan};
use crate::{
    END, Entry, Limits, MAX_ENTRIES, Manifest, Receipt, copy_hash, invalid,
    require, validate_id, validate_path,
};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Pins explicitly selected roots and object identities. Payload reopening uses
/// only their positive source aliases, never a peer-supplied computer path.
pub struct Selection {
    manifest: Manifest,
    files: Sources,
}

enum Sources {
    Volume(File),
    Mapped {
        roots: Vec<Directory>,
        files: Vec<Source>,
    },
}

struct Source {
    root: usize,
    path: String,
    device: u64,
    inode: u64,
}

struct Chosen {
    root: usize,
    name: String,
    path: String,
    device: u64,
    inode: u64,
    directory: bool,
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
    pub fn encrypted_volume(file: File, maximum: u64) -> io::Result<Self> {
        let (manifest, file) = crate::backup::Source::from_file(file, maximum)?.into_parts();
        Ok(Self {
            manifest,
            files: Sources::Volume(file),
        })
    }

    pub fn prepare(root: &Path, paths: &[String], limits: Limits) -> io::Result<Self> {
        Self::prepare_at(Directory::open(root)?, paths, limits)
    }

    pub(crate) fn prepare_at(
        root: Directory,
        paths: &[String],
        limits: Limits,
    ) -> io::Result<Self> {
        Self::prepare_checked(root, paths, limits, &mut || Ok(()))
    }

    pub(crate) fn prepare_checked(
        root: Directory,
        paths: &[String],
        limits: Limits,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Self> {
        check()?;
        require(
            limits.entries > 0 && limits.entries <= MAX_ENTRIES,
            "invalid_entry_limit",
        )?;
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
                        path,
                        0,
                        None,
                        limits,
                        &mut entries,
                        &mut files,
                        &mut bytes,
                        check,
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
            files: Sources::Mapped {
                roots: vec![root],
                files,
            },
        })
    }

    /// Native desktop choices are independent explicit roots. Their absolute
    /// paths stay in this process; only approved logical aliases reach the peer.
    pub(crate) fn host_collection(
        paths: &[PathBuf],
        limits: Limits,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<(Self, Plan, Vec<bool>)> {
        require(
            (1..=selection::MAX_SELECTIONS).contains(&paths.len()),
            "selection_limit",
        )?;
        let keys = paths
            .iter()
            .map(|path| {
                require(path.is_absolute(), "invalid_file_source")?;
                path.to_str()
                    .map(str::to_owned)
                    .ok_or_else(|| invalid("invalid_file_source"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        selection::validate_paths(&keys)?;
        let mut roots = Vec::new();
        let mut chosen = Vec::new();
        for (path, key) in paths.iter().zip(keys) {
            check()?;
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| invalid("invalid_source_name"))?;
            let parent = path
                .parent()
                .ok_or_else(|| invalid("invalid_source_root"))?;
            chosen.push(choose(&mut roots, Directory::open(parent)?, name, key)?);
        }
        Self::collection(roots, chosen, limits, check, Plan::new)
    }

    /// Every guest source is resolved beneath the fixed Documents authority.
    /// Parent traversal never follows links, including across the two roots.
    pub(crate) fn document_collection(
        root: &Path,
        paths: &[String],
        limits: Limits,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<(Self, Plan, Vec<bool>)> {
        require(
            paths.iter().all(|path| {
                matches!(path.split('/').next(), Some("workspace" | "imports"))
            }),
            "invalid_document_selection",
        )?;
        Self::rooted_collection(root, paths, limits, check)
    }

    /// The read-only media VM uses its fixed mount as the source authority.
    pub(crate) fn rooted_collection(
        root: &Path,
        paths: &[String],
        limits: Limits,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<(Self, Plan, Vec<bool>)> {
        selection::validate_rooted_paths(paths)?;
        let root = Directory::open(root)?;
        let mut roots = Vec::new();
        let mut chosen = Vec::new();
        for path in paths {
            check()?;
            let mut components = path.split('/').collect::<Vec<_>>();
            let name = components.pop().ok_or_else(|| invalid("invalid_path"))?;
            let parent = components
                .into_iter()
                .try_fold(root.clone()?, |parent, name| parent.directory(name))?;
            chosen.push(choose(&mut roots, parent, name, path.clone())?);
        }
        Self::collection(roots, chosen, limits, check, Plan::rooted)
    }

    fn collection(
        roots: Vec<Directory>,
        chosen: Vec<Chosen>,
        limits: Limits,
        check: &mut dyn FnMut() -> io::Result<()>,
        plan: fn(&[Input]) -> io::Result<Plan>,
    ) -> io::Result<(Self, Plan, Vec<bool>)> {
        let plan = plan(
            &chosen
                .iter()
                .map(|source| Input {
                    path: source.path.clone(),
                    directory: source.directory,
                })
                .collect::<Vec<_>>(),
        )?;
        let mut entries = Vec::new();
        let mut files = Vec::new();
        let mut bytes = 0;
        if chosen.len() > 1 {
            entries.push(Entry::Directory {
                path: plan.selected.clone(),
            });
        }
        for (index, source) in chosen.iter().enumerate() {
            let Some(path) = plan.manifest_path(index) else {
                continue;
            };
            collect(
                &roots[source.root],
                &source.name,
                &path,
                &source.name,
                source.root,
                Some((source.device, source.inode)),
                limits,
                &mut entries,
                &mut files,
                &mut bytes,
                check,
            )?;
        }
        Ok((
            Self {
                manifest: Manifest::new(entries, limits)?,
                files: Sources::Mapped { roots, files },
            },
            plan,
            chosen.iter().map(|source| source.directory).collect(),
        ))
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
                let alias = aliases
                    .get(sources.len())
                    .ok_or_else(|| invalid("source_alias_missing"))?;
                validate_path(alias)?;
                let mut components = alias.split('/').collect::<Vec<_>>();
                let name = components.pop().ok_or_else(|| invalid("invalid_path"))?;
                let parent = components
                    .into_iter()
                    .try_fold(root.clone()?, |parent, name| parent.directory(name))?;
                let mut file = parent.source(name)?;
                let metadata = file.metadata()?;
                require(
                    metadata.is_file() && metadata.nlink() == 1 && metadata.len() == *size,
                    "source_changed",
                )?;
                require(
                    copy_hash(&mut file, &mut io::sink(), *size)? == *sha256,
                    "source_changed",
                )?;
                sources.push(Source {
                    root: 0,
                    path: alias.clone(),
                    device: metadata.dev(),
                    inode: metadata.ino(),
                });
            }
        }
        require(sources.len() == aliases.len(), "source_alias_expanded")?;
        Ok(Self {
            manifest,
            files: Sources::Mapped {
                roots: vec![root],
                files: sources,
            },
        })
    }

    /// Writes the already offered files; a changed source aborts before END.
    /// The caller owns transport deadlines, cancellation and the final receipt.
    pub fn send_data(&mut self, writer: &mut impl Write) -> io::Result<()> {
        if let Sources::Volume(file) = &mut self.files {
            return crate::backup::write_volume(file, &self.manifest, writer);
        }
        let Sources::Mapped { roots, files } = &self.files else {
            unreachable!()
        };
        let mut index = 0;
        for entry in self.manifest.entries() {
            if let Entry::File { size, sha256, .. } = entry {
                let mut file = {
                    let source = files.get(index).ok_or_else(|| invalid("source_changed"))?;
                    let root = roots
                        .get(source.root)
                        .ok_or_else(|| invalid("source_changed"))?;
                    let mut components = source.path.split('/').collect::<Vec<_>>();
                    let name = components.pop().ok_or_else(|| invalid("invalid_path"))?;
                    let parent = components
                        .into_iter()
                        .try_fold(root.clone()?, |parent, name| parent.directory(name))?;
                    let file = parent.source(name)?;
                    let metadata = file.metadata()?;
                    require(
                        metadata.is_file()
                            && metadata.nlink() == 1
                            && metadata.dev() == source.device
                            && metadata.ino() == source.inode,
                        "source_changed",
                    )?;
                    file
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

fn choose(
    roots: &mut Vec<Directory>,
    parent: Directory,
    name: &str,
    path: String,
) -> io::Result<Chosen> {
    let metadata = parent.source(name)?.metadata()?;
    require(
        metadata.is_dir() || metadata.is_file() && metadata.nlink() == 1,
        "unsupported_source",
    )?;
    let identity = parent.metadata()?;
    let mut index = None;
    for (offset, root) in roots.iter().enumerate() {
        let metadata = root.metadata()?;
        if metadata.dev() == identity.dev() && metadata.ino() == identity.ino() {
            index = Some(offset);
            break;
        }
    }
    let root = match index {
        Some(index) => index,
        None => {
            // Retain parents, not every selected file. Leave room for bounded
            // descriptor-relative traversal, transport and receiver metadata.
            let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
            if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            require(
                unsafe { limit.assume_init() }.rlim_cur >= (roots.len() + 41) as libc::rlim_t,
                "selection_descriptor_limit",
            )?;
            let index = roots.len();
            roots.push(parent);
            index
        }
    };
    Ok(Chosen {
        root,
        name: name.into(),
        path,
        device: metadata.dev(),
        inode: metadata.ino(),
        directory: metadata.is_dir(),
    })
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
    receive_at(reader, manifest, &Directory::open(root)?, id)
}

pub(crate) fn receive_at(
    reader: &mut impl Read,
    manifest: &Manifest,
    root: &Directory,
    id: &str,
) -> io::Result<Receipt> {
    validate_id(id)?;
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
    /// exFAT permissions come from the isolated guest's mount options.
    Portable,
    /// FAT also limits each individual file to 2^32 - 1 bytes.
    Fat32,
}

/// Plaintext export into a new, exclusive directory on the authorized medium.
pub fn receive_external(
    reader: &mut impl Read,
    manifest: &Manifest,
    root: &Path,
    id: &str,
    mode: ExportMode,
) -> io::Result<Receipt> {
    ExternalExport::prepare(manifest, root, id, mode)?.receive(reader, |_| Ok(()))
}

/// The isolated guest pins and validates its selected filesystem before
/// acknowledging that it can receive the approved manifest.
pub(crate) struct ExternalExport<'a> {
    root: Directory,
    manifest: &'a Manifest,
    id: &'a str,
    mode: ExportMode,
    name: String,
    pending: String,
}

impl<'a> ExternalExport<'a> {
    pub fn prepare(
        manifest: &'a Manifest,
        root: &Path,
        id: &'a str,
        mode: ExportMode,
    ) -> io::Result<Self> {
        validate_id(id)?;
        if mode != ExportMode::Posix {
            validate_portable_export(manifest, mode)?;
        }
        let root = Directory::open(root)?;
        let name = format!("Oblivion-{id}");
        let pending = format!(".{name}.pending");
        for candidate in [&name, &pending] {
            match root.source(candidate) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                Err(error) => return Err(error),
                Ok(_) => return Err(io::ErrorKind::AlreadyExists.into()),
            }
        }
        Ok(Self {
            root,
            manifest,
            id,
            mode,
            name,
            pending,
        })
    }

    pub fn receive<R: Read>(
        self,
        reader: &mut R,
        check: impl Fn(&mut R) -> io::Result<()>,
    ) -> io::Result<Receipt> {
        check(reader)?;
        let transaction = self.root.create_directory(&self.pending)?;
        let receipt = Receipt {
            id: self.id.to_owned(),
            manifest_sha256: self.manifest.sha256(),
            entries: self.manifest.entries().len(),
            bytes: self.manifest.bytes(),
        };
        let result = (|| {
            self.root.sync()?;
            receive_transaction(reader, self.manifest, &transaction)?;
            let files = transaction.directory("files")?;
            // FAT/exFAT use mount-synthesized modes. POSIX exports are readable
            // by the user's other machine after unplugging the medium.
            if self.mode == ExportMode::Posix {
                for entry in self.manifest.entries() {
                    check(reader)?;
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
            let mut manifest_file = transaction.create_file("manifest.bin")?;
            self.manifest.write(&mut manifest_file)?;
            manifest_file.sync_all()?;
            let mut receipt_file = transaction.create_file("receipt.json")?;
            serde_json::to_writer(&mut receipt_file, &receipt)
                .map_err(|_| invalid("invalid_receipt"))?;
            receipt_file.sync_all()?;
            transaction.sync()?;
            check(reader)?;
            self.root
                .rename_exclusive(&self.pending, &self.root, &self.name)
        })();
        if let Err(error) = result {
            self.root.remove_directory(&self.pending)?;
            self.root.sync()?;
            return Err(error);
        }
        // A failure after the atomic rename is an uncertain outcome. The
        // receiver must never discard a visible publication on that basis.
        self.root.sync()?;
        Ok(receipt)
    }
}

fn validate_portable_export(manifest: &Manifest, mode: ExportMode) -> io::Result<()> {
    let mut paths = BTreeSet::new();
    for entry in manifest.entries() {
        for name in entry.path().split('/') {
            require(selection::portable_name(name), "unsupported_export_name")?;
        }
        require(
            paths.insert(selection::collision_key(entry.path())),
            "export_name_collision",
        )?;
        if let Entry::File { size, .. } = entry {
            require(
                mode != ExportMode::Fat32 || *size <= u64::from(u32::MAX),
                "fat32_file_too_large",
            )?;
        }
    }
    Ok(())
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
    source: &str,
    root: usize,
    expected: Option<(u64, u64)>,
    limits: Limits,
    entries: &mut Vec<Entry>,
    files: &mut Vec<Source>,
    bytes: &mut u64,
    check: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<()> {
    check()?;
    validate_path(path)?;
    require(entries.len() < limits.entries, "entry_limit")?;
    let mut file = parent.source(name)?;
    let metadata = file.metadata()?;
    require(
        expected.is_none_or(|identity| identity == (metadata.dev(), metadata.ino())),
        "source_changed",
    )?;
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
                &format!("{source}/{child}"),
                root,
                None,
                limits,
                entries,
                files,
                bytes,
                check,
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
    let sha256 = copy_hash(
        &mut CheckedRead {
            file: &mut file,
            check,
        },
        &mut io::sink(),
        metadata.len(),
    )?;
    require(file.metadata()?.len() == metadata.len(), "source_changed")?;
    entries.push(Entry::File {
        path: path.to_owned(),
        size: metadata.len(),
        sha256,
    });
    files.push(Source {
        root,
        path: source.to_owned(),
        device: metadata.dev(),
        inode: metadata.ino(),
    });
    Ok(())
}

/// Cancellation is observed during the existing bounded hash reads, without
/// a second collector, alternate digest implementation or source snapshot.
struct CheckedRead<'a> {
    file: &'a mut File,
    check: &'a mut dyn FnMut() -> io::Result<()>,
}
impl Read for CheckedRead<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        (self.check)()?;
        self.file.read(buffer)
    }
}
