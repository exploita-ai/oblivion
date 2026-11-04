//! Explicit desktop copies over an already authorized private stream.
//! Manifest, file hashes, limits and receipts use the existing copy protocol.
use crate::channel::Channel;
use crate::directory::Directory;
use crate::endpoint::{
    Approval, OfferRequest, ReceiveRequest, SelectionOffer, read_message, write_message,
};
use crate::native_file_events::{Phase, Summary};
use crate::native_files::{Context, Direction};
use crate::{Limits, Manifest, Receipt, Selection, invalid, require, validate_id, validate_path};
#[path = "stream_operations.rs"]
pub mod operations;

use crate::selection::{self, Input, Plan};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The source selection is prepared once, then retained through human review.
/// No destination connection, receiver state or source snapshot is created here.
pub struct PreparedUpload {
    selection: Selection,
    context: Context,
    plan: Plan,
}

impl PreparedUpload {
    pub fn prepare(
        sources: &[PathBuf],
        context: Context,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Self> {
        context.validate()?;
        require(
            context.direction == Direction::Import,
            "invalid_file_source",
        )?;
        let (selection, plan, _) = Selection::host_collection(
            sources,
            Limits {
                entries: crate::MAX_ENTRIES,
                bytes: crate::MAX_DOCUMENT_BYTES,
            },
            check,
        )?;
        let prepared = Self {
            selection,
            context,
            plan,
        };
        prepared.summary()?;
        Ok(prepared)
    }

    pub fn summary(&self) -> io::Result<Summary> {
        Summary::from_manifest(self.selection.manifest(), &self.plan)
    }

    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    pub fn send(
        mut self,
        channel: &mut Channel,
        approved_digest: &str,
        observer: &mut dyn FnMut(Phase, u64) -> io::Result<()>,
    ) -> io::Result<Receipt> {
        let summary = self.summary()?;
        require(
            approved_digest == summary.manifest_sha256,
            "offer_not_approved",
        )?;
        send_observed(channel, &mut self.selection, &self.context.id, observer)
    }
}

/// Personal ciphertext backups already own their reviewed Selection. They
/// share this exact source protocol without introducing native Files state.
pub fn send(channel: &mut Channel, selection: &mut Selection, id: &str) -> io::Result<Receipt> {
    send_observed(channel, selection, id, &mut |_, _| Ok(()))
}

fn send_observed(
    channel: &mut Channel,
    selection: &mut Selection,
    id: &str,
    observer: &mut dyn FnMut(Phase, u64) -> io::Result<()>,
) -> io::Result<Receipt> {
    validate_id(id)?;
    observer(Phase::Copying, 0)?;
    channel.check()?;
    write_message(
        channel,
        &ReceiveRequest {
            approval: Approval {
                id: id.into(),
                manifest_sha256: selection.manifest().sha256(),
            },
            limits: Limits {
                entries: selection.manifest().entries().len(),
                bytes: selection.manifest().bytes(),
            },
        },
    )?;
    selection.manifest().write(channel)?;
    let mut accepted = [0; 8];
    channel.read_exact(&mut accepted)?;
    require(&accepted == b"receive\n", "offer_rejected")?;
    let total = selection.manifest().bytes();
    selection.send_data(&mut Payload {
        inner: channel,
        observer,
        bytes: 0,
        total,
    })?;
    observer(Phase::Finalizing, total)?;
    channel.check()?;
    let receipt: Receipt = read_message(channel, 1024)?;
    verify_receipt(&receipt, id, selection.manifest())?;
    Ok(receipt)
}

/// The source offer and destination descriptor remain pinned during review.
/// The source receives no Approval and the receiver writes nothing in prepare.
pub struct PreparedDownload {
    channel: Channel,
    manifest: Manifest,
    target: Directory,
    context: Context,
    plan: Plan,
}

impl PreparedDownload {
    pub fn prepare(
        mut channel: Channel,
        selected: &[String],
        target: &Path,
        context: Context,
    ) -> io::Result<Self> {
        context.validate()?;
        require(
            context.direction == Direction::Export,
            "invalid_file_destination",
        )?;
        selection::validate_paths(selected)?;
        for path in selected {
            validate_path(path)?;
            require(
                matches!(path.split('/').next(), Some("workspace" | "imports")),
                "invalid_document_selection",
            )?;
        }
        let target = Directory::open(target)?;
        target.require_controlled()?;
        channel.check()?;
        write_message(
            &mut channel,
            &OfferRequest {
                id: context.id.clone(),
                limits: Limits {
                    entries: crate::MAX_ENTRIES,
                    bytes: crate::MAX_DOCUMENT_BYTES,
                },
                paths: selected.to_vec(),
            },
        )?;
        let offer: SelectionOffer = read_message(&mut channel, 64 * 1024)?;
        let plan = selection_plan(selected, &offer)?;
        let manifest = Manifest::read(
            &mut channel,
            Limits {
                entries: crate::MAX_ENTRIES,
                bytes: crate::MAX_DOCUMENT_BYTES,
            },
        )?;
        require_collection(&manifest, &plan, &offer.directories)?;
        let prepared = Self {
            channel,
            manifest,
            target,
            context,
            plan,
        };
        prepared.summary()?;
        Ok(prepared)
    }

    pub fn summary(&self) -> io::Result<Summary> {
        Summary::from_manifest(&self.manifest, &self.plan)
    }

    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    pub fn receive(
        mut self,
        approved_digest: &str,
        observer: &mut dyn FnMut(Phase, u64) -> io::Result<()>,
    ) -> io::Result<Receipt> {
        let summary = self.summary()?;
        require(
            approved_digest == summary.manifest_sha256,
            "offer_not_approved",
        )?;
        observer(Phase::Copying, 0)?;
        self.channel.check()?;
        // Create staging only after approval, beneath the reviewed descriptor
        // even if the destination's pathname was replaced while showing review.
        let inbox = match self.target.create_directory(".oblivion-transfers") {
            Ok(directory) => {
                self.target.sync()?;
                directory
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                self.target.directory(".oblivion-transfers")?
            }
            Err(error) => return Err(error),
        };
        inbox.require_private()?;
        inbox.lock()?;
        operations::begin_at(&inbox, &self.target, &self.context)?;
        self.channel.check()?;
        write_message(
            &mut self.channel,
            &Approval {
                id: self.context.id.clone(),
                manifest_sha256: summary.manifest_sha256,
            },
        )?;
        let receipt = crate::filesystem::receive_at(
            &mut Payload {
                inner: &mut self.channel,
                observer,
                bytes: 0,
                total: summary.bytes,
            },
            &self.manifest,
            &inbox,
            &self.context.id,
        )?;
        observer(Phase::Finalizing, summary.bytes)?;
        self.channel.check()?;
        publish(
            &inbox,
            &self.target,
            &self.context.name,
            &self.plan.selected,
            &receipt,
            &self.manifest,
        )?;
        write_message(&mut self.channel, &receipt)?;
        let mut completed = [0; 7];
        self.channel.read_exact(&mut completed)?;
        require(&completed == b"copied\n", "source_not_completed")?;
        Ok(receipt)
    }
}

// Wrap only the existing payload copy, not its offer or manifest. END is part
// of that stream but never contributes to document-byte progress.
struct Payload<'a, T> {
    inner: &'a mut T,
    observer: &'a mut dyn FnMut(Phase, u64) -> io::Result<()>,
    bytes: u64,
    total: u64,
}
impl<T> Payload<'_, T> {
    fn advance(&mut self, count: usize) -> io::Result<()> {
        self.bytes += (count as u64).min(self.total - self.bytes);
        (self.observer)(Phase::Copying, self.bytes)
    }
}
impl<T: Read> Read for Payload<'_, T> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        (self.observer)(Phase::Copying, self.bytes)?;
        let count = self.inner.read(buffer)?;
        self.advance(count)?;
        Ok(count)
    }
}
impl<T: Write> Write for Payload<'_, T> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        (self.observer)(Phase::Copying, self.bytes)?;
        let count = self.inner.write(buffer)?;
        self.advance(count)?;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        (self.observer)(Phase::Copying, self.bytes)?;
        self.inner.flush()
    }
}

/// A personal backup receiver owns one empty local file. The peer can offer
/// only the fixed LUKS2 payload, never a local path or an archive to extract.
pub fn download_open_file(
    channel: &mut Channel,
    mut file: std::fs::File,
    maximum: u64,
    id: &str,
) -> io::Result<Receipt> {
    use std::io::Seek;
    use std::os::fd::AsRawFd;
    validate_id(id)?;
    require(
        (32 * 1024 * 1024..=crate::MAX_ENCRYPTED_VOLUME_BYTES).contains(&maximum),
        "invalid_backup_limit",
    )?;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    let metadata = file.metadata()?;
    require(
        flags >= 0
            && flags & libc::O_ACCMODE != libc::O_RDONLY
            && flags & libc::O_APPEND == 0
            && metadata.is_file()
            && metadata.nlink() == 1
            && metadata.len() == 0
            && metadata.uid() == unsafe { libc::getuid() }
            && metadata.mode() & 0o077 == 0,
        "unsafe_backup_destination",
    )?;
    let limits = Limits {
        entries: 1,
        bytes: maximum,
    };
    write_message(
        channel,
        &OfferRequest {
            id: id.into(),
            limits,
            paths: vec![crate::ENCRYPTED_VOLUME_NAME.into()],
        },
    )?;
    let manifest = Manifest::read(channel, limits)?;
    let [crate::Entry::File { path, size, sha256 }] = manifest.entries() else {
        return Err(invalid("invalid_backup_selection"));
    };
    require(
        path == crate::ENCRYPTED_VOLUME_NAME && *size >= 32 * 1024 * 1024,
        "invalid_backup_selection",
    )?;
    write_message(
        channel,
        &Approval {
            id: id.into(),
            manifest_sha256: manifest.sha256(),
        },
    )?;
    file.rewind()?;
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
    let receipt = Receipt {
        id: id.into(),
        manifest_sha256: manifest.sha256(),
        entries: 1,
        bytes: *size,
    };
    write_message(channel, &receipt)?;
    let mut copied = [0; 7];
    channel.read_exact(&mut copied)?;
    require(&copied == b"copied\n", "source_not_completed")?;
    Ok(receipt)
}

/// The local launcher chooses both roots, name and ceiling. The peer supplies
/// only one declared top-level file/directory, never an archive to extract.
pub fn receive_directory(
    channel: &mut Channel,
    inbox: &Path,
    target: &Path,
    context: &crate::native_files::Context,
) -> io::Result<Receipt> {
    let name = context.name.as_str();
    let limits = Limits {
        entries: crate::MAX_ENTRIES,
        bytes: crate::MAX_DOCUMENT_BYTES,
    };
    validate_name(name)?;
    let guard = Directory::open(inbox)?;
    guard.require_private()?;
    guard.lock()?;
    let target = Directory::open(target)?;
    target.require_controlled()?;
    operations::require_active(&guard, &target, context)?;
    let request: ReceiveRequest = read_message(channel, 1024)?;
    validate_id(&request.approval.id)?;
    require(request.approval.id == context.id, "file_operation_changed")?;
    require(
        request.limits.entries <= limits.entries && request.limits.bytes <= limits.bytes,
        "transfer_limit",
    )?;
    let manifest = Manifest::read(channel, request.limits)?;
    require(
        manifest.sha256() == request.approval.manifest_sha256,
        "offer_not_approved",
    )?;
    let selected = manifest.entries()[0].path().to_owned();
    require(!selected.contains('/'), "invalid_source_selection")?;
    require_selection(&manifest, &selected)?;
    channel.write_all(b"receive\n")?;
    let receipt = crate::filesystem::receive_at(channel, &manifest, &guard, &request.approval.id)?;
    channel.check()?;
    publish(&guard, &target, name, &selected, &receipt, &manifest)?;
    write_message(channel, &receipt)?;
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

/// Finish only the verified operation's publication under its inbox lock.
fn recover_directory_locked(
    guard: &Directory,
    target: &Directory,
    id: &str,
) -> io::Result<Receipt> {
    let transaction = guard.directory(id)?;
    let publication: Publication =
        serde_json::from_reader(transaction.source("publication.json")?.take(8192))
            .map_err(|_| invalid("invalid_publication"))?;
    validate_name(&publication.name)?;
    validate_path(&publication.selected)?;
    let receipt: Receipt = serde_json::from_reader(transaction.source("receipt.json")?.take(1024))
        .map_err(|_| invalid("invalid_receipt"))?;
    require(receipt.id == id, "invalid_receipt")?;
    let manifest = Manifest::read(
        &mut transaction.source("manifest.bin")?,
        Limits {
            entries: crate::MAX_ENTRIES,
            bytes: crate::MAX_DOCUMENT_BYTES,
        },
    )?;
    verify_receipt(&receipt, id, &manifest)?;
    require_selection(&manifest, &publication.selected)?;
    // A recovered private receive can have waited while its source agent was
    // running. Recheck the actual private bytes before publication. An already
    // moved/published working tree is intentionally editable and never rehashed.
    if let Ok(parent) = selected_parent(&transaction, &publication.selected) {
        if let Ok(file) = parent.source(
            publication
                .selected
                .rsplit('/')
                .next()
                .ok_or_else(|| invalid("invalid_selection"))?,
        ) {
            let metadata = file.metadata()?;
            require(
                metadata.dev() == publication.device && metadata.ino() == publication.inode,
                "publication_changed",
            )?;
            let current = Selection::prepare_at(
                transaction.directory("files")?,
                &[publication.selected.clone()],
                Limits {
                    entries: crate::MAX_ENTRIES,
                    bytes: crate::MAX_DOCUMENT_BYTES,
                },
            )?;
            require(
                current.manifest().sha256() == manifest.sha256(),
                "publication_changed",
            )?;
        }
    }
    finish_publication(&transaction, target, &publication)?;
    Ok(receipt)
}

fn publish(
    inbox: &Directory,
    target: &Directory,
    name: &str,
    selected: &str,
    receipt: &Receipt,
    manifest: &Manifest,
) -> io::Result<()> {
    let transaction = inbox.directory(&receipt.id)?;
    let mut offer = transaction.create_file("manifest.pending")?;
    manifest.write(&mut offer)?;
    offer.sync_all()?;
    transaction.rename("manifest.pending", "manifest.bin")?;
    transaction.sync()?;
    let parent = selected_parent(&transaction, selected)?;
    let file = parent.source(
        selected
            .rsplit('/')
            .next()
            .ok_or_else(|| invalid("invalid_selection"))?,
    )?;
    let metadata = file.metadata()?;
    let publication = Publication {
        name: name.to_owned(),
        selected: selected.to_owned(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let mut record = transaction.create_file("publication.pending")?;
    serde_json::to_writer(&mut record, &publication).map_err(|_| invalid("invalid_publication"))?;
    record.sync_all()?;
    transaction.rename("publication.pending", "publication.json")?;
    transaction.sync()?;
    finish_publication(&transaction, target, &publication)
}

fn finish_publication(
    transaction: &Directory,
    target: &Directory,
    publication: &Publication,
) -> io::Result<()> {
    target.require_controlled()?;
    let current = target.source(&publication.name);
    match current {
        Ok(file) => {
            let metadata = file.metadata()?;
            require(
                metadata.dev() == publication.device && metadata.ino() == publication.inode,
                "destination_exists",
            )?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = selected_parent(transaction, &publication.selected)?;
            let selected = publication
                .selected
                .rsplit('/')
                .next()
                .ok_or_else(|| invalid("invalid_selection"))?;
            let metadata = parent.source(selected)?.metadata()?;
            require(
                metadata.dev() == publication.device && metadata.ino() == publication.inode,
                "publication_changed",
            )?;
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
    components
        .pop()
        .ok_or_else(|| invalid("invalid_selection"))?;
    components
        .into_iter()
        .try_fold(transaction.directory("files")?, |parent, component| {
            parent.directory(component)
        })
}

/// Both the native receiver and the media relay verify the source's path-free
/// plan against the exact requested document selection before approving bytes.
pub(crate) fn selection_plan(selected: &[String], offer: &SelectionOffer) -> io::Result<Plan> {
    require(
        offer.directories.len() == selected.len(),
        "invalid_selection_offer",
    )?;
    for path in selected {
        validate_path(path)?;
        require(
            matches!(path.split('/').next(), Some("workspace" | "imports")),
            "invalid_document_selection",
        )?;
    }
    let plan = Plan::new(
        &selected
            .iter()
            .zip(&offer.directories)
            .map(|(path, directory)| Input {
                path: path.clone(),
                directory: *directory,
            })
            .collect::<Vec<_>>(),
    )?;
    require(plan == offer.plan, "selection_changed")?;
    Ok(plan)
}

pub(crate) fn require_collection(
    manifest: &Manifest,
    plan: &Plan,
    directories: &[bool],
) -> io::Result<()> {
    require_selection(manifest, &plan.selected)?;
    let roots = plan
        .mappings
        .iter()
        .filter_map(|mapping| {
            plan.manifest_path(mapping.input_index)
                .map(|path| (mapping.input_index, path))
        })
        .collect::<Vec<_>>();
    for (index, path) in &roots {
        let entry = manifest
            .entries()
            .iter()
            .find(|entry| entry.path() == path)
            .ok_or_else(|| invalid("selection_missing"))?;
        require(
            matches!(entry, crate::Entry::Directory { .. }) == directories[*index],
            "selection_changed",
        )?;
    }
    for entry in manifest.entries() {
        let wrapper = plan.mappings.len() > 1
            && entry.path() == plan.selected
            && matches!(entry, crate::Entry::Directory { .. });
        require(
            wrapper
                || roots.iter().any(|(_, path)| {
                    entry.path() == path
                        || entry
                            .path()
                            .strip_prefix(path)
                            .is_some_and(|suffix| suffix.starts_with('/'))
                }),
            "selection_expanded",
        )?;
    }
    Ok(())
}

fn require_selection(manifest: &Manifest, selected: &str) -> io::Result<()> {
    require(
        manifest
            .entries()
            .iter()
            .any(|entry| entry.path() == selected),
        "selection_missing",
    )?;
    for entry in manifest.entries() {
        let ancestor = selected
            .strip_prefix(entry.path())
            .is_some_and(|tail| tail.starts_with('/'));
        let descendant = entry
            .path()
            .strip_prefix(selected)
            .is_some_and(|tail| tail.starts_with('/'));
        require(
            entry.path() == selected || ancestor || descendant,
            "selection_expanded",
        )?;
    }
    Ok(())
}

fn validate_name(name: &str) -> io::Result<()> {
    validate_path(name)?;
    require(!name.contains('/'), "invalid_destination_name")
}

fn verify_receipt(receipt: &Receipt, id: &str, manifest: &Manifest) -> io::Result<()> {
    require(
        receipt.id == id
            && receipt.manifest_sha256 == manifest.sha256()
            && receipt.entries == manifest.entries().len()
            && receipt.bytes == manifest.bytes(),
        "invalid_receipt",
    )
}
