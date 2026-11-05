//! Explicit desktop copies over an already authorized private stream.
//! Manifest, file hashes, limits and receipts use the existing copy protocol.
#[cfg(unix)]
use crate::Selection;
#[cfg(unix)]
use crate::channel::Channel;
use crate::copy_protocol;
use crate::copy_protocol::{Payload, Transport, verify_receipt};
use crate::directory::Directory;
#[cfg(unix)]
use crate::endpoint::ReceiveRequest;
use crate::endpoint::{Approval, OfferRequest, SelectionOffer, read_message, write_message};
use crate::file_identity::FileIdentity;
use crate::native_file_events::{Phase, Summary};
use crate::native_files::{Context, Direction};
use crate::validate_id;
use crate::{Limits, Manifest, Receipt, invalid, require, validate_path};
#[path = "stream_operations.rs"]
pub mod operations;

use crate::selection::{self, Input, Plan};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::io::Write;
use std::io::{self, Read};
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

/// The source selection is prepared once, then retained through human review.
/// No destination connection, receiver state or source snapshot is created here.
#[cfg(unix)]
pub struct PreparedUpload {
    selection: Selection,
    context: Context,
    plan: Plan,
}

#[cfg(unix)]
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
        copy_protocol::send(
            channel,
            &mut self.selection,
            &self.context.id,
            approved_digest,
            observer,
        )
    }
}

/// One verified offer from a private read-only media source. The source stays
/// attached through review, and no destination or staging is opened here.
#[cfg(unix)]
pub struct PreparedMediaImport<S: Transport> {
    source: S,
    manifest: Manifest,
    context: Context,
    plan: Plan,
}

#[cfg(unix)]
impl<S: Transport> PreparedMediaImport<S> {
    pub fn prepare(mut source: S, selected: &[String], context: Context) -> io::Result<Self> {
        context.validate()?;
        require(
            context.direction == Direction::Import,
            "invalid_file_source",
        )?;
        selection::validate_rooted_paths(selected)?;
        let (manifest, plan) =
            request_selection(&mut source, selected, &context.id, |paths, offer| {
                plan_from_offer(paths, offer, Plan::rooted)
            })?;
        let prepared = Self {
            source,
            manifest,
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

    /// The destination has already been authorized for this exact operation
    /// and dispatched to its native Files receive endpoint by the caller.
    pub fn send<T: Transport>(
        mut self,
        destination: &mut T,
        approved_digest: &str,
        observer: &mut dyn FnMut(Phase, u64) -> io::Result<()>,
    ) -> io::Result<Receipt> {
        send_relay(
            &mut self.source,
            &self.manifest,
            &self.context.id,
            destination,
            approved_digest,
            observer,
        )
    }
}

/// A Safe Documents offer retained through review. Preparing this copy does
/// not open a destination device or send approval to the Safe.
#[cfg(unix)]
pub struct PreparedMediaExport<S: Transport> {
    source: S,
    manifest: Manifest,
    context: Context,
    plan: Plan,
}

#[cfg(unix)]
impl<S: Transport> PreparedMediaExport<S> {
    pub fn prepare(mut source: S, selected: &[String], context: Context) -> io::Result<Self> {
        context.validate()?;
        require(
            context.direction == Direction::Export
                && context.name == format!("Oblivion-{}", context.id),
            "invalid_file_destination",
        )?;
        selection::validate_paths(selected)?;
        require_document_paths(selected)?;
        let (manifest, plan) =
            request_selection(&mut source, selected, &context.id, selection_plan)?;
        let prepared = Self {
            source,
            manifest,
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

    /// The caller supplies the isolated writable guest only after approval.
    /// Receipt and source completion do not prove unmount or physical eject.
    pub fn send<T: Transport>(
        mut self,
        destination: &mut T,
        approved_digest: &str,
        observer: &mut dyn FnMut(Phase, u64) -> io::Result<()>,
    ) -> io::Result<Receipt> {
        send_relay(
            &mut self.source,
            &self.manifest,
            &self.context.id,
            destination,
            approved_digest,
            observer,
        )
    }
}

#[cfg(unix)]
fn send_relay(
    source: &mut impl Transport,
    manifest: &Manifest,
    id: &str,
    destination: &mut impl Transport,
    approved_digest: &str,
    observer: &mut dyn FnMut(Phase, u64) -> io::Result<()>,
) -> io::Result<Receipt> {
    source.check()?;
    let receipt = copy_protocol::send(
        destination,
        &mut MediaPayload {
            source,
            manifest,
            approval: Approval {
                id: id.into(),
                manifest_sha256: approved_digest.into(),
            },
        },
        id,
        approved_digest,
        observer,
    )?;
    source.check()?;
    write_message(source, &receipt)?;
    source.flush()?;
    let mut completed = [0; 7];
    source.read_exact(&mut completed)?;
    require(&completed == b"copied\n", "source_not_completed")?;
    Ok(receipt)
}

#[cfg(unix)]
struct MediaPayload<'a, S> {
    source: &'a mut S,
    manifest: &'a Manifest,
    approval: Approval,
}

#[cfg(unix)]
impl<S: Transport> copy_protocol::Source for MediaPayload<'_, S> {
    fn manifest(&self) -> &Manifest {
        self.manifest
    }

    fn write_payload<W: Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.source.check()?;
        write_message(self.source, &self.approval)?;
        self.source.flush()?;
        relay_payload(self.source, writer, self.manifest)?;
        writer.write_all(crate::END)
    }
}

/// A relay can release the terminator only after validating all offered bytes
/// and observing the source's own terminator.
#[cfg(unix)]
pub(crate) fn relay_payload(
    source: &mut impl Transport,
    writer: &mut impl Write,
    manifest: &Manifest,
) -> io::Result<()> {
    for entry in manifest.entries() {
        if let crate::Entry::File { size, sha256, .. } = entry {
            require(
                crate::copy_hash(source, writer, *size)? == *sha256,
                "content_changed",
            )?;
        }
    }
    let mut end = [0; 8];
    source.read_exact(&mut end)?;
    require(&end == crate::END, "invalid_transfer_end")?;
    source.check()
}

/// Personal ciphertext backups already own their reviewed Selection. They
/// share this exact source protocol without introducing native Files state.
pub fn send<T: Transport, S: copy_protocol::Source>(
    channel: &mut T,
    selection: &mut S,
    id: &str,
) -> io::Result<Receipt> {
    let digest = selection.manifest().sha256();
    copy_protocol::send(channel, selection, id, &digest, &mut |_, _| Ok(()))
}

#[cfg(unix)]
impl copy_protocol::Source for Selection {
    fn manifest(&self) -> &Manifest {
        Selection::manifest(self)
    }
    fn write_payload<W: Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.send_data(writer)
    }
}

/// The source offer and destination descriptor remain pinned during review.
/// The source receives no Approval and the receiver writes nothing in prepare.
pub struct PreparedDownload<T: Transport> {
    channel: T,
    manifest: Manifest,
    target: Directory,
    context: Context,
    plan: Plan,
}

impl<T: Transport> PreparedDownload<T> {
    pub fn prepare(
        mut channel: T,
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
        require_document_paths(selected)?;
        let target = Directory::open(target)?;
        target.require_controlled()?;
        target.identity()?;
        let (manifest, plan) =
            request_selection(&mut channel, selected, &context.id, selection_plan)?;
        #[cfg(windows)]
        crate::windows_destination::validate(&manifest, &context.name)?;
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
                #[cfg(windows)]
                directory.initialize_lock()?;
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
        self.channel.flush()?;
        let receipt = receive_payload(
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
        self.channel.flush()?;
        let mut completed = [0; 7];
        self.channel.read_exact(&mut completed)?;
        require(&completed == b"copied\n", "source_not_completed")?;
        Ok(receipt)
    }
}

fn receive_payload(
    reader: &mut impl Read,
    manifest: &Manifest,
    inbox: &Directory,
    id: &str,
) -> io::Result<Receipt> {
    #[cfg(unix)]
    return crate::filesystem::receive_at(reader, manifest, inbox, id);
    #[cfg(windows)]
    return crate::windows_destination::receive_at(reader, manifest, inbox, id);
}

/// A personal backup receiver owns one empty local file. The peer can offer
/// only the fixed LUKS2 payload, never a local path or an archive to extract.
pub fn download_open_file<T: Transport>(
    channel: &mut T,
    mut file: std::fs::File,
    maximum: u64,
    id: &str,
) -> io::Result<Receipt> {
    use std::io::Seek;
    validate_id(id)?;
    require(
        (32 * 1024 * 1024..=crate::MAX_ENCRYPTED_VOLUME_BYTES).contains(&maximum),
        "invalid_backup_limit",
    )?;
    crate::local_file::verify_output(&file, true)?;
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
    channel.flush()?;
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
    channel.flush()?;
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
    channel.flush()?;
    let mut copied = [0; 7];
    channel.read_exact(&mut copied)?;
    require(&copied == b"copied\n", "source_not_completed")?;
    Ok(receipt)
}

/// The local launcher chooses both roots, name and ceiling. The peer supplies
/// only one declared top-level file/directory, never an archive to extract.
#[cfg(unix)]
pub fn receive_directory<T: Transport>(
    channel: &mut T,
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
    // Reject an import that already exceeds its staging filesystem before the
    // sender starts writing to the virtio channel.
    if !guard.has_space(manifest.bytes())? {
        channel.write_all(copy_protocol::DESTINATION_FULL)?;
        channel.flush()?;
        return Err(invalid("insufficient_destination_space"));
    }
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
    source: FileIdentity,
}

/// Finish only the verified operation's publication under its inbox lock.
fn recover_directory_locked(
    guard: &Directory,
    target: &Directory,
    id: &str,
) -> io::Result<Receipt> {
    let transaction = guard.directory(id)?;
    let publication: Publication =
        serde_json::from_reader(transaction.record("publication.json", 8192)?.take(8192))
            .map_err(|_| invalid("invalid_publication"))?;
    validate_name(&publication.name)?;
    validate_path(&publication.selected)?;
    let receipt: Receipt =
        serde_json::from_reader(transaction.record("receipt.json", 1024)?.take(1024))
            .map_err(|_| invalid("invalid_receipt"))?;
    require(receipt.id == id, "invalid_receipt")?;
    let manifest = Manifest::read(
        &mut transaction.record("manifest.bin", 8 * 1024 * 1024 + 12)?,
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
            require(publication.source.matches(&file)?, "publication_changed")?;
            require(
                staged_digest(&transaction, &publication.selected)? == manifest.sha256(),
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
    let publication = Publication {
        name: name.to_owned(),
        selected: selected.to_owned(),
        source: FileIdentity::of(&file)?,
    };
    let mut record = transaction.create_file("publication.pending")?;
    serde_json::to_writer(&mut record, &publication).map_err(|_| invalid("invalid_publication"))?;
    record.sync_all()?;
    transaction.rename("publication.pending", "publication.json")?;
    transaction.sync()?;
    drop(file);
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
            require(
                target.same_device(&file)? && publication.source.matches(&file)?,
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
            let file = parent.source(selected)?;
            require(
                target.same_device(&file)? && publication.source.matches(&file)?,
                "publication_changed",
            )?;
            drop(file);
            parent.move_exclusive(selected, target, &publication.name, &publication.source)?;
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

fn staged_digest(transaction: &Directory, selected: &str) -> io::Result<String> {
    let root = transaction.directory("files")?;
    let paths = [selected.to_owned()];
    let limits = Limits {
        entries: crate::MAX_ENTRIES,
        bytes: crate::MAX_DOCUMENT_BYTES,
    };
    #[cfg(unix)]
    return Ok(Selection::prepare_at(root, &paths, limits)?
        .manifest()
        .sha256());
    #[cfg(windows)]
    return Ok(crate::windows_source::SourceSelection::manifest_at(
        &root,
        &paths,
        limits,
        &mut || Ok(()),
    )?
    .sha256());
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

fn request_selection(
    source: &mut impl Transport,
    selected: &[String],
    id: &str,
    selection_plan: fn(&[String], &SelectionOffer) -> io::Result<Plan>,
) -> io::Result<(Manifest, Plan)> {
    let limits = Limits {
        entries: crate::MAX_ENTRIES,
        bytes: crate::MAX_DOCUMENT_BYTES,
    };
    source.check()?;
    write_message(
        source,
        &OfferRequest {
            id: id.into(),
            limits,
            paths: selected.to_vec(),
        },
    )?;
    source.flush()?;
    let offer = read_message(source, 64 * 1024)?;
    let plan = selection_plan(selected, &offer)?;
    let manifest = Manifest::read(source, limits)?;
    require_collection(&manifest, &plan, &offer.directories)?;
    Ok((manifest, plan))
}

/// Both the native receiver and the media relay verify the source's path-free
/// plan against the exact requested document selection before approving bytes.
pub(crate) fn selection_plan(selected: &[String], offer: &SelectionOffer) -> io::Result<Plan> {
    require_document_paths(selected)?;
    plan_from_offer(selected, offer, Plan::new)
}

fn require_document_paths(selected: &[String]) -> io::Result<()> {
    for path in selected {
        validate_path(path)?;
        require(
            matches!(path.split('/').next(), Some("workspace" | "imports")),
            "invalid_document_selection",
        )?;
    }
    Ok(())
}

fn plan_from_offer(
    selected: &[String],
    offer: &SelectionOffer,
    plan: fn(&[Input]) -> io::Result<Plan>,
) -> io::Result<Plan> {
    require(
        offer.directories.len() == selected.len(),
        "invalid_selection_offer",
    )?;
    let plan = plan(
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
