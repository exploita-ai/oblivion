use super::{Rejection, Request, Response, State, Status};
use crate::channel::Channel;
use crate::directory::Directory;
use crate::filesystem::{finish_export_files, validate_portable_export};
use crate::{
    Entry, ExportMode, Limits, Manifest, Receipt, Selection, invalid, require, validate_id,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const LIMITS: Limits = Limits {
    entries: crate::MAX_ENTRIES,
    bytes: crate::MAX_DOCUMENT_BYTES,
};
const RECORD_LIMIT: u64 = 1024;
const MANIFEST_LIMIT: u64 = 8 * 1024 * 1024 + 12;

/// Trusted launcher authority. The peer cannot change this fixed guest role.
pub enum Authority {
    Inspect,
    Recover(ExportMode),
    Discard,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    version: u8,
    id: String,
    manifest_sha256: String,
}

pub(crate) fn operation_names(id: &str) -> (String, String) {
    let final_name = format!("Oblivion-{id}");
    let pending = format!(".{final_name}.pending");
    (final_name, pending)
}

/// Publish the expected manifest before the first payload byte. Its marker is
/// evidence for one explicit operation, never proof of an originating Safe.
pub(crate) fn write_operation(
    directory: &Directory,
    manifest: &Manifest,
    receipt: &Receipt,
) -> io::Result<()> {
    let mut manifest_file = directory.create_file("manifest.bin")?;
    manifest.write(&mut manifest_file)?;
    manifest_file.sync_all()?;
    let mut marker = directory.create_file("operation.json")?;
    let operation = Operation {
        version: 1,
        id: receipt.id.clone(),
        manifest_sha256: receipt.manifest_sha256.clone(),
    };
    serde_json::to_writer(&mut marker, &operation).map_err(|_| invalid("invalid_usb_operation"))?;
    marker.sync_all()?;
    directory.sync()
}

pub(crate) fn write_receipt(directory: &Directory, receipt: &Receipt) -> io::Result<()> {
    let mut file = directory.create_file("receipt.pending")?;
    serde_json::to_writer(&mut file, receipt).map_err(|_| invalid("invalid_usb_receipt"))?;
    file.sync_all()?;
    directory.rename_exclusive("receipt.pending", directory, "receipt.json")?;
    directory.sync()
}

pub fn serve(channel: &mut Channel, root: &Path, authority: Authority) -> io::Result<()> {
    let response = crate::endpoint::read_message::<Request>(channel, 1024)
        .and_then(|request| execute(root, &request, authority, || channel.check()))
        .unwrap_or_else(|error| Response::Rejected {
            reason: match error.to_string().as_str() {
                "usb_review_changed" => Rejection::ReviewChanged,
                "usb_operation_not_authorized" => Rejection::NotAuthorized,
                _ => Rejection::Unavailable,
            },
        });
    crate::endpoint::write_message(channel, &response)
}

/// Inspect or mutate one independently authorized mount. No wire field can
/// select a mount, directory component, or a different guest action.
pub fn execute(
    root: &Path,
    request: &Request,
    authority: Authority,
    mut check: impl FnMut() -> io::Result<()>,
) -> io::Result<Response> {
    request.validate()?;
    require(
        matches!(
            (&authority, request),
            (
                Authority::Inspect,
                Request::Inventory { .. } | Request::Status { .. }
            ) | (Authority::Recover(_), Request::Recover { .. })
                | (Authority::Discard, Request::Discard { .. })
        ),
        "usb_operation_not_authorized",
    )?;
    check()?;
    let root = Directory::open(root)?;
    root.lock()?;
    let response = match request {
        Request::Inventory { after, limit } => {
            inventory(&root, after.as_deref(), *limit, &mut check)?
        }
        Request::Status { id } => Response::Status {
            status: observe(&root, id, &mut check)?.status(id),
        },
        Request::Recover { id, review_sha256 } | Request::Discard { id, review_sha256 } => {
            let Observed::Staged(staged) = observe(&root, id, &mut check)? else {
                return Err(invalid("usb_staging_unavailable"));
            };
            require(staged.review == *review_sha256, "usb_review_changed")?;
            let (name, pending) = operation_names(id);
            require(
                optional_directory(&root, &name)?.is_none(),
                "usb_publication_exists",
            )?;
            let current = root.directory(&pending)?.metadata()?;
            let reviewed = staged.directory.metadata()?;
            require(
                (current.dev(), current.ino()) == (reviewed.dev(), reviewed.ino()),
                "usb_staging_changed",
            )?;
            check()?;
            let status = if let Authority::Recover(mode) = authority {
                require(staged.ready, "usb_staging_incomplete")?;
                if mode != ExportMode::Posix {
                    validate_portable_export(&staged.manifest, mode)?;
                }
                finish_export_files(&staged.directory, &staged.manifest, mode, &mut check)?;
                if !staged.receipt_exists {
                    if let Some(file) = staged.pending_receipt {
                        staged.directory.remove_file("receipt.pending", &file)?;
                    }
                    write_receipt(&staged.directory, &staged.receipt)?;
                }
                check()?;
                root.rename_exclusive(&pending, &root, &name)?;
                root.sync()?;
                status(id, State::Published, Some(staged.receipt), None)
            } else {
                // A partial discard remains inspectable until the payload and
                // its completion evidence have been removed and synced.
                if let Some(file) = staged.pending_receipt {
                    staged.directory.remove_file("receipt.pending", &file)?;
                }
                if staged.receipt_exists {
                    let file = staged.directory.record("receipt.json", RECORD_LIMIT)?;
                    staged.directory.remove_file("receipt.json", &file)?;
                }
                if let Some(tree) = staged.tree {
                    staged.directory.remove_directory(tree)?;
                }
                staged.directory.sync()?;
                check()?;
                root.remove_directory(&pending)?;
                root.sync()?;
                status(id, State::Discarded, None, None)
            };
            Response::Status { status }
        }
    };
    response.validate(request)?;
    Ok(response)
}

fn inventory(
    root: &Directory,
    after: Option<&str>,
    limit: usize,
    check: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<Response> {
    let mut ids = BTreeSet::new();
    root.visit(|entry| {
        check()?;
        let Ok(name) = entry.to_str() else {
            return Ok(());
        };
        let candidate = name.strip_prefix("Oblivion-").or_else(|| {
            name.strip_prefix(".Oblivion-")
                .and_then(|rest| rest.strip_suffix(".pending"))
        });
        if let Some(id) =
            candidate.filter(|id| validate_id(id).is_ok() && after.is_none_or(|after| *id > after))
        {
            ids.insert(id.to_owned());
            if ids.len() > limit + 1 {
                ids.pop_last();
            }
        }
        Ok(())
    })?;
    // Candidate names are not verification. Only a fresh exact-ID status may
    // read the marker/manifest and authorize an operation on this medium.
    let has_more = ids.len() > limit;
    let operations = ids.into_iter().take(limit).collect::<Vec<_>>();
    let next_cursor = if has_more {
        operations.last().cloned()
    } else {
        None
    };
    Ok(Response::Inventory {
        operations,
        next_cursor,
    })
}

enum Observed {
    Unknown,
    Staged(Stage),
    Published(Receipt),
}

struct Stage {
    directory: Directory,
    manifest: Manifest,
    review: String,
    receipt: Receipt,
    ready: bool,
    tree: Option<&'static str>,
    receipt_exists: bool,
    pending_receipt: Option<File>,
}

impl Observed {
    fn status(self, id: &str) -> Status {
        match self {
            Self::Unknown => status(id, State::Unknown, None, None),
            Self::Published(receipt) => status(id, State::Published, Some(receipt), None),
            Self::Staged(stage) if stage.ready => {
                status(id, State::Ready, Some(stage.receipt), Some(stage.review))
            }
            Self::Staged(stage) => status(id, State::Incomplete, None, Some(stage.review)),
        }
    }
}

fn status(
    id: &str,
    state: State,
    receipt: Option<Receipt>,
    review_sha256: Option<String>,
) -> Status {
    Status {
        operation_id: id.to_owned(),
        state,
        receipt,
        review_sha256,
    }
}

fn observe(
    root: &Directory,
    id: &str,
    check: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<Observed> {
    let (name, pending) = operation_names(id);
    let result = (|| {
        let final_dir = optional_directory(root, &name)?;
        let staged = optional_directory(root, &pending)?;
        match (final_dir, staged) {
            (Some(directory), None) => inspect(directory, id, true, check),
            (None, Some(directory)) => inspect(directory, id, false, check),
            _ => Ok(Observed::Unknown),
        }
    })();
    match result {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::InvalidData
                    | io::ErrorKind::NotFound
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::NotADirectory
            ) || error.raw_os_error() == Some(libc::ELOOP) =>
        {
            Ok(Observed::Unknown)
        }
        result => result,
    }
}

fn optional_directory(root: &Directory, name: &str) -> io::Result<Option<Directory>> {
    match root.directory(name) {
        Ok(directory) => Ok(Some(directory)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn inspect(
    directory: Directory,
    id: &str,
    published: bool,
    check: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<Observed> {
    let names = directory.names(5)?;
    require(
        names.iter().all(|name| {
            matches!(
                name.as_str(),
                "manifest.bin"
                    | "operation.json"
                    | "files"
                    | "pending"
                    | "receipt.json"
                    | "receipt.pending"
            )
        }),
        "unknown_usb_staging_entries",
    )?;
    let contains = |name: &str| names.iter().any(|value| value == name);
    let operation: Operation = serde_json::from_reader(
        directory
            .record("operation.json", RECORD_LIMIT)?
            .take(RECORD_LIMIT),
    )
    .map_err(|_| invalid("invalid_usb_operation"))?;
    require(
        operation.version == 1 && operation.id == id,
        "usb_operation_changed",
    )?;
    let mut reader = directory.record("manifest.bin", MANIFEST_LIMIT)?;
    let manifest = Manifest::read(&mut reader, LIMITS)?;
    require(
        reader.read(&mut [0])? == 0 && operation.manifest_sha256 == manifest.sha256(),
        "invalid_usb_manifest",
    )?;
    let receipt = Receipt {
        id: id.to_owned(),
        manifest_sha256: operation.manifest_sha256,
        entries: manifest.entries().len(),
        bytes: manifest.bytes(),
    };
    let receipt_exists = contains("receipt.json");
    if receipt_exists {
        let recorded: Receipt = serde_json::from_reader(
            directory
                .record("receipt.json", RECORD_LIMIT)?
                .take(RECORD_LIMIT),
        )
        .map_err(|_| invalid("invalid_usb_receipt"))?;
        crate::copy_protocol::verify_receipt(&recorded, id, &manifest)?;
    }
    let (pending_receipt, pending_digest) = if contains("receipt.pending") {
        require(
            !published && !receipt_exists && contains("files"),
            "invalid_usb_receipt",
        )?;
        let file = directory.record("receipt.pending", RECORD_LIMIT)?;
        let mut bytes = Vec::new();
        (&file).take(RECORD_LIMIT + 1).read_to_end(&mut bytes)?;
        require(bytes.len() <= RECORD_LIMIT as usize, "invalid_usb_receipt")?;
        (Some(file), Some(format!("{:x}", Sha256::digest(bytes))))
    } else {
        (None, None)
    };
    let tree = match (contains("files"), contains("pending")) {
        (true, false) => Some("files"),
        (false, true) => Some("pending"),
        (false, false) if !receipt_exists => None,
        _ => return Err(invalid("invalid_usb_staging_tree")),
    };
    let (complete, contents) = if let Some(tree) = tree {
        verify_tree(&directory.directory(tree)?, &manifest, check)?
    } else {
        (false, None)
    };
    let ready = tree == Some("files") && complete;
    if published {
        return Ok(if ready && receipt_exists {
            Observed::Published(receipt)
        } else {
            Observed::Unknown
        });
    }
    // Files is renamed into place only after END and content verification.
    // Pending remains incomplete even if its bytes happen to match.
    let observation = serde_json::to_vec(&(
        1,
        id,
        &receipt.manifest_sha256,
        tree,
        contents,
        ready,
        receipt_exists,
        pending_digest,
    ))
    .map_err(|_| invalid("invalid_usb_operation"))?;
    let review = format!("{:x}", Sha256::digest(observation));
    Ok(Observed::Staged(Stage {
        directory,
        manifest,
        review,
        receipt,
        ready,
        tree,
        receipt_exists,
        pending_receipt,
    }))
}

fn verify_tree(
    root: &Directory,
    expected: &Manifest,
    check: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<(bool, Option<String>)> {
    let names = root.names(expected.entries().len())?;
    if names.is_empty() {
        return Ok((false, None));
    }
    let limits = Limits {
        entries: expected.entries().len(),
        bytes: expected.bytes(),
    };
    let actual = Selection::prepare_checked(root.clone()?, &names, limits, check)?;
    let actual = actual.manifest();
    let expected_by_path = expected
        .entries()
        .iter()
        .map(|entry| (entry.path(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut complete = actual.entries().len() == expected.entries().len();
    for entry in actual.entries() {
        match (entry, expected_by_path.get(entry.path())) {
            (Entry::Directory { .. }, Some(Entry::Directory { .. })) => (),
            (
                Entry::File { size, sha256, .. },
                Some(Entry::File {
                    size: expected_size,
                    sha256: expected_hash,
                    ..
                }),
            ) if size <= expected_size => {
                complete &= size == expected_size && sha256 == expected_hash;
            }
            _ => return Err(invalid("unexpected_usb_staging_entry")),
        }
    }
    Ok((complete, Some(actual.sha256())))
}
