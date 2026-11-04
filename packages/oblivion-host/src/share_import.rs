//! Unpublished portable imports. A whole directory is the publication unit;
//! no destination Safe exists in the visible catalog before its final rename.
use crate::storage::{Error, Result, require, trusted_file, validate_id};
use oblivion_host::{autolock::Opening, sharing};
use oblivion_share::{Package, Safe};
use oblivion_transfer::Receipt;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const LIMIT: usize = 8 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;

pub(crate) fn request<T: serde::de::DeserializeOwned>(limit: usize) -> Result<T> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::stdin().take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|_| Error("invalid_share_import_request"))?;
    require(bytes.len() <= limit, "invalid_share_import_request")?;
    serde_json::from_slice(&bytes).map_err(|_| Error("invalid_share_import_request"))
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Progress {
    Awaiting,
    Receiving { opening: Opening, request_id: String },
    Ready { receipt: Receipt },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Destination {
    pub package_id: String,
    pub safe_id: String,
    pub title: String,
    pub parent: Option<String>,
    pub family_root: String,
    pub mib: u64,
    pub progress: Progress,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Batch {
    pub version: u8,
    pub transaction: String,
    pub nonce: String,
    pub host_opening: String,
    pub metadata_sha256: String,
    pub package: Package,
    pub destinations: Vec<Destination>,
    pub families: BTreeMap<String, Vec<u8>>,
}

pub(crate) struct Imported {
    pub id: String,
    pub parent: Option<String>,
    pub source: Safe,
    pub directory: PathBuf,
}

impl Batch {
    pub(crate) fn started(&self) -> sharing::Begun {
        sharing::Begun { transaction: self.transaction.clone(), nonce: self.nonce.clone(), destinations: self.choices() }
    }

    pub(crate) fn choices(&self) -> Vec<sharing::Destination> {
        self.destinations.iter().map(|destination| sharing::Destination {
            package_id: destination.package_id.clone(), safe_id: destination.safe_id.clone(),
            title: destination.title.clone(), parent: destination.parent.clone(), mib: destination.mib,
        }).collect()
    }

    pub(crate) fn new(package: Package, metadata_sha256: String, mut titles: BTreeSet<String>, host_opening: String) -> Result<Self> {
        package.validate().map_err(|_| Error("invalid_share_package"))?;
        let identities: BTreeMap<_, _> = package.safes.iter()
            .map(|safe| Ok((safe.id.clone(), crate::storage::random_id()?)))
            .collect::<Result<_>>()?;
        let sources: BTreeMap<_, _> = package.safes.iter().map(|safe| (safe.id.as_str(), safe)).collect();
        let destinations = package.safes.iter().map(|safe| {
            oblivion_host::session_title::validate(&safe.title).map_err(|_| Error("share_import_title_invalid"))?;
            let mut title = safe.title.clone();
            let mut number = 1;
            while titles.contains(&title) {
                let suffix = if number == 1 { " (imported)".to_owned() } else { format!(" (imported {number})") };
                title = safe.title.chars().take(80 - suffix.chars().count()).collect::<String>();
                while title.len() + suffix.len() > 256 { title.pop(); }
                title.push_str(&suffix);
                number += 1;
            }
            titles.insert(title.clone());
            let mut root = safe;
            while let Some(parent) = &root.parent { root = sources[parent.as_str()]; }
            Ok(Destination {
            package_id: safe.id.clone(), safe_id: identities[&safe.id].clone(),
            title,
            parent: safe.parent.as_ref().map(|parent| identities[parent].clone()),
            family_root: identities[&root.id].clone(),
            mib: capacity(safe)?, progress: Progress::Awaiting,
        })}).collect::<Result<_>>()?;
        let batch = Self { version: 1, transaction: crate::storage::random_id()?,
            nonce: crate::storage::random_id()?, host_opening, metadata_sha256, package, destinations, families: BTreeMap::new() };
        batch.validate()?;
        Ok(batch)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_id(&self.transaction)?;
        validate_id(&self.nonce)?;
        validate_id(&self.host_opening)?;
        require(self.version == 1, "invalid_share_import")?;
        require(self.metadata_sha256.len() == 64 && self.metadata_sha256.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "invalid_share_hash")?;
        self.package.validate().map_err(|_| Error("invalid_share_package"))?;
        require(self.destinations.len() == self.package.safes.len(), "invalid_share_import")?;
        let mut identities = BTreeMap::new();
        let mut destinations = BTreeSet::new();
        let mut titles = BTreeSet::new();
        for (safe, destination) in self.package.safes.iter().zip(&self.destinations) {
            validate_id(&destination.safe_id)?;
            oblivion_host::session_title::validate(&destination.title).map_err(|_| Error("share_import_title_invalid"))?;
            require(destination.package_id == safe.id && destination.mib == capacity(safe)?
                && destinations.insert(&destination.safe_id) && titles.insert(&destination.title)
                && !self.package.safes.iter().any(|source| source.id == destination.safe_id), "invalid_share_import")?;
            identities.insert(safe.id.as_str(), destination.safe_id.as_str());
            match &destination.progress {
                Progress::Awaiting => {}
                Progress::Receiving { opening, request_id } => {
                    validate_id(&opening.nonce)?;
                    validate_id(request_id)?;
                    require(opening.safe_id == destination.safe_id, "invalid_share_import")?;
                }
                Progress::Ready { receipt } => validate_receipt(receipt, safe)?,
            }
        }
        for (safe, destination) in self.package.safes.iter().zip(&self.destinations) {
            require(destination.parent.as_deref() == safe.parent.as_deref().map(|parent| identities[parent]), "invalid_share_import")?;
            let mut root = safe;
            let mut depth = 0;
            while let Some(parent) = &root.parent {
                root = self.package.safes.iter().find(|source| source.id == *parent).ok_or(Error("invalid_share_import"))?;
                depth += 1;
                require(depth <= 4, "share_import_depth_limit")?;
            }
            require(destination.family_root == identities[root.id.as_str()], "invalid_share_import")?;
            require(matches!(destination.progress, Progress::Awaiting) || self.families.contains_key(&destination.family_root), "invalid_share_import")?;
        }
        let mut family_ids = BTreeSet::new();
        for (root, bytes) in &self.families {
            require(self.destinations.iter().any(|destination| destination.family_root == *root), "invalid_share_import")?;
            let descriptor = oblivion_host::family::Descriptor::decode(bytes).map_err(Error)?;
            require(family_ids.insert(descriptor.family_id().to_owned()), "invalid_share_import")?;
        }
        require(self.destinations.iter().filter(|destination| matches!(destination.progress, Progress::Receiving { .. })).count() <= 1,
            "invalid_share_import")
    }

    pub(crate) fn authorize(&self, nonce: &str) -> Result<()> {
        require(self.nonce == nonce, "share_import_changed")?;
        require(crate::storage::share_import_host()?.as_deref() == Some(self.host_opening.as_str()), "share_import_authority_expired")
    }

    pub(crate) fn destination(&self, package_id: &str) -> Result<&Destination> {
        self.destinations.iter().find(|destination| destination.package_id == package_id).ok_or(Error("share_import_safe_not_found"))
    }

    pub(crate) fn receiving(&mut self, package_id: &str, opening: Opening, request_id: String) -> Result<()> {
        validate_id(&request_id)?;
        require(!self.destinations.iter().any(|destination| matches!(destination.progress, Progress::Receiving { .. })), "share_import_busy")?;
        let destination = self.destinations.iter_mut().find(|destination| destination.package_id == package_id)
            .ok_or(Error("share_import_safe_not_found"))?;
        require(matches!(destination.progress, Progress::Awaiting) && opening.safe_id == destination.safe_id, "share_import_changed")?;
        destination.progress = Progress::Receiving { opening, request_id };
        self.validate()
    }

    /// Called only after its maintenance VM and block mapping have stopped.
    pub(crate) fn ready(&mut self, package_id: &str, receipt: Receipt) -> Result<()> {
        let index = self.destinations.iter().position(|destination| destination.package_id == package_id)
            .ok_or(Error("share_import_safe_not_found"))?;
        let Progress::Receiving { request_id, .. } = &self.destinations[index].progress else { return Err(Error("share_import_changed")) };
        require(receipt.id == *request_id, "invalid_share_receipt")?;
        validate_receipt(&receipt, &self.package.safes[index])?;
        self.destinations[index].progress = Progress::Ready { receipt };
        Ok(())
    }

    pub(crate) fn ready_to_publish(&self, metadata_sha256: &str) -> Result<()> {
        require(self.metadata_sha256 == metadata_sha256 && self.destinations.iter().all(|destination| matches!(destination.progress, Progress::Ready { .. })),
            "share_import_not_verified")
    }

    pub(crate) fn bytes(&self) -> u64 { self.destinations.iter().map(|destination| destination.mib * MIB).sum() }
}

fn validate_receipt(receipt: &Receipt, safe: &Safe) -> Result<()> {
    validate_id(&receipt.id)?;
    require(receipt.manifest_sha256 == safe.contents_sha256 && receipt.entries == safe.entries && receipt.bytes == safe.bytes,
        "invalid_share_receipt")
}

fn capacity(safe: &Safe) -> Result<u64> {
    // Files move within their new filesystem; only the portable catalog needs
    // temporary input plus fresh SQLite rows. Keep explicit space for both.
    let mib = safe.bytes.div_ceil(MIB).saturating_add(safe.bytes.div_ceil(10 * MIB)).saturating_add(512).max(512);
    oblivion_host::volume::size(mib).map_err(Error)?;
    Ok(mib)
}

pub(crate) struct Repository(PathBuf);

impl Repository {
    pub(crate) fn new(root: &Path) -> Self { Self(root.to_path_buf()) }
    pub(crate) fn pending(&self, transaction: &str) -> PathBuf { self.0.join("share-imports").join(transaction) }
    fn published(&self, transaction: &str) -> PathBuf { self.0.join("imported").join(transaction) }
    pub(crate) fn volume(&self, batch: &Batch, destination: &Destination) -> PathBuf {
        self.pending(&batch.transaction).join("safes").join(&destination.safe_id).join("volume.luks")
    }

    pub(crate) fn imported(&self) -> Result<Vec<Imported>> {
        let mut result = Vec::new();
        let mut ids = BTreeSet::new();
        for batch in self.transactions(true)? {
            for (source, destination) in batch.package.safes.into_iter().zip(batch.destinations) {
                require(ids.insert(destination.safe_id.clone()), "invalid_share_import")?;
                result.push(Imported { id: destination.safe_id.clone(), parent: destination.parent, source,
                    directory: self.published(&batch.transaction).join("safes").join(destination.safe_id) });
            }
        }
        Ok(result)
    }

    pub(crate) fn status(&self) -> Result<Vec<sharing::Status>> {
        let host = crate::storage::share_import_host()?;
        let mut result = Vec::new();
        for published in [false, true] {
            let directory = self.0.join(if published { "imported" } else { "share-imports" });
            if !directory.try_exists().map_err(|_| Error("share_import_unavailable"))? { continue }
            private_directory(&directory, false)?;
            for entry in fs::read_dir(&directory).map_err(|_| Error("share_import_unavailable"))? {
                require(result.len() < 1024, "share_import_transaction_limit")?;
                let entry = entry.map_err(|_| Error("share_import_unavailable"))?;
                let transaction = entry.file_name().into_string().map_err(|_| Error("invalid_share_import"))?;
                validate_id(&transaction)?;
                let batch = match read_batch(&entry.path(), &transaction) {
                    Ok(batch) => batch,
                    Err(_) if !published => {
                        private_directory(&entry.path(), false)?;
                        result.push(sharing::Status { transaction, package_id: None, metadata_sha256: None,
                            outcome: sharing::Outcome::RecoveryRequired, safes: 0, ready: 0, openings: Vec::new() });
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                if published { batch.ready_to_publish(&batch.metadata_sha256)?; }
                let outcome = if published { sharing::Outcome::Committed }
                    else if host.as_deref() == Some(batch.host_opening.as_str()) { sharing::Outcome::Pending }
                    else { sharing::Outcome::RecoveryRequired };
                result.push(sharing::Status { transaction: batch.transaction, package_id: Some(batch.package.id),
                    metadata_sha256: Some(batch.metadata_sha256), outcome,
                    safes: batch.destinations.len(),
                    ready: batch.destinations.iter().filter(|destination| matches!(destination.progress, Progress::Ready { .. })).count(),
                    openings: batch.destinations.iter().filter_map(|destination| match &destination.progress {
                        Progress::Receiving { opening, .. } => Some(opening.clone()), _ => None,
                    }).collect(),
                });
            }
        }
        Ok(result)
    }

    /// An incomplete first journal precedes every volume allocation. Recovery
    /// may discard root-owned metadata only; any directory/data refuses it.
    pub(crate) fn discard_initial_metadata(&self, transaction: &str) -> Result<()> {
        validate_id(transaction)?;
        require(!self.published(transaction).try_exists().map_err(|_| Error("share_import_unavailable"))?, "share_import_committed")?;
        let path = self.pending(transaction);
        private_directory(&path, false)?;
        let mut files = Vec::new();
        for entry in fs::read_dir(&path).map_err(|_| Error("share_import_cleanup_required"))? {
            let entry = entry.map_err(|_| Error("share_import_cleanup_required"))?;
            require(matches!(entry.file_name().to_str(), Some("batch.pending" | "batch.json")), "share_import_cleanup_required")?;
            trusted_file(&entry.path())?;
            files.push(entry.path());
        }
        for file in files { fs::remove_file(file).map_err(|_| Error("share_import_cleanup_required"))?; }
        fs::remove_dir(path).map_err(|_| Error("share_import_cleanup_required"))?;
        sync(&self.0.join("share-imports"))
    }

    pub(crate) fn create(&self, batch: &Batch) -> Result<()> {
        batch.validate()?;
        private_directory(&self.0.join("share-imports"), true)?;
        private_directory(&self.0.join("imported"), true)?;
        require(self.transactions(false)?.is_empty(), "share_import_pending")?;
        let path = self.pending(&batch.transaction);
        fs::DirBuilder::new().mode(0o700).create(&path).map_err(|_| Error("share_import_create_failed"))?;
        self.write(batch)?;
        private_directory(&path.join("safes"), true)?;
        for destination in &batch.destinations {
            let safe = path.join("safes").join(&destination.safe_id);
            private_directory(&safe, true)?;
            private_directory(&safe.join("profile"), true)?;
            write_new(&safe.join("title"), destination.title.as_bytes())?;
            write_new(&safe.join("profile/access.json"), b"\"offline\"")?;
            sync(&safe.join("profile"))?;
            sync(&safe)?;
        }
        sync(&path.join("safes"))
    }

    pub(crate) fn read(&self, transaction: &str) -> Result<Batch> {
        validate_id(transaction)?;
        require(!self.published(transaction).try_exists().map_err(|_| Error("share_import_unavailable"))?, "share_import_committed")?;
        read_batch(&self.pending(transaction), transaction)
    }

    pub(crate) fn write(&self, batch: &Batch) -> Result<()> {
        batch.validate()?;
        let directory = self.pending(&batch.transaction);
        private_directory(&directory, false)?;
        let bytes = serde_json::to_vec(batch).map_err(|_| Error("encode_failed"))?;
        require(bytes.len() <= LIMIT, "share_import_metadata_limit")?;
        let pending = directory.join("batch.pending");
        if pending.try_exists().map_err(|_| Error("share_import_unavailable"))? { trusted_file(&pending)?; }
        let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&pending).map_err(|_| Error("share_import_write_failed"))?;
        file.write_all(&bytes).and_then(|()| file.sync_all()).map_err(|_| Error("share_import_write_failed"))?;
        fs::rename(pending, directory.join("batch.json")).map_err(|_| Error("share_import_write_failed"))?;
        sync(&directory)
    }

    pub(crate) fn commit(&self, batch: &Batch, metadata_sha256: &str) -> Result<()> {
        batch.ready_to_publish(metadata_sha256)?;
        for destination in &batch.destinations {
            let volume = self.volume(batch, destination);
            let file = trusted_file(&volume)?;
            require(file.metadata().map_err(|_| Error("share_import_unavailable"))?.len() == destination.mib * MIB, "share_import_changed")?;
            file.sync_all().map_err(|_| Error("sync_failed"))?;
            let safe = volume.parent().ok_or(Error("invalid_path"))?;
            sync(&safe.join("profile"))?;
            sync(safe)?;
        }
        self.write(batch)?;
        sync(&self.pending(&batch.transaction).join("safes"))?;
        let source = CString::new(self.pending(&batch.transaction).as_os_str().as_encoded_bytes()).map_err(|_| Error("invalid_path"))?;
        let target = CString::new(self.published(&batch.transaction).as_os_str().as_encoded_bytes()).map_err(|_| Error("invalid_path"))?;
        require(unsafe { libc::renameat2(libc::AT_FDCWD, source.as_ptr(), libc::AT_FDCWD, target.as_ptr(), libc::RENAME_NOREPLACE) } == 0,
            "share_import_publish_failed")?;
        sync(&self.0.join("imported"))?;
        sync(&self.0.join("share-imports"))
    }

    pub(crate) fn transactions(&self, published: bool) -> Result<Vec<Batch>> {
        let directory = self.0.join(if published { "imported" } else { "share-imports" });
        if !directory.try_exists().map_err(|_| Error("share_import_unavailable"))? { return Ok(Vec::new()) }
        private_directory(&directory, false)?;
        let mut result = Vec::new();
        let mut safes = 0;
        for entry in fs::read_dir(directory).map_err(|_| Error("share_import_unavailable"))? {
            require(result.len() < 1024, "share_import_transaction_limit")?;
            let entry = entry.map_err(|_| Error("share_import_unavailable"))?;
            let id = entry.file_name().into_string().map_err(|_| Error("invalid_share_import"))?;
            validate_id(&id)?;
            let batch = read_batch(&entry.path(), &id)?;
            if published { batch.ready_to_publish(&batch.metadata_sha256)?; }
            safes += batch.destinations.len();
            require(safes <= oblivion_share::manifest::MAX_SAFES, "share_import_safe_limit")?;
            result.push(batch);
        }
        Ok(result)
    }

    /// Storage must first verify every recorded VM/mapping owner stopped.
    pub(crate) fn discard(&self, transaction: &str) -> Result<()> {
        let batch = self.read(transaction)?;
        let path = self.pending(&batch.transaction);
        for destination in &batch.destinations {
            let safe = path.join("safes").join(&destination.safe_id);
            if !safe.try_exists().map_err(|_| Error("share_import_cleanup_required"))? { continue }
            private_directory(&safe, false)?;
            for entry in fs::read_dir(&safe).map_err(|_| Error("share_import_cleanup_required"))? {
                let entry = entry.map_err(|_| Error("share_import_cleanup_required"))?;
                match entry.file_name().to_str() {
                    Some("volume.luks" | "title") => { trusted_file(&entry.path())?; fs::remove_file(entry.path()).map_err(|_| Error("share_import_cleanup_required"))?; }
                    Some("profile") => {
                        private_directory(&entry.path(), false)?;
                        let access = entry.path().join("access.json");
                        if access.try_exists().map_err(|_| Error("share_import_cleanup_required"))? {
                            trusted_file(&access)?; fs::remove_file(access).map_err(|_| Error("share_import_cleanup_required"))?;
                        }
                        fs::remove_dir(entry.path()).map_err(|_| Error("share_import_cleanup_required"))?;
                    }
                    _ => return Err(Error("share_import_cleanup_required")),
                }
            }
            fs::remove_dir(safe).map_err(|_| Error("share_import_cleanup_required"))?;
        }
        if path.join("safes").try_exists().map_err(|_| Error("share_import_cleanup_required"))? {
            fs::remove_dir(path.join("safes")).map_err(|_| Error("share_import_cleanup_required"))?;
        }
        for name in ["batch.pending", "batch.json"] {
            let file = path.join(name);
            if file.try_exists().map_err(|_| Error("share_import_cleanup_required"))? {
                trusted_file(&file)?; fs::remove_file(file).map_err(|_| Error("share_import_cleanup_required"))?;
            }
        }
        fs::remove_dir(path).map_err(|_| Error("share_import_cleanup_required"))?;
        sync(&self.0.join("share-imports"))
    }
}

fn read_batch(directory: &Path, transaction: &str) -> Result<Batch> {
    private_directory(directory, false)?;
    let mut bytes = Vec::new();
    trusted_file(&directory.join("batch.json"))?.take(LIMIT as u64 + 1).read_to_end(&mut bytes)
        .map_err(|_| Error("share_import_unavailable"))?;
    require(bytes.len() <= LIMIT, "share_import_metadata_limit")?;
    let batch: Batch = serde_json::from_slice(&bytes).map_err(|_| Error("invalid_share_import"))?;
    batch.validate()?;
    require(batch.transaction == transaction, "invalid_share_import")?;
    Ok(batch)
}

fn private_directory(path: &Path, create: bool) -> Result<()> {
    if create { fs::DirBuilder::new().recursive(true).mode(0o700).create(path).map_err(|_| Error("share_import_unavailable"))?; }
    let info = fs::symlink_metadata(path).map_err(|_| Error("share_import_unavailable"))?;
    require(info.is_dir() && info.uid() == 0 && info.mode() & 0o077 == 0, "unsafe_share_import")
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path).map_err(|_| Error("share_import_write_failed"))?;
    file.write_all(bytes).and_then(|()| file.sync_all()).map_err(|_| Error("share_import_write_failed"))
}

fn sync(path: &Path) -> Result<()> {
    File::open(path).and_then(|file| file.sync_all()).map_err(|_| Error("sync_failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checked<T>(result: Result<T>) -> T { result.unwrap_or_else(|error| panic!("{}", error.0)) }

    fn package() -> Package {
        let safe = |id: u8, parent: Option<u8>| Safe {
            id: format!("{id:032x}"), title: "Research".into(), parent: parent.map(|value| format!("{value:032x}")),
            provenance: None, policy: oblivion_share::Policy::OpenInternet, required_proxy: Some("Private proxy label".into()),
            contents_sha256: "a".repeat(64), entries: 1, bytes: 0,
        };
        Package { format: "oblivion-share".into(), version: 1, id: "4".repeat(32),
            safes: vec![safe(1, None), safe(2, Some(1)), safe(3, None)], settings: None }
    }

    fn batch() -> Batch {
        checked(Batch::new(package(), "b".repeat(64), ["Research".into()].into_iter().collect(), "8".repeat(32)))
    }

    // These public descriptor bytes exercise metadata/state grammar only.
    // No test treats them as authenticated family credentials.
    fn descriptor(root: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"version":1,"family_id":root,
            "kdf":{"algorithm":"argon2id","version":19,"memory_kib":262144,"passes":4,"lanes":1},
            "salt":vec![0;16],"nonce":vec![0;24],"wrapped_capability":vec![0;48]})).unwrap()
    }

    fn receive(batch: &mut Batch, index: usize) {
        let destination = &batch.destinations[index];
        let package_id = destination.package_id.clone();
        batch.families.entry(destination.family_root.clone()).or_insert_with(|| descriptor(&destination.family_root));
        let opening = Opening { slot: Default::default(), safe_id: destination.safe_id.clone(), nonce: format!("{:032x}", index + 100) };
        let request_id = format!("{:032x}", index + 200);
        checked(batch.receiving(&package_id, opening, request_id.clone()));
        let source = &batch.package.safes[index];
        checked(batch.ready(&package_id, Receipt { id: request_id, manifest_sha256: source.contents_sha256.clone(), entries: source.entries, bytes: source.bytes }));
    }

    #[test]
    fn remaps_new_ids_and_preserves_family_roots_without_copying_source_identity_or_auth() {
        let batch = batch();
        assert_eq!(batch.destinations[1].parent.as_deref(), Some(batch.destinations[0].safe_id.as_str()));
        assert_eq!(batch.destinations[0].family_root, batch.destinations[1].family_root);
        assert_ne!(batch.destinations[0].family_root, batch.destinations[2].family_root);
        assert!(batch.destinations.iter().all(|destination| !batch.package.safes.iter().any(|source| source.id == destination.safe_id)));
        assert_eq!(batch.destinations.iter().map(|destination| destination.title.as_str()).collect::<Vec<_>>(),
            ["Research (imported)", "Research (imported 2)", "Research (imported 3)"]);
        assert!(batch.families.is_empty());
        assert!(batch.authorize(&"0".repeat(32)).is_err());
        let mut too_long = package();
        too_long.safes[0].title = "x".repeat(81);
        assert!(Batch::new(too_long, "b".repeat(64), BTreeSet::new(), "8".repeat(32)).is_err());
    }

    #[test]
    fn partial_receipts_and_wrong_final_metadata_cannot_authorize_publication() {
        let mut batch = batch();
        receive(&mut batch, 0);
        assert!(batch.ready_to_publish(&"b".repeat(64)).is_err());
        receive(&mut batch, 1);
        receive(&mut batch, 2);
        checked(batch.validate());
        assert!(batch.ready_to_publish(&"c".repeat(64)).is_err());
        checked(batch.ready_to_publish(&"b".repeat(64)));
        let mut tampered: serde_json::Value = serde_json::from_slice(&serde_json::to_vec(&batch).unwrap()).unwrap();
        tampered["destinations"][1]["parent"] = serde_json::Value::String("f".repeat(32));
        assert!(serde_json::from_value::<Batch>(tampered).is_ok_and(|batch| batch.validate().is_err()));
    }

    #[test]
    #[ignore = "requires isolated root-owned tmpfs /run; no production state"]
    fn retained_request_nonce_expires_at_the_real_host_opening_authorization_boundary() {
        assert_eq!(std::env::var("OBLIVION_SHARE_IMPORT_AUTH_TEST").as_deref(), Ok("1"));
        assert_eq!(unsafe { libc::geteuid() }, 0);
        fs::DirBuilder::new().mode(0o700).create("/run/oblivion").unwrap();
        let marker = Path::new("/run/oblivion/host-opening");
        checked(write_new(marker, "8".repeat(32).as_bytes()));
        let root = Path::new("/run/oblivion/import-fixture");
        checked(private_directory(root, true));
        let repository = Repository::new(root);
        let batch = batch();
        checked(repository.create(&batch));
        let request_nonce = batch.nonce.clone();
        checked(repository.read(&batch.transaction)).authorize(&request_nonce).unwrap_or_else(|error| panic!("{}", error.0));
        assert!(matches!(checked(repository.status())[0].outcome, sharing::Outcome::Pending));
        // Lock removes the trusted RAM identity while the encrypted pending
        // journal and the old CLI's request nonce remain unchanged.
        fs::remove_file(marker).unwrap();
        assert!(matches!(checked(repository.read(&batch.transaction)).authorize(&request_nonce), Err(Error("share_import_authority_expired"))));
        // Unlock/restart creates another identity; the old persisted nonce
        // and even the old password cannot make the old batch resumable.
        checked(write_new(marker, "9".repeat(32).as_bytes()));
        assert!(matches!(checked(repository.read(&batch.transaction)).authorize(&request_nonce), Err(Error("share_import_authority_expired"))));
        let status = checked(repository.status());
        assert!(matches!(status[0].outcome, sharing::Outcome::RecoveryRequired));
        assert_eq!(status[0].metadata_sha256.as_deref(), Some(batch.metadata_sha256.as_str()));
        // A closing host fence revokes new authority before physical teardown.
        let current = checked(Batch::new(package(), "b".repeat(64), BTreeSet::new(), "9".repeat(32)));
        checked(current.authorize(&current.nonce));
        let fence = crate::idle_controller::Target::Host { nonce: "9".repeat(32) };
        checked(crate::idle_controller::latch(&fence));
        assert!(matches!(current.authorize(&current.nonce), Err(Error("share_import_authority_expired"))));
        // Explicit recovery deletes unpublished staging without reviving it.
        checked(repository.discard(&batch.transaction));
        assert!(checked(repository.imported()).is_empty());
        assert!(!repository.pending(&batch.transaction).exists());
    }

    #[test]
    #[ignore = "requires isolated root-owned fixture directory; no production state"]
    fn atomic_collection_publish_and_abort_keep_existing_safes_untouched() {
        assert_eq!(std::env::var("OBLIVION_SHARE_IMPORT_TEST").as_deref(), Ok("1"));
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let root = PathBuf::from("/tmp").join(format!("oblivion-share-import-{}", checked(crate::storage::random_id())));
        private_directory(&root, true).unwrap_or_else(|error| panic!("{}", error.0));
        private_directory(&root.join("sessions"), true).unwrap_or_else(|error| panic!("{}", error.0));
        write_new(&root.join("sessions/existing.luks"), b"existing Safe remains unchanged").unwrap_or_else(|error| panic!("{}", error.0));
        let repository = Repository::new(&root);
        let mut batch = batch();
        checked(repository.create(&batch));
        assert!(checked(repository.imported()).is_empty());
        for index in 0..batch.destinations.len() {
            let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(repository.volume(&batch, &batch.destinations[index])).unwrap();
            file.set_len(batch.destinations[index].mib * MIB).unwrap();
            receive(&mut batch, index);
            checked(repository.write(&batch));
            assert!(checked(repository.imported()).is_empty());
        }
        assert!(repository.commit(&batch, &"c".repeat(64)).is_err());
        checked(repository.commit(&batch, &"b".repeat(64)));
        let published: Vec<_> = checked(repository.imported()).into_iter().map(|safe| safe.id).collect();
        assert_eq!(published.len(), 3);
        assert!(!repository.pending(&batch.transaction).exists());
        assert!(repository.discard(&batch.transaction).is_err());
        assert!(matches!(checked(repository.status())[0].outcome, sharing::Outcome::Committed));
        let pending = self::batch();
        checked(repository.create(&pending));
        checked(repository.discard(&pending.transaction));
        assert_eq!(checked(repository.imported()).into_iter().map(|safe| safe.id).collect::<Vec<_>>(), published);
        let transaction = "9".repeat(32);
        let path = repository.pending(&transaction);
        checked(private_directory(&path, true));
        checked(write_new(&path.join("batch.pending"), b"interrupted metadata"));
        assert!(checked(repository.status()).iter().any(|status| status.transaction == transaction && status.metadata_sha256.is_none()
            && matches!(status.outcome, sharing::Outcome::RecoveryRequired)));
        checked(write_new(&path.join("unknown.bin"), b"never discard unknown data"));
        assert!(repository.discard_initial_metadata(&transaction).is_err());
        assert!(path.join("unknown.bin").exists());
        fs::remove_file(path.join("unknown.bin")).unwrap();
        checked(repository.discard_initial_metadata(&transaction));
        assert_eq!(fs::read(root.join("sessions/existing.luks")).unwrap(), b"existing Safe remains unchanged");
        fs::remove_dir_all(root).unwrap();
    }
}
