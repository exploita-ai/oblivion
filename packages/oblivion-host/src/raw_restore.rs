//! Personal recovery preserves the original encrypted volume and identity.
//! A typed collection directory publishes its volume and origin together.
use crate::storage::{Error, Result, require, trusted_file, validate_id};
use oblivion_host::{safe_admin::Metadata, safe_origin};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const LIMIT: usize = 36 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record { format: String, version: u8, transfer_id: String, metadata: Metadata }

pub(crate) struct Restored { pub directory: PathBuf, pub metadata: Metadata }

pub(crate) struct Repository(PathBuf);

impl Repository {
    pub(crate) fn new(root: &Path) -> Self { Self(root.to_path_buf()) }
    fn staging_root(&self) -> PathBuf { self.0.join("raw-restore-pending") }
    fn published_root(&self) -> PathBuf { self.0.join("restored") }
    fn pending(&self, id: &str) -> PathBuf { self.staging_root().join(id) }
    fn published(&self, id: &str) -> PathBuf { self.published_root().join(id) }

    pub(crate) fn staged(&self, id: &str) -> Result<bool> {
        validate_id(id)?;
        self.pending(id).try_exists().map_err(|_| Error("restore_record_failed"))
    }

    pub(crate) fn committed(&self, id: &str) -> Result<bool> {
        validate_id(id)?;
        self.published(id).try_exists().map_err(|_| Error("restore_record_failed"))
    }

    pub(crate) fn staged_ids(&self) -> Result<Vec<String>> { entries(&self.staging_root()) }

    pub(crate) fn restored(&self) -> Result<Vec<Restored>> {
        let mut result = Vec::new();
        let mut ids = BTreeSet::new();
        for id in entries(&self.published_root())? {
            let directory = self.published(&id);
            let record = read_record(&directory, &id)?;
            require(ids.insert(record.metadata.safe_id.clone()), "duplicate_safe_identity")?;
            result.push(Restored { directory, metadata: record.metadata });
        }
        Ok(result)
    }

    /// The caller has authenticated token0, the queued-task context and its
    /// guest metadata, then stopped every guest/DM owner before calling here.
    pub(crate) fn publish(&self, transfer_id: &str, source: &Path, metadata: Metadata) -> Result<()> {
        validate_id(transfer_id)?;
        require(metadata.valid(), "invalid_backup_metadata")?;
        require(!self.committed(transfer_id)?, "restore_already_committed")?;
        require(!self.staged(transfer_id)?, "restore_staged_recovery_required")?;
        private_directory(&self.staging_root(), true)?;
        private_directory(&self.published_root(), true)?;
        let directory = self.pending(transfer_id);
        fs::DirBuilder::new().mode(0o700).create(&directory).map_err(|_| Error("restore_record_failed"))?;
        let record = Record { format: "oblivion-personal-restore".into(), version: 1, transfer_id: transfer_id.into(), metadata };
        write_record(&directory, &record)?;
        private_directory(&directory.join("profile"), true)?;
        write_new(&directory.join("profile/access.json"), b"\"offline\"")?;
        if let Some(title) = &record.metadata.title { write_new(&directory.join("title"), title.as_bytes())?; }
        sync(&directory.join("profile"))?;
        trusted_file(source)?.sync_all().map_err(|_| Error("sync_failed"))?;
        rename_exclusive(source, &directory.join("volume.luks"))?;
        sync(source.parent().ok_or(Error("invalid_path"))?)?;
        sync(&directory)?;
        rename_exclusive(&directory, &self.published(transfer_id))?;
        sync(&self.published_root())?;
        sync(&self.staging_root())
    }

    pub(crate) fn write_agent_origin(&self, origin: safe_origin::AgentCreated) -> Result<()> {
        require(origin.valid(), "invalid_safe_provenance")?;
        for id in entries(&self.published_root())? {
            let directory = self.published(&id);
            let mut record = read_record(&directory, &id)?;
            if record.metadata.safe_id != origin.safe_id { continue }
            let safe_origin::Origin::AgentCreated { record: old } = &record.metadata.origin else { return Err(Error("safe_origin_changed")) };
            require(old.safe_id == origin.safe_id && old.parent_id == origin.parent_id && old.request_id == origin.request_id
                && old.agent == origin.agent && old.creator_chat_id == origin.creator_chat_id && old.sealed_task == origin.sealed_task,
                "safe_origin_changed")?;
            require(origin.attempts.starts_with(&old.attempts) && origin.attempts.len() <= old.attempts.len() + 1, "task_attempt_conflict")?;
            record.metadata.origin = safe_origin::Origin::AgentCreated { record: origin };
            return write_record(&directory, &record);
        }
        Err(Error("safe_origin_not_found"))
    }

    /// Recovery never publishes an interrupted transaction and never removes
    /// a committed collection. Unknown files remain visible recovery work.
    pub(crate) fn discard(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        require(!self.committed(id)?, "restore_already_committed")?;
        if !self.staged(id)? { return Ok(()) }
        let directory = self.pending(id);
        private_directory(&directory, false)?;
        let volume = directory.join("volume.luks");
        let has_volume = volume.try_exists().map_err(|_| Error("restore_cleanup_required"))?;
        if has_volume { read_record(&directory, id)?; }
        let mut files = Vec::new();
        let mut profile = None;
        for entry in fs::read_dir(&directory).map_err(|_| Error("restore_cleanup_required"))? {
            let entry = entry.map_err(|_| Error("restore_cleanup_required"))?;
            match entry.file_name().to_str() {
                Some("volume.luks") => { trusted_file(&entry.path())?; }
                Some("record.json" | "record.pending" | "title") => { trusted_file(&entry.path())?; files.push(entry.path()); }
                Some("profile") => {
                    private_directory(&entry.path(), false)?;
                    for child in fs::read_dir(entry.path()).map_err(|_| Error("restore_cleanup_required"))? {
                        let child = child.map_err(|_| Error("restore_cleanup_required"))?;
                        require(child.file_name() == "access.json", "restore_cleanup_required")?;
                        trusted_file(&child.path())?; files.push(child.path());
                    }
                    profile = Some(entry.path());
                }
                _ => return Err(Error("restore_cleanup_required")),
            }
        }
        if has_volume { fs::remove_file(volume).map_err(|_| Error("restore_cleanup_required"))?; }
        // A retry can observe a previous unlink before it reached disk.
        sync(&directory)?;
        for file in files { fs::remove_file(file).map_err(|_| Error("restore_cleanup_required"))?; }
        if let Some(profile) = profile { fs::remove_dir(profile).map_err(|_| Error("restore_cleanup_required"))?; }
        fs::remove_dir(directory).map_err(|_| Error("restore_cleanup_required"))?;
        sync(&self.staging_root())
    }
}

fn read_record(directory: &Path, id: &str) -> Result<Record> {
    private_directory(directory, false)?;
    let mut bytes = Vec::new();
    trusted_file(&directory.join("record.json"))?.take(LIMIT as u64 + 1).read_to_end(&mut bytes).map_err(|_| Error("restore_record_failed"))?;
    require(bytes.len() <= LIMIT, "invalid_restore_record")?;
    let record: Record = serde_json::from_slice(&bytes).map_err(|_| Error("invalid_restore_record"))?;
    require(record.format == "oblivion-personal-restore" && record.version == 1 && record.transfer_id == id && record.metadata.valid(), "invalid_restore_record")?;
    Ok(record)
}

fn write_record(directory: &Path, record: &Record) -> Result<()> {
    let bytes = serde_json::to_vec(record).map_err(|_| Error("encode_failed"))?;
    require(bytes.len() <= LIMIT, "invalid_restore_record")?;
    let pending = directory.join("record.pending");
    if pending.try_exists().map_err(|_| Error("restore_record_failed"))? { trusted_file(&pending)?; }
    let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&pending).map_err(|_| Error("restore_record_failed"))?;
    file.write_all(&bytes).and_then(|()| file.sync_all()).map_err(|_| Error("restore_record_failed"))?;
    fs::rename(pending, directory.join("record.json")).map_err(|_| Error("restore_record_failed"))?;
    sync(directory)
}

fn entries(path: &Path) -> Result<Vec<String>> {
    if !path.try_exists().map_err(|_| Error("restore_record_failed"))? { return Ok(Vec::new()) }
    private_directory(path, false)?;
    let mut result = Vec::new();
    for entry in fs::read_dir(path).map_err(|_| Error("restore_record_failed"))? {
        require(result.len() < 1024, "restore_collection_limit")?;
        let entry = entry.map_err(|_| Error("restore_record_failed"))?;
        let id = entry.file_name().into_string().map_err(|_| Error("invalid_restore_record"))?;
        validate_id(&id)?;
        private_directory(&entry.path(), false)?;
        result.push(id);
    }
    Ok(result)
}

fn private_directory(path: &Path, create: bool) -> Result<()> {
    if create { fs::DirBuilder::new().recursive(true).mode(0o700).create(path).map_err(|_| Error("restore_record_failed"))?; }
    let info = fs::symlink_metadata(path).map_err(|_| Error("restore_record_failed"))?;
    require(info.is_dir() && info.uid() == 0 && info.mode() & 0o077 == 0, "unsafe_restore_record")
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path).map_err(|_| Error("restore_record_failed"))?;
    file.write_all(bytes).and_then(|()| file.sync_all()).map_err(|_| Error("restore_record_failed"))
}

fn rename_exclusive(source: &Path, destination: &Path) -> Result<()> {
    let source = CString::new(source.as_os_str().as_encoded_bytes()).map_err(|_| Error("invalid_path"))?;
    let destination = CString::new(destination.as_os_str().as_encoded_bytes()).map_err(|_| Error("invalid_path"))?;
    require(unsafe { libc::renameat2(libc::AT_FDCWD, source.as_ptr(), libc::AT_FDCWD, destination.as_ptr(), libc::RENAME_NOREPLACE) } == 0, "restore_publish_failed")
}

fn sync(path: &Path) -> Result<()> { File::open(path).and_then(|file| file.sync_all()).map_err(|_| Error("sync_failed")) }

#[cfg(test)]
mod tests {
    use super::*;
    use oblivion_host::family::{Capability, SealedTask, TaskContext};
    use zeroize::Zeroizing;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            assert_eq!(std::env::var("OBLIVION_PERSONAL_RESTORE_TEST").as_deref(), Ok("1"));
            assert_eq!(unsafe { libc::geteuid() }, 0, "requires a disposable root-owned temporary directory");
            let path = std::env::temp_dir().join(format!("oblivion-personal-restore-{}", crate::storage::random_id().unwrap_or_else(|error| panic!("{}", error.0))));
            private_directory(&path, true).unwrap_or_else(|error| panic!("{}", error.0));
            Self(path)
        }
        fn repository(&self) -> Repository { Repository::new(&self.0) }
    }
    impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

    fn agent_metadata() -> (Metadata, Capability) {
        let capability = Capability::from_root_secret(&"1".repeat(32), Zeroizing::new([7; 32])).unwrap();
        let context = TaskContext { safe_id: &"2".repeat(32), parent_id: &"3".repeat(32), request_id: &"4".repeat(32), agent: "codex" };
        let metadata = Metadata {
            format: "oblivion-safe".into(), version: 1, safe_id: context.safe_id.into(), title: Some("Restored child".into()),
            origin: safe_origin::Origin::AgentCreated { record: safe_origin::AgentCreated {
                safe_id: context.safe_id.into(), parent_id: context.parent_id.into(), request_id: context.request_id.into(), agent: context.agent.into(),
                creator_chat_id: Some("reported-creator".into()), sealed_task: SealedTask::seal(&capability, &context, "private-task-canary").unwrap(),
                attempts: vec![context.request_id.into()],
            } },
        };
        (metadata, capability)
    }

    #[test]
    #[ignore = "requires disposable root-owned /tmp; no production state"]
    fn publishes_original_ciphertext_with_origin_and_offline_profile_as_one_collection() {
        let fixture = Fixture::new();
        let repository = fixture.repository();
        let transfer = "a".repeat(32);
        let source = fixture.0.join("source.luks");
        let ciphertext = b"LUKS encrypted source bytes: never rekeyed or copied by publication";
        write_new(&source, ciphertext).unwrap_or_else(|error| panic!("{}", error.0));
        let (metadata, capability) = agent_metadata();
        assert!(repository.restored().unwrap_or_else(|error| panic!("{}", error.0)).is_empty());
        repository.publish(&transfer, &source, metadata.clone()).unwrap_or_else(|error| panic!("{}", error.0));
        assert!(!source.exists());
        assert!(repository.committed(&transfer).unwrap_or(false));
        assert!(!repository.staged(&transfer).unwrap_or(true));
        let restored = repository.restored().unwrap_or_else(|error| panic!("{}", error.0)).pop().unwrap();
        assert!(restored.metadata == metadata);
        assert_eq!(fs::read(restored.directory.join("volume.luks")).unwrap(), ciphertext);
        assert_eq!(fs::read(restored.directory.join("profile/access.json")).unwrap(), b"\"offline\"");
        assert!(!restored.directory.join("profile/transport.json").exists());
        let safe_origin::Origin::AgentCreated { mut record } = restored.metadata.origin else { panic!("origin lost") };
        assert_eq!(record.sealed_task.open(&capability, &record.context()).unwrap().as_str(), "private-task-canary");
        assert!(!String::from_utf8_lossy(&fs::read(restored.directory.join("record.json")).unwrap()).contains("private-task-canary"));
        record.attempts.push("5".repeat(32));
        repository.write_agent_origin(record.clone()).unwrap_or_else(|error| panic!("{}", error.0));
        let safe_origin::Origin::AgentCreated { record: updated } = repository.restored().unwrap_or_else(|error| panic!("{}", error.0)).pop().unwrap().metadata.origin else { panic!("origin lost") };
        assert_eq!(updated.attempts, record.attempts);
        record.attempts.pop();
        assert!(matches!(repository.write_agent_origin(record), Err(Error("task_attempt_conflict"))));
        assert!(matches!(repository.discard(&transfer), Err(Error("restore_already_committed"))));
        assert!(fs::read(restored.directory.join("volume.luks")).unwrap() == ciphertext);
    }

    #[test]
    #[ignore = "requires disposable root-owned /tmp; no production state"]
    fn interrupted_stage_is_hidden_and_discard_refuses_unknown_volume_metadata() {
        let fixture = Fixture::new();
        let repository = fixture.repository();
        let transfer = "b".repeat(32);
        let directory = repository.pending(&transfer);
        private_directory(&directory, true).unwrap_or_else(|error| panic!("{}", error.0));
        write_new(&directory.join("volume.luks"), b"original encrypted bytes").unwrap_or_else(|error| panic!("{}", error.0));
        assert_eq!(repository.staged_ids().unwrap_or_else(|error| panic!("{}", error.0)), [transfer.clone()]);
        assert!(repository.restored().unwrap_or_else(|error| panic!("{}", error.0)).is_empty());
        assert!(repository.discard(&transfer).is_err());
        assert!(directory.join("volume.luks").exists());
        let (metadata, _) = agent_metadata();
        write_record(&directory, &Record { format: "oblivion-personal-restore".into(), version: 1, transfer_id: transfer.clone(), metadata }).unwrap_or_else(|error| panic!("{}", error.0));
        write_new(&directory.join("unknown-data"), b"must remain untouched").unwrap_or_else(|error| panic!("{}", error.0));
        assert!(matches!(repository.discard(&transfer), Err(Error("restore_cleanup_required"))));
        assert!(directory.join("volume.luks").exists());
        fs::remove_file(directory.join("unknown-data")).unwrap();
        repository.discard(&transfer).unwrap_or_else(|error| panic!("{}", error.0));
        assert!(!directory.exists());
        assert!(repository.restored().unwrap_or_else(|error| panic!("{}", error.0)).is_empty());
    }
}
