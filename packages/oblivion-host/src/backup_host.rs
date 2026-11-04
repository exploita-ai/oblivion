//! Revocable ciphertext-only personal copies. No guest filesystem is mounted.
use crate::storage::{Error, Result, require, trusted_file, validate_id};
use oblivion_host::{backup, scope};
use oblivion_transfer::{Receipt, endpoint};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const RAM: &str = "/run/oblivion/personal-backups";
const GENERAL: &str = "/run/oblivion/general";
const LIMIT: usize = 1024;
const RECORD_BYTES: u64 = 4096;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Identity { device: u64, inode: u64, bytes: u64, modified: i64, modified_ns: i64 }

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    host_opening: String,
    created: u64,
    maximum: u64,
    entry: backup::Entry,
    source: Option<Identity>,
    receipt: Option<Receipt>,
}

struct Copy { child: Child, began: Instant, completion: Option<Vec<u8>> }
static COPIES: OnceLock<Mutex<BTreeMap<String, Copy>>> = OnceLock::new();
fn copies() -> &'static Mutex<BTreeMap<String, Copy>> { COPIES.get_or_init(|| Mutex::new(BTreeMap::new())) }

fn persistent() -> PathBuf { Path::new(GENERAL).join("personal-backups") }
fn path(id: &str, kind: backup::Kind) -> PathBuf {
    (if kind == backup::Kind::Export { PathBuf::from(RAM) } else { persistent() }).join(format!("{id}.json"))
}

fn directory(path: &Path, create: bool) -> Result<bool> {
    if !path.try_exists().map_err(|_| Error("backup_record_failed"))? {
        if !create { return Ok(false) }
        fs::DirBuilder::new().recursive(true).mode(0o700).create(path).map_err(|_| Error("backup_record_failed"))?;
    }
    let info = fs::symlink_metadata(path).map_err(|_| Error("backup_record_failed"))?;
    require(info.is_dir() && info.uid() == 0 && info.mode() & 0o077 == 0, "unsafe_backup_record")?;
    Ok(true)
}

fn write(record: &Record) -> Result<()> {
    let target = path(&record.entry.transaction, record.entry.kind);
    let root = target.parent().ok_or(Error("backup_record_failed"))?;
    directory(root, true)?;
    let pending = target.with_extension("pending");
    for old in [&target, &pending] { if old.try_exists().map_err(|_| Error("backup_record_failed"))? { trusted_file(old)?; } }
    let bytes = serde_json::to_vec(record).map_err(|_| Error("encode_failed"))?;
    require(bytes.len() as u64 <= RECORD_BYTES, "invalid_backup_record")?;
    let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&pending).map_err(|_| Error("backup_record_failed"))?;
    file.write_all(&bytes).and_then(|()| file.sync_all()).map_err(|_| Error("backup_record_failed"))?;
    fs::rename(&pending, &target).map_err(|_| Error("backup_record_failed"))?;
    File::open(root).and_then(|file| file.sync_all()).map_err(|_| Error("sync_failed"))
}

fn records() -> Result<Vec<Record>> {
    let mut records = Vec::new();
    for (root, kind) in [(PathBuf::from(RAM), backup::Kind::Export), (persistent(), backup::Kind::Import)] {
        if !directory(&root, false)? { continue }
        for entry in fs::read_dir(&root).map_err(|_| Error("backup_record_failed"))? {
            let entry = entry.map_err(|_| Error("backup_record_failed"))?;
            if entry.file_name().to_str().is_some_and(|name| name.ends_with(".pending")) { continue }
            require(records.len() < LIMIT, "backup_transaction_limit")?;
            let name = entry.file_name().into_string().map_err(|_| Error("invalid_backup_record"))?;
            let id = name.strip_suffix(".json").ok_or(Error("invalid_backup_record"))?;
            validate_id(id)?;
            let mut bytes = Vec::new();
            trusted_file(&entry.path())?.take(RECORD_BYTES + 1).read_to_end(&mut bytes).map_err(|_| Error("backup_record_failed"))?;
            require(bytes.len() as u64 <= RECORD_BYTES, "invalid_backup_record")?;
            let record: Record = serde_json::from_slice(&bytes).map_err(|_| Error("invalid_backup_record"))?;
            require(record.version == 1 && record.entry.transaction == id && record.entry.kind == kind
                && record.entry.safe_id.as_ref().is_none_or(|id| oblivion_host::managed::id(id))
                && oblivion_host::managed::id(&record.host_opening)
                && (32 * 1024 * 1024..=oblivion_transfer::MAX_ENCRYPTED_VOLUME_BYTES).contains(&record.maximum)
                && !records.iter().any(|old: &Record| old.entry.transaction == id), "invalid_backup_record")?;
            records.push(record);
        }
    }
    Ok(records)
}

fn read(id: &str) -> Result<Record> {
    validate_id(id)?;
    records()?.into_iter().find(|record| record.entry.transaction == id).ok_or(Error("backup_transaction_not_found"))
}

fn authorize(record: &Record) -> Result<()> {
    authorize_generation(record, scope::current(), &crate::storage::share_export_host()?)
}

fn authorize_generation(record: &Record, slot: scope::Slot, host_opening: &str) -> Result<()> {
    require(record.entry.slot == slot && record.host_opening == host_opening, "backup_authority_expired")
}

fn admission() -> Result<()> {
    let records = records()?;
    require(records.len() < LIMIT && records.iter().filter(|record|
        matches!(record.entry.outcome, backup::Outcome::Prepared | backup::Outcome::Copying)).count() < 32,
        "backup_transaction_limit")
}

pub(crate) fn begin_export(id: &str, source: &File) -> Result<backup::Exported> {
    admission()?;
    let info = source.metadata().map_err(|_| Error("metadata_failed"))?;
    let transaction = crate::storage::random_id()?;
    let result = backup::Exported { transaction: transaction.clone(), safe_id: id.into(), bytes: info.len() };
    write(&Record { version: 1, host_opening: crate::storage::share_export_host()?, created: now(), maximum: info.len(),
        entry: backup::Entry { transaction, slot: scope::current(), kind: backup::Kind::Export, safe_id: Some(id.into()),
            bytes: Some(info.len()), outcome: backup::Outcome::Prepared, active: false },
        source: Some(Identity { device: info.dev(), inode: info.ino(), bytes: info.len(), modified: info.mtime(), modified_ns: info.mtime_nsec() }), receipt: None })?;
    Ok(result)
}

pub(crate) fn begin_import() -> Result<backup::Imported> {
    admission()?;
    let maximum = crate::storage::restore_budget()?;
    let transaction = crate::storage::random_id()?;
    let result = backup::Imported { transaction: transaction.clone(), maximum };
    write(&Record { version: 1, host_opening: crate::storage::share_export_host()?, created: now(), maximum,
        entry: backup::Entry { transaction, slot: scope::current(), kind: backup::Kind::Import, safe_id: None, bytes: None,
            outcome: backup::Outcome::Prepared, active: false }, source: None, receipt: None })?;
    // The catalog entry is durable before allocating any pending payload, so
    // an interrupted begin is visible to explicit status/discard recovery.
    crate::storage::create_restore_copy(&result.transaction)?.sync_all().map_err(|_| Error("sync_failed"))?;
    Ok(result)
}

/// Called while storage.lock is held. Prepared exports have no open volume FD;
/// their short reservation also expires if a launcher dies before attaching.
pub(crate) fn require_safe_available(id: &str) -> Result<()> {
    for record in records()?.into_iter().filter(|record| record.entry.kind == backup::Kind::Export && record.entry.safe_id.as_deref() == Some(id)) {
        require(!matches!(record.entry.outcome, backup::Outcome::Copying)
            && !(record.entry.outcome == backup::Outcome::Prepared && now().saturating_sub(record.created) < 120), "backup_active")?;
    }
    Ok(())
}

pub(crate) fn attach(id: &str) -> Result<(UnixStream, String)> {
    let mut registry = copies().lock().map_err(|_| Error("backup_registry_failed"))?;
    refresh_locked(&mut registry)?;
    require(registry.len() < 4, "backup_copy_limit")?;
    let mut record = read(id)?;
    authorize(&record)?;
    require(record.entry.outcome == backup::Outcome::Prepared && now().saturating_sub(record.created) < 120
        && !registry.contains_key(id), "backup_not_attachable")?;
    let file = if record.entry.kind == backup::Kind::Export {
        let source = record.entry.safe_id.as_deref().ok_or(Error("invalid_backup_record"))?;
        crate::storage::backup_source_closed(source)?;
        let file = trusted_file(&crate::storage::persistent_safe_path(source)?)?;
        let info = file.metadata().map_err(|_| Error("metadata_failed"))?;
        let identity = record.source.as_ref().ok_or(Error("invalid_backup_record"))?;
        require(info.dev() == identity.device && info.ino() == identity.inode && info.len() == identity.bytes
            && info.mtime() == identity.modified && info.mtime_nsec() == identity.modified_ns, "backup_source_changed")?;
        file
    } else {
        crate::storage::open_restore_copy(id)?
    };
    record.entry.outcome = backup::Outcome::Copying;
    record.entry.active = true;
    write(&record)?;
    let (client, copy) = spawn_copy(file, id, record.entry.kind, record.maximum,
        &std::env::current_exe().map_err(|_| Error("executable_unavailable"))?)?;
    registry.insert(id.into(), copy);
    Ok((client, id.into()))
}

fn spawn_copy(file: File, id: &str, kind: backup::Kind, maximum: u64, executable: &Path) -> Result<(UnixStream, Copy)> {
    let (client, worker) = UnixStream::pair().map_err(|_| Error("backup_channel_failed"))?;
    let file = duplicate(file.as_raw_fd())?;
    let worker = duplicate(worker.as_raw_fd())?;
    let mut command = Command::new(executable);
    command.args(["--backup-copy", if kind == backup::Kind::Export { "export" } else { "import" }, id, &maximum.to_string()])
        .env_clear().current_dir("/").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    unsafe { command.pre_exec(move || {
        if libc::dup2(file.as_raw_fd(), 4) < 0 || libc::dup2(worker.as_raw_fd(), 5) < 0 { return Err(std::io::Error::last_os_error()) }
        // A copy is not a formatter: it must not inherit storage.lock or the
        // controller's daemon lock, otherwise status/Lock would deadlock.
        if libc::syscall(libc::SYS_close_range, 3u32, 3u32, libc::CLOSE_RANGE_CLOEXEC) != 0
            || libc::syscall(libc::SYS_close_range, 6u32, u32::MAX, libc::CLOSE_RANGE_CLOEXEC) != 0 { return Err(std::io::Error::last_os_error()) }
        Ok(())
    }); }
    let child = command.spawn().map_err(|_| Error("backup_worker_failed"))?;
    drop(command);
    Ok((client, Copy { child, began: Instant::now(), completion: None }))
}

fn duplicate(fd: i32) -> Result<OwnedFd> {
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
    require(copy >= 0, "backup_channel_failed")?;
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}

fn finish_copy(copy: &mut Copy, id: &str, kill: bool) -> Result<()> {
    if kill && copy.child.try_wait().map_err(|_| Error("backup_worker_failed"))?.is_none() {
        copy.child.kill().map_err(|_| Error("backup_cleanup_required"))?;
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if copy.child.try_wait().map_err(|_| Error("backup_cleanup_required"))?.is_some() { break }
        require(Instant::now() < deadline, "backup_cleanup_required")?;
        std::thread::sleep(Duration::from_millis(5));
    }
    if copy.completion.is_none() {
        let mut bytes = Vec::new();
        copy.child.stdout.take().ok_or(Error("backup_worker_failed"))?.take(1025).read_to_end(&mut bytes).map_err(|_| Error("backup_worker_failed"))?;
        copy.completion = Some(bytes);
    }
    let mut record = read(id)?;
    let receipt = serde_json::from_slice::<Receipt>(copy.completion.as_deref().ok_or(Error("backup_worker_failed"))?).ok().filter(|receipt| receipt.id == id && receipt.entries == 1
        && (32 * 1024 * 1024..=record.maximum).contains(&receipt.bytes)
        && receipt.manifest_sha256.len() == 64 && receipt.manifest_sha256.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && (record.entry.kind == backup::Kind::Import || record.entry.bytes == Some(receipt.bytes)));
    if let Some(receipt) = receipt {
        if record.entry.kind == backup::Kind::Import { crate::storage::record_backup_receipt(&receipt)?; }
        record.entry.bytes = Some(receipt.bytes);
        record.receipt = Some(receipt);
        record.entry.outcome = backup::Outcome::Copied;
    } else { record.entry.outcome = if record.entry.kind == backup::Kind::Import { backup::Outcome::RecoveryRequired } else { backup::Outcome::Cancelled }; }
    record.entry.active = false;
    write(&record)
}

fn refresh_locked(registry: &mut BTreeMap<String, Copy>) -> Result<()> {
    let mut done = Vec::new();
    for (id, copy) in registry.iter_mut() {
        let expired = copy.began.elapsed() >= Duration::from_secs(3600);
        if expired || copy.child.try_wait().map_err(|_| Error("backup_worker_failed"))?.is_some() { done.push((id.clone(), expired)); }
    }
    for (id, kill) in done {
        finish_copy(registry.get_mut(&id).ok_or(Error("backup_registry_failed"))?, &id, kill)?;
        registry.remove(&id);
    }
    Ok(())
}

pub(crate) fn cancel(id: &str) -> Result<()> {
    validate_id(id)?;
    let mut record = read(id)?;
    require(record.entry.slot == scope::current(), "backup_slot_changed")?;
    let mut registry = copies().lock().map_err(|_| Error("backup_registry_failed"))?;
    if let Some(copy) = registry.get_mut(id) {
        finish_copy(copy, id, true)?;
        registry.remove(id);
        return Ok(())
    }
    if matches!(record.entry.outcome, backup::Outcome::Prepared | backup::Outcome::Copying) {
        record.entry.outcome = if record.entry.kind == backup::Kind::Import { backup::Outcome::RecoveryRequired } else { backup::Outcome::Cancelled };
        record.entry.active = false;
        write(&record)?;
    }
    Ok(())
}

/// Private daemon entry point: wait for every ciphertext descriptor to close
/// before its caller can unmount General, even if a peer stalled in hashing.
pub(crate) fn stop_all() -> Result<()> {
    let mut registry = copies().lock().map_err(|_| Error("backup_registry_failed"))?;
    let mut error = None;
    let ids: Vec<_> = registry.keys().cloned().collect();
    for id in ids {
        match finish_copy(registry.get_mut(&id).ok_or(Error("backup_registry_failed"))?, &id, true) {
            Ok(()) => { registry.remove(&id); }
            Err(failed) => { error = Some(failed); }
        }
    }
    for mut record in records()? {
        if registry.contains_key(&record.entry.transaction) { continue }
        if matches!(record.entry.outcome, backup::Outcome::Prepared | backup::Outcome::Copying) {
            record.entry.outcome = if record.entry.kind == backup::Kind::Import { backup::Outcome::RecoveryRequired } else { backup::Outcome::Cancelled };
            record.entry.active = false;
            if let Err(failed) = write(&record) { error = Some(failed) }
        }
    }
    error.map_or(Ok(()), Err)
}

pub(crate) fn owners_closed() -> Result<bool> {
    let mut registry = copies().lock().map_err(|_| Error("backup_registry_failed"))?;
    for copy in registry.values_mut() {
        if copy.child.try_wait().map_err(|_| Error("backup_cleanup_required"))?.is_none() { return Ok(false) }
    }
    Ok(true)
}

pub(crate) fn status() -> Result<backup::Status> {
    crate::storage::backup_catalog_open()?;
    let mut registry = copies().lock().map_err(|_| Error("backup_registry_failed"))?;
    refresh_locked(&mut registry)?;
    let host = crate::storage::backup_host_nonce()?;
    let mut transactions = Vec::new();
    for record in records()? {
        let mut entry = record.entry;
        if entry.kind == backup::Kind::Import {
            if let Some(safe_id) = crate::storage::committed_personal_restore(&entry.transaction)? {
                entry.outcome = backup::Outcome::Committed; entry.safe_id = Some(safe_id); entry.active = false;
            } else if host.as_deref() != Some(record.host_opening.as_str()) {
                entry.outcome = backup::Outcome::RecoveryRequired; entry.active = false;
            }
        }
        if entry.active && !registry.contains_key(&entry.transaction) { entry.outcome = backup::Outcome::RecoveryRequired; entry.active = false; }
        transactions.push(entry);
    }
    transactions.sort_by(|a, b| a.transaction.cmp(&b.transaction));
    Ok(backup::Status { transactions })
}

pub(crate) fn pending() -> Result<bool> {
    Ok(records()?.iter().any(|record| matches!(record.entry.outcome, backup::Outcome::Prepared | backup::Outcome::Copying | backup::Outcome::Copied)
        && (record.entry.kind == backup::Kind::Import || record.entry.outcome == backup::Outcome::Copying
            || record.entry.outcome == backup::Outcome::Prepared && now().saturating_sub(record.created) < 120)))
}

pub(crate) fn ready_import(id: &str) -> Result<()> {
    let record = read(id)?; authorize(&record)?;
    require(record.entry.kind == backup::Kind::Import && record.entry.outcome == backup::Outcome::Copied && !record.entry.active,
        "backup_copy_not_complete")
}

pub(crate) fn committed(id: &str, safe_id: &str) -> Result<()> {
    let mut record = read(id)?; authorize(&record)?;
    record.entry.outcome = backup::Outcome::Committed;
    record.entry.safe_id = Some(safe_id.into());
    write(&record)
}

pub(crate) fn discard(id: &str) -> Result<()> {
    let record = read(id)?;
    require(record.entry.slot == scope::current(), "backup_slot_changed")?;
    require(!record.entry.active && !copies().lock().map_err(|_| Error("backup_registry_failed"))?.contains_key(id), "backup_active")?;
    require(record.entry.outcome != backup::Outcome::Committed && crate::storage::committed_personal_restore(id)?.is_none(), "restore_already_committed")?;
    if record.entry.kind == backup::Kind::Import { crate::storage::discard_personal_restore(id)?; }
    fs::remove_file(path(id, record.entry.kind)).map_err(|_| Error("backup_record_failed"))?;
    Ok(())
}

pub(crate) fn watchdog() {
    std::thread::spawn(|| loop {
        std::thread::sleep(Duration::from_secs(1));
        let Ok(_lock) = crate::storage::lock_named("storage.lock") else { continue };
        if let Ok(mut registry) = copies().lock() { let _ = refresh_locked(&mut registry); }
    });
}

/// This mode receives only parent-owned descriptors; it accepts no path.
pub(crate) fn copy_worker(args: &[String]) -> Result<()> {
    require(args.len() == 4 && matches!(args[1].as_str(), "export" | "import"), "invalid_backup_worker")?;
    validate_id(&args[2])?;
    let maximum = args[3].parse::<u64>().map_err(|_| Error("invalid_backup_worker"))?;
    require((32 * 1024 * 1024..=oblivion_transfer::MAX_ENCRYPTED_VOLUME_BYTES).contains(&maximum), "invalid_backup_worker")?;
    unsafe {
        require(libc::geteuid() == 0 && libc::fcntl(4, libc::F_SETFD, libc::FD_CLOEXEC) == 0
            && libc::fcntl(5, libc::F_SETFD, libc::FD_CLOEXEC) == 0
            && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "invalid_backup_worker")?;
    }
    oblivion_host::control::protect().map_err(|_| Error("dump_protection_failed"))?;
    let file = unsafe { File::from_raw_fd(4) };
    let socket = unsafe { File::from_raw_fd(5) };
    let mut channel = oblivion_transfer::channel::Channel::new(socket, Duration::from_secs(3600)).map_err(|_| Error("backup_channel_failed"))?;
    let expected = &args[2];
    let completed = |receipt: &Receipt| -> std::io::Result<()> {
        if receipt.id != *expected { return Err(std::io::ErrorKind::InvalidData.into()) }
        serde_json::to_writer(std::io::stdout().lock(), receipt).map_err(std::io::Error::other)?;
        std::io::stdout().flush()
    };
    if args[1] == "export" { endpoint::send_open_file_completed(&mut channel, file, maximum, completed) }
    else { endpoint::receive_open_file_completed(&mut channel, file, maximum, completed) }.map_err(|_| Error("backup_copy_failed"))?;
    Ok(())
}

fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.as_secs()) }

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Record {
        Record { version: 1, host_opening: "1".repeat(32), created: now(), maximum: oblivion_transfer::MAX_ENCRYPTED_VOLUME_BYTES,
            entry: backup::Entry { transaction: "2".repeat(32), slot: Default::default(), kind: backup::Kind::Export,
                safe_id: Some("3".repeat(32)), bytes: Some(oblivion_transfer::MAX_ENCRYPTED_VOLUME_BYTES), outcome: backup::Outcome::Copying, active: true },
            source: None, receipt: None }
    }

    #[test]
    fn mutation_authority_is_bound_to_host_opening_and_original_slot() {
        let record = record();
        assert!(authorize_generation(&record, Default::default(), &record.host_opening).is_ok());
        assert!(matches!(authorize_generation(&record, Default::default(), &"4".repeat(32)), Err(Error("backup_authority_expired"))));
        assert!(matches!(authorize_generation(&record, 1.try_into().unwrap(), &record.host_opening), Err(Error("backup_authority_expired"))));
    }

    #[test]
    #[ignore = "requires disposable root-owned tmpfs /run and actual storage executable"]
    fn lock_revokes_a_real_hashing_process_without_inheriting_controller_locks() {
        assert_eq!(std::env::var("OBLIVION_BACKUP_PROCESS_TEST").as_deref(), Ok("1"));
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert!(!Path::new("/run/oblivion").exists());
        let executable = std::env::var_os("OBLIVION_BACKUP_WORKER_BINARY").unwrap();
        let executable = Path::new(&executable);
        let record = record();
        let sessions = Path::new(GENERAL).join("sessions");
        directory(&sessions, true).unwrap_or_else(|error| panic!("{}", error.0));
        let source = sessions.join("source.luks");
        let mut file = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&source).unwrap();
        file.write_all(b"LUKS\xba\xbe\x00\x02").unwrap();
        file.set_len(record.maximum).unwrap(); // Sparse: no GiB allocation or completed scan.
        file.sync_all().unwrap();
        drop(file);
        write(&record).unwrap_or_else(|error| panic!("{}", error.0));
        let lock = crate::storage::lock_named("storage.lock").unwrap_or_else(|error| panic!("{}", error.0));
        let (client, copy) = spawn_copy(trusted_file(&source).unwrap_or_else(|error| panic!("{}", error.0)),
            &record.entry.transaction, backup::Kind::Export, record.maximum, executable).unwrap_or_else(|error| panic!("{}", error.0));
        let pid = copy.child.id();
        copies().lock().unwrap().insert(record.entry.transaction.clone(), copy);
        drop(lock);
        let deadline = Instant::now() + Duration::from_secs(2);
        let lock = loop {
            match crate::storage::lock_named("storage.lock") {
                Ok(lock) => break lock,
                Err(Error("controller_busy")) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
                Err(error) => panic!("controller lock leaked into copy worker: {}", error.0),
            }
        };
        assert!(matches!(require_safe_available(record.entry.safe_id.as_deref().unwrap()), Err(Error("backup_active"))));
        assert!(require_safe_available(&"4".repeat(32)).is_ok());
        let mut channel = oblivion_transfer::channel::Channel::new(File::from(OwnedFd::from(client)), Duration::from_secs(10)).unwrap();
        endpoint::write_message(&mut channel, &endpoint::OfferRequest { id: record.entry.transaction.clone(),
            limits: oblivion_transfer::Limits { entries: 1, bytes: record.maximum }, paths: vec![oblivion_transfer::ENCRYPTED_VOLUME_NAME.into()] }).unwrap();
        // A 1TiB sparse payload cannot finish its hash in this interval. CPU
        // progress demonstrates work after the offer without a sleep heuristic.
        let cpu = || fs::read_to_string(format!("/proc/{pid}/stat")).unwrap().split_whitespace().nth(13).unwrap().parse::<u64>().unwrap();
        let initial = cpu();
        let deadline = Instant::now() + Duration::from_secs(3);
        while cpu() < initial + 3 {
            assert!(Instant::now() < deadline, "copy worker never began hashing");
            std::thread::yield_now();
        }
        let stopped = Instant::now();
        stop_all().unwrap_or_else(|error| panic!("{}", error.0));
        assert!(stopped.elapsed() < Duration::from_secs(3));
        assert!(copies().lock().unwrap().is_empty());
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        assert!(require_safe_available(record.entry.safe_id.as_deref().unwrap()).is_ok());
        assert_eq!(fs::metadata(source).unwrap().len(), record.maximum);
        assert!(read(&record.entry.transaction).unwrap_or_else(|error| panic!("{}", error.0)).entry.outcome == backup::Outcome::Cancelled);
        drop(lock);
    }
}
