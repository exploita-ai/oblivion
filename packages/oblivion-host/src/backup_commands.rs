//! Native full-volume personal recovery. Portable Share is a separate command.
use oblivion_host::{backup, control, managed, scope};
use oblivion_transfer::channel::Channel;
use oblivion_transfer::{MAX_ENCRYPTED_VOLUME_BYTES, Selection, stream};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const HELP: &str = "Use backup export --safe SAFE FILE, backup import FILE, backup finish TRANSACTION, backup status [--json] or backup discard TRANSACTION";

enum Options<'a> {
    Export { safe: &'a str, path: &'a str },
    Import(&'a str),
    Finish(&'a str),
    Status { json: bool },
    Discard(&'a str),
}

pub fn run(args: &[String]) -> control::Result<i32> {
    let options = options(args)?;
    let state = super::status()?;
    if !state.app_open || state.app_mode != super::AppMode::Persistent {
        return Err("Unlock writable encrypted storage before using personal backups".into());
    }
    match options {
        Options::Status { json } => {
            let status = status()?;
            if json {
                println!("{}", serde_json::to_string(&status)?);
                return Ok(0);
            }
            for entry in status.transactions {
                println!("{}\t{}\t{}{}", entry.transaction,
                    if entry.kind == backup::Kind::Export { "Export" } else { "Import" },
                    outcome(entry.outcome), entry.safe_id.map(|id| format!("\t{id}")).unwrap_or_default());
            }
            Ok(0)
        }
        Options::Discard(transaction) => discard(transaction),
        Options::Finish(transaction) => {
            let status = status()?;
            let entry = status.transactions.iter().find(|entry| entry.transaction == transaction).ok_or("Backup transaction not found")?;
            if entry.kind != backup::Kind::Import || entry.outcome != backup::Outcome::Copied || entry.active {
                return Err("Only a verified copy from this unlocked Oblivion opening can be finished".into());
            }
            scope::within(entry.slot, || {
                let result = finish_import(transaction).and_then(|finished| {
                    println!("{}", serde_json::to_string(&finished)?);
                    eprintln!("Safe {} restored offline.", finished.safe_id);
                    Ok(0)
                });
                finish_attempt(transaction, result)
            })
        }
        Options::Export { safe, path } => {
            if state.recovery_required { return Err("Complete recovery before exporting a personal backup".into()); }
            let id = super::find_safe(&state, safe)?.ok_or("Safe not found")?;
            if !state.sessions.contains(&id) {
                return Err("Personal backups require a persistent Safe".into());
            }
            if state.open_sessions.iter().any(|safe| safe.id.as_ref() == Some(&id)) {
                return Err("Close the Safe before exporting its personal backup".into());
            }
            let destination = OutputTarget::new(Path::new(path))?;
            let slot = super::free_slot(&state)?;
            scope::within(slot, || export(&id, destination))
        }
        Options::Import(path) => {
            if state.recovery_required { return Err("Complete recovery before importing a personal backup".into()); }
            let source = OpenOptions::new().read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(std::path::absolute(path)?)?;
            let mut selection = Selection::encrypted_volume(source, MAX_ENCRYPTED_VOLUME_BYTES)?;
            let slot = super::free_slot(&state)?;
            scope::within(slot, || import(&mut selection))
        }
    }
}

fn options(args: &[String]) -> control::Result<Options<'_>> {
    let Some((action, rest)) = args.split_first() else { return Err(HELP.into()) };
    match (action.as_str(), rest) {
        ("export", [flag, safe, path]) if flag == "--safe"
            && !safe.is_empty() && !safe.starts_with('-') && !path.is_empty() && !path.starts_with('-') => Ok(Options::Export { safe, path }),
        ("export", [path, flag, safe]) if flag == "--safe"
            && !safe.is_empty() && !safe.starts_with('-') && !path.is_empty() && !path.starts_with('-') => Ok(Options::Export { safe, path }),
        ("import", [path]) if !path.is_empty() && !path.starts_with('-') => Ok(Options::Import(path)),
        ("finish", [transaction]) if managed::id(transaction) => Ok(Options::Finish(transaction)),
        ("status", []) => Ok(Options::Status { json: false }),
        ("status", [flag]) if flag == "--json" => Ok(Options::Status { json: true }),
        ("discard", [transaction]) if managed::id(transaction) => Ok(Options::Discard(transaction)),
        _ => Err(HELP.into()),
    }
}

fn export(id: &str, destination: OutputTarget) -> control::Result<i32> {
    eprintln!("A personal backup contains the complete encrypted Safe, including saved logins and installed software. Keep its original Safe password.");
    let prepared: backup::Exported = serde_json::from_str(&control::request_for(
        id, "backup-export-begin", Some(id), &super::password("Safe password", false)?,
    )?)?;
    if !managed::id(&prepared.transaction) {
        return Err("invalid_backup_preparation".into());
    }
    if prepared.safe_id != id || !volume_size(prepared.bytes) {
        return finish_attempt(&prepared.transaction, Err("invalid_backup_preparation".into()));
    }
    let result = (|| -> control::Result<i32> {
        let mut output = destination.create(&prepared.transaction)?;
        let (connection, lease, _) = control::attach_backup(&prepared.transaction)?;
        let mut channel = Channel::new(File::from(OwnedFd::from(connection)), Duration::from_secs(3600))?;
        let copy_result = stream::download_open_file(&mut channel, output.copy_file()?, prepared.bytes, &prepared.transaction);
        drop(channel);
        drop(lease);
        let receipt = copy_result?;
        if receipt.id != prepared.transaction || receipt.entries != 1 || receipt.bytes != prepared.bytes {
            return Err("invalid_backup_receipt".into());
        }
        copied(&prepared.transaction)?;
        output.publish()?;
        println!("{}", serde_json::to_string(&receipt)?);
        eprintln!("Personal backup saved to {}", output.target.display());
        Ok(0)
    })();
    finish_attempt(&prepared.transaction, result)
}

fn import(selection: &mut Selection) -> control::Result<i32> {
    eprintln!("Restore the complete Safe with its original identity and saved logins. It will remain offline after restoration.");
    let prepared: backup::Imported = serde_json::from_str(&control::request("backup-import-begin", None, &[])?)?;
    if !managed::id(&prepared.transaction) {
        return Err("invalid_backup_preparation".into());
    }
    if !volume_size(prepared.maximum) {
        return finish_attempt(&prepared.transaction, Err("invalid_backup_preparation".into()));
    }
    let result = (|| -> control::Result<i32> {
        if selection.manifest().bytes() > prepared.maximum { return Err("insufficient_restore_space".into()); }
        let (connection, lease, _) = control::attach_backup(&prepared.transaction)?;
        let mut channel = Channel::new(File::from(OwnedFd::from(connection)), Duration::from_secs(3600))?;
        let receipt = stream::send(&mut channel, selection, &prepared.transaction);
        drop(channel);
        drop(lease);
        receipt?;
        copied(&prepared.transaction)?;
        let finished = finish_import(&prepared.transaction)?;
        println!("{}", serde_json::to_string(&finished)?);
        eprintln!("Safe {} restored offline.", finished.safe_id);
        Ok(0)
    })();
    finish_attempt(&prepared.transaction, result)
}

fn finish_import(transaction: &str) -> control::Result<backup::Finished> {
    let request = backup::Finish { transaction: transaction.into(), password: Zeroizing::new(String::from_utf8(
        super::password("Original Safe password", false)?.to_vec(),
    )?) };
    let body = Zeroizing::new(serde_json::to_vec(&request)?);
    drop(request);
    let response = control::request("backup-import-finish", None, &body);
    drop(body);
    let finished: backup::Finished = match response {
        Ok(response) => serde_json::from_str(&response)?,
        Err(error) => match committed(&status()?, transaction)? {
            Some(finished) => {
                eprintln!("Restoration was confirmed by status after the connection ended; it was not repeated.");
                finished
            }
            None => return Err(error),
        },
    };
    if finished.transaction != transaction || !managed::id(&finished.safe_id) { return Err("invalid_backup_completion".into()); }
    Ok(finished)
}

fn finish_attempt(transaction: &str, result: control::Result<i32>) -> control::Result<i32> {
    if result.is_err() {
        eprintln!("Personal backup transaction {transaction}. Inspect `oblivion backup status --json`; do not repeat an uncertain restore.");
        if let Err(error) = control::request("backup-cancel", Some(transaction), &[]) {
            eprintln!("Backup cleanup needs review: {error}");
        }
    }
    result
}

fn status() -> control::Result<backup::Status> {
    let status: backup::Status = serde_json::from_str(&control::request("backup-status", None, &[])?)?;
    let mut ids = std::collections::BTreeSet::new();
    if status.transactions.iter().any(|entry| !managed::id(&entry.transaction) || !ids.insert(&entry.transaction)
        || entry.safe_id.as_ref().is_some_and(|id| !managed::id(id)) || entry.bytes.is_some_and(|bytes| !volume_size(bytes))) {
        return Err("invalid_backup_status".into());
    }
    Ok(status)
}

fn copied(transaction: &str) -> control::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = status()?;
        let entry = status.transactions.iter().find(|entry| entry.transaction == transaction).ok_or("backup_status_missing")?;
        if entry.outcome == backup::Outcome::Copied && !entry.active { return Ok(()); }
        if !matches!(entry.outcome, backup::Outcome::Prepared | backup::Outcome::Copying | backup::Outcome::Copied) || Instant::now() >= deadline {
            return Err("backup_copy_requires_recovery".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn committed(status: &backup::Status, transaction: &str) -> control::Result<Option<backup::Finished>> {
    let Some(entry) = status.transactions.iter().find(|entry| entry.transaction == transaction) else { return Ok(None) };
    if entry.kind != backup::Kind::Import || entry.outcome != backup::Outcome::Committed { return Ok(None); }
    let safe_id = entry.safe_id.as_ref().ok_or("invalid_backup_completion")?;
    Ok(Some(backup::Finished { transaction: transaction.into(), safe_id: safe_id.clone() }))
}

fn discard(transaction: &str) -> control::Result<i32> {
    let status = status()?;
    let entry = status.transactions.iter().find(|entry| entry.transaction == transaction).ok_or("Backup transaction not found")?;
    if entry.outcome == backup::Outcome::Committed || entry.active {
        return Err("A committed or active backup cannot be discarded".into());
    }
    eprintln!("Discard incomplete backup {transaction}. Existing Safes and committed restores remain intact.");
    if !super::init_commands::confirm("DISCARD")? { return Ok(130); }
    scope::within(entry.slot, || control::request("backup-discard", Some(transaction), &[]))?;
    eprintln!("Incomplete backup removed.");
    Ok(0)
}

fn outcome(outcome: backup::Outcome) -> &'static str {
    match outcome {
        backup::Outcome::Prepared => "Prepared",
        backup::Outcome::Copying => "Copying",
        backup::Outcome::Copied => "Copied",
        backup::Outcome::Committed => "Restored",
        backup::Outcome::RecoveryRequired => "Recovery required",
        backup::Outcome::Cancelled => "Cancelled",
    }
}

fn volume_size(bytes: u64) -> bool { (32 * 1024 * 1024..=MAX_ENCRYPTED_VOLUME_BYTES).contains(&bytes) }

struct OutputTarget { parent: PathBuf, name: std::ffi::OsString }
impl OutputTarget {
    fn new(path: &Path) -> control::Result<Self> {
        let path = std::path::absolute(path)?;
        let name = path.file_name().filter(|name| !name.is_empty()).ok_or("Choose an output filename")?.to_owned();
        let parent = path.parent().ok_or("Choose an output directory")?.canonicalize()?;
        if !parent.is_dir() { return Err("Choose an output directory".into()); }
        match fs::symlink_metadata(parent.join(&name)) {
            Ok(_) => return Err("The output file already exists".into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(Self { parent, name })
    }

    fn create(self, transaction: &str) -> control::Result<Output> {
        let temporary = self.parent.join(format!(".oblivion-backup-{transaction}.partial"));
        let file = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&temporary)?;
        if file.metadata()?.uid() != unsafe { libc::getuid() } { return Err("unsafe_backup_output".into()); }
        Ok(Output { target: self.parent.join(self.name), temporary: Some(temporary), file })
    }
}

struct Output { target: PathBuf, temporary: Option<PathBuf>, file: File }
impl Output {
    fn copy_file(&self) -> control::Result<File> { Ok(self.file.try_clone()?) }
    fn publish(&mut self) -> control::Result<()> {
        let temporary = self.temporary.as_ref().ok_or("backup_output_unavailable")?;
        let metadata = self.file.metadata()?;
        let path = fs::symlink_metadata(temporary)?;
        if !metadata.is_file() || metadata.uid() != unsafe { libc::getuid() } || metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
            return Err("unsafe_backup_output".into());
        }
        if path.dev() != metadata.dev() || path.ino() != metadata.ino() { return Err("backup_output_changed".into()); }
        self.file.sync_all()?;
        fs::hard_link(temporary, &self.target)?;
        fs::remove_file(temporary)?;
        self.temporary = None;
        File::open(self.target.parent().ok_or("backup_output_unavailable")?)?.sync_all()?;
        Ok(())
    }
}
impl Drop for Output {
    fn drop(&mut self) {
        if let Some(path) = self.temporary.take() {
            if fs::symlink_metadata(&path).ok().zip(self.file.metadata().ok())
                .is_some_and(|(path, file)| path.dev() == file.dev() && path.ino() == file.ino()) { let _ = fs::remove_file(path); }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn backup_parser_refuses_mixed_actions_or_password_arguments() {
        assert!(matches!(options(&["export".into(), "--safe".into(), "GB".into(), "backup.luks".into()]).unwrap(), Options::Export { safe: "GB", .. }));
        assert!(matches!(options(&["status".into(), "--json".into()]).unwrap(), Options::Status { json: true }));
        for args in [vec!["import", "file", "--password", "secret"], vec!["export", "--safe", "GB", "--safe", "file"], vec!["discard", "../outside"], vec!["status", "--json", "file"]] {
            assert!(options(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err());
        }
    }

    #[test]
    fn output_publication_is_private_and_never_overwrites_a_late_destination() {
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).unwrap();
        let id = random.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let root = std::env::temp_dir().join(format!("oblivion-backup-cli-{id}"));
        fs::create_dir(&root).unwrap();
        let target = root.join("personal.luks");
        let mut output = OutputTarget::new(&target).unwrap().create(&id).unwrap();
        output.copy_file().unwrap().write_all(b"encrypted bytes").unwrap();
        fs::write(&target, b"unrelated destination").unwrap();
        assert!(output.publish().is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unrelated destination");
        drop(output);
        assert!(!root.join(format!(".oblivion-backup-{id}.partial")).exists());
        fs::remove_file(&target).unwrap();
        let mut output = OutputTarget::new(&target).unwrap().create(&id).unwrap();
        output.copy_file().unwrap().write_all(b"complete ciphertext").unwrap();
        output.publish().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"complete ciphertext");
        assert_eq!(fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&target).unwrap().nlink(), 1);
        drop(output);
        fs::remove_file(&target).unwrap();
        let mut output = OutputTarget::new(&target).unwrap().create(&id).unwrap();
        output.copy_file().unwrap().write_all(b"verified inode").unwrap();
        let temporary = output.temporary.as_ref().unwrap().clone();
        fs::rename(&temporary, root.join("moved-original")).unwrap();
        fs::write(&temporary, b"unverified replacement").unwrap();
        assert!(output.publish().is_err());
        drop(output);
        assert!(!target.exists());
        assert_eq!(fs::read(temporary).unwrap(), b"unverified replacement");
        fs::remove_dir_all(root).unwrap();
    }
}
