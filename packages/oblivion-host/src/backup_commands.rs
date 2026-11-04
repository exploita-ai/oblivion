//! Native full-volume personal recovery. Portable Share is a separate command.
use oblivion_cli::backup::Command;
use oblivion_host::{backup, control, managed, scope};
use oblivion_transfer::channel::Channel;
use oblivion_transfer::{MAX_ENCRYPTED_VOLUME_BYTES, Selection, stream};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn run(command: Command) -> control::Result<i32> {
    let mut runtime = super::UnixRuntime::new();
    match command {
        Command::Control(command) => oblivion_cli::backup::execute(
            &mut runtime,
            command,
            &mut io::stdout(),
            &mut io::stderr(),
        ),
        Command::Export { safe, path } => {
            let state = oblivion_cli::backup::writable_state(&mut runtime)?;
            if state.recovery_required {
                return Err("Complete recovery before exporting a personal backup".into());
            }
            let id = state.find_safe(&safe)?.ok_or("Safe not found")?;
            if !state.sessions.contains(&id) {
                return Err("Personal backups require a persistent Safe".into());
            }
            if state
                .open_sessions
                .iter()
                .any(|safe| safe.id.as_ref() == Some(&id))
            {
                return Err("Close the Safe before exporting its personal backup".into());
            }
            let destination = OutputTarget::new(Path::new(&path))?;
            let slot = oblivion_cli::run::free_slot(&runtime, &state)?;
            scope::within(slot, || export(&mut runtime, &id, destination, slot))
        }
        Command::Import { path } => {
            let state = oblivion_cli::backup::writable_state(&mut runtime)?;
            if state.recovery_required {
                return Err("Complete recovery before importing a personal backup".into());
            }
            let source = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(std::path::absolute(path)?)?;
            let mut selection = Selection::encrypted_volume(source, MAX_ENCRYPTED_VOLUME_BYTES)?;
            let slot = oblivion_cli::run::free_slot(&runtime, &state)?;
            scope::within(slot, || import(&mut runtime, &mut selection, slot))
        }
    }
}

fn export(
    runtime: &mut super::UnixRuntime,
    id: &str,
    destination: OutputTarget,
    slot: scope::Slot,
) -> control::Result<i32> {
    eprintln!(
        "A personal backup contains the complete encrypted Safe, including saved logins and installed software. Keep its original Safe password."
    );
    let prepared: backup::Exported = serde_json::from_str(&control::request_for(
        id,
        "backup-export-begin",
        Some(id),
        &super::password("Safe password", false)?,
    )?)
    .map_err(|_| "invalid_backup_preparation")?;
    if !managed::id(&prepared.transaction) {
        return Err("invalid_backup_preparation".into());
    }
    if prepared.safe_id != id || !oblivion_wire::backup::volume_size(prepared.bytes) {
        return oblivion_cli::backup::finish_attempt(
            runtime,
            &prepared.transaction,
            slot,
            Err("invalid_backup_preparation".into()),
            &mut io::stderr(),
        );
    }
    let result = (|| -> control::Result<i32> {
        let mut output = destination.create(&prepared.transaction)?;
        let (connection, lease, _) = control::attach_backup(&prepared.transaction)?;
        let mut channel = Channel::new(
            File::from(OwnedFd::from(connection)),
            Duration::from_secs(3600),
        )?;
        let copy_result = stream::download_open_file(
            &mut channel,
            output.copy_file()?,
            prepared.bytes,
            &prepared.transaction,
        );
        drop(channel);
        drop(lease);
        let receipt = copy_result?;
        if receipt.id != prepared.transaction
            || receipt.entries != 1
            || receipt.bytes != prepared.bytes
        {
            return Err("invalid_backup_receipt".into());
        }
        oblivion_cli::backup::copied(runtime, &prepared.transaction, slot)?;
        output.publish()?;
        println!("{}", serde_json::to_string(&receipt)?);
        eprintln!("Personal backup saved to {}", output.target.display());
        Ok(0)
    })();
    oblivion_cli::backup::finish_attempt(
        runtime,
        &prepared.transaction,
        slot,
        result,
        &mut io::stderr(),
    )
}

fn import(
    runtime: &mut super::UnixRuntime,
    selection: &mut Selection,
    slot: scope::Slot,
) -> control::Result<i32> {
    eprintln!(
        "Restore the complete Safe with its original identity and saved logins. It will remain offline after restoration."
    );
    let prepared: backup::Imported =
        serde_json::from_str(&control::request("backup-import-begin", None, &[])?)
            .map_err(|_| "invalid_backup_preparation")?;
    if !managed::id(&prepared.transaction) {
        return Err("invalid_backup_preparation".into());
    }
    if !oblivion_wire::backup::volume_size(prepared.maximum) {
        return oblivion_cli::backup::finish_attempt(
            runtime,
            &prepared.transaction,
            slot,
            Err("invalid_backup_preparation".into()),
            &mut io::stderr(),
        );
    }
    let result = (|| -> control::Result<i32> {
        if selection.manifest().bytes() > prepared.maximum {
            return Err("insufficient_restore_space".into());
        }
        let (connection, lease, _) = control::attach_backup(&prepared.transaction)?;
        let mut channel = Channel::new(
            File::from(OwnedFd::from(connection)),
            Duration::from_secs(3600),
        )?;
        let receipt = stream::send(&mut channel, selection, &prepared.transaction);
        drop(channel);
        drop(lease);
        receipt?;
        oblivion_cli::backup::copied(runtime, &prepared.transaction, slot)?;
        let finished = oblivion_cli::backup::finish_import(
            runtime,
            &prepared.transaction,
            slot,
            &mut io::stderr(),
        )?;
        println!("{}", serde_json::to_string(&finished)?);
        eprintln!("Safe {} restored offline.", finished.safe_id);
        Ok(0)
    })();
    oblivion_cli::backup::finish_attempt(
        runtime,
        &prepared.transaction,
        slot,
        result,
        &mut io::stderr(),
    )
}

struct OutputTarget {
    parent: PathBuf,
    name: std::ffi::OsString,
}
impl OutputTarget {
    fn new(path: &Path) -> control::Result<Self> {
        let path = std::path::absolute(path)?;
        let name = path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or("Choose an output filename")?
            .to_owned();
        let parent = path
            .parent()
            .ok_or("Choose an output directory")?
            .canonicalize()?;
        if !parent.is_dir() {
            return Err("Choose an output directory".into());
        }
        match fs::symlink_metadata(parent.join(&name)) {
            Ok(_) => return Err("The output file already exists".into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(Self { parent, name })
    }

    fn create(self, transaction: &str) -> control::Result<Output> {
        let temporary = self
            .parent
            .join(format!(".oblivion-backup-{transaction}.partial"));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        if file.metadata()?.uid() != unsafe { libc::getuid() } {
            return Err("unsafe_backup_output".into());
        }
        Ok(Output {
            target: self.parent.join(self.name),
            temporary: Some(temporary),
            file,
        })
    }
}

struct Output {
    target: PathBuf,
    temporary: Option<PathBuf>,
    file: File,
}
impl Output {
    fn copy_file(&self) -> control::Result<File> {
        Ok(self.file.try_clone()?)
    }
    fn publish(&mut self) -> control::Result<()> {
        let temporary = self.temporary.as_ref().ok_or("backup_output_unavailable")?;
        let metadata = self.file.metadata()?;
        let path = fs::symlink_metadata(temporary)?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::getuid() }
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err("unsafe_backup_output".into());
        }
        if path.dev() != metadata.dev() || path.ino() != metadata.ino() {
            return Err("backup_output_changed".into());
        }
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
            if fs::symlink_metadata(&path)
                .ok()
                .zip(self.file.metadata().ok())
                .is_some_and(|(path, file)| path.dev() == file.dev() && path.ino() == file.ino())
            {
                let _ = fs::remove_file(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OutputTarget;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn output_publication_is_private_and_never_overwrites_a_late_destination() {
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).unwrap();
        let id = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let root = std::env::temp_dir().join(format!("oblivion-backup-cli-{id}"));
        fs::create_dir(&root).unwrap();
        let target = root.join("personal.luks");
        let mut output = OutputTarget::new(&target).unwrap().create(&id).unwrap();
        output
            .copy_file()
            .unwrap()
            .write_all(b"encrypted bytes")
            .unwrap();
        fs::write(&target, b"unrelated destination").unwrap();
        assert!(output.publish().is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unrelated destination");
        drop(output);
        assert!(!root.join(format!(".oblivion-backup-{id}.partial")).exists());
        fs::remove_file(&target).unwrap();
        let mut output = OutputTarget::new(&target).unwrap().create(&id).unwrap();
        output
            .copy_file()
            .unwrap()
            .write_all(b"complete ciphertext")
            .unwrap();
        output.publish().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"complete ciphertext");
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::metadata(&target).unwrap().nlink(), 1);
        drop(output);
        fs::remove_file(&target).unwrap();
        let mut output = OutputTarget::new(&target).unwrap().create(&id).unwrap();
        output
            .copy_file()
            .unwrap()
            .write_all(b"verified inode")
            .unwrap();
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
