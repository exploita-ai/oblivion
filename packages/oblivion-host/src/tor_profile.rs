//! Selective Tor infrastructure state in the already unlocked private profile.
//! Model and file-transfer gateways never share a state file or fallback.
use oblivion_tor_state::State;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

#[derive(Clone, Copy)]
pub enum Purpose {
    Model,
    Transfer,
}

impl Purpose {
    fn filename(self) -> &'static str {
        match self {
            // Retain compatibility with existing model gateway profiles.
            Self::Model => "tor-state",
            Self::Transfer => "onion-tor-state",
        }
    }
}

pub fn load(profile: &Path, purpose: Purpose) -> Result<Option<State>, &'static str> {
    directory(profile)?;
    let Some(file) = state_file(&profile.join(purpose.filename()))? else {
        return Ok(None);
    };
    let mut text = String::new();
    file.take(oblivion_tor_state::LIMIT as u64 + 1)
        .read_to_string(&mut text)
        .map_err(|_| "profile_unavailable")?;
    State::parse(&text)
        .map(Some)
        .map_err(|_| "invalid_tor_state")
}

/// The caller must first enforce its general-vault writable/ephemeral policy.
/// Only State::parse/select can construct the accepted selective state value.
pub fn save(profile: &Path, purpose: Purpose, state: &State) -> Result<(), &'static str> {
    let directory = directory(profile)?;
    let path = profile.join(purpose.filename());
    state_file(&path)?;
    let pending = path.with_extension("pending");
    if state_file(&pending)?.is_some() {
        fs::remove_file(&pending).map_err(|_| "profile_write_failed")?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&pending)
        .map_err(|_| "profile_write_failed")?;
    file.write_all(state.as_str().as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| "profile_write_failed")?;
    fs::rename(pending, path).map_err(|_| "profile_write_failed")?;
    directory.sync_all().map_err(|_| "sync_failed")
}

fn directory(path: &Path) -> Result<File, &'static str> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open(path)
        .map_err(|_| "profile_unavailable")?;
    let metadata = directory.metadata().map_err(|_| "profile_unavailable")?;
    // The controller is root; native filesystem tests use their current owner.
    // No owner or profile path can be supplied by the private client protocol.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err("unsafe_profile");
    }
    Ok(directory)
}

fn state_file(path: &Path) -> Result<Option<File>, &'static str> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("file_unavailable"),
    };
    let metadata = file.metadata().map_err(|_| "metadata_failed")?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err("unsafe_file");
    }
    Ok(Some(file))
}
