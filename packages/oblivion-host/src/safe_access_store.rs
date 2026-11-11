use crate::storage::{Error, Result, require, trusted_file};
use oblivion_host::safe_access::Status;
use oblivion_transport::policy::Access;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub fn status(open: bool) -> Result<Status> {
    if !open || crate::storage::session_info()?.is_none() {
        return Ok(Status::new(None, None));
    }
    Ok(Status::new(
        read_profile(&crate::storage::network_profile()?.join("access.json"))?,
        read_profile(&crate::storage::runtime_record("access.json"))?,
    ))
}

pub fn set(mode: Access, save: bool) -> Result<()> {
    require(
        crate::storage::session_info()?.is_some(),
        "session_not_open",
    )?;
    let temporary = crate::storage::runtime_record("access.json");
    let path = if save {
        crate::storage::network_profile()?.join("access.json")
    } else {
        temporary.clone()
    };
    write(&path, mode)?;
    if save
        && temporary
            .try_exists()
            .map_err(|_| Error("safe_access_unavailable"))?
    {
        fs::remove_file(temporary).map_err(|_| Error("safe_access_save_failed"))?;
    }
    Ok(())
}

pub fn write(path: &Path, mode: Access) -> Result<()> {
    let pending = path.with_extension("pending");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&pending)
        .map_err(|_| Error("safe_access_save_failed"))?;
    file.write_all(&serde_json::to_vec(&mode).map_err(|_| Error("encode_failed"))?)
        .and_then(|_| file.sync_all())
        .map_err(|_| Error("safe_access_save_failed"))?;
    fs::rename(pending, path).map_err(|_| Error("safe_access_save_failed"))?;
    File::open(path.parent().ok_or(Error("invalid_path"))?)
        .and_then(|file| file.sync_all())
        .map_err(|_| Error("safe_access_save_failed"))
}

pub(crate) fn read_profile(path: &Path) -> Result<Option<Access>> {
    if !path
        .try_exists()
        .map_err(|_| Error("safe_access_unavailable"))?
    {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    trusted_file(path)?
        .take(129)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("safe_access_unavailable"))?;
    require(bytes.len() <= 128, "invalid_safe_access")?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| Error("invalid_safe_access"))
}
