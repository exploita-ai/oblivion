//! A maintenance lease delegates only one private portable-data stream.
use crate::storage::{Error, Result, require};
use oblivion_host::{autolock::Opening, scope};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Serialize)]
pub(crate) struct Metadata {
    pub opening: Opening,
    pub title: String,
    pub created_by_agent: bool,
    pub requested_agent: Option<String>,
    pub parent_not_included: bool,
    pub policy: &'static str,
    pub required_proxy: Option<String>,
}

pub(crate) fn require_closed_target(requested: &str, expected: &str, current: Option<&str>) -> Result<()> {
    require(requested == expected && current.is_none(), "session_changed")
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Client {
    version: u8,
    opening: Opening,
    import: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Maintenance { version: u8, opening: Opening }

fn directory() -> PathBuf { PathBuf::from(scope::current().runtime()).join("share-clients") }

/// This root-owned record survives partial teardown. An idle timeout for a
/// maintenance opening must not become a branch-close for its descendants.
pub(crate) fn maintenance_opening() -> Result<Option<Opening>> {
    let path = crate::storage::runtime_record("share-opening");
    if !path.try_exists().map_err(|_| Error("invalid_share_lease"))? { return Ok(None) }
    let record: Maintenance = serde_json::from_reader(crate::storage::trusted_file(&path)?.take(1025))
        .map_err(|_| Error("invalid_share_lease"))?;
    crate::storage::validate_id(&record.opening.safe_id)?;
    crate::storage::validate_id(&record.opening.nonce)?;
    require(record.version == 1 && record.opening.slot == scope::current(), "invalid_share_lease")?;
    Ok(Some(record.opening))
}

pub(crate) fn is_maintenance(opening: &Opening) -> Result<bool> {
    scope::within(opening.slot, || Ok(maintenance_opening()?.as_ref() == Some(opening)))
}

pub(crate) fn begin(opening: &Opening) -> Result<()> {
    require(opening.slot == scope::current() && maintenance_opening()?.is_none(), "share_maintenance_active")?;
    let encoded = serde_json::to_vec(&Maintenance { version: 1, opening: opening.clone() }).map_err(|_| Error("encode_failed"))?;
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(crate::storage::runtime_record("share-opening"))
        .map_err(|_| Error("share_lease_failed"))?;
    if file.write_all(&encoded).is_err() {
        drop(file);
        fs::remove_file(crate::storage::runtime_record("share-opening")).map_err(|_| Error("share_cleanup_required"))?;
        return Err(Error("share_lease_failed"));
    }
    Ok(())
}

pub(crate) fn occupied() -> Result<bool> {
    if !directory().try_exists().map_err(|_| Error("share_lease_failed"))? { return Ok(false) }
    let info = fs::symlink_metadata(directory()).map_err(|_| Error("share_lease_failed"))?;
    require(info.is_dir() && info.uid() == 0 && info.mode() & 0o077 == 0, "share_lease_failed")?;
    Ok(fs::read_dir(directory()).map_err(|_| Error("share_lease_failed"))?.next().is_some())
}

pub(crate) fn client(id: &str) -> Result<Opening> {
    Ok(client_record(id)?.opening)
}

pub(crate) fn import_client(id: &str) -> Result<Opening> {
    let record = client_record(id)?;
    require(record.import, "invalid_share_lease")?;
    Ok(record.opening)
}

fn client_record(id: &str) -> Result<Client> {
    crate::storage::validate_id(id)?;
    let record: Client = serde_json::from_reader(crate::storage::trusted_file(&directory().join(id))?.take(1025))
        .map_err(|_| Error("invalid_share_lease"))?;
    crate::storage::validate_id(&record.opening.safe_id)?;
    crate::storage::validate_id(&record.opening.nonce)?;
    require(record.version == 1 && record.opening.slot == scope::current(), "invalid_share_lease")?;
    Ok(record)
}

/// The caller holds storage.lock and later releases this exact opening through
/// share-release. It must never use the normal branch-closing agent callback.
pub(crate) fn attach(expected: &str) -> Result<(UnixStream, String, Opening)> {
    attach_role(expected, false)
}

pub(crate) fn attach_import(expected: &str) -> Result<(UnixStream, String, Opening)> {
    attach_role(expected, true)
}

fn attach_role(expected: &str, import: bool) -> Result<(UnixStream, String, Opening)> {
    require(crate::storage::session_info()?.is_some_and(|entry| entry.0 == expected && entry.1 == "share"), "session_changed")?;
    let imported = crate::storage::runtime_record("share-import");
    require(imported.try_exists().map_err(|_| Error("invalid_share_lease"))? == import, "invalid_share_lease")?;
    if import { crate::storage::trusted_file(&imported)?; }
    crate::storage::require_safe_branch_open(expected)?;
    require(!occupied()?, "share_already_attached")?;
    let opening = crate::storage::idle_opening()?.ok_or(Error("idle_opening_unknown"))?;
    let id = crate::storage::random_id()?;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(directory()).map_err(|_| Error("share_lease_failed"))?;
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(directory().join(&id)).map_err(|_| Error("share_lease_failed"))?;
    let encoded = serde_json::to_vec(&Client { version: 1, opening: opening.clone(), import }).map_err(|_| Error("encode_failed"))?;
    if file.write_all(&encoded).is_err() {
        drop(file);
        fs::remove_file(directory().join(&id)).map_err(|_| Error("share_cleanup_required"))?;
        return Err(Error("share_lease_failed"));
    }
    let result = crate::vm::share_port(&id, import).and_then(|port| {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let mut ready = [0; 6];
            let count = unsafe { libc::recv(port.as_raw_fd(), ready.as_mut_ptr().cast(), ready.len(), libc::MSG_PEEK | libc::MSG_DONTWAIT) };
            if count == ready.len() as isize {
                require(&ready == b"OBSH1\n", "share_not_ready")?;
                return Ok(port);
            }
            require(count != 0 && Instant::now() < deadline, "share_not_ready")?;
            if count < 0 {
                require(matches!(std::io::Error::last_os_error().kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted), "share_not_ready")?;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    match result {
        Ok(port) => Ok((port, id, opening)),
        Err(error) => {
            fs::remove_file(directory().join(&id)).map_err(|_| Error("share_cleanup_required"))?;
            crate::vm::remove_copy_port(&id).map_err(|_| Error("share_cleanup_required"))?;
            Err(error)
        }
    }
}

pub(crate) fn clear() -> Result<()> {
    if directory().try_exists().map_err(|_| Error("share_lease_failed"))? {
        occupied()?;
        fs::remove_dir_all(directory()).map_err(|_| Error("share_cleanup_required"))?;
    }
    if maintenance_opening()?.is_some() {
        fs::remove_file(crate::storage::runtime_record("share-opening")).map_err(|_| Error("share_cleanup_required"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_export_binds_the_selected_identity_without_adopting_an_open_slot() {
        let safe = "11111111111111111111111111111111";
        let other = "22222222222222222222222222222222";
        assert!(require_closed_target(safe, safe, None).is_ok());
        assert!(require_closed_target(other, safe, None).is_err());
        assert!(require_closed_target(safe, safe, Some(safe)).is_err());
        assert!(require_closed_target(safe, safe, Some(other)).is_err());
    }

    #[test]
    #[ignore = "requires isolated root-owned tmpfs /run; no production state"]
    fn maintenance_idle_authority_is_bound_to_exact_slot_identity_and_nonce() {
        assert_eq!(std::env::var("OBLIVION_SHARE_HOST_TEST").as_deref(), Ok("1"));
        assert_eq!(unsafe { libc::geteuid() }, 0);
        fs::DirBuilder::new().mode(0o700).create("/run/oblivion").unwrap();
        let opening = Opening { slot: Default::default(), safe_id: "11111111111111111111111111111111".into(), nonce: "22222222222222222222222222222222".into() };
        assert!(!is_maintenance(&opening).unwrap_or_else(|error| panic!("{}", error.0)));
        begin(&opening).unwrap_or_else(|error| panic!("{}", error.0));
        assert!(is_maintenance(&opening).unwrap_or_else(|error| panic!("{}", error.0)));
        let mut reopened = opening.clone();
        reopened.nonce = "33333333333333333333333333333333".into();
        assert!(!is_maintenance(&reopened).unwrap_or_else(|error| panic!("{}", error.0)));
        let mut other = opening.clone();
        other.safe_id = "44444444444444444444444444444444".into();
        assert!(!is_maintenance(&other).unwrap_or_else(|error| panic!("{}", error.0)));
        other = opening.clone();
        other.slot = 1.try_into().unwrap();
        assert!(!is_maintenance(&other).unwrap_or_else(|error| panic!("{}", error.0)));
        assert!(begin(&reopened).is_err());
        clear().unwrap_or_else(|error| panic!("{}", error.0));
        assert!(!is_maintenance(&opening).unwrap_or_else(|error| panic!("{}", error.0)));
    }
}
