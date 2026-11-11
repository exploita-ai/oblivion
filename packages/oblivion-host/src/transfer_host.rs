use crate::storage::{Error, Result, require};
use crate::vm::{self, Role};
use oblivion_host::channel::Channel;
use oblivion_host::transfers::{self, Source, SourceKind, Started, Status};
use oblivion_transfer::relay::{self, Permit};
use oblivion_wire::live_media::{DETACHED, Direction, Purpose, STOP};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn unit() -> String { oblivion_host::scope::owner("oblivion-transfer-host") }
fn job_path() -> String { oblivion_host::scope::path("/run/oblivion/transfer.json") }
fn pending_job() -> String { oblivion_host::scope::path("/run/oblivion/transfer.pending") }

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Job {
    id: String,
    live_media: Option<Purpose>,
    recovery: bool,
    export: bool,
    backup: Option<Backup>,
    restore: Option<Restore>,
}

impl Job {
    fn matches_live(&self, id: &str, direction: Direction) -> bool {
        self.live_media.is_some() && self.id == id && self.export == (direction == Direction::Export)
    }
}

fn live_uid(direction: Direction) -> u32 {
    oblivion_host::scope::uid(match direction {
        Direction::Import => vm::IMPORT_UID,
        Direction::Export => vm::EXPORT_UID,
    })
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Backup {
    session: String,
    bytes: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Restore {
    maximum: u64,
}

pub fn status(configured: bool, export_configured: bool, general: &Path) -> Result<Status> {
    Ok(Status {
        configured,
        export_configured,
        active: !matches!(vm::unit_state(&unit())?.as_str(), "inactive" | "failed"),
        sources: if configured || export_configured {
            sources(general)?
        } else {
            Vec::new()
        },
    })
}

fn sources(general: &Path) -> Result<Vec<Source>> {
    let entries: Vec<_> = fs::read_dir("/sys/class/block")
        .map_err(|_| Error("device_list_failed"))?
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| fs::canonicalize(entry.path()).ok())
        .collect();
    let mounted =
        fs::read_to_string("/proc/self/mountinfo").map_err(|_| Error("mount_check_failed"))?;
    let metadata = fs::metadata(general).map_err(|_| Error("image_check_failed"))?;
    let backing = if metadata.file_type().is_block_device() {
        metadata.rdev()
    } else {
        metadata.dev()
    };
    let backing_path = fs::canonicalize(format!(
        "/sys/dev/block/{}:{}",
        libc::major(backing),
        libc::minor(backing)
    ))
    .ok();
    require(
        !metadata.file_type().is_block_device() || backing_path.is_some(),
        "image_check_failed",
    )?;
    let backing_disk = backing_path.as_ref().and_then(|path| {
        if path.join("partition").exists() {
            path.parent()
        } else {
            Some(path.as_path())
        }
    });
    let mut devices = Vec::new();
    for path in &entries {
        // Exclude the entire live/profile USB, including its boot partitions.
        if backing_disk.is_some_and(|disk| path.starts_with(disk)) {
            continue;
        }
        // Offer leaf devices only. A partitioned whole disk must never bypass
        // the exclusion of a mounted partition or the live/profile medium.
        if entries
            .iter()
            .any(|child| child.parent() == Some(path.as_path()))
        {
            continue;
        }
        let usb = path.ancestors().any(|parent| {
            fs::read_link(parent.join("subsystem"))
                .ok()
                .is_some_and(|link| link.ends_with("usb"))
        });
        let disk = if path.join("partition").exists() {
            path.parent().ok_or(Error("invalid_device"))?
        } else {
            path.as_path()
        };
        let serial = fs::read_to_string(disk.join("serial")).unwrap_or_default();
        let virtio = virtio_disk(disk);
        // A virtual drive is opt-in through the supplied import/export profile.
        // Arbitrary internal disks never become eligible merely by being virtio.
        let Some(kind) = SourceKind::detect(
            usb,
            virtio || cfg!(feature = "lab-emulation"),
            serial.trim(),
        ) else {
            continue;
        };
        // A device leased to another session must not be mounted twice. This
        // also covers read/write aliases while an export is still being set up.
        if fs::read_dir(path.join("holders")).map_or(true, |mut entries| entries.next().is_some()) {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            continue;
        }
        let Ok(id) = fs::read_to_string(path.join("dev")) else {
            continue;
        };
        let id = id.trim();
        if mounted
            .lines()
            .any(|line| line.split_whitespace().nth(2) == Some(id))
        {
            continue;
        }
        let Some((major, minor)) = id.split_once(':').and_then(|(major, minor)| {
            Some((major.parse::<u32>().ok()?, minor.parse::<u32>().ok()?))
        }) else {
            continue;
        };
        if libc::major(backing) == major && libc::minor(backing) == minor {
            continue;
        }
        let Some(bytes) = fs::read_to_string(path.join("size"))
            .ok()
            .and_then(|n| n.trim().parse::<u64>().ok())
            .and_then(|n| n.checked_mul(512))
            .filter(|n| *n > 0)
        else {
            continue;
        };
        devices.push(Source {
            id: id.to_owned(),
            name: name.to_owned(),
            bytes,
            kind,
            read_only: serial.trim() == "oblivion-import"
                || fs::read_to_string(path.join("ro")).map_or(true, |value| value.trim() != "0"),
        });
    }
    devices.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(devices)
}

pub fn start(source: &str, general: &Path, export: bool) -> Result<Started> {
    idle()?;
    prepare_device(source, general, export)?;
    start_job(false, export, None, None)
}

fn prepare_device(source: &str, general: &Path, export: bool) -> Result<()> {
    let source = sources(general)?
        .into_iter()
        .find(|device| device.id == source)
        .ok_or(Error("source_not_available"))?;
    let path = format!("/dev/{}", source.name);
    require(!export || !source.read_only, "source_read_only")?;
    let device = OpenOptions::new()
        .read(true)
        .write(export)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error("source_not_available"))?;
    let metadata = device
        .metadata()
        .map_err(|_| Error("source_not_available"))?;
    require(
        metadata.file_type().is_block_device()
            && format!(
                "{}:{}",
                libc::major(metadata.rdev()),
                libc::minor(metadata.rdev())
            ) == source.id,
        "source_changed",
    )?;
    map_device(&source, export)
}

fn virtio_disk(disk: &Path) -> bool {
    disk.ancestors().any(|parent| {
        fs::read_link(parent.join("subsystem"))
            .ok()
            .is_some_and(|link| link.ends_with("virtio"))
    })
}

fn map_device(source: &Source, export: bool) -> Result<()> {
    let name = oblivion_host::scope::current().mapping(if export {
        "oblivion-export"
    } else {
        "oblivion-import"
    });
    let uid = if export {
        oblivion_host::scope::uid(vm::EXPORT_UID)
    } else {
        oblivion_host::scope::uid(vm::IMPORT_UID)
    };
    let mut args = vec!["create".into(), name];
    if !export {
        args.push("--readonly".into());
    }
    args.extend([
        "--table".into(),
        format!("0 {} linear {} 0", source.bytes / 512, source.id),
    ]);
    vm::execute("/usr/sbin/dmsetup", &args)?;
    let path = oblivion_host::scope::path(if export { vm::EXPORT_DEVICE } else { vm::IMPORT_DEVICE });
    require(
        unsafe {
            libc::chown(
                CString::new(path.as_str())
                    .map_err(|_| Error("invalid_device"))?
                    .as_ptr(),
                uid,
                uid,
            )
        } == 0,
        "device_owner_failed",
    )?;
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if export { 0o600 } else { 0o400 }),
    )
    .map_err(|_| Error("device_permissions_failed"))?;
    Ok(())
}

pub fn start_backup(session: &str, target: &str, general: &Path) -> Result<Started> {
    idle()?;
    let file = crate::storage::closed_session_file(session)?;
    let bytes = file
        .metadata()
        .map_err(|_| Error("image_check_failed"))?
        .len();
    require(
        (32 * 1024 * 1024..=oblivion_transfer::MAX_ENCRYPTED_VOLUME_BYTES).contains(&bytes),
        "invalid_backup_size",
    )?;
    prepare_device(target, general, true)?;
    start_job(
        false,
        true,
        Some(Backup {
            session: session.into(),
            bytes,
        }),
        None,
    )
}

pub fn start_restore(source: &str, general: &Path) -> Result<Started> {
    idle()?;
    let maximum = crate::storage::restore_budget()?;
    prepare_device(source, general, false)?;
    start_job(false, false, None, Some(Restore { maximum }))
}

pub fn archiving() -> Result<bool> {
    Ok(job()?.is_some_and(|job| job.backup.is_some() || job.restore.is_some()))
}

pub fn start_recovery() -> Result<Started> {
    idle()?;
    start_job(true, false, None, None)
}

pub fn idle() -> Result<()> {
    require(
        matches!(vm::unit_state(&unit())?.as_str(), "inactive" | "failed")
            && vm::stopped_role(Role::Import)?
            && vm::stopped_role(Role::Export)?,
        "transfer_already_running",
    )?;
    for path in [job_path(), pending_job(), oblivion_host::scope::path(vm::IMPORT_DEVICE), oblivion_host::scope::path(vm::EXPORT_DEVICE)] {
        require(!Path::new(&path).try_exists().map_err(|_| Error("transfer_state_failed"))?, "transfer_cleanup_required")?;
    }
    Ok(())
}

fn start_job(
    recovery: bool,
    export: bool,
    backup: Option<Backup>,
    restore: Option<Restore>,
) -> Result<Started> {
    let id = crate::storage::random_id()?;
    let bytes = backup
        .as_ref()
        .map(|backup| backup.bytes)
        .or_else(|| restore.as_ref().map(|restore| restore.maximum));
    publish_job(&Job {
        id: id.clone(),
        live_media: None,
        recovery,
        export,
        backup,
        restore,
    })?;
    vm::execute("/usr/bin/systemctl", &["start".into(), unit()])?;
    Ok(Started { id, bytes })
}

fn publish_job(record: &Job) -> Result<()> {
    let encoded = serde_json::to_vec(record).map_err(|_| Error("transfer_state_failed"))?;
    require(!Path::new(&job_path()).exists(), "transfer_already_running")?;
    let mut job = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&pending_job())
        .map_err(|_| Error("transfer_state_failed"))?;
    let published = job.write_all(&encoded)
        .and_then(|()| job.sync_all())
        .and_then(|()| fs::rename(pending_job(), job_path()));
    // The storage operation lock serializes starts. Publish only a complete
    // record so interruption cannot leave an undecodable live job.
    if published.is_err() {
        fs::remove_file(pending_job()).map_err(|_| Error("transfer_state_failed"))?;
        return Err(Error("transfer_state_failed"));
    }
    Ok(())
}

/// The live outer helper attached exactly one direction-bound virtio disk. Its
/// kernel-assigned block device is selected by the reserved serial, not by a
/// path, numeric device, partition or size supplied by the launcher.
pub struct LiveDevice {
    source: Source,
    file: File,
}

pub fn wait_live_media(
    id: &str,
    direction: Direction,
    mut check: impl FnMut() -> Result<()>,
) -> Result<LiveDevice> {
    crate::storage::validate_id(id)?;
    let serial = format!("obl-{}", &id[..16]);
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        check()?;
        match live_media_device(Path::new("/sys"), &serial, direction).and_then(open_live_device) {
            Err(Error("live_media_device_unavailable")) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(25));
            }
            result => return result,
        }
    }
}

fn open_live_device(source: Source) -> Result<LiveDevice> {
    let file = OpenOptions::new()
        .read(true)
        .write(!source.read_only)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(format!("/dev/{}", source.name))
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ENODEV)
            {
                Error("live_media_device_unavailable")
            } else {
                Error("invalid_live_media_device")
            }
        })?;
    let device = LiveDevice { source, file };
    verify_live_device(&device)?;
    Ok(device)
}

fn verify_live_device(device: &LiveDevice) -> Result<()> {
    let file = &device.file;
    let source = &device.source;
    let info = file
        .metadata()
        .map_err(|_| Error("live_media_device_unavailable"))?;
    let mut read_only: libc::c_int = 0;
    let mut bytes: u64 = 0;
    require(
        info.file_type().is_block_device()
            && source.id == format!("{}:{}", libc::major(info.rdev()), libc::minor(info.rdev()))
            && unsafe { libc::ioctl(file.as_raw_fd(), 0x125e, &mut read_only) } == 0
            && read_only == i32::from(source.read_only)
            && unsafe { libc::ioctl(file.as_raw_fd(), 0x80081272, &mut bytes) } == 0
            && bytes == source.bytes,
        "live_media_device_changed",
    )
}

pub fn start_live_media(
    id: &str,
    direction: Direction,
    purpose: Purpose,
    device: &LiveDevice,
) -> Result<()> {
    crate::storage::validate_id(id)?;
    let current = live_media_device(Path::new("/sys"), &format!("obl-{}", &id[..16]), direction)?;
    require(
        current.id == device.source.id
            && current.name == device.source.name
            && current.bytes == device.source.bytes
            && current.read_only == device.source.read_only,
        "live_media_device_changed",
    )?;
    verify_live_device(device)?;
    require(!live_mapping_present(direction)?, "transfer_cleanup_required")?;
    let export = direction == Direction::Export;
    // Publish exact cleanup authority before the first external mutation.
    publish_job(&Job {
        id: id.into(),
        live_media: Some(purpose),
        recovery: false,
        export,
        backup: None,
        restore: None,
    })?;
    map_device(&current, export)?;
    vm::execute(
        "/usr/bin/systemctl",
        &["start".into(), "--no-block".into(), unit()],
    )
}

fn live_media_device(sysfs: &Path, serial: &str, direction: Direction) -> Result<Source> {
    let read_only = direction == Direction::Import;
    let mut found = None;
    let entries = fs::read_dir(sysfs.join("class/block"))
        .map_err(|_| Error("live_media_device_unavailable"))?;
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let Ok(disk) = fs::canonicalize(entry.path()) else {
            continue;
        };
        if !disk.starts_with(sysfs.join("devices"))
            || !fs::read_to_string(disk.join("serial")).is_ok_and(|value| value.trim() == serial)
        {
            continue;
        }
        let virtio_block = disk.ancestors().any(|device| {
            fs::read_link(device.join("subsystem")).is_ok_and(|link| link.ends_with("virtio"))
                && fs::read_link(device.join("driver")).is_ok_and(|link| link.ends_with("virtio_blk"))
        });
        require(
            found.is_none()
                && virtio_block
                && !disk.join("partition").exists()
                && fs::read_to_string(disk.join("ro"))
                    .is_ok_and(|value| value.trim() == if read_only { "1" } else { "0" }),
            "invalid_live_media_device",
        )?;
        let name = disk
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| {
                value.len() <= 64 && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
            })
            .ok_or(Error("invalid_live_media_device"))?;
        let id =
            fs::read_to_string(disk.join("dev")).map_err(|_| Error("invalid_live_media_device"))?;
        let id = id.trim();
        let valid = id.split_once(':').is_some_and(|(major, minor)| {
            major.parse::<u32>().is_ok() && minor.parse::<u32>().is_ok()
        });
        require(valid, "invalid_live_media_device")?;
        let bytes = fs::read_to_string(disk.join("size"))
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .and_then(|sectors| sectors.checked_mul(512))
            .filter(|bytes| *bytes > 0)
            .ok_or(Error("invalid_live_media_device"))?;
        found = Some(Source {
            id: id.into(),
            name: name.into(),
            bytes,
            kind: SourceKind::Virtual,
            read_only,
        });
    }
    found.ok_or(Error("live_media_device_unavailable"))
}

#[cfg(test)]
mod live_media_device_tests {
    use super::{Job, live_media_device, wait_export_flush};
    use oblivion_wire::live_media::Direction::{Export, Import};
    use oblivion_wire::live_media::{DETACHED, STOP};
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};

    #[test]
    fn job_requires_explicit_operation_flags() {
        let record = serde_json::to_value(Job {
            id: "a".repeat(32),
            live_media: None,
            recovery: false,
            export: false,
            backup: None,
            restore: None,
        }).unwrap();
        assert!(serde_json::from_value::<Job>(record.clone()).is_ok());
        for field in ["recovery", "export"] {
            let mut incomplete = record.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Job>(incomplete).is_err());
        }
    }

    struct Tree(PathBuf);

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn disk(sysfs: &Path, name: &str, serial: &str, number: &str) -> PathBuf {
        let device = sysfs.join("devices/pci").join(format!("virtio-{name}"));
        let disk = device.join("block").join(name);
        fs::create_dir_all(&disk).unwrap();
        symlink("/sys/bus/virtio", device.join("subsystem")).unwrap();
        symlink("/sys/bus/virtio/drivers/virtio_blk", device.join("driver")).unwrap();
        for (entry, value) in [
            ("serial", serial),
            ("ro", "1"),
            ("size", "2048"),
            ("dev", number),
        ] {
            fs::write(disk.join(entry), format!("{value}\n")).unwrap();
        }
        symlink(&disk, sysfs.join("class/block").join(name)).unwrap();
        disk
    }

    #[test]
    fn media_resolves_only_one_exact_virtio_serial_with_the_requested_access() {
        let id = crate::storage::random_id().unwrap_or_else(|error| panic!("{}", error.0));
        let root = Tree(std::env::temp_dir().join(format!("oblivion-live-media-{id}")));
        fs::create_dir_all(root.0.join("class/block")).unwrap();
        let serial = "obl-1234567890abcdef";
        let foreign = disk(&root.0, "vda", "oblivion-import", "253:0");
        let source = disk(&root.0, "vdb", serial, "253:16");
        assert!(live_media_device(&root.0, "obl-1234567890abcdee", Import).is_err());
        let selected =
            live_media_device(&root.0, serial, Import).unwrap_or_else(|error| panic!("{}", error.0));
        assert_eq!(selected.name, "vdb");
        assert_eq!(selected.bytes, 1024 * 1024);
        assert!(live_media_device(&root.0, serial, Export).is_err());
        fs::write(source.join("ro"), "0").unwrap();
        assert!(live_media_device(&root.0, serial, Import).is_err());
        let target = live_media_device(&root.0, serial, Export)
            .unwrap_or_else(|error| panic!("{}", error.0));
        assert_eq!(target.id, selected.id);
        assert!(!target.read_only);
        fs::write(source.join("ro"), "1").unwrap();
        fs::write(foreign.join("serial"), serial).unwrap();
        assert!(live_media_device(&root.0, serial, Import).is_err());
    }

    #[test]
    fn live_media_export_flush_requires_exact_sideband_ack_even_after_stop() {
        for (response, acknowledged) in [
            (DETACHED.as_slice(), true),
            (b"copied\n", false),
            (b"detached", false),
            (b"", false),
        ] {
            let (controller, mut guest) = UnixStream::pair().unwrap();
            let worker = std::thread::spawn(move || {
                let mut cancel = [0];
                guest.read_exact(&mut cancel).unwrap();
                assert_eq!(cancel, [STOP]);
                guest.write_all(response).unwrap();
            });
            assert_eq!(wait_export_flush(&controller).is_ok(), acknowledged);
            worker.join().unwrap();
        }
    }
}

const EXPORT_PROOF: &str = "live-media-export.json";
const EXPORT_FLUSH_GRACE: Duration = Duration::from_secs(18);

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExportProof {
    id: String,
    flushed: bool,
}

fn export_proof(id: &str) -> Result<Option<ExportProof>> {
    let path = crate::storage::runtime_record(EXPORT_PROOF);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error("invalid_live_media_export_proof")),
        Ok(_) => {}
    }
    let mut bytes = Vec::new();
    crate::storage::trusted_file(&path)?
        .take(129)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("invalid_live_media_export_proof"))?;
    require(bytes.len() <= 128, "invalid_live_media_export_proof")?;
    let proof: ExportProof =
        serde_json::from_slice(&bytes).map_err(|_| Error("invalid_live_media_export_proof"))?;
    crate::storage::validate_id(&proof.id)?;
    Ok((proof.id == id).then_some(proof))
}

fn write_export_proof(id: &str, flushed: bool) -> Result<()> {
    let proof = ExportProof { id: id.into(), flushed };
    let bytes = serde_json::to_vec(&proof).map_err(|_| Error("invalid_live_media_export_proof"))?;
    crate::storage::write_key_file(EXPORT_PROOF, &bytes)
}

pub fn stop_live_media(id: &str, direction: Direction) -> Result<()> {
    if let Some(record) = job()? {
        require(
            record.matches_live(id, direction),
            "live_media_worker_changed",
        )?;
        stop()?;
    }
    // A concurrent authorized Safe close may have reaped this worker already.
    // Verify all scoped roles and mappings regardless of who performed stop.
    idle()?;
    require(!live_mapping_present(direction)?, "transfer_cleanup_required")?;
    if direction == Direction::Export && let Some(proof) = export_proof(id)? {
        require(proof.flushed, "live_media_export_cleanup_unconfirmed")?;
    }
    Ok(())
}

fn live_mapping_present(direction: Direction) -> Result<bool> {
    let name = oblivion_host::scope::current().mapping(match direction {
        Direction::Import => "oblivion-import",
        Direction::Export => "oblivion-export",
    });
    // The mapper's udev alias may be missing even after the kernel created a
    // mapping. The kernel name is authoritative for Live cleanup and eject.
    for entry in fs::read_dir("/sys/block").map_err(|_| Error("transfer_state_failed"))? {
        let entry = entry.map_err(|_| Error("transfer_state_failed"))?;
        let filename = entry.file_name();
        if !filename
            .to_str()
            .and_then(|value| value.strip_prefix("dm-"))
            .is_some_and(|number| {
                !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            continue;
        }
        let mapped = fs::read_to_string(entry.path().join("dm/name"))
            .map_err(|_| Error("transfer_state_failed"))?;
        if mapped.trim() == name {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn live_media_prepared() -> Result<bool> {
    Ok(job()?.is_some_and(|job| job.live_media.is_some()))
}

/// Only the daemon that owns the current reservation can acquire this one
/// copy descriptor. The second descriptor keeps the worker alive.
pub fn attach_live_media(
    id: &str,
    direction: Direction,
    purpose: Purpose,
    deadline: Instant,
    mut check: impl FnMut() -> Result<()>,
) -> Result<(UnixStream, UnixStream)> {
    let path = oblivion_host::scope::path(transfers::SOCKET);
    loop {
        check()?;
        require(
            job()?.is_some_and(|job| job.matches_live(id, direction) && job.live_media == Some(purpose)),
            "live_media_worker_changed",
        )?;
        require(Instant::now() < deadline, "live_media_source_timeout")?;
        if let Ok(control) =
            oblivion_host::channel::connect(Path::new(&path), Duration::from_millis(100))
        {
            crate::gateway::peer(&control, 0)?;
            let channel = Channel::new(&control, Duration::from_secs(2));
            let source = oblivion_host::control::receive_descriptor(&control, &channel)
                .map_err(|_| Error("transfer_port_unavailable"))?;
            crate::gateway::peer(&source, live_uid(direction))?;
            check()?;
            return Ok((source, control));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub fn prepared() -> Result<bool> {
    for path in [&job_path(), &pending_job(), vm::IMPORT_DEVICE, vm::EXPORT_DEVICE] {
        if Path::new(path)
            .try_exists()
            .map_err(|_| Error("transfer_state_failed"))?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn stop() -> Result<()> {
    let record = job().ok().flatten();
    if let Some(job) = &record && job.live_media.is_some() && job.export {
        // Reservation revocation has closed the copy holder. The worker can
        // still cancel the guest receiver and collect its final flush proof.
        let deadline = Instant::now() + EXPORT_FLUSH_GRACE + Duration::from_secs(2);
        let path = job_path();
        while Instant::now() < deadline
            && export_proof(&job.id).is_ok_and(|proof| proof.is_some_and(|proof| !proof.flushed))
            && Path::new(&path).exists()
        {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    // Live admission queues an asynchronous start. A stop must cancel that
    // exact unit job even if the unit has not entered "activating" yet.
    if record.is_some_and(|job| job.live_media.is_some())
        || !matches!(vm::unit_state(&unit())?.as_str(), "inactive" | "failed") {
        vm::execute("/usr/bin/systemctl", &["stop".into(), unit()])?;
    }
    require(
        matches!(vm::unit_state(&unit())?.as_str(), "inactive" | "failed"),
        "transfer_still_running",
    )?;
    cleanup()
}

fn job() -> Result<Option<Job>> {
    if !Path::new(&job_path())
        .try_exists()
        .map_err(|_| Error("transfer_state_failed"))?
    {
        return Ok(None);
    }
    let file = crate::storage::trusted_file(Path::new(&job_path()))?;
    require(
        file.metadata()
            .map_err(|_| Error("transfer_state_failed"))?
            .len()
            <= 1024,
        "invalid_transfer_state",
    )?;
    let job: Job = serde_json::from_reader(file).map_err(|_| Error("invalid_transfer_state"))?;
    require(
        job.id.len() == 32
            && job
                .id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid_transfer_state",
    )?;
    require(!(job.export && job.recovery), "invalid_transfer_state")?;
    if let Some(purpose) = job.live_media {
        let direction = if job.export { Direction::Export } else { Direction::Import };
        require(
            purpose.valid_for(direction) && !job.recovery && job.backup.is_none() && job.restore.is_none(),
            "invalid_transfer_state",
        )?;
    }
    if let Some(backup) = &job.backup {
        require(
            job.export
                && !job.recovery
                && job.restore.is_none()
                && backup.session.len() == 32
                && backup
                    .session
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && (32 * 1024 * 1024..=oblivion_transfer::MAX_ENCRYPTED_VOLUME_BYTES)
                    .contains(&backup.bytes),
            "invalid_transfer_state",
        )?;
    }
    if let Some(restore) = &job.restore {
        require(
            !job.export
                && !job.recovery
                && job.backup.is_none()
                && (32 * 1024 * 1024..=oblivion_transfer::MAX_ENCRYPTED_VOLUME_BYTES)
                    .contains(&restore.maximum),
            "invalid_transfer_state",
        )?;
    }
    Ok(Some(job))
}

pub fn cleanup() -> Result<()> {
    vm::stop_role(Role::Import, true)?;
    vm::stop_role(Role::Export, true)?;
    let record = job()?;
    if let Some(job) = &record {
        if job.live_media.is_none() { vm::remove_copy_port(&job.id)?; }
        if job.restore.is_some() {
            crate::storage::cleanup_restore(&job.id)?;
        }
    }
    for base in ["oblivion-import", "oblivion-export"] {
        let name = oblivion_host::scope::current().mapping(base);
        if Path::new(&format!("/dev/mapper/{name}"))
            .try_exists()
            .map_err(|_| Error("device_check_failed"))?
            || record.as_ref().is_some_and(|job| job.live_media.is_some() && job.export == (base == "oblivion-export"))
                && live_mapping_present(if base == "oblivion-export" { Direction::Export } else { Direction::Import })?
        {
            vm::execute(
                "/usr/sbin/dmsetup",
                &["remove".into(), "--retry".into(), name.into()],
            )?;
        }
    }
    if record.is_some() {
        fs::remove_file(&job_path()).map_err(|_| Error("transfer_cleanup_failed"))?;
    }
    if Path::new(&pending_job())
        .try_exists()
        .map_err(|_| Error("transfer_state_failed"))?
    {
        crate::storage::trusted_file(Path::new(&pending_job()))?;
        fs::remove_file(&pending_job()).map_err(|_| Error("transfer_cleanup_failed"))?;
    }
    Ok(())
}

pub fn serve(import: Option<&vm::Config>, export: Option<&vm::Config>, uid: u32) -> Result<()> {
    let job = job()?.ok_or(Error("transfer_not_prepared"))?;
    if let Some(purpose) = job.live_media {
        let config = if job.export { export } else { import };
        return serve_live_media(config.ok_or(Error("transfers_not_configured"))?, &job, purpose);
    }
    if let Some(restore) = &job.restore {
        let config = import.ok_or(Error("transfers_not_configured"))?;
        config.validate()?;
        config.start_role(Role::Import)?;
        let source = UnixStream::connect(format!("{}/copy.sock", Role::Import.runtime()))
            .map_err(|_| Error("transfer_port_unavailable"))?;
        crate::gateway::peer(&source, oblivion_host::scope::uid(vm::IMPORT_UID))?;
        vm::resume_transfer(Role::Import)?;
        let mut ready = [0; 6];
        Channel::new(&source, Duration::from_secs(90))
            .read_exact(&mut ready)
            .map_err(|_| Error("transfer_guest_not_ready"))?;
        require(&ready == b"ready\n", "invalid_transfer_guest")?;
        let file = crate::storage::create_restore_copy(&job.id)?;
        let (destination, mut process) =
            CopyProcess::start(file, restore.maximum, CopyDirection::Receive)?;
        let source = File::from(OwnedFd::from(source));
        let owners = vec![
            relay::peer_process(&source).map_err(|_| Error("transfer_owner_failed"))?,
            process
                .owner
                .try_clone()
                .map_err(|_| Error("transfer_owner_failed"))?,
        ];
        return relay_job(
            job,
            Some(source),
            destination,
            owners,
            uid,
            Some(&mut process),
        );
    }
    if let Some(backup) = &job.backup {
        let config = export.ok_or(Error("exports_not_configured"))?;
        config.validate()?;
        config.start_role(Role::Export)?;
        let destination = UnixStream::connect(format!("{}/copy.sock", Role::Export.runtime()))
            .map_err(|_| Error("transfer_port_unavailable"))?;
        crate::gateway::peer(&destination, oblivion_host::scope::uid(vm::EXPORT_UID))?;
        vm::resume_transfer(Role::Export)?;
        let mut ready = [0; 6];
        Channel::new(&destination, Duration::from_secs(90))
            .read_exact(&mut ready)
            .map_err(|_| Error("transfer_guest_not_ready"))?;
        require(&ready == b"ready\n", "invalid_transfer_guest")?;
        let source = crate::storage::closed_session_file(&backup.session)?;
        require(
            source
                .metadata()
                .map_err(|_| Error("image_check_failed"))?
                .len()
                == backup.bytes,
            "source_changed",
        )?;
        let (source, mut process) = CopyProcess::start(source, backup.bytes, CopyDirection::Send)?;
        let destination = File::from(OwnedFd::from(destination));
        let owners = vec![
            process
                .owner
                .try_clone()
                .map_err(|_| Error("transfer_owner_failed"))?,
            relay::peer_process(&destination).map_err(|_| Error("transfer_owner_failed"))?,
        ];
        let result = relay_job(job, Some(source), destination, owners, uid, None);
        if result.is_ok() {
            process.release()?;
        }
        return result;
    }
    let external = if job.recovery {
        None
    } else {
        let config =
            if job.export { export } else { import }.ok_or(Error("transfers_not_configured"))?;
        let role = if job.export {
            Role::Export
        } else {
            Role::Import
        };
        config.validate()?;
        config.start_role(role)?;
        let source = UnixStream::connect(format!("{}/copy.sock", role.runtime()))
            .map_err(|_| Error("transfer_port_unavailable"))?;
        crate::gateway::peer(
            &source,
            if job.export {
                oblivion_host::scope::uid(vm::EXPORT_UID)
            } else {
                oblivion_host::scope::uid(vm::IMPORT_UID)
            },
        )?;
        vm::resume_transfer(role)?;
        Some(source)
    };
    let session = vm::copy_port(&job.id, job.export)?;
    for port in external.iter().chain(std::iter::once(&session)) {
        let mut ready = [0; 6];
        Channel::new(port, Duration::from_secs(90))
            .read_exact(&mut ready)
            .map_err(|_| Error("transfer_guest_not_ready"))?;
        require(&ready == b"ready\n", "invalid_transfer_guest")?;
    }
    let session = File::from(OwnedFd::from(session));
    let external = external.map(|port| File::from(OwnedFd::from(port)));
    let (source, destination) = if job.export {
        (
            Some(session),
            external.ok_or(Error("transfer_port_unavailable"))?,
        )
    } else {
        (external, session)
    };
    let owners = source
        .iter()
        .chain(std::iter::once(&destination))
        .map(|port| relay::peer_process(port).map_err(|_| Error("transfer_owner_failed")))
        .collect::<Result<Vec<_>>>()?;
    relay_job(job, source, destination, owners, uid, None)
}

fn serve_live_media(config: &vm::Config, job: &Job, purpose: Purpose) -> Result<()> {
    config.validate()?;
    let (role, direction) = if job.export {
        config.start_live_export()?;
        (Role::Export, Direction::Export)
    } else {
        config.start_role(Role::Import)?;
        (Role::Import, Direction::Import)
    };
    let runtime = role.runtime();
    let port = oblivion_host::channel::connect(
        &Path::new(&runtime).join("copy.sock"),
        Duration::from_secs(2),
    )
    .map_err(|_| Error("transfer_port_unavailable"))?;
    let uid = live_uid(direction);
    let peer = live_peer(&port, uid)?;
    let owner = relay::peer_process(&File::from(OwnedFd::from(
        port.try_clone().map_err(|_| Error("transfer_descriptor_failed"))?,
    )))
    .map_err(|_| Error("transfer_owner_failed"))?;
    let proof = if job.export {
        let proof = oblivion_host::channel::connect(
            &Path::new(&runtime).join("proof.sock"),
            Duration::from_secs(2),
        )
        .map_err(|_| Error("transfer_port_unavailable"))?;
        require(live_peer(&proof, uid)? == peer, "invalid_transfer_peer")?;
        Some(proof)
    } else {
        None
    };
    vm::resume_transfer(role)?;
    let mut ready = [0; 6];
    Channel::new(&port, Duration::from_secs(90))
        .read_exact(&mut ready)
        .map_err(|_| Error("transfer_guest_not_ready"))?;
    require(&ready == b"ready\n", "invalid_transfer_guest")?;

    let path = oblivion_host::scope::path(transfers::SOCKET);
    let listener = UnixListener::bind(&path).map_err(|_| Error("transfer_socket_failed"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|_| Error("transfer_socket_failed"))?;
    crate::ipc::notify_ready()?;
    let (control, _) = listener.accept().map_err(|_| Error("transfer_socket_failed"))?;
    crate::gateway::peer(&control, 0)?;
    Channel::new(&control, Duration::from_secs(2))
        .prepare_write()
        .map_err(|_| Error("transfer_descriptor_failed"))?;
    if proof.is_some() {
        // This record precedes the first command which can mount writable
        // media. A crashed worker leaves an unconfirmed proof behind.
        write_export_proof(&job.id, false)?;
    }
    let command = match purpose {
        Purpose::Copy => b"M",
        Purpose::Inspect => b"I",
        Purpose::Recover => b"R",
        Purpose::Discard => b"D",
    };
    let handoff = Channel::new(&port, Duration::from_secs(2))
        .write_all(command)
        .map_err(|_| Error("transfer_guest_not_ready"))
        .and_then(|()| crate::ipc::send_console(&control, &port));
    // Only the admitted caller holds the connected copy port after handoff.
    drop(port);
    if handoff.is_ok() {
        let mut control = oblivion_transfer::channel::Channel::new(
            File::from(OwnedFd::from(control)),
            Duration::from_secs(transfers::BUDGET_SECONDS),
        )
        .map_err(|_| Error("transfer_owner_failed"))?;
        control.watch(owner);
        let _ = control.read(&mut [0]);
    }
    if let Some(proof) = proof {
        wait_export_flush(&proof)?;
        write_export_proof(&job.id, true)?;
    }
    handoff
}

fn live_peer(port: &UnixStream, uid: u32) -> Result<libc::pid_t> {
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    require(
        unsafe {
            libc::getsockopt(
                port.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut length,
            ) == 0
        } && peer.uid == uid && peer.pid > 0,
        "invalid_transfer_peer",
    )?;
    Ok(peer.pid)
}

fn wait_export_flush(proof: &UnixStream) -> Result<()> {
    let mut channel = Channel::new(proof, EXPORT_FLUSH_GRACE);
    // A completed receiver may already have emitted its proof. Still read it
    // if the cancellation write fails after the guest closes its side.
    let _ = channel.write_all(&[STOP]);
    let mut marker = [0; DETACHED.len()];
    channel.read_exact(&mut marker).map_err(|_| Error("live_media_export_cleanup_unconfirmed"))?;
    require(&marker == DETACHED, "live_media_export_cleanup_unconfirmed")
}

fn relay_job(
    job: Job,
    source: Option<File>,
    destination: File,
    mut owners: Vec<OwnedFd>,
    uid: u32,
    process: Option<&mut CopyProcess>,
) -> Result<()> {
    let listener =
        UnixListener::bind(&oblivion_host::scope::path(transfers::SOCKET)).map_err(|_| Error("transfer_socket_failed"))?;
    fs::set_permissions(&oblivion_host::scope::path(transfers::SOCKET), fs::Permissions::from_mode(0o600))
        .map_err(|_| Error("transfer_socket_failed"))?;
    require(
        unsafe {
            libc::chown(
                std::ffi::CString::new(oblivion_host::scope::path("/run/oblivion-transfer-host/control.sock")).unwrap().as_ptr(),
                uid,
                !0,
            )
        } == 0,
        "transfer_socket_failed",
    )?;
    listener
        .set_nonblocking(true)
        .map_err(|_| Error("transfer_socket_failed"))?;
    crate::ipc::notify_ready()?;
    let deadline = Instant::now()
        + Duration::from_secs(if job.backup.is_some() || job.restore.is_some() {
            3600
        } else {
            transfers::BUDGET_SECONDS
        });
    loop {
        let mut descriptors = vec![libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        descriptors.extend(owners.iter().map(|owner| libc::pollfd {
            fd: owner.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }));
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(Error("transfer_expired"))?;
        require(
            unsafe {
                libc::poll(
                    descriptors.as_mut_ptr(),
                    descriptors.len() as _,
                    remaining.as_millis().min(i32::MAX as u128) as i32,
                )
            } >= 0,
            "transfer_wait_failed",
        )?;
        require(
            !descriptors[1..].iter().any(|fd| fd.revents != 0),
            "transfer_owner_exited",
        )?;
        if descriptors[0].revents == 0 {
            continue;
        }
        let (control, _) = listener
            .accept()
            .map_err(|_| Error("transfer_socket_failed"))?;
        crate::gateway::peer(&control, uid)?;
        for port in source
            .iter()
            .filter(|_| job.backup.is_none())
            .chain(std::iter::once(&destination).filter(|_| job.restore.is_none()))
        {
            let mut port = port;
            port.write_all(if job.backup.is_some() || job.restore.is_some() {
                b"B"
            } else if job.recovery {
                b"R"
            } else {
                b"G"
            })
            .map_err(|_| Error("transfer_guest_not_ready"))?;
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(Error("transfer_expired"))?;
        let control = File::from(OwnedFd::from(control));
        let Some(source) = source else {
            return relay::recover(
                destination,
                control,
                owners.pop().ok_or(Error("transfer_owner_failed"))?,
                remaining,
            )
            .map_err(|_| Error("transfer_failed"));
        };
        if let Some(restore) = job.restore {
            let reply = control
                .try_clone()
                .map_err(|_| Error("transfer_descriptor_failed"))?;
            let receipt = relay::stage(
                source,
                destination,
                control,
                owners,
                remaining,
                Permit {
                    id: job.id.clone(),
                    limits: oblivion_transfer::Limits {
                        entries: 1,
                        bytes: restore.maximum,
                    },
                },
            )
            .map_err(|_| Error("transfer_failed"))?;
            process.ok_or(Error("transfer_owner_failed"))?.release()?;
            crate::storage::complete_restore_copy(&receipt)?;
            vm::stop_role(Role::Import, true)?;
            vm::execute(
                "/usr/sbin/dmsetup",
                &["remove".into(), "--retry".into(), "oblivion-import".into()],
            )?;
            let mut reply = oblivion_transfer::channel::Channel::new(reply, Duration::from_secs(5))
                .map_err(|_| Error("transfer_reply_failed"))?;
            return oblivion_transfer::endpoint::write_message(&mut reply, &receipt)
                .map_err(|_| Error("transfer_reply_failed"));
        }
        if job.export {
            let limits = job
                .backup
                .as_ref()
                .map_or_else(transfers::limits, |backup| oblivion_transfer::Limits {
                    entries: 1,
                    bytes: backup.bytes,
                });
            return relay::export(
                source,
                destination,
                control,
                owners,
                remaining,
                Permit { id: job.id, limits },
                if job.backup.is_some() { relay::ExportSource::Ciphertext } else { relay::ExportSource::Documents },
            )
            .map_err(|_| Error("transfer_failed"));
        }
        return relay::run_permitted(
            source,
            destination,
            control,
            owners,
            remaining,
            Some(Permit {
                id: job.id,
                limits: transfers::limits(),
            }),
        )
        .map_err(|_| Error("transfer_failed"));
    }
}

struct CopyProcess {
    child: Child,
    owner: OwnedFd,
    channel: UnixStream,
    reaped: bool,
}

enum CopyDirection {
    Send,
    Receive,
}

impl CopyProcess {
    fn start(file: File, bytes: u64, direction: CopyDirection) -> Result<(File, Self)> {
        let (source, peer) = UnixStream::pair().map_err(|_| Error("transfer_socket_failed"))?;
        let keepalive = source
            .try_clone()
            .map_err(|_| Error("transfer_descriptor_failed"))?;
        let duplicate = |fd| -> Result<OwnedFd> {
            let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
            require(copy >= 10, "transfer_descriptor_failed")?;
            Ok(unsafe { OwnedFd::from_raw_fd(copy) })
        };
        let channel = duplicate(peer.as_raw_fd())?;
        let file = duplicate(file.as_raw_fd())?;
        let channel_fd = channel.as_raw_fd();
        let file_fd = file.as_raw_fd();
        let mut command = Command::new("/usr/bin/setpriv");
        command
            .args([
                "--reuid=65534",
                "--regid=65534",
                "--clear-groups",
                "--no-new-privs",
                "--",
                "/usr/bin/oblivion-copy",
                match direction {
                    CopyDirection::Send => "send-open-file",
                    CopyDirection::Receive => "receive-open-file",
                },
                &bytes.to_string(),
                "3600000",
            ])
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(channel_fd, 3) < 0 || libc::dup2(file_fd, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .map_err(|_| Error("transfer_start_failed"))?;
        let owner = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) } as libc::c_int;
        if owner < 0 {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error("transfer_owner_failed"));
        }
        Ok((
            File::from(OwnedFd::from(source)),
            Self {
                child,
                owner: unsafe { OwnedFd::from_raw_fd(owner) },
                channel: keepalive,
                reaped: false,
            },
        ))
    }

    fn release(&mut self) -> Result<()> {
        self.channel
            .set_write_timeout(Some(Duration::from_secs(1)))
            .map_err(|_| Error("transfer_release_failed"))?;
        self.channel
            .write_all(b"released\n")
            .map_err(|_| Error("transfer_release_failed"))?;
        let mut poll = libc::pollfd {
            fd: self.owner.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        require(
            unsafe { libc::poll(&mut poll, 1, 5000) } > 0,
            "transfer_still_running",
        )?;
        let status = self
            .child
            .wait()
            .map_err(|_| Error("transfer_wait_failed"))?;
        self.reaped = true;
        require(status.success(), "transfer_failed")
    }
}

impl Drop for CopyProcess {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
