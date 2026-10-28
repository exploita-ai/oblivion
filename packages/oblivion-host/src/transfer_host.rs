use crate::storage::{Error, Result, require};
use crate::vm::{self, Role};
use oblivion_host::channel::Channel;
use oblivion_host::transfers::{self, Source, SourceKind, Started, Status};
use oblivion_transfer::relay::{self, Permit};
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

const UNIT: &str = "oblivion-transfer-host.service";
const JOB: &str = "/run/oblivion/transfer.json";
const PENDING_JOB: &str = "/run/oblivion/transfer.pending";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Job {
    id: String,
    #[serde(default)]
    recovery: bool,
    #[serde(default)]
    export: bool,
    #[serde(default)]
    backup: Option<Backup>,
    #[serde(default)]
    restore: Option<Restore>,
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
        active: !matches!(vm::unit_state(UNIT)?.as_str(), "inactive" | "failed"),
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
        let virtio = disk.ancestors().any(|parent| {
            fs::read_link(parent.join("subsystem"))
                .ok()
                .is_some_and(|link| link.ends_with("virtio"))
        });
        // A virtual drive is opt-in through the supplied import/export profile.
        // Arbitrary internal disks never become eligible merely by being virtio.
        let Some(kind) = SourceKind::detect(
            usb,
            virtio || cfg!(feature = "lab-emulation"),
            serial.trim(),
        ) else {
            continue;
        };
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
    let name = if export {
        "oblivion-export"
    } else {
        "oblivion-import"
    };
    let uid = if export {
        vm::EXPORT_UID
    } else {
        vm::IMPORT_UID
    };
    let mut args = vec!["create".into(), name.into()];
    if !export {
        args.push("--readonly".into());
    }
    args.extend([
        "--table".into(),
        format!("0 {} linear {} 0", source.bytes / 512, source.id),
    ]);
    vm::execute("/usr/sbin/dmsetup", &args)?;
    let path = if export {
        vm::EXPORT_DEVICE
    } else {
        vm::IMPORT_DEVICE
    };
    require(
        unsafe {
            libc::chown(
                CString::new(path)
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
        matches!(vm::unit_state(UNIT)?.as_str(), "inactive" | "failed")
            && vm::stopped_role(Role::Import)?
            && vm::stopped_role(Role::Export)?,
        "transfer_already_running",
    )?;
    require(
        !Path::new(JOB).exists()
            && !Path::new(PENDING_JOB).exists()
            && !Path::new(vm::IMPORT_DEVICE).exists()
            && !Path::new(vm::EXPORT_DEVICE).exists(),
        "transfer_cleanup_required",
    )?;
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
    let encoded = serde_json::to_vec(&Job {
        id: id.clone(),
        recovery,
        export,
        backup,
        restore,
    })
    .map_err(|_| Error("transfer_state_failed"))?;
    let mut job = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(PENDING_JOB)
        .map_err(|_| Error("transfer_state_failed"))?;
    job.write_all(&encoded)
        .and_then(|()| job.sync_all())
        .map_err(|_| Error("transfer_state_failed"))?;
    // The storage operation lock serializes starts. Publish only a complete
    // record so interruption cannot leave an undecodable live job.
    require(!Path::new(JOB).exists(), "transfer_already_running")?;
    fs::rename(PENDING_JOB, JOB).map_err(|_| Error("transfer_state_failed"))?;
    vm::execute("/usr/bin/systemctl", &["start".into(), UNIT.into()])?;
    Ok(Started { id, bytes })
}

pub fn prepared() -> Result<bool> {
    for path in [JOB, PENDING_JOB, vm::IMPORT_DEVICE, vm::EXPORT_DEVICE] {
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
    if !matches!(vm::unit_state(UNIT)?.as_str(), "inactive" | "failed") {
        vm::execute("/usr/bin/systemctl", &["stop".into(), UNIT.into()])?;
    }
    require(
        matches!(vm::unit_state(UNIT)?.as_str(), "inactive" | "failed"),
        "transfer_still_running",
    )?;
    cleanup()
}

fn job() -> Result<Option<Job>> {
    if !Path::new(JOB)
        .try_exists()
        .map_err(|_| Error("transfer_state_failed"))?
    {
        return Ok(None);
    }
    let file = crate::storage::trusted_file(Path::new(JOB))?;
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
    if let Some(job) = job()? {
        vm::remove_copy_port(&job.id)?;
        if job.restore.is_some() {
            crate::storage::cleanup_restore(&job.id)?;
        }
    }
    for name in ["oblivion-import", "oblivion-export"] {
        if Path::new(&format!("/dev/mapper/{name}"))
            .try_exists()
            .map_err(|_| Error("device_check_failed"))?
        {
            vm::execute(
                "/usr/sbin/dmsetup",
                &["remove".into(), "--retry".into(), name.into()],
            )?;
        }
    }
    if job()?.is_some() {
        fs::remove_file(JOB).map_err(|_| Error("transfer_cleanup_failed"))?;
    }
    if Path::new(PENDING_JOB)
        .try_exists()
        .map_err(|_| Error("transfer_state_failed"))?
    {
        crate::storage::trusted_file(Path::new(PENDING_JOB))?;
        fs::remove_file(PENDING_JOB).map_err(|_| Error("transfer_cleanup_failed"))?;
    }
    Ok(())
}

pub fn serve(import: Option<&vm::Config>, export: Option<&vm::Config>, uid: u32) -> Result<()> {
    let job = job()?.ok_or(Error("transfer_not_prepared"))?;
    if let Some(restore) = &job.restore {
        let config = import.ok_or(Error("transfers_not_configured"))?;
        config.validate()?;
        config.start_role(Role::Import)?;
        let source = UnixStream::connect(format!("{}/copy.sock", Role::Import.runtime()))
            .map_err(|_| Error("transfer_port_unavailable"))?;
        crate::gateway::peer(&source, vm::IMPORT_UID)?;
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
        crate::gateway::peer(&destination, vm::EXPORT_UID)?;
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
                vm::EXPORT_UID
            } else {
                vm::IMPORT_UID
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

fn relay_job(
    job: Job,
    source: Option<File>,
    destination: File,
    mut owners: Vec<OwnedFd>,
    uid: u32,
    process: Option<&mut CopyProcess>,
) -> Result<()> {
    let listener =
        UnixListener::bind(transfers::SOCKET).map_err(|_| Error("transfer_socket_failed"))?;
    fs::set_permissions(transfers::SOCKET, fs::Permissions::from_mode(0o600))
        .map_err(|_| Error("transfer_socket_failed"))?;
    require(
        unsafe {
            libc::chown(
                c"/run/oblivion-transfer-host/control.sock".as_ptr(),
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
