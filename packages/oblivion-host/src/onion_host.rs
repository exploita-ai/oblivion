//! Private transfer owner. Preparation never exposes a URL; receive publication
//! requires an explicit recipient public key and a verified file worker.
use crate::storage::{Error, Result, require};
use crate::vm::{self, Role};
use oblivion_host::onion::{Access, ClientAuth, OwnerRequest, Phase, Progress, Status};
use oblivion_host::tor_profile::Purpose;
use oblivion_transfer::channel::Channel;
use oblivion_transfer::endpoint::read_message;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const JOB: &str = "/run/oblivion/onion.json";
const PENDING: &str = "/run/oblivion/onion.pending";
const SOCKET: &str = "/run/oblivion-onion-host/control.sock";
const COPY_SOCKET: &str = "/run/oblivion-onion-host/copy.sock";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    gateway: vm::Config,
    files: vm::Config,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Job {
    id: String,
    session: String,
    ttl_seconds: u16,
    #[serde(default)]
    backup: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    ready: bool,
    version: u8,
    role: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Initialized {
    ok: bool,
    initialized: bool,
    active: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observed {
    ok: bool,
    isolated: bool,
    tor_progress: Option<u8>,
    tor_ready: bool,
    active: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum FilePhase {
    Fresh,
    Staging,
    Sharing,
    Receiving,
    Review,
    Copying,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileObserved {
    ok: bool,
    phase: FilePhase,
    worker: Option<FileWorker>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileWorker {
    state: String,
    mode: String,
    files: usize,
    bytes: u64,
    transferred_bytes: u64,
    rejected: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Published {
    ok: bool,
    service_id: Option<String>,
    error: Option<serde::de::IgnoredAny>,
}

struct Pending {
    thread: oblivion_host::onion_task::Task,
    operation: PendingOperation,
}

enum PendingOperation {
    Receive(ClientAuth),
    Stage,
    Share(ClientAuth),
    Backup(ClientAuth),
    Freeze,
    Import,
}

struct Copy {
    thread: JoinHandle<Result<oblivion_host::onion_copy::Completed>>,
    ready: Arc<AtomicBool>,
    exporting: bool,
}

struct Staged {
    receipt: oblivion_transfer::Receipt,
    paths: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    ok: bool,
    state: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Stopped {
    ok: bool,
    closed: bool,
    checkpoint: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayStopped {
    ok: bool,
    closed: bool,
    state: Option<String>,
}

struct Peer {
    file: File,
    owner: OwnedFd,
}

struct Guests {
    session: OwnedFd,
    uplink: Option<Peer>,
    gateway: Option<Peer>,
    files: Option<Peer>,
    initialized: bool,
    saved: Option<oblivion_tor_state::State>,
    writable: bool,
    pending: Option<Pending>,
    access: Option<Access>,
    progress: Option<Progress>,
    review: bool,
    intake: Option<Peer>,
    copy: Option<Copy>,
    receipt: Option<oblivion_transfer::Receipt>,
    staged: Option<Staged>,
    sharing: bool,
    backup: bool,
    backup_bytes: u64,
}

pub fn prepared() -> Result<bool> {
    for path in [
        JOB.into(),
        PENDING.into(),
        "/run/oblivion-onion-host".into(),
        Role::OnionUplink.runtime(),
        Role::OnionGateway.runtime(),
        Role::OnionFile.runtime(),
    ] {
        match fs::symlink_metadata(path) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error("onion_state_failed")),
        }
    }
    Ok(false)
}

pub fn archiving() -> Result<bool> {
    match fs::symlink_metadata(JOB) {
        Ok(_) => Ok(read_job()?.backup),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(Error("onion_state_failed")),
    }
}

pub fn start(session: String, ttl_seconds: u16, backup: bool) -> Result<Status> {
    require(
        !prepared()? && !crate::transfer_host::prepared()?,
        "transfer_active",
    )?;
    let job = Job {
        id: crate::storage::random_id()?,
        session,
        ttl_seconds,
        backup,
    };
    let bytes = serde_json::to_vec(&job).map_err(|_| Error("onion_state_failed"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(PENDING)
        .map_err(|_| Error("onion_state_failed"))?;
    file.write_all(&bytes)
        .map_err(|_| Error("onion_state_failed"))?;
    fs::rename(PENDING, JOB).map_err(|_| Error("onion_state_failed"))?;
    let started = vm::execute(
        "/usr/bin/systemctl",
        &["start".into(), oblivion_host::onion_vm::OWNER.into()],
    );
    if started.is_err() {
        let _checkpoint = shutdown()?;
        return Err(Error("onion_start_failed"));
    }
    status(true)
}

pub fn status(configured: bool) -> Result<Status> {
    if !prepared()? {
        return Ok(Status::closed(configured));
    }
    let socket = oblivion_host::channel::connect(Path::new(SOCKET), Duration::from_secs(3))
        .map_err(|_| Error("onion_unavailable"))?;
    crate::gateway::peer(&socket, 0)?;
    exchange(
        &File::from(OwnedFd::from(socket)),
        &OwnerRequest::Observe {},
        &[],
        Duration::from_secs(4),
    )
}

pub fn receive(client_auth: ClientAuth) -> Result<Status> {
    let current = status(true)?;
    require(
        current.phase == Phase::Ready && current.tor_ready,
        "onion_not_ready",
    )?;
    command(&OwnerRequest::Receive { client_auth })
}

pub fn access() -> Result<Access> {
    let current = status(true)?;
    require(
        matches!(current.phase, Phase::Receiving | Phase::Sharing) && current.tor_ready,
        "onion_not_published",
    )?;
    command(&OwnerRequest::Access {})
}

pub fn freeze() -> Result<Status> {
    require(
        status(true)?.phase == Phase::Receiving,
        "onion_not_receiving",
    )?;
    command(&OwnerRequest::Freeze {})
}

pub fn import() -> Result<Status> {
    require(status(true)?.phase == Phase::Review, "onion_not_reviewable")?;
    command(&OwnerRequest::Import {})
}

pub fn stage() -> Result<Status> {
    require(status(true)?.phase == Phase::Ready, "onion_not_ready")?;
    command(&OwnerRequest::Stage {})
}

pub fn share(client_auth: ClientAuth) -> Result<Status> {
    let current = status(true)?;
    require(
        current.phase == Phase::Staged || (archiving()? && current.phase == Phase::Ready),
        "onion_not_staged",
    )?;
    command(&OwnerRequest::Share { client_auth })
}

fn command<T: for<'de> Deserialize<'de>>(request: &OwnerRequest) -> Result<T> {
    let socket = oblivion_host::channel::connect(Path::new(SOCKET), Duration::from_secs(3))
        .map_err(|_| Error("onion_unavailable"))?;
    crate::gateway::peer(&socket, 0)?;
    exchange(
        &File::from(OwnedFd::from(socket)),
        request,
        &[],
        Duration::from_secs(30),
    )
}

/// Only a checkpoint failure is advisory. Every auxiliary unit must actually
/// be stopped before a caller may close any mapping or report a lock.
pub fn shutdown() -> Result<bool> {
    if !prepared()? {
        return Ok(true);
    }
    let checkpoint = (|| {
        let socket = oblivion_host::channel::connect(Path::new(SOCKET), Duration::from_secs(2))
            .map_err(|_| Error("onion_unavailable"))?;
        crate::gateway::peer(&socket, 0)?;
        let reply: Stopped = exchange(
            &File::from(OwnedFd::from(socket)),
            &OwnerRequest::Stop {},
            &[],
            Duration::from_secs(30),
        )?;
        require(
            reply.ok && reply.closed && reply.checkpoint,
            "onion_checkpoint_failed",
        )
    })();
    let stopped = vm::execute(
        "/usr/bin/systemctl",
        &["stop".into(), oblivion_host::onion_vm::OWNER.into()],
    );
    let cleaned = cleanup();
    stopped?;
    cleaned?;
    Ok(checkpoint.is_ok())
}

pub fn cleanup() -> Result<()> {
    stop_guests()?;
    cleanup_records()
}

fn stop_guests() -> Result<()> {
    // Attempt every independent stop, even when a preceding one fails. Killing
    // the network-only actor first cuts public traffic before other teardown.
    let stopped = [Role::OnionUplink, Role::OnionGateway, Role::OnionFile]
        .map(|role| vm::stop_role(role, true));
    for result in stopped {
        result?;
    }
    Ok(())
}

fn cleanup_records() -> Result<()> {
    if Path::new(JOB)
        .try_exists()
        .map_err(|_| Error("onion_state_failed"))?
    {
        let job = read_job()?;
        if !job.backup {
            vm::remove_copy_port(&job.id)?;
        }
    }
    match fs::remove_file(COPY_SOCKET) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Error("onion_cleanup_failed")),
    }
    for path in [JOB, PENDING] {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(Error("onion_state_failed")),
            Ok(_) => {}
        }
        crate::storage::trusted_file(Path::new(path))?;
        fs::remove_file(path).map_err(|_| Error("onion_cleanup_failed"))?;
    }
    Ok(())
}

fn read_job() -> Result<Job> {
    let job: Job =
        serde_json::from_reader(crate::storage::trusted_file(Path::new(JOB))?.take(1025))
            .map_err(|_| Error("invalid_onion_job"))?;
    crate::storage::validate_id(&job.id)?;
    crate::storage::validate_id(&job.session)?;
    require(
        (1..=3600).contains(&job.ttl_seconds),
        "invalid_onion_deadline",
    )?;
    Ok(job)
}

pub fn serve(config: &Config, uid: u32) -> Result<()> {
    let _lock = crate::storage::lock_named("onion.lock")?;
    let job = read_job()?;
    if !job.backup {
        require(
            crate::storage::session_info()?.is_some_and(|(id, mode)| {
                id == job.session && matches!(mode.as_str(), "documents" | "chat")
            }),
            "session_not_open",
        )?;
    }
    config.gateway.validate()?;
    config.files.validate()?;
    let mut guests = Guests {
        session: if job.backup {
            crate::storage::closed_session_file(&job.session)?;
            let socket = oblivion_host::channel::connect(
                Path::new(crate::ipc::SOCKET),
                Duration::from_secs(2),
            )
            .map_err(|_| Error("onion_watch_failed"))?;
            crate::gateway::peer(&socket, 0)?;
            oblivion_transfer::relay::peer_process(&File::from(OwnedFd::from(socket)))
                .map_err(|_| Error("onion_watch_failed"))?
        } else {
            vm::session_owner()?
        },
        uplink: None,
        gateway: None,
        files: None,
        initialized: false,
        saved: crate::storage::tor_state(Purpose::Transfer)?,
        writable: crate::storage::tor_state_writable()?,
        pending: None,
        access: None,
        progress: None,
        review: false,
        intake: None,
        copy: None,
        receipt: None,
        staged: None,
        sharing: false,
        backup: job.backup,
        backup_bytes: if job.backup {
            crate::storage::closed_session_file(&job.session)?
                .metadata()
                .map_err(|_| Error("invalid_backup_volume"))?
                .len()
        } else {
            0
        },
    };
    let result = guests.run(config, &job, uid);
    let checkpoint = guests.finish();
    guests.disconnect();
    let stopped = stop_guests();
    // Retain peer pidfds through the stop, then verify the exact processes died.
    let exited = guests.verify_stopped();
    // Disconnect/reap first so a cancelled worker RPC cannot retain a thread
    // or outlive the job. Cancellation does not require that RPC to succeed.
    if let Some(pending) = guests.pending.take() {
        let _ = pending.thread.join();
    }
    if let Some(copy) = guests.copy.take() {
        let _ = copy.thread.join();
    }
    stopped?;
    exited?;
    cleanup_records()?;
    if let Some(client) = result? {
        respond(
            &client,
            &Stopped {
                ok: true,
                closed: true,
                checkpoint: checkpoint.is_ok(),
            },
        )?;
    }
    checkpoint
}

impl Guests {
    fn run(&mut self, config: &Config, job: &Job, uid: u32) -> Result<Option<UnixStream>> {
        let deadline = Instant::now() + Duration::from_secs(u64::from(job.ttl_seconds));
        let startup = deadline.min(Instant::now() + Duration::from_secs(120));
        config.gateway.start_role(Role::OnionUplink)?;
        self.uplink = Some(Peer::connect(Role::OnionUplink, "qmp.sock")?);
        config.gateway.start_role(Role::OnionGateway)?;
        self.gateway = Some(Peer::connect(Role::OnionGateway, "control.sock")?);
        config.files.start_role(Role::OnionFile)?;
        self.files = Some(Peer::connect(Role::OnionFile, "control.sock")?);
        if job.backup {
            vm::attach_onion_backup(&crate::storage::closed_session_file(&job.session)?)?;
        }
        vm::resume_transfer(Role::OnionGateway)?;
        self.boot(Role::OnionGateway, startup)?;
        // Tor initialization starts, stops and restarts the disabled service.
        // Keep the file guest paused so its idle watchdog cannot expire while
        // those cold starts exceed the normal five-second observation budget.
        let peer = self
            .gateway
            .as_ref()
            .ok_or(Error("onion_guest_not_ready"))?;
        let initialized: Initialized = exchange_channel(
            &mut self.channel(
                peer,
                startup.saturating_duration_since(Instant::now()).min(Duration::from_secs(30)),
                true,
            )?,
            &json!({"operation":"initialize","state":self.saved.as_ref().map(oblivion_tor_state::State::as_str)}),
        ).map_err(|_| Error("onion_initialization_failed"))?;
        require(
            initialized.ok && initialized.initialized && !initialized.active,
            "onion_initialization_failed",
        )?;
        self.initialized = true;
        vm::resume_transfer(Role::OnionFile)?;
        self.boot(Role::OnionFile, startup)?;
        let enabled: Initialized = self.gateway(&json!({"operation":"enable"}))?;
        require(
            enabled.ok && enabled.initialized && !enabled.active,
            "onion_initialization_failed",
        )?;
        let listener = UnixListener::bind(SOCKET).map_err(|_| Error("onion_socket_failed"))?;
        fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o600))
            .map_err(|_| Error("onion_socket_failed"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| Error("onion_socket_failed"))?;
        let mut observed = self.observe()?;
        let mut checked = Instant::now();
        crate::ipc::notify_ready()?;
        loop {
            require(!exited(&self.session)?, "session_already_exited")?;
            if Instant::now() >= deadline {
                return Ok(None);
            }
            self.complete_file(deadline, job, uid)?;
            self.complete_copy(job)?;
            if checked.elapsed() >= Duration::from_secs(4) {
                self.checkpoint()?;
                observed = self.observe()?;
                checked = Instant::now();
            }
            match listener.accept() {
                Ok((client, _)) => {
                    crate::gateway::peer(&client, 0)?;
                    let file = File::from(OwnedFd::from(
                        client
                            .try_clone()
                            .map_err(|_| Error("onion_socket_failed"))?,
                    ));
                    let request: OwnerRequest = read_message(
                        &mut Channel::new(file, Duration::from_secs(2))
                            .map_err(|_| Error("onion_socket_failed"))?,
                        1024,
                    )
                    .map_err(|_| Error("invalid_onion_request"))?;
                    match request {
                        OwnerRequest::Stop {} => return Ok(Some(client)),
                        OwnerRequest::Observe {} => {
                            respond(&client, &self.status(job, &observed, checked))?
                        }
                        OwnerRequest::Receive { client_auth } => {
                            require(!job.backup, "invalid_onion_operation")?;
                            require(
                                self.pending.is_none() && self.access.is_none(),
                                "onion_already_started",
                            )?;
                            observed = self.observe()?;
                            checked = Instant::now();
                            require(observed.tor_ready, "onion_not_ready")?;
                            self.begin_receive(client_auth, deadline)?;
                            respond(&client, &self.status(job, &observed, checked))?;
                        }
                        OwnerRequest::Access {} => {
                            observed = self.observe()?;
                            checked = Instant::now();
                            require(observed.tor_ready, "onion_not_ready")?;
                            respond(
                                &client,
                                self.access.as_ref().ok_or(Error("onion_not_published"))?,
                            )?;
                        }
                        OwnerRequest::Freeze {} => {
                            require(
                                self.access.is_some() && self.pending.is_none(),
                                "onion_not_receiving",
                            )?;
                            self.begin_freeze(deadline)?;
                            observed = self.observe()?;
                            checked = Instant::now();
                            respond(&client, &self.status(job, &observed, checked))?;
                        }
                        OwnerRequest::Import {} => {
                            require(!job.backup, "invalid_onion_operation")?;
                            require(
                                self.review && self.pending.is_none(),
                                "onion_not_reviewable",
                            )?;
                            self.begin_import(deadline)?;
                            respond(&client, &self.status(job, &observed, checked))?;
                        }
                        OwnerRequest::Stage {} => {
                            require(!job.backup, "invalid_onion_operation")?;
                            require(
                                self.pending.is_none()
                                    && self.access.is_none()
                                    && self.copy.is_none()
                                    && self.staged.is_none(),
                                "onion_already_started",
                            )?;
                            self.begin_stage(deadline)?;
                            respond(&client, &self.status(job, &observed, checked))?;
                        }
                        OwnerRequest::Share { client_auth } => {
                            require(
                                self.pending.is_none()
                                    && self.access.is_none()
                                    && (self.staged.is_some() || job.backup),
                                "onion_not_staged",
                            )?;
                            if job.backup {
                                observed = self.observe()?;
                                checked = Instant::now();
                                require(observed.tor_ready, "onion_not_ready")?;
                                self.sharing = true;
                                let peer =
                                    self.files.as_ref().ok_or(Error("onion_guest_not_ready"))?;
                                self.pending = Some(Pending {
                                    thread: oblivion_host::onion_task::Task::start(
                                        self.channel(peer, Duration::from_secs(120), true)?,
                                        oblivion_host::onion_task::Command::Backup {
                                            ttl_seconds: remaining_seconds(deadline)?,
                                        },
                                    )
                                    .map_err(|_| Error("onion_worker_failed"))?,
                                    operation: PendingOperation::Backup(client_auth),
                                });
                            } else {
                                self.begin_share(client_auth, deadline)?;
                            }
                            respond(&client, &self.status(job, &observed, checked))?;
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return Err(Error("onion_socket_failed")),
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn status(&self, job: &Job, observed: &Observed, checked: Instant) -> Status {
        let mut status = Status::observed(
            job.id.clone(),
            observed.tor_progress,
            observed.tor_ready,
            checked.elapsed().as_millis().min(u64::MAX as u128) as u64,
        );
        if let Some(pending) = &self.pending {
            status.phase = match pending.operation {
                PendingOperation::Receive(_) => Phase::Starting,
                PendingOperation::Stage => Phase::PreparingShare,
                PendingOperation::Share(_) | PendingOperation::Backup(_) => Phase::Starting,
                PendingOperation::Freeze => Phase::Freezing,
                PendingOperation::Import => Phase::PreparingImport,
            };
        }
        if self.access.is_some() {
            status.phase = if self.sharing {
                Phase::Sharing
            } else {
                Phase::Receiving
            };
        }
        if self.review {
            status.phase = Phase::Review;
        }
        if let Some(copy) = &self.copy {
            status.phase = if copy.exporting && copy.ready.load(Ordering::Acquire) {
                Phase::Staging
            } else if copy.exporting {
                Phase::PreparingShare
            } else if copy.ready.load(Ordering::Acquire) {
                Phase::Copying
            } else {
                Phase::PreparingImport
            };
        }
        if self.staged.is_some() && self.pending.is_none() && self.access.is_none() {
            status.phase = Phase::Staged;
        }
        if let Some(receipt) = &self.receipt {
            status.phase = Phase::Imported;
            status.receipt = Some(oblivion_transfer::Receipt {
                id: receipt.id.clone(),
                manifest_sha256: receipt.manifest_sha256.clone(),
                entries: receipt.entries,
                bytes: receipt.bytes,
            });
        }
        if self.backup && self.progress.is_none() {
            status.progress = Some(Progress {
                files: 1,
                bytes: self.backup_bytes,
                transferred_bytes: 0,
                rejected: 0,
            });
        }
        if self.progress.is_some() {
            status.progress = self.progress.as_ref().map(|progress| Progress {
                files: progress.files,
                bytes: progress.bytes,
                transferred_bytes: progress.transferred_bytes,
                rejected: progress.rejected,
            });
        }
        status
    }

    fn begin_receive(&mut self, client_auth: ClientAuth, deadline: Instant) -> Result<()> {
        let peer = self.files.as_ref().ok_or(Error("onion_guest_not_ready"))?;
        let channel = self.channel(
            peer,
            Duration::from_secs(120).min(deadline.saturating_duration_since(Instant::now())),
            true,
        )?;
        let seconds = remaining_seconds(deadline)?;
        self.pending = Some(Pending {
            // A file worker may take longer than the Tor heartbeat interval.
            // Keep its single RPC off the owner loop; do not concurrently read
            // observations from the same file-control stream.
            thread: oblivion_host::onion_task::Task::start(
                channel,
                oblivion_host::onion_task::Command::Receive {
                    ttl_seconds: seconds,
                },
            )
            .map_err(|_| Error("onion_worker_failed"))?,
            operation: PendingOperation::Receive(client_auth),
        });
        Ok(())
    }

    fn begin_freeze(&mut self, deadline: Instant) -> Result<()> {
        // Confirm Tor revocation before defining any intake review boundary.
        // Keep the file RPC alive while the now-revoked network VMs are reaped.
        self.finish()?;
        self.initialized = false;
        self.access.take();
        self.progress.take();
        let peer = self.files.as_ref().ok_or(Error("onion_guest_not_ready"))?;
        let mut channel = Channel::until(
            peer.file
                .try_clone()
                .map_err(|_| Error("onion_socket_failed"))?,
            deadline.min(Instant::now() + Duration::from_secs(120)),
        )
        .map_err(|_| Error("onion_socket_failed"))?;
        for owner in [&peer.owner, &self.session] {
            channel.watch(owner.try_clone().map_err(|_| Error("onion_watch_failed"))?);
        }
        self.pending = Some(Pending {
            thread: oblivion_host::onion_task::Task::start(
                channel,
                oblivion_host::onion_task::Command::Freeze {},
            )
            .map_err(|_| Error("onion_worker_failed"))?,
            operation: PendingOperation::Freeze,
        });
        let stopped = [Role::OnionUplink, Role::OnionGateway].map(|role| vm::stop_role(role, true));
        for result in stopped {
            result?;
        }
        for peer in self.uplink.iter().chain(self.gateway.iter()) {
            require(exited(&peer.owner)?, "onion_still_running")?;
        }
        self.uplink.take();
        self.gateway.take();
        Ok(())
    }

    fn begin_import(&mut self, deadline: Instant) -> Result<()> {
        // Connect before starting the source unit so QEMU cannot discard its
        // initial ready marker. This port exposes only the frozen intake.
        self.intake = Some(Peer::connect(Role::OnionFile, "source.sock")?);
        let peer = self.files.as_ref().ok_or(Error("onion_guest_not_ready"))?;
        let channel = self.channel(
            peer,
            Duration::from_secs(120).min(deadline.saturating_duration_since(Instant::now())),
            true,
        )?;
        self.pending = Some(Pending {
            thread: oblivion_host::onion_task::Task::start(
                channel,
                oblivion_host::onion_task::Command::Source {},
            )
            .map_err(|_| Error("onion_worker_failed"))?,
            operation: PendingOperation::Import,
        });
        self.review = false;
        Ok(())
    }

    fn begin_stage(&mut self, deadline: Instant) -> Result<()> {
        self.intake = Some(Peer::connect(Role::OnionFile, "stage.sock")?);
        let peer = self.files.as_ref().ok_or(Error("onion_guest_not_ready"))?;
        self.pending = Some(Pending {
            thread: oblivion_host::onion_task::Task::start(
                self.channel(
                    peer,
                    Duration::from_secs(120)
                        .min(deadline.saturating_duration_since(Instant::now())),
                    true,
                )?,
                oblivion_host::onion_task::Command::PrepareShare {},
            )
            .map_err(|_| Error("onion_worker_failed"))?,
            operation: PendingOperation::Stage,
        });
        Ok(())
    }

    fn begin_share(&mut self, client_auth: ClientAuth, deadline: Instant) -> Result<()> {
        let staged = self.staged.as_ref().ok_or(Error("onion_not_staged"))?;
        let peer = self.files.as_ref().ok_or(Error("onion_guest_not_ready"))?;
        self.pending = Some(Pending {
            thread: oblivion_host::onion_task::Task::start(
                self.channel(
                    peer,
                    Duration::from_secs(120)
                        .min(deadline.saturating_duration_since(Instant::now())),
                    true,
                )?,
                oblivion_host::onion_task::Command::Share {
                    receipt: oblivion_transfer::Receipt {
                        id: staged.receipt.id.clone(),
                        manifest_sha256: staged.receipt.manifest_sha256.clone(),
                        entries: staged.receipt.entries,
                        bytes: staged.receipt.bytes,
                    },
                    paths: staged.paths.clone(),
                    ttl_seconds: remaining_seconds(deadline)?,
                },
            )
            .map_err(|_| Error("onion_worker_failed"))?,
            operation: PendingOperation::Share(client_auth),
        });
        self.sharing = true;
        Ok(())
    }

    fn complete_copy(&mut self, job: &Job) -> Result<()> {
        if !self
            .copy
            .as_ref()
            .is_some_and(|copy| copy.thread.is_finished())
        {
            return Ok(());
        }
        let copy = self.copy.take().unwrap();
        let completed = copy
            .thread
            .join()
            .map_err(|_| Error("onion_import_failed"))??;
        vm::remove_copy_port(&job.id)?;
        let paths = copy.exporting.then(|| completed.paths().to_vec());
        let receipt = completed
            .acknowledge()
            .map_err(|_| Error("onion_import_failed"))?;
        if let Some(paths) = paths {
            self.staged = Some(Staged { receipt, paths });
        } else {
            self.receipt = Some(receipt);
        }
        Ok(())
    }

    fn complete_file(&mut self, deadline: Instant, job: &Job, uid: u32) -> Result<()> {
        if !self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.thread.is_finished())
        {
            return Ok(());
        }
        let pending = self.pending.take().unwrap();
        pending
            .thread
            .join()
            .map_err(|_| Error("onion_worker_failed"))?;
        let client_auth = match pending.operation {
            PendingOperation::Freeze => {
                self.review = true;
                return Ok(());
            }
            PendingOperation::Import => {
                self.copy = Some(Copy::start(
                    self.intake.take().ok_or(Error("onion_guest_not_ready"))?,
                    self.session
                        .try_clone()
                        .map_err(|_| Error("onion_watch_failed"))?,
                    job.id.clone(),
                    uid,
                    deadline,
                    false,
                )?);
                return Ok(());
            }
            PendingOperation::Stage => {
                self.copy = Some(Copy::start(
                    self.intake.take().ok_or(Error("onion_guest_not_ready"))?,
                    self.session
                        .try_clone()
                        .map_err(|_| Error("onion_watch_failed"))?,
                    job.id.clone(),
                    uid,
                    deadline,
                    true,
                )?);
                return Ok(());
            }
            PendingOperation::Share(client_auth) | PendingOperation::Backup(client_auth) => {
                client_auth
            }
            PendingOperation::Receive(client_auth) => client_auth,
        };
        let observed: Observed = self.gateway(&json!({"operation":"observe"}))?;
        require(
            observed.ok
                && observed.isolated
                && !observed.active
                && observed.tor_ready
                && observed.tor_progress == Some(100),
            "onion_not_ready",
        )?;
        let published: Published = self.gateway(&json!({
            "operation":"publish", "client_auth":client_auth,
            "ttl_seconds":remaining_seconds(deadline)?,
        }))?;
        require(
            published.ok && published.error.is_none(),
            "onion_publish_failed",
        )?;
        self.access = Some(
            Access::published(published.service_id.ok_or(Error("onion_publish_failed"))?)
                .map_err(Error)?,
        );
        Ok(())
    }

    fn owners(&self) -> impl Iterator<Item = &OwnedFd> {
        self.uplink
            .iter()
            .chain(self.gateway.iter())
            .chain(self.files.iter())
            .map(|peer| &peer.owner)
    }

    fn boot(&self, role: Role, deadline: Instant) -> Result<()> {
        let (peer, expected) = match role {
            Role::OnionGateway => (self.gateway.as_ref(), "onion-gateway"),
            Role::OnionFile => (self.files.as_ref(), "onion-file"),
            _ => return Err(Error("invalid_onion_role")),
        };
        let peer = peer.ok_or(Error("onion_guest_not_ready"))?;
        let mut checked = Instant::now();
        loop {
            require(Instant::now() < deadline, "onion_guest_not_ready")?;
            for owner in self.owners().chain(std::iter::once(&self.session)) {
                require(!exited(owner)?, "onion_guest_not_ready")?;
            }
            let mut descriptor = libc::pollfd {
                fd: peer.file.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            require(
                unsafe { libc::poll(&mut descriptor, 1, 0) } >= 0,
                "onion_channel_failed",
            )?;
            if descriptor.revents != 0 {
                let hello: Hello =
                    read_message(&mut self.channel(peer, Duration::from_secs(5), true)?, 4096)
                        .map_err(|_| Error("onion_guest_not_ready"))?;
                require(
                    hello.ready && hello.version == 1 && hello.role == expected,
                    "invalid_onion_guest",
                )?;
                return Ok(());
            }
            // The initialized gateway stays disabled and observed while the
            // file VM boots. Its network is enabled only after both are ready.
            if self.initialized && checked.elapsed() >= Duration::from_secs(4) {
                let value: Observed = self.gateway(&json!({"operation":"observe"}))?;
                require(
                    value.ok && value.isolated && !value.active && !value.tor_ready,
                    "invalid_onion_observation",
                )?;
                checked = Instant::now();
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn channel(&self, peer: &Peer, budget: Duration, session: bool) -> Result<Channel> {
        let mut channel = Channel::new(
            peer.file
                .try_clone()
                .map_err(|_| Error("onion_socket_failed"))?,
            budget,
        )
        .map_err(|_| Error("onion_socket_failed"))?;
        for owner in self.owners().chain(session.then_some(&self.session)) {
            channel.watch(owner.try_clone().map_err(|_| Error("onion_watch_failed"))?);
        }
        Ok(channel)
    }

    fn gateway<T: for<'de> Deserialize<'de>>(&self, request: &serde_json::Value) -> Result<T> {
        let peer = self
            .gateway
            .as_ref()
            .ok_or(Error("onion_guest_not_ready"))?;
        exchange_channel(
            &mut self.channel(peer, Duration::from_secs(5), true)?,
            request,
        )
    }

    fn observe(&mut self) -> Result<Observed> {
        let value: Observed = if self.gateway.is_some() {
            self.gateway(&json!({"operation":"observe"}))?
        } else {
            // The network VMs have been stopped and their exact pidfds reaped.
            Observed {
                ok: true,
                isolated: true,
                tor_progress: None,
                tor_ready: false,
                active: false,
            }
        };
        require(
            value.ok
                && value.isolated
                && value.tor_progress.is_none_or(|value| value <= 100)
                && (!value.tor_ready || value.tor_progress == Some(100))
                && value.active == self.access.is_some(),
            "invalid_onion_observation",
        )?;
        if self.pending.is_some() {
            return Ok(value);
        }
        let peer = self.files.as_ref().ok_or(Error("onion_guest_not_ready"))?;
        let file: FileObserved = exchange_channel(
            &mut self.channel(peer, Duration::from_secs(5), true)?,
            &json!({"operation":"observe"}),
        )?;
        require(file.ok, "invalid_onion_observation")?;
        match (self.access.is_some(), file.phase, file.worker) {
            (false, FilePhase::Fresh, None) => self.progress = None,
            (false, FilePhase::Staging, None)
                if self.copy.as_ref().is_some_and(|copy| copy.exporting)
                    || self.staged.is_some() =>
            {
                self.progress = None
            }
            (false, FilePhase::Review, None) if self.review => self.progress = None,
            (false, FilePhase::Copying, None) if self.copy.is_some() || self.receipt.is_some() => {
                self.progress = None
            }
            (true, FilePhase::Receiving, Some(worker)) if !self.sharing => {
                require(
                    worker.state == "serving"
                        && worker.mode == "receive"
                        && worker.files <= 1024
                        && worker.bytes <= 272 * 1024 * 1024
                        && worker.transferred_bytes <= 272 * 1024 * 1024,
                    "invalid_onion_observation",
                )?;
                self.progress = Some(Progress {
                    files: worker.files,
                    bytes: worker.bytes,
                    transferred_bytes: worker.transferred_bytes,
                    rejected: worker.rejected,
                });
            }
            (true, FilePhase::Sharing, Some(worker)) if self.sharing => {
                require(
                    worker.state == "serving"
                        && worker.mode == if self.backup { "backup" } else { "share" }
                        && worker.files <= 1024
                        && worker.bytes
                            <= if self.backup {
                                oblivion_transfer::MAX_ENCRYPTED_VOLUME_BYTES
                            } else {
                                272 * 1024 * 1024
                            }
                        && worker.transferred_bytes <= worker.bytes,
                    "invalid_onion_observation",
                )?;
                self.progress = Some(Progress {
                    files: worker.files,
                    bytes: worker.bytes,
                    transferred_bytes: worker.transferred_bytes,
                    rejected: worker.rejected,
                });
            }
            _ => return Err(Error("invalid_onion_observation")),
        }
        Ok(value)
    }

    fn save(&mut self, state: &str) -> Result<()> {
        let state =
            oblivion_tor_state::State::parse(state).map_err(|_| Error("invalid_tor_state"))?;
        if self
            .saved
            .as_ref()
            .is_none_or(|saved| !saved.same_guards(&state))
        {
            if self.writable {
                crate::storage::save_tor_state(Purpose::Transfer, &state)?;
            }
            self.saved = Some(state);
        }
        Ok(())
    }

    fn checkpoint(&mut self) -> Result<()> {
        if !self.initialized {
            return Ok(());
        }
        let snapshot: Snapshot = self.gateway(&json!({"operation":"snapshot"}))?;
        require(snapshot.ok, "onion_checkpoint_failed")?;
        self.save(&snapshot.state)
    }

    fn finish(&mut self) -> Result<()> {
        if !self.initialized {
            return Ok(());
        }
        let peer = self
            .gateway
            .as_ref()
            .ok_or(Error("onion_guest_not_ready"))?;
        // Teardown still works if the originating session has already died.
        let reply: GatewayStopped = exchange_channel(
            &mut self.channel(peer, Duration::from_secs(8), false)?,
            &json!({"operation":"shutdown"}),
        )?;
        require(reply.ok && reply.closed, "onion_checkpoint_failed")?;
        self.save(&reply.state.ok_or(Error("onion_checkpoint_failed"))?)?;
        Ok(())
    }

    fn disconnect(&mut self) {
        for peer in self
            .uplink
            .iter()
            .chain(self.gateway.iter())
            .chain(self.files.iter())
        {
            let _ = unsafe { libc::shutdown(peer.file.as_raw_fd(), libc::SHUT_RDWR) };
        }
    }

    fn verify_stopped(&self) -> Result<()> {
        for owner in self.owners() {
            require(exited(owner)?, "onion_still_running")?;
        }
        Ok(())
    }
}

fn remaining_seconds(deadline: Instant) -> Result<u16> {
    let seconds = deadline.saturating_duration_since(Instant::now()).as_secs();
    require((1..=3600).contains(&seconds), "onion_expired")?;
    Ok(seconds as u16)
}

impl Copy {
    fn start(
        source: Peer,
        session: OwnedFd,
        id: String,
        uid: u32,
        deadline: Instant,
        exporting: bool,
    ) -> Result<Self> {
        let deadline = deadline
            .min(Instant::now() + Duration::from_secs(oblivion_host::transfers::BUDGET_SECONDS));
        let ready = Arc::new(AtomicBool::new(false));
        let observed = ready.clone();
        let thread = std::thread::Builder::new()
            .name("onion-import".into())
            .spawn(move || {
                let port = File::from(OwnedFd::from(vm::copy_port(&id, exporting)?));
                let owners = vec![source.owner, session];
                let (source, destination) = if exporting {
                    (port, source.file)
                } else {
                    (source.file, port)
                };
                oblivion_host::onion_copy::ready(
                    &source,
                    &destination,
                    &owners,
                    deadline.min(Instant::now() + Duration::from_secs(90)),
                )
                .map_err(|_| Error("transfer_guest_not_ready"))?;
                let listener =
                    UnixListener::bind(COPY_SOCKET).map_err(|_| Error("onion_socket_failed"))?;
                fs::set_permissions(COPY_SOCKET, fs::Permissions::from_mode(0o600))
                    .map_err(|_| Error("onion_socket_failed"))?;
                require(
                    unsafe { libc::chown(c"/run/oblivion-onion-host/copy.sock".as_ptr(), uid, !0) }
                        == 0,
                    "onion_socket_failed",
                )?;
                listener
                    .set_nonblocking(true)
                    .map_err(|_| Error("onion_socket_failed"))?;
                observed.store(true, Ordering::Release);
                loop {
                    let remaining = deadline
                        .checked_duration_since(Instant::now())
                        .ok_or(Error("onion_expired"))?;
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
                    require(
                        unsafe {
                            libc::poll(
                                descriptors.as_mut_ptr(),
                                descriptors.len() as _,
                                remaining.as_millis().min(1000) as i32,
                            )
                        } >= 0,
                        "onion_socket_failed",
                    )?;
                    require(
                        !descriptors[1..].iter().any(|fd| fd.revents != 0),
                        "transfer_owner_exited",
                    )?;
                    if descriptors[0].revents == 0 {
                        continue;
                    }
                    let (client, _) = listener
                        .accept()
                        .map_err(|_| Error("onion_socket_failed"))?;
                    crate::gateway::peer(&client, uid)?;
                    return (if exporting {
                        oblivion_host::onion_copy::share
                    } else {
                        oblivion_host::onion_copy::stage
                    })(
                        source,
                        destination,
                        File::from(OwnedFd::from(client)),
                        owners,
                        deadline,
                        id,
                    )
                    .map_err(|_| Error("onion_import_failed"));
                }
            })
            .map_err(|_| Error("onion_import_failed"))?;
        Ok(Self {
            thread,
            ready,
            exporting,
        })
    }
}

impl Peer {
    fn connect(role: Role, name: &str) -> Result<Self> {
        let socket = oblivion_host::channel::connect(
            &Path::new(&role.runtime()).join(name),
            Duration::from_secs(3),
        )
        .map_err(|_| Error("onion_guest_not_ready"))?;
        let uid = match role {
            Role::OnionUplink => vm::GATEWAY_UID,
            Role::OnionGateway => oblivion_host::onion_vm::GATEWAY_UID,
            Role::OnionFile => oblivion_host::onion_vm::FILE_UID,
            _ => return Err(Error("invalid_onion_role")),
        };
        crate::gateway::peer(&socket, uid)?;
        let file = File::from(OwnedFd::from(socket));
        let owner = oblivion_transfer::relay::peer_process(&file)
            .map_err(|_| Error("onion_watch_failed"))?;
        require(!exited(&owner)?, "onion_guest_not_ready")?;
        Ok(Self { file, owner })
    }
}

fn exchange<T: for<'de> Deserialize<'de>>(
    file: &File,
    request: &impl Serialize,
    owners: &[OwnedFd],
    budget: Duration,
) -> Result<T> {
    let mut channel = Channel::new(
        file.try_clone().map_err(|_| Error("onion_socket_failed"))?,
        budget,
    )
    .map_err(|_| Error("onion_socket_failed"))?;
    for owner in owners {
        channel.watch(owner.try_clone().map_err(|_| Error("onion_watch_failed"))?);
    }
    exchange_channel(&mut channel, request)
}

fn exchange_channel<T: for<'de> Deserialize<'de>>(
    channel: &mut Channel,
    request: &impl Serialize,
) -> Result<T> {
    let bytes =
        Zeroizing::new(serde_json::to_vec(request).map_err(|_| Error("onion_encode_failed"))?);
    require(bytes.len() <= 512 * 1024, "onion_request_too_large")?;
    channel
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|()| channel.write_all(&bytes))
        .map_err(|_| Error("onion_channel_failed"))?;
    read_message(channel, 512 * 1024).map_err(|_| Error("invalid_onion_response"))
}

fn respond(client: &UnixStream, value: &impl Serialize) -> Result<()> {
    let mut channel = Channel::new(
        File::from(OwnedFd::from(
            client
                .try_clone()
                .map_err(|_| Error("onion_socket_failed"))?,
        )),
        Duration::from_secs(2),
    )
    .map_err(|_| Error("onion_socket_failed"))?;
    oblivion_transfer::endpoint::write_message(&mut channel, value)
        .map_err(|_| Error("onion_socket_failed"))
}

fn exited(owner: &OwnedFd) -> Result<bool> {
    let mut descriptor = libc::pollfd {
        fd: owner.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    require(
        unsafe { libc::poll(&mut descriptor, 1, 0) } >= 0,
        "onion_watch_failed",
    )?;
    Ok(descriptor.revents != 0)
}
