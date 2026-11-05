//! One headless supervisor owns the helper Child and its inherited lifetime.
//! Clients own private pipe leases, never a PID record or an HCS handle. An
//! uncertain shutdown is a persistent admission fence, not an idle observation.
use crate::client::{Channel, Client};
use crate::files::{self, CreationParent, Executable};
use crate::private::{self, Endpoint, Pipe, Purpose};
use crate::security::Identity;
use crate::{Error, Result};
use oblivion_wire::agent;
use oblivion_wire::control::{Operation, Request, valid_id};
use oblivion_wire::runtime_auth::Data;
use oblivion_wire::slot::Slot;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::ptr::null_mut;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_SHARING_VIOLATION, GENERIC_READ, GENERIC_WRITE, GetLastError,
    INVALID_HANDLE_VALUE, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_ALWAYS,
    OPEN_EXISTING, READ_CONTROL,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateMutexW, ReleaseMutex, WaitForSingleObject,
};

const LIMIT: usize = 4096;
const CLIENTS: usize = 64;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Binding {
    runtime_id: String,
    config_sha256: String,
    source_sha256: String,
    client_sid: String,
    storage_sid: String,
}

#[derive(Clone)]
pub struct Settings {
    binding: Binding,
    helper: PathBuf,
    config: PathBuf,
    storage: Identity,
}

impl Settings {
    pub fn new(
        runtime_id: &str,
        helper: &Path,
        config: &Path,
        config_sha256: &str,
        source_sha256: &str,
    ) -> Result<Self> {
        let identity = Identity::current()?;
        Self::new_for(
            runtime_id,
            helper,
            config,
            config_sha256,
            source_sha256,
            &identity,
            &identity,
        )
    }

    pub fn new_for(
        runtime_id: &str,
        helper: &Path,
        config: &Path,
        config_sha256: &str,
        source_sha256: &str,
        client: &Identity,
        storage: &Identity,
    ) -> Result<Self> {
        let settings = Self::binding(
            runtime_id,
            helper,
            config,
            config_sha256,
            source_sha256,
            client,
            storage,
        )?;
        settings.verify()?;
        Ok(settings)
    }

    /// Installation metadata can still address its stopped journal after the
    /// owned software has been removed. This conveys no permission to boot.
    pub fn maintenance(
        runtime_id: &str,
        helper: &Path,
        config: &Path,
        config_sha256: &str,
        source_sha256: &str,
    ) -> Result<Self> {
        let identity = Identity::current()?;
        Self::maintenance_for(
            runtime_id,
            helper,
            config,
            config_sha256,
            source_sha256,
            &identity,
            &identity,
        )
    }

    pub fn maintenance_for(
        runtime_id: &str,
        helper: &Path,
        config: &Path,
        config_sha256: &str,
        source_sha256: &str,
        client: &Identity,
        storage: &Identity,
    ) -> Result<Self> {
        let settings = Self::binding(
            runtime_id,
            helper,
            config,
            config_sha256,
            source_sha256,
            client,
            storage,
        )?;
        settings.verify_configuration()?;
        Ok(settings)
    }

    pub fn with_client(mut self, client: &Identity) -> Result<Self> {
        self.binding.client_sid = client.sid().into();
        Ok(self)
    }

    pub fn with_storage(mut self, storage: &Identity) -> Result<Self> {
        self.binding.storage_sid = storage.sid().into();
        self.storage = storage.clone();
        self.verify_configuration()?;
        Ok(self)
    }

    pub fn client_sid(&self) -> &str {
        &self.binding.client_sid
    }

    pub fn storage_sid(&self) -> &str {
        &self.binding.storage_sid
    }

    fn storage_identity(&self) -> Identity {
        self.storage.clone()
    }

    fn binding(
        runtime_id: &str,
        helper: &Path,
        config: &Path,
        config_sha256: &str,
        source_sha256: &str,
        client: &Identity,
        storage: &Identity,
    ) -> Result<Self> {
        if !valid_id(runtime_id)
            || runtime_id.bytes().all(|byte| byte == b'0')
            || !digest(config_sha256)
            || !digest(source_sha256)
        {
            return Err(Error("invalid_supervisor_binding"));
        }
        Ok(Self {
            binding: Binding {
                runtime_id: runtime_id.into(),
                config_sha256: config_sha256.into(),
                source_sha256: source_sha256.into(),
                client_sid: client.sid().into(),
                storage_sid: storage.sid().into(),
            },
            helper: helper.to_owned(),
            config: config.to_owned(),
            storage: storage.clone(),
        })
    }

    pub fn runtime_id(&self) -> &str {
        &self.binding.runtime_id
    }

    fn name(&self) -> String {
        format!(r"\\.\pipe\oblivion.{}.supervision", self.runtime_id())
    }

    fn journal(&self) -> Result<String> {
        Ok(format!(
            "{}.supervision.json",
            self.config
                .to_str()
                .ok_or(Error("invalid_supervisor_path"))?
        ))
    }

    fn verify(&self) -> Result<Verified> {
        let configuration = self.verify_configuration()?;
        Ok(Verified {
            _parent: configuration._parent,
            _config: configuration._config,
            data: configuration.data,
            helper: Executable::open(
                self.helper
                    .to_str()
                    .ok_or(Error("invalid_supervisor_path"))?,
                &self.storage_identity(),
            )?,
        })
    }

    fn verify_configuration(&self) -> Result<VerifiedConfiguration> {
        let identity = self.storage_identity();
        let config = self
            .config
            .to_str()
            .ok_or(Error("invalid_supervisor_path"))?;
        let parent = CreationParent::open(config, &identity)?;
        let mut file = open(parent.path(), Access::Configuration, false, &identity)?
            .ok_or(Error("runtime_configuration_unavailable"))?;
        let mut bytes = Vec::new();
        Read::take(&mut file, (crate::config::CONFIG_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("runtime_configuration_unavailable"))?;
        let configuration = crate::config::RuntimeConfig::decode(&bytes)?;
        if configuration.runtime_id != self.runtime_id()
            || format!("{:x}", Sha256::digest(&bytes)) != self.binding.config_sha256
        {
            return Err(Error("runtime_configuration_binding_changed"));
        }
        parent.verify()?;
        Ok(VerifiedConfiguration {
            _parent: parent,
            _config: file,
            data: PathBuf::from(&configuration.disks[1].path),
        })
    }
}

struct VerifiedConfiguration {
    _parent: CreationParent,
    _config: File,
    data: PathBuf,
}

struct Verified {
    _parent: CreationParent,
    _config: File,
    data: PathBuf,
    helper: Executable,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    Starting,
    Ready,
    Quiescing,
    StopRequested,
    Stopping,
    Stopped,
    Recovery,
}

impl Phase {
    fn admitting(self) -> bool {
        matches!(self, Self::Starting | Self::Ready)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    binding: Binding,
    generation: String,
    phase: Phase,
    resident: bool,
    boot: Boot,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
enum Action {
    Join,
    JoinInit { bytes: u64 },
    Status,
    Resident,
    Stop,
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Boot {
    Existing,
    Initialize { bytes: u64 },
}

impl Boot {
    fn validate(self, runtime_id: &str) -> Result<()> {
        match self {
            Self::Existing => Ok(()),
            Self::Initialize { bytes } => Data::NewDisk {
                runtime_id: runtime_id.into(),
                bytes,
            }
            .validate()
            .map_err(|_| Error("invalid_runtime_data_authority")),
        }
    }
    fn admit(self, action: Action, phase: Phase, joined: bool, started: bool) -> Result<()> {
        match action {
            Action::Join if phase.admitting() => {
                if matches!(self, Self::Initialize { .. }) && !joined {
                    return Err(Error("runtime_initialization_required"));
                }
                Ok(())
            }
            Action::JoinInit { bytes }
                if phase == Phase::Starting
                    && !joined
                    && !started
                    && self == (Self::Initialize { bytes }) =>
            {
                Ok(())
            }
            Action::JoinInit { .. } => Err(Error("runtime_initialization_unavailable")),
            _ => Err(Error("runtime_closing")),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Message {
    version: u8,
    binding: Binding,
    generation: String,
    action: Action,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    version: u8,
    binding: Binding,
    generation: String,
    phase: Phase,
    error: Option<String>,
}

/// Kept beside the frontend Runtime until that command/terminal exits. Closing
/// this exact pipe is sufficient even when the client process is terminated.
pub struct Lease {
    settings: Settings,
    generation: String,
    channel: Channel,
}

impl Lease {
    pub fn runtime_id(&self) -> &str {
        self.settings.runtime_id()
    }
    pub fn generation(&self) -> &str {
        &self.generation
    }

    pub fn start_resident(&self, stop: Arc<AtomicBool>, deadline: Instant) -> Result<()> {
        exchange(
            &self.settings,
            Action::Resident,
            &self.generation,
            stop,
            deadline,
            None,
        )?;
        Ok(())
    }

    pub fn close(&mut self) -> Result<()> {
        self.channel
            .close()
            .map_err(|_| Error("supervisor_lease_close_failed"))
    }
}

/// A private startup mutex serializes only journal/election. It is released
/// before boot/status RPCs, so a slow controller never holds admission locks.
pub fn acquire(settings: &Settings, stop: Arc<AtomicBool>, deadline: Instant) -> Result<Lease> {
    acquire_as(settings, Boot::Existing, stop, deadline)
}

pub fn initialize(
    settings: &Settings,
    bytes: u64,
    stop: Arc<AtomicBool>,
    deadline: Instant,
) -> Result<Lease> {
    let boot = Boot::Initialize { bytes };
    boot.validate(settings.runtime_id())?;
    acquire_as(settings, boot, stop, deadline)
}

fn acquire_as(
    settings: &Settings,
    boot: Boot,
    stop: Arc<AtomicBool>,
    deadline: Instant,
) -> Result<Lease> {
    let identity = settings.storage_identity();
    let election = Election::acquire(settings.runtime_id(), &identity, &stop, deadline)?;
    // Maintenance owns this same mutex. Do not pin old software while waiting
    // for an update/collection to release it.
    let verified = settings.verify()?;
    let previous = Journal::read(settings, &identity)?;
    if matches!(boot, Boot::Initialize { .. }) {
        if previous.as_ref().is_some_and(|record| {
            record.phase != Phase::Stopped
                && (record.phase != Phase::Starting || record.boot != boot)
        }) {
            return Err(Error("runtime_initialization_unavailable"));
        }
        match std::fs::symlink_metadata(&verified.data) {
            Ok(_) => return Err(Error("runtime_data_already_exists")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error("runtime_data_unavailable")),
        }
    }
    let starting = previous
        .as_ref()
        .is_none_or(|record| matches!(record.phase, Phase::Starting | Phase::Stopped));
    let mut spawned = None;
    let generation = match previous {
        Some(record) if record.phase.admitting() => record.generation,
        Some(record) if record.phase != Phase::Stopped => {
            return Err(Error("runtime_recovery_required"));
        }
        _ => {
            let generation = random_id()?;
            let mut journal = Journal::writer(settings, &identity, true)?;
            journal.save(&Record {
                version: 1,
                binding: settings.binding.clone(),
                generation: generation.clone(),
                phase: Phase::Starting,
                resident: false,
                boot,
            })?;
            drop(journal);
            verified.helper.verify()?;
            let result = Command::new(verified.helper.path())
                .args(["supervise", "--config"])
                .arg(&settings.config)
                .args([
                    "--client-sid",
                    settings.client_sid(),
                    "--storage-sid",
                    settings.storage_sid(),
                ])
                .args([
                    "--runtime-id",
                    settings.runtime_id(),
                    "--config-sha256",
                    &settings.binding.config_sha256,
                    "--source-sha256",
                    &settings.binding.source_sha256,
                    "--generation",
                    &generation,
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW)
                .spawn();
            match result {
                Ok(child) => spawned = Some(child),
                Err(_) => {
                    let mut journal = Journal::writer(settings, &identity, false)?;
                    journal.save(&Record {
                        version: 1,
                        binding: settings.binding.clone(),
                        generation,
                        phase: Phase::Stopped,
                        resident: false,
                        boot,
                    })?;
                    return Err(Error("runtime_supervisor_start_failed"));
                }
            }
            generation
        }
    };
    drop(election);
    let (mut channel, mut reply) = loop {
        check(&stop, deadline)?;
        if spawned
            .as_mut()
            .is_some_and(|child| child.try_wait().ok().flatten().is_some())
        {
            return Err(Error("runtime_recovery_required"));
        }
        match exchange(
            settings,
            match boot {
                Boot::Existing => Action::Join,
                Boot::Initialize { bytes } => Action::JoinInit { bytes },
            },
            &generation,
            Arc::clone(&stop),
            deadline.min(Instant::now() + Duration::from_secs(5)),
            spawned.as_ref(),
        ) {
            Ok(result) => break result,
            Err(Error("supervisor_unavailable")) if starting => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(Error("supervisor_unavailable")) => return Err(Error("runtime_recovery_required")),
            Err(error) => return Err(error),
        }
    };
    channel
        .claim_lease()
        .map_err(|_| Error("supervisor_lease_lost"))?;
    while reply.phase != Phase::Ready {
        check(&stop, deadline)?;
        if !reply.phase.admitting() {
            return Err(Error("runtime_recovery_required"));
        }
        match channel.try_read(&mut [0]) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            _ => return Err(Error("supervisor_lease_lost")),
        }
        std::thread::sleep(Duration::from_millis(100));
        reply = exchange(
            settings,
            Action::Status,
            &generation,
            Arc::clone(&stop),
            deadline.min(Instant::now() + Duration::from_secs(5)),
            spawned.as_ref(),
        )?
        .1;
    }
    Ok(Lease {
        settings: settings.clone(),
        generation,
        channel,
    })
}

pub fn stop(settings: &Settings, cancelled: Arc<AtomicBool>, deadline: Instant) -> Result<()> {
    let identity = settings.storage_identity();
    let record = Journal::read(settings, &identity)?.ok_or(Error("runtime_not_owned"))?;
    if record.phase == Phase::Stopped {
        return Ok(());
    }
    let reply = exchange(
        settings,
        Action::Stop,
        &record.generation,
        cancelled,
        deadline,
        None,
    )?
    .1;
    if reply.phase != Phase::Stopped {
        return Err(Error("runtime_recovery_required"));
    }
    Ok(())
}

/// Exclusive software-maintenance authority. Windows mutex ownership belongs
/// to the acquiring thread, so this capability cannot move to another thread.
/// The journal writer also excludes an old supervisor still finishing its exit.
#[must_use]
pub struct Stopped {
    journal: Journal,
    settings: Settings,
    _election: Election,
    _thread: PhantomData<Rc<()>>,
}

impl Stopped {
    /// Publish the verified target binding only after the caller has installed
    /// its artifacts. A failed write leaves the normal recovery fence intact.
    pub fn rebind(&mut self, target: &Settings) -> Result<()> {
        same_runtime(&self.settings, target)?;
        let _verified = target.verify()?;
        let mut record = self
            .journal
            .load()?
            .ok_or(Error("runtime_generation_missing"))?;
        if record.phase != Phase::Stopped {
            return Err(Error("runtime_recovery_required"));
        }
        record.binding = target.binding.clone();
        self.journal.save(&record)?;
        self.journal.binding = target.binding.clone();
        self.settings = target.clone();
        Ok(())
    }
}

pub fn stopped(settings: &Settings, stop: Arc<AtomicBool>, deadline: Instant) -> Result<Stopped> {
    stopped_for(settings, None, stop, deadline)
}

/// Only a persisted update transaction supplies both exact permitted bindings.
/// This is not a search for an arbitrary older/newer installation to adopt.
pub fn stopped_update(
    base: &Settings,
    target: &Settings,
    stop: Arc<AtomicBool>,
    deadline: Instant,
) -> Result<Stopped> {
    same_runtime(base, target)?;
    stopped_for(base, Some(target), stop, deadline)
}

fn same_runtime(base: &Settings, target: &Settings) -> Result<()> {
    if base.runtime_id() != target.runtime_id()
        || base.config != target.config
        || base.client_sid() != target.client_sid()
        || base.storage_sid() != target.storage_sid()
    {
        return Err(Error("runtime_maintenance_binding_changed"));
    }
    Ok(())
}

fn stopped_for(
    settings: &Settings,
    target: Option<&Settings>,
    stop: Arc<AtomicBool>,
    deadline: Instant,
) -> Result<Stopped> {
    let identity = settings.storage_identity();
    let bindings = match target {
        Some(target) => vec![&settings.binding, &target.binding],
        None => vec![&settings.binding],
    };
    loop {
        let election = Election::acquire(settings.runtime_id(), &identity, &stop, deadline)?;
        let record =
            Journal::read_for(settings, &bindings, &identity)?.ok_or(Error("runtime_not_owned"))?;
        if record.phase != Phase::Stopped {
            return Err(Error("runtime_recovery_required"));
        }
        let mut journal = match Journal::writer(settings, &identity, false) {
            Ok(journal) => journal,
            Err(Error("supervision_journal_busy")) => {
                // A stopped supervisor may still be draining its final peer.
                // Release election so any final failure can publish Recovery.
                drop(election);
                check(&stop, deadline)?;
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
            Err(error) => return Err(error),
        };
        let record = read_record_for(
            journal
                .file
                .as_mut()
                .ok_or(Error("supervision_journal_unavailable"))?,
            &bindings,
        )?
        .ok_or(Error("runtime_generation_missing"))?;
        if record.phase != Phase::Stopped {
            return Err(Error("runtime_recovery_required"));
        }
        journal.binding = record.binding.clone();
        return Ok(Stopped {
            journal,
            settings: settings.clone(),
            _election: election,
            _thread: PhantomData,
        });
    }
}

/// A live, authenticated supervisor may retry its owned shutdown. No HCS/HCN/
/// ACL adoption exists here: pipe absence cannot clear an unknown helper exit.
pub fn recover(settings: &Settings, stop: Arc<AtomicBool>, deadline: Instant) -> Result<()> {
    let identity = settings.storage_identity();
    match Journal::read(settings, &identity)? {
        None => return Err(Error("runtime_not_owned")),
        Some(record) if record.phase.admitting() => return Err(Error("runtime_busy")),
        Some(record) if record.phase != Phase::Stopped => {
            match exchange(
                settings,
                Action::Stop,
                &record.generation,
                Arc::clone(&stop),
                deadline,
                None,
            ) {
                Ok((_, reply)) if reply.phase == Phase::Stopped => {}
                Err(Error("supervisor_unavailable")) => {
                    return Err(Error("windows_owned_reconciliation_required"));
                }
                Err(error) => return Err(error),
                _ => return Err(Error("runtime_recovery_required")),
            }
        }
        _ => {}
    }
    drop(stopped(settings, stop, deadline)?);
    Ok(())
}

fn exchange(
    settings: &Settings,
    action: Action,
    generation: &str,
    stop: Arc<AtomicBool>,
    deadline: Instant,
    process: Option<&Child>,
) -> Result<(Channel, Reply)> {
    check(&stop, deadline)?;
    let name: Vec<_> = settings.name().encode_utf16().chain(Some(0)).collect();
    let pipe = private::connect_control(&name, &settings.storage_identity(), &stop, deadline)
        .map_err(|_| Error("supervisor_unavailable"))?;
    if let Some(process) = process {
        pipe.verify_server_process(process)
            .map_err(|_| Error("untrusted_supervisor_peer"))?;
    }
    let mut channel = Channel::new(pipe, stop, deadline);
    let request = Message {
        version: 1,
        binding: settings.binding.clone(),
        generation: generation.into(),
        action,
    };
    let bytes = serde_json::to_vec(&request).map_err(|_| Error("invalid_supervision_request"))?;
    agent::write_frame(&mut channel, 0, &bytes).map_err(|_| Error("supervisor_exchange_failed"))?;
    channel
        .flush()
        .map_err(|_| Error("supervisor_exchange_failed"))?;
    let (kind, bytes) =
        agent::read_frame(&mut channel).map_err(|_| Error("supervisor_exchange_failed"))?;
    if kind != 1 || bytes.len() > LIMIT {
        return Err(Error("invalid_supervision_response"));
    }
    let reply: Reply =
        serde_json::from_slice(&bytes).map_err(|_| Error("invalid_supervision_response"))?;
    if reply.version != 1 || reply.binding != settings.binding || reply.generation != generation {
        return Err(Error("invalid_supervision_response"));
    }
    if let Some(error) = &reply.error {
        return Err(Error(match error.as_str() {
            "runtime_closing" => "runtime_closing",
            "runtime_recovery_required" => "runtime_recovery_required",
            "runtime_busy" => "runtime_busy",
            "runtime_initialization_required" => "runtime_initialization_required",
            "runtime_initialization_unavailable" => "runtime_initialization_unavailable",
            _ => "supervisor_exchange_failed",
        }));
    }
    Ok((channel, reply))
}

pub fn supervise(settings: Settings, generation: &str) -> Result<()> {
    if !valid_id(generation) {
        return Err(Error("invalid_runtime_generation"));
    }
    let verified = settings.verify()?;
    let identity = settings.storage_identity();
    let mut endpoint = Endpoint::bind_for(&settings.name(), Purpose::Supervision, &identity)?;
    let mut journal = Journal::writer(&settings, &identity, false)?;
    let mut record = journal.load()?.ok_or(Error("runtime_generation_missing"))?;
    if record.generation != generation || record.phase != Phase::Starting {
        return Err(Error("runtime_generation_changed"));
    }
    let mut peers: Vec<Peer> = Vec::new();
    let mut backend: Option<Backend> = None;
    let mut first_owner = false;
    let first_deadline = Instant::now() + Duration::from_secs(10);
    let startup_deadline = Instant::now() + Duration::from_secs(390);
    let mut next_probe = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let result = (|| {
        loop {
            if private::drain_failed() {
                return Err(Error("private_pipe_cancellation_failed"));
            }
            if peers.len() < CLIENTS {
                if let Some(pipe) =
                    endpoint.accept(&stop, Instant::now() + Duration::from_millis(1))?
                {
                    peers.push(Peer::new(pipe));
                }
            }
            for peer in &mut peers {
                let Some(message) = peer.poll() else {
                    continue;
                };
                if message.version != 1
                    || message.binding != settings.binding
                    || message.generation != generation
                {
                    peer.reply(&record, Some("invalid_supervision_request"), false)?;
                    continue;
                }
                let error = match message.action {
                    action @ (Action::Join | Action::JoinInit { .. }) => {
                        match record.boot.admit(
                            action,
                            record.phase,
                            first_owner,
                            backend.is_some(),
                        ) {
                            Ok(()) => {
                                peer.lease = true;
                                first_owner = true;
                                None
                            }
                            Err(error) => Some(error.0),
                        }
                    }
                    Action::Status => None,
                    Action::Resident if record.phase == Phase::Ready => {
                        record.resident = true;
                        journal.save(&record)?;
                        None
                    }
                    Action::Resident => Some("runtime_closing"),
                    Action::Stop => {
                        record.phase = Phase::StopRequested;
                        record.resident = false;
                        journal.save(&record)?;
                        let result = backend
                            .as_mut()
                            .ok_or(Error("runtime_recovery_required"))
                            .and_then(|backend| backend.shutdown(false));
                        record.phase = if result.is_ok() {
                            Phase::Stopped
                        } else {
                            Phase::Recovery
                        };
                        journal.save(&record)?;
                        result.err().map(|_| "runtime_recovery_required")
                    }
                };
                peer.reply(&record, error, peer.lease)?;
            }
            peers.retain(|peer| !peer.closed);
            let owners = peers.iter().filter(|peer| peer.lease).count();
            if record.phase == Phase::Starting && backend.is_none() && owners > 0 {
                backend = Some(Backend::start(&settings, &verified, record.boot)?);
            }
            if let Some(backend) = backend.as_mut() {
                if backend
                    .child
                    .try_wait()
                    .map_err(|_| Error("runtime_process_observation_failed"))?
                    .is_some()
                    && !matches!(record.phase, Phase::Stopped | Phase::Recovery)
                {
                    record.phase = Phase::Recovery;
                    record.resident = false;
                    journal.save(&record)?;
                }
                if record.phase == Phase::Starting && Instant::now() >= next_probe {
                    next_probe = Instant::now() + Duration::from_millis(250);
                    if Instant::now() >= startup_deadline {
                        record.phase = Phase::Recovery;
                        journal.save(&record)?;
                    } else if backend.probe().is_ok() {
                        record.phase = Phase::Ready;
                        journal.save(&record)?;
                    }
                }
            }
            if owners == 0 && !record.resident {
                if record.phase == Phase::Starting
                    && (first_owner || Instant::now() >= first_deadline)
                {
                    record.phase = match backend.as_mut() {
                        None => Phase::Stopped,
                        Some(backend) => {
                            let _ = backend.close_lifetime();
                            Phase::Recovery
                        }
                    };
                    journal.save(&record)?;
                }
                if record.phase == Phase::Ready && Instant::now() >= next_probe {
                    record.phase = Phase::Quiescing;
                    journal.save(&record)?;
                    let outcome = backend
                        .as_mut()
                        .ok_or(Error("runtime_recovery_required"))?
                        .shutdown(true);
                    record.phase = match outcome {
                        Ok(()) => Phase::Stopped,
                        Err(Error("runtime_busy")) => Phase::Ready,
                        Err(_) => Phase::Recovery,
                    };
                    next_probe = Instant::now() + Duration::from_secs(1);
                    journal.save(&record)?;
                }
            }
            if record.phase == Phase::Stopped {
                for peer in &mut peers {
                    if peer.lease {
                        peer.closed = true;
                        peer.lease = false;
                    }
                }
                peers.retain(|peer| !peer.closed);
                if peers.is_empty() {
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    })();
    if result.is_err() {
        record.phase = Phase::Recovery;
        record.resident = false;
        let _ = journal.save(&record);
    }
    // Backend drop revokes lifetime even if observation/journal I/O failed.
    drop(backend);
    result
}

struct Backend {
    child: Child,
    writer: Option<ChildStdin>,
    client: Client,
}
impl Backend {
    fn start(settings: &Settings, verified: &Verified, boot: Boot) -> Result<Self> {
        verified.helper.verify()?;
        boot.validate(settings.runtime_id())?;
        let mut command = Command::new(verified.helper.path());
        command
            .arg(if matches!(boot, Boot::Existing) {
                "run"
            } else {
                "install"
            })
            .arg("--config")
            .arg(&settings.config)
            .args([
                "--client-sid",
                settings.client_sid(),
                "--storage-sid",
                settings.storage_sid(),
            ]);
        if let Boot::Initialize { bytes } = boot {
            command.args(["--data-mib", &(bytes / (1024 * 1024)).to_string()]);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|_| Error("runtime_helper_start_failed"))?;
        let writer = child
            .stdin
            .take()
            .ok_or(Error("runtime_lifetime_unavailable"))?;
        let client = Client::for_child(
            settings.runtime_id(),
            &child,
            &Identity::from_sid(settings.client_sid())?,
        )?;
        Ok(Self {
            child,
            writer: Some(writer),
            client,
        })
    }

    fn call(&self, operation: Operation, budget: Duration) -> Result<String> {
        self.client
            .request(
                Request {
                    operation,
                    slot: Slot::ZERO,
                    session: None,
                    expected_session: None,
                    secret_len: 0,
                },
                &[],
                Arc::new(AtomicBool::new(false)),
                Instant::now() + budget,
            )
            .map_err(|error| {
                Error(match error.to_string().as_str() {
                    "runtime_busy" | "controller_busy" => "runtime_busy",
                    _ => "runtime_control_unavailable",
                })
            })
    }
    fn probe(&self) -> Result<()> {
        let output = self.call(Operation::Status, Duration::from_secs(2))?;
        oblivion_wire::idle::View::<Slot>::decode_status(output.as_bytes()).map_err(Error)?;
        Ok(())
    }

    fn shutdown(&mut self, idle: bool) -> Result<()> {
        if let Some(status) = self
            .child
            .try_wait()
            .map_err(|_| Error("runtime_process_observation_failed"))?
        {
            return if status.success() {
                Ok(())
            } else {
                Err(Error("runtime_recovery_required"))
            };
        }
        if !idle {
            self.call(Operation::Lock, Duration::from_secs(120))?;
        }
        self.call(
            if idle {
                Operation::ShutdownIdle
            } else {
                Operation::ShutdownRuntime
            },
            if idle {
                Duration::from_secs(2)
            } else {
                Duration::from_secs(120)
            },
        )?;
        // Preserve lifetime while the guest powers off and the helper proves
        // HCS stop plus network/ACL cleanup. Early EOF would cause failure.
        self.wait_exit()
    }

    fn close_lifetime(&mut self) -> Result<()> {
        self.writer.take();
        self.wait_exit()
    }

    fn wait_exit(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(50);
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|_| Error("runtime_process_observation_failed"))?
            {
                self.writer.take();
                return if status.success() {
                    Ok(())
                } else {
                    Err(Error("runtime_recovery_required"))
                };
            }
            if Instant::now() >= deadline {
                self.writer.take();
                // Only this owned Child can be terminated. Completion of kill
                // is not evidence that HCS/HCN/ACL cleanup succeeded.
                let _ = self.child.kill();
                let _ = self.child.wait();
                return Err(Error("runtime_recovery_required"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        self.writer.take();
    }
}

struct Peer {
    pipe: Pipe,
    decoder: agent::Decoder,
    outbound: Vec<u8>,
    written: usize,
    waiting: bool,
    deadline: Instant,
    lease: bool,
    closed: bool,
}
impl Peer {
    fn new(pipe: Pipe) -> Self {
        Self {
            pipe,
            decoder: agent::Decoder::default(),
            outbound: vec![],
            written: 0,
            waiting: true,
            deadline: Instant::now() + Duration::from_secs(10),
            lease: false,
            closed: false,
        }
    }
    fn poll(&mut self) -> Option<Message> {
        let result = self.poll_io();
        match result {
            Ok(message) => message,
            Err(_) => {
                self.closed = true;
                self.lease = false;
                None
            }
        }
    }
    fn poll_io(&mut self) -> io::Result<Option<Message>> {
        if !self.lease && Instant::now() >= self.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if self.waiting {
            let Some((kind, bytes)) = self
                .decoder
                .read(&mut self.pipe)
                .map_err(|_| io::Error::other("invalid_supervision_request"))?
            else {
                return Ok(None);
            };
            self.waiting = false;
            if kind != 0 || bytes.len() > LIMIT {
                return Err(io::ErrorKind::InvalidData.into());
            }
            return serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| io::ErrorKind::InvalidData.into());
        }
        if self.written < self.outbound.len() {
            match self.pipe.write(&self.outbound[self.written..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => self.written += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        if self.written == self.outbound.len() && !self.outbound.is_empty() {
            match self.pipe.flush() {
                Ok(()) => {
                    self.outbound.clear();
                    self.written = 0;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        if self.outbound.is_empty() {
            match self.pipe.read(&mut [0]) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                _ => {
                    self.closed = true;
                    self.lease = false;
                }
            }
        }
        Ok(None)
    }
    fn reply(&mut self, record: &Record, error: Option<&str>, lease: bool) -> Result<()> {
        self.lease = lease && error.is_none();
        self.deadline = Instant::now() + Duration::from_secs(2);
        let bytes = serde_json::to_vec(&Reply {
            version: 1,
            binding: record.binding.clone(),
            generation: record.generation.clone(),
            phase: record.phase,
            error: error.map(str::to_owned),
        })
        .map_err(|_| Error("invalid_supervision_response"))?;
        if bytes.len() > LIMIT {
            return Err(Error("invalid_supervision_response"));
        }
        agent::write_frame(&mut self.outbound, 1, &bytes)
            .map_err(|_| Error("invalid_supervision_response"))?;
        Ok(())
    }
}

struct Journal {
    file: Option<File>,
    parent: CreationParent,
    path: String,
    identity: Identity,
    binding: Binding,
}
impl Journal {
    fn writer(settings: &Settings, identity: &Identity, create: bool) -> Result<Self> {
        let _election = Election::acquire(
            settings.runtime_id(),
            identity,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(2),
        )?;
        let path = settings.journal()?;
        let parent = CreationParent::open(&path, identity)?;
        let file = open(parent.path(), Access::JournalWrite, create, identity)?
            .ok_or(Error("runtime_generation_missing"))?;
        Ok(Self {
            file: Some(file),
            parent,
            path,
            identity: identity.clone(),
            binding: settings.binding.clone(),
        })
    }
    fn read(settings: &Settings, identity: &Identity) -> Result<Option<Record>> {
        Self::read_for(settings, &[&settings.binding], identity)
    }
    fn read_for(
        settings: &Settings,
        bindings: &[&Binding],
        identity: &Identity,
    ) -> Result<Option<Record>> {
        let _election = Election::acquire(
            settings.runtime_id(),
            identity,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(2),
        )?;
        let path = settings.journal()?;
        let parent = CreationParent::open(&path, identity)?;
        let Some(mut file) = open(parent.path(), Access::JournalRead, false, identity)? else {
            return Ok(None);
        };
        let record = read_record_for(&mut file, bindings)?;
        parent.verify()?;
        Ok(record)
    }
    fn load(&mut self) -> Result<Option<Record>> {
        let _election = Election::acquire(
            &self.binding.runtime_id,
            &self.identity,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(2),
        )?;
        read_record(
            self.file
                .as_mut()
                .ok_or(Error("supervision_journal_unavailable"))?,
            &self.binding,
        )
    }
    fn save(&mut self, record: &Record) -> Result<()> {
        let _election = Election::acquire(
            &self.binding.runtime_id,
            &self.identity,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(2),
        )?;
        self.parent.verify()?;
        files::verify_private(
            self.file
                .as_ref()
                .ok_or(Error("supervision_journal_unavailable"))?,
            &self.path,
            &self.identity,
        )?;
        let bytes = serde_json::to_vec(record).map_err(|_| Error("invalid_supervision_journal"))?;
        if bytes.len() > LIMIT {
            return Err(Error("invalid_supervision_journal"));
        }
        let path = Path::new(&self.path);
        let parent = path
            .parent()
            .and_then(Path::to_str)
            .ok_or(Error("invalid_supervisor_path"))?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(Error("invalid_supervisor_path"))?;
        let directory = files::Directory::open(parent, &self.identity, true)?;
        directory.sync()?;
        // The current no-delete writer pins this exact file while its identity
        // is observed. The replacement helper checks that identity again.
        let previous_id = files::data_file_identity(&self.path)?;
        let mut pending = directory.create_file(
            &format!("supervision-{}.pending", random_id()?),
            &self.identity,
        )?;
        pending
            .writer()
            .write_all(&bytes)
            .map_err(|_| Error("supervision_journal_write_failed"))?;
        pending.finish()?;
        directory.sync()?;
        // Every reader/writer takes election. No admission can observe this
        // brief handoff, and the old/new durable record stays whole on crash.
        drop(self.file.take());
        let previous = directory.asset(name, &self.identity, true)?;
        if previous.identity() != previous_id {
            return Err(Error("supervision_journal_changed"));
        }
        let published = pending.replace(previous, &self.identity)?;
        drop(published);
        self.file = Some(
            open(&self.path, Access::JournalWrite, false, &self.identity)?
                .ok_or(Error("supervision_journal_unavailable"))?,
        );
        directory.sync()?;
        self.parent.verify()
    }
}
fn read_record(file: &mut File, binding: &Binding) -> Result<Option<Record>> {
    read_record_for(file, &[binding])
}
fn read_record_for(file: &mut File, bindings: &[&Binding]) -> Result<Option<Record>> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Error("supervision_journal_unavailable"))?;
    let mut bytes = vec![];
    file.take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("supervision_journal_unavailable"))?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > LIMIT {
        return Err(Error("invalid_supervision_journal"));
    }
    let record: Record =
        serde_json::from_slice(&bytes).map_err(|_| Error("invalid_supervision_journal"))?;
    if record.version != 1 || !bindings.contains(&&record.binding) || !valid_id(&record.generation)
    {
        return Err(Error("invalid_supervision_journal"));
    }
    record
        .boot
        .validate(&record.binding.runtime_id)
        .map_err(|_| Error("invalid_supervision_journal"))?;
    Ok(Some(record))
}
enum Access {
    Configuration,
    JournalRead,
    JournalWrite,
}

fn open(path: &str, access: Access, create: bool, identity: &Identity) -> Result<Option<File>> {
    let descriptor = identity.file_descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    let name: Vec<_> = path.encode_utf16().chain(Some(0)).collect();
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ
                | READ_CONTROL
                | if matches!(access, Access::JournalWrite) {
                    GENERIC_WRITE
                } else {
                    0
                },
            FILE_SHARE_READ
                | if matches!(access, Access::JournalRead) {
                    FILE_SHARE_WRITE
                } else {
                    0
                },
            &attributes,
            if create { OPEN_ALWAYS } else { OPEN_EXISTING },
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = unsafe { GetLastError() };
        return if !create && error == ERROR_FILE_NOT_FOUND {
            Ok(None)
        } else if matches!(access, Access::JournalWrite) && error == ERROR_SHARING_VIOLATION {
            Err(Error("supervision_journal_busy"))
        } else {
            Err(Error("private_supervision_file_unavailable"))
        };
    }
    let file = unsafe { File::from_raw_handle(handle) };
    files::verify_private(&file, path, identity)?;
    Ok(Some(file))
}

struct Election(OwnedHandle);
impl Election {
    fn acquire(
        runtime_id: &str,
        identity: &Identity,
        stop: &AtomicBool,
        deadline: Instant,
    ) -> Result<Self> {
        // SCM runs in session zero; an elevated installer can run in another
        // session. Their writer handoff must use the same kernel namespace.
        let name: Vec<_> = format!("Global\\Oblivion.{}.{}.startup", identity.sid(), runtime_id)
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let descriptor = identity.descriptor()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_ptr(),
            bInheritHandle: 0,
        };
        let handle = unsafe { CreateMutexW(&attributes, 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(Error("runtime_election_unavailable"));
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        loop {
            check(stop, deadline)?;
            match unsafe { WaitForSingleObject(handle.as_raw_handle(), 100) } {
                WAIT_OBJECT_0 | WAIT_ABANDONED => return Ok(Self(handle)),
                WAIT_TIMEOUT => {}
                _ => return Err(Error("runtime_election_failed")),
            }
        }
    }
}
impl Drop for Election {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0.as_raw_handle());
        }
    }
}
fn random_id() -> Result<String> {
    let mut bytes = [0; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| Error("runtime_entropy_unavailable"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn check(stop: &AtomicBool, deadline: Instant) -> Result<()> {
    if stop.load(Ordering::Acquire) {
        return Err(Error("runtime_cancelled"));
    }
    if Instant::now() >= deadline {
        return Err(Error("runtime_start_timeout"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Access, Action, Backend, Binding, Boot, Election, Journal, Peer, Phase, Record, Settings,
        initialize, open, random_id, recover, stopped, stopped_update,
    };
    use crate::client::Client;
    use crate::private::{Endpoint, Purpose};
    use crate::security::Identity;
    use oblivion_wire::control::{Operation, Request};
    use oblivion_wire::slot::Slot;
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::os::windows::process::CommandExt;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::ptr::null_mut;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{DuplicateHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, GetCurrentProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };

    struct Area(PathBuf);
    impl Area {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("oblivion-supervision-{}", random_id().unwrap()));
            let name: Vec<_> = path
                .to_str()
                .unwrap()
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let identity = Identity::current().unwrap();
            let descriptor = identity.file_descriptor().unwrap();
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.as_ptr(),
                bInheritHandle: 0,
            };
            assert_ne!(unsafe { CreateDirectoryW(name.as_ptr(), &attributes) }, 0);
            Self(path)
        }
        fn settings(&self) -> Settings {
            Settings {
                binding: Binding {
                    runtime_id: random_id().unwrap(),
                    config_sha256: "1".repeat(64),
                    source_sha256: "2".repeat(64),
                    client_sid: Identity::current().unwrap().sid().into(),
                    storage_sid: Identity::current().unwrap().sid().into(),
                },
                config: self.0.join("vm.json"),
                helper: self.0.join("oblivion-vm.exe"),
                storage: Identity::current().unwrap(),
            }
        }
    }
    impl Drop for Area {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn initialization_authority_is_only_the_first_matching_starting_join() {
        let bytes = 8 * 1024 * 1024 * 1024;
        let boot = Boot::Initialize { bytes };
        assert!(
            boot.admit(Action::JoinInit { bytes }, Phase::Starting, false, false)
                .is_ok()
        );
        assert_eq!(
            boot.admit(Action::Join, Phase::Starting, false, false)
                .unwrap_err()
                .0,
            "runtime_initialization_required"
        );
        assert!(
            boot.admit(Action::Join, Phase::Starting, true, true)
                .is_ok()
        );
        for (phase, joined, started) in [
            (Phase::Ready, false, false),
            (Phase::Starting, true, false),
            (Phase::Starting, false, true),
            (Phase::Recovery, false, false),
        ] {
            assert_eq!(
                boot.admit(Action::JoinInit { bytes }, phase, joined, started)
                    .unwrap_err()
                    .0,
                "runtime_initialization_unavailable"
            );
        }
        assert!(
            Boot::Existing
                .admit(Action::Join, Phase::Starting, false, false)
                .is_ok()
        );
        assert_eq!(
            Boot::Existing
                .admit(Action::JoinInit { bytes }, Phase::Starting, false, false)
                .unwrap_err()
                .0,
            "runtime_initialization_unavailable"
        );
        assert_eq!(
            boot.admit(
                Action::JoinInit {
                    bytes: bytes + 1024 * 1024
                },
                Phase::Starting,
                false,
                false
            )
            .unwrap_err()
            .0,
            "runtime_initialization_unavailable"
        );
    }

    #[test]
    fn invalid_new_disk_authority_is_rejected_before_config_or_runtime_access() {
        let area = Area::new();
        let settings = area.settings();
        // The fixture has no configuration/helper. Reaching either would fail
        // differently; size validation must precede any runtime side effect.
        for bytes in [1, 4 * 1024 * 1024 * 1024 + 1, 1025 * 1024 * 1024 * 1024] {
            let error = initialize(
                &settings,
                bytes,
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(1),
            )
            .err()
            .unwrap();
            assert_eq!(error.0, "invalid_runtime_data_authority");
            assert!(!PathBuf::from(settings.journal().unwrap()).exists());
        }
    }

    #[test]
    fn recovery_journal_survives_reopen_and_cannot_be_cleared_by_absent_pipes() {
        let area = Area::new();
        let settings = area.settings();
        let identity = Identity::current().unwrap();
        let generation = random_id().unwrap();
        {
            let mut journal = Journal::writer(&settings, &identity, true).unwrap();
            journal
                .save(&Record {
                    version: 1,
                    binding: settings.binding.clone(),
                    generation: generation.clone(),
                    phase: Phase::Recovery,
                    resident: false,
                    boot: Boot::Existing,
                })
                .unwrap();
            let observed = Journal::read(&settings, &identity).unwrap().unwrap();
            assert_eq!(observed.phase, Phase::Recovery);
            assert_eq!(observed.generation, generation);
        }
        assert_eq!(
            recover(
                &settings,
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_millis(100),
            )
            .unwrap_err()
            .0,
            "windows_owned_reconciliation_required"
        );
        let record = Journal::writer(&settings, &identity, false)
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(record.phase, Phase::Recovery);
        assert_eq!(record.generation, generation);
        let mut changed = settings.clone();
        changed.binding.source_sha256 = "3".repeat(64);
        assert_eq!(
            Journal::read(&changed, &identity).err().unwrap().0,
            "invalid_supervision_journal"
        );
    }

    #[test]
    fn stopped_guard_waits_for_supervisor_writer_and_excludes_a_new_election() {
        let area = Area::new();
        let settings = area.settings();
        let identity = Identity::current().unwrap();
        let mut writer = Journal::writer(&settings, &identity, true).unwrap();
        writer
            .save(&Record {
                version: 1,
                binding: settings.binding.clone(),
                generation: random_id().unwrap(),
                phase: Phase::Stopped,
                resident: false,
                boot: Boot::Existing,
            })
            .unwrap();
        let (acquired, waiting) = std::sync::mpsc::sync_channel(0);
        let (release, released) = std::sync::mpsc::sync_channel(0);
        let candidate = settings.clone();
        let worker = std::thread::spawn(move || {
            let guard = stopped(
                &candidate,
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(4),
            )
            .unwrap();
            acquired.send(()).unwrap();
            released.recv().unwrap();
            drop(guard);
        });
        assert!(waiting.recv_timeout(Duration::from_millis(100)).is_err());
        // A Stopped journal alone is not enough while its old writer survives.
        drop(writer);
        waiting.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            Election::acquire(
                settings.runtime_id(),
                &identity,
                &AtomicBool::new(false),
                Instant::now() + Duration::from_millis(100),
            )
            .err()
            .unwrap()
            .0,
            "runtime_start_timeout"
        );
        assert_eq!(
            open(
                &settings.journal().unwrap(),
                Access::JournalWrite,
                false,
                &identity
            )
            .err()
            .unwrap()
            .0,
            "supervision_journal_busy"
        );
        release.send(()).unwrap();
        worker.join().unwrap();
        drop(
            Election::acquire(
                settings.runtime_id(),
                &identity,
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap(),
        );
    }

    #[test]
    fn stopped_update_accepts_only_the_two_transaction_bindings_and_never_recovery() {
        let area = Area::new();
        let base = area.settings();
        let mut target = base.clone();
        target.binding.source_sha256 = "3".repeat(64);
        let identity = Identity::current().unwrap();
        for phase in [Phase::Stopped, Phase::Recovery] {
            let mut writer = Journal::writer(&base, &identity, true).unwrap();
            writer
                .save(&Record {
                    version: 1,
                    binding: target.binding.clone(),
                    generation: random_id().unwrap(),
                    phase,
                    resident: false,
                    boot: Boot::Existing,
                })
                .unwrap();
            drop(writer);
            assert_eq!(
                stopped(
                    &base,
                    Arc::new(AtomicBool::new(false)),
                    Instant::now() + Duration::from_secs(1),
                )
                .err()
                .unwrap()
                .0,
                "invalid_supervision_journal"
            );
            let result = stopped_update(
                &base,
                &target,
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(1),
            );
            if phase == Phase::Stopped {
                drop(result.unwrap());
            } else {
                assert_eq!(result.err().unwrap().0, "runtime_recovery_required");
            }
            let mut stranger = target.clone();
            stranger.binding.source_sha256 = "4".repeat(64);
            assert_eq!(
                stopped_update(
                    &base,
                    &stranger,
                    Arc::new(AtomicBool::new(false)),
                    Instant::now() + Duration::from_secs(1),
                )
                .err()
                .unwrap()
                .0,
                "invalid_supervision_journal"
            );
        }
    }

    #[test]
    fn stopped_proof_and_updates_cannot_switch_client_or_storage_principal() {
        let area = Area::new();
        let settings = area.settings();
        let identity = Identity::current().unwrap();
        let other = if identity.sid() == "S-1-5-18" {
            Identity::administrators().unwrap()
        } else {
            Identity::from_sid("S-1-5-18").unwrap()
        };
        let mut writer = Journal::writer(&settings, &identity, true).unwrap();
        writer
            .save(&Record {
                version: 1,
                binding: settings.binding.clone(),
                generation: random_id().unwrap(),
                phase: Phase::Stopped,
                resident: false,
                boot: Boot::Existing,
            })
            .unwrap();
        drop(writer);
        let changed = settings.clone().with_client(&other).unwrap();
        assert_eq!(
            stopped(
                &changed,
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(1),
            )
            .err()
            .unwrap()
            .0,
            "invalid_supervision_journal"
        );
        let mut storage = settings.clone();
        storage.binding.storage_sid = other.sid().into();
        storage.storage = other.clone();
        for changed in [changed, storage] {
            assert_eq!(
                stopped_update(
                    &settings,
                    &changed,
                    Arc::new(AtomicBool::new(false)),
                    Instant::now() + Duration::from_secs(1),
                )
                .err()
                .unwrap()
                .0,
                "runtime_maintenance_binding_changed"
            );
        }
    }

    #[test]
    fn maintenance_after_software_removal_still_requires_config_and_stopped_proof() {
        let area = Area::new();
        let mut settings = area.settings();
        let identity = Identity::current().unwrap();
        let configuration = crate::config::RuntimeConfig {
            version: 1,
            backend: "hcs-hyperv".into(),
            runtime_id: settings.runtime_id().into(),
            kernel: area.0.join("vmlinuz").to_str().unwrap().into(),
            initrd: area.0.join("initrd.img").to_str().unwrap().into(),
            command_line: format!(
                "boot=live components quiet loglevel=0 oblivion.runtime=1 oblivion.runtime-backend=hcs-hyperv oblivion.runtime-id={}",
                settings.runtime_id()
            ),
            disks: vec![
                crate::config::Disk {
                    path: area.0.join("controller.iso").to_str().unwrap().into(),
                    read_only: true,
                },
                crate::config::Disk {
                    path: area.0.join("data.vhdx").to_str().unwrap().into(),
                    read_only: false,
                },
            ],
            cpu_count: 2,
            memory_mi_b: 1024,
            control_pipe: format!(r"\\.\pipe\oblivion.{}.control", settings.runtime_id()),
            control_port: 4050,
            network: false,
            serial_stdio: false,
        };
        let bytes = serde_json::to_vec(&configuration).unwrap();
        let mut config = open(
            settings.config.to_str().unwrap(),
            Access::JournalWrite,
            true,
            &identity,
        )
        .unwrap()
        .unwrap();
        config.write_all(&bytes).unwrap();
        config.sync_all().unwrap();
        drop(config);
        settings.binding.config_sha256 = format!("{:x}", Sha256::digest(&bytes));
        let maintained = Settings::maintenance(
            settings.runtime_id(),
            &settings.helper,
            &settings.config,
            &settings.binding.config_sha256,
            &settings.binding.source_sha256,
        )
        .unwrap();
        assert!(!settings.helper.exists());
        assert!(
            super::acquire(
                &maintained,
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(1),
            )
            .is_err()
        );
        assert!(!PathBuf::from(settings.journal().unwrap()).exists());
        assert_eq!(
            stopped(
                &maintained,
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(1),
            )
            .err()
            .unwrap()
            .0,
            "runtime_not_owned"
        );
        let mut writer = Journal::writer(&settings, &identity, true).unwrap();
        writer
            .save(&Record {
                version: 1,
                binding: settings.binding.clone(),
                generation: random_id().unwrap(),
                phase: Phase::Stopped,
                resident: false,
                boot: Boot::Existing,
            })
            .unwrap();
        drop(writer);
        let mut guard = stopped(
            &maintained,
            Arc::new(AtomicBool::new(false)),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        let mut target = settings.clone();
        target.binding.source_sha256 = "3".repeat(64);
        // Rebinding still requires a verified target executable. This fixture
        // is never executed; it exercises file admission and journal ordering.
        assert!(guard.rebind(&target).is_err());
        let mut helper = open(
            settings.helper.to_str().unwrap(),
            Access::JournalWrite,
            true,
            &identity,
        )
        .unwrap()
        .unwrap();
        helper.write_all(b"not executed").unwrap();
        helper.sync_all().unwrap();
        drop(helper);
        guard.rebind(&target).unwrap();
        guard.rebind(&target).unwrap();
        let observed = Journal::read(&target, &identity).unwrap().unwrap();
        assert_eq!(observed.phase, Phase::Stopped);
        assert!(observed.binding == target.binding);
        assert!(Journal::read(&settings, &identity).is_err());
    }

    #[test]
    fn recovery_retries_owned_live_stop_and_waits_for_the_supervisor_writer_to_exit() {
        let area = Area::new();
        let settings = area.settings();
        let identity = Identity::current().unwrap();
        let record = Record {
            version: 1,
            binding: settings.binding.clone(),
            generation: random_id().unwrap(),
            phase: Phase::Recovery,
            resident: false,
            boot: Boot::Existing,
        };
        let mut journal = Journal::writer(&settings, &identity, true).unwrap();
        journal.save(&record).unwrap();
        let mut endpoint = Endpoint::bind(&settings.name(), Purpose::Supervision).unwrap();
        let worker = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let pipe = endpoint
                .accept(&AtomicBool::new(false), deadline)
                .unwrap()
                .unwrap();
            let mut peer = Peer::new(pipe);
            let message = loop {
                assert!(Instant::now() < deadline);
                if let Some(message) = peer.poll() {
                    break message;
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            assert!(matches!(message.action, Action::Stop));
            assert!(message.binding == record.binding);
            assert_eq!(message.generation, record.generation);
            // A real helper is deliberately absent. This fixture models only
            // the supervisor's authenticated stop-reply/journal handoff.
            let mut record = record;
            record.phase = Phase::Stopped;
            journal.save(&record).unwrap();
            peer.reply(&record, None, false).unwrap();
            while !peer.closed {
                assert!(Instant::now() < deadline);
                peer.poll();
                std::thread::sleep(Duration::from_millis(1));
            }
            drop(journal);
        });
        recover(
            &settings,
            Arc::new(AtomicBool::new(false)),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        worker.join().unwrap();
        assert_eq!(
            Journal::read(&settings, &identity).unwrap().unwrap().phase,
            Phase::Stopped
        );
    }

    #[test]
    fn recovery_never_stops_a_healthy_starting_or_ready_generation() {
        let area = Area::new();
        let settings = area.settings();
        let identity = Identity::current().unwrap();
        for phase in [Phase::Starting, Phase::Ready] {
            let record = Record {
                version: 1,
                binding: settings.binding.clone(),
                generation: random_id().unwrap(),
                phase,
                resident: true,
                boot: Boot::Existing,
            };
            let mut writer = Journal::writer(&settings, &identity, true).unwrap();
            writer.save(&record).unwrap();
            assert_eq!(
                recover(
                    &settings,
                    Arc::new(AtomicBool::new(false)),
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap_err()
                .0,
                "runtime_busy"
            );
            let observed = writer.load().unwrap().unwrap();
            assert_eq!(observed.phase, phase);
            assert_eq!(observed.generation, record.generation);
            assert!(observed.resident);
        }
    }

    #[test]
    fn journal_updates_replace_the_whole_private_record_and_retain_writer_exclusion() {
        let area = Area::new();
        let settings = area.settings();
        let identity = Identity::current().unwrap();
        let mut writer = Journal::writer(&settings, &identity, true).unwrap();
        let mut record = Record {
            version: 1,
            binding: settings.binding.clone(),
            generation: random_id().unwrap(),
            phase: Phase::Starting,
            resident: false,
            boot: Boot::Existing,
        };
        writer.save(&record).unwrap();
        let previous = crate::files::data_file_identity(&settings.journal().unwrap()).unwrap();
        record.phase = Phase::Stopped;
        writer.save(&record).unwrap();
        let current = crate::files::data_file_identity(&settings.journal().unwrap()).unwrap();
        assert_ne!(
            previous, current,
            "save must replace, rather than overwrite, the old file"
        );
        assert_eq!(writer.load().unwrap().unwrap().phase, Phase::Stopped);
        assert_eq!(
            Journal::read(&settings, &identity).unwrap().unwrap().phase,
            Phase::Stopped
        );
        assert_eq!(
            Journal::writer(&settings, &identity, false)
                .err()
                .unwrap()
                .0,
            "supervision_journal_busy"
        );
        drop(writer);
        drop(
            stopped(
                &settings,
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap(),
        );
        assert!(std::fs::read_dir(&area.0).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .ends_with(".pending")
        }));
    }

    #[test]
    fn supervision_namespace_has_a_single_private_election_owner() {
        let name = format!(r"\\.\pipe\oblivion.{}.supervision", random_id().unwrap());
        let first = Endpoint::bind(&name, Purpose::Supervision).unwrap();
        assert!(Endpoint::bind(&name, Purpose::Supervision).is_err());
        drop(first);
        assert!(Endpoint::bind(&name, Purpose::Supervision).is_ok());
    }

    fn lifetime_child() -> Child {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "supervisor::tests::lifetime_fixture_child",
                "--ignored",
                "--nocapture",
            ])
            .env("OBLIVION_SUPERVISOR_FIXTURE", "lifetime")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap()
    }

    #[test]
    #[ignore = "Private subprocess fixture; parent tests execute it with inherited stdin, no VM"]
    fn lifetime_fixture_child() {
        if std::env::var("OBLIVION_SUPERVISOR_FIXTURE").as_deref() != Ok("lifetime") {
            return;
        }
        let mut bytes = vec![];
        std::io::stdin().read_to_end(&mut bytes).unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn backend_drop_revokes_lifetime_without_a_pid_record_or_detached_reader() {
        let mut child = lifetime_child();
        let writer = child.stdin.take().unwrap();
        let mut observed = null_mut();
        let current = unsafe { GetCurrentProcess() };
        assert_ne!(
            unsafe {
                DuplicateHandle(
                    current,
                    child.as_raw_handle(),
                    current,
                    &mut observed,
                    PROCESS_SYNCHRONIZE,
                    0,
                    0,
                )
            },
            0
        );
        let observed = unsafe { OwnedHandle::from_raw_handle(observed) };
        let client =
            Client::for_child(&random_id().unwrap(), &child, &Identity::current().unwrap())
                .unwrap();
        let backend = Backend {
            child,
            writer: Some(writer),
            client,
        };
        drop(backend);
        assert_eq!(
            unsafe { WaitForSingleObject(observed.as_raw_handle(), 5000) },
            WAIT_OBJECT_0
        );
    }

    #[test]
    fn same_user_control_pipe_cannot_impersonate_the_owned_helper_process() {
        let runtime_id = random_id().unwrap();
        let name = format!(r"\\.\pipe\oblivion.{runtime_id}.control");
        let mut endpoint = Endpoint::bind(&name, Purpose::Control).unwrap();
        let mut child = lifetime_child();
        let client = Client::for_child(&runtime_id, &child, &Identity::current().unwrap()).unwrap();
        let worker = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut pipe = endpoint
                .accept(&AtomicBool::new(false), deadline)
                .unwrap()
                .unwrap();
            loop {
                assert!(Instant::now() < deadline);
                match pipe.read(&mut [0]) {
                    Ok(0) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    result => panic!("unowned peer received a request: {result:?}"),
                }
            }
        });
        let error = client
            .request(
                Request {
                    operation: Operation::Status,
                    slot: Slot::ZERO,
                    session: None,
                    expected_session: None,
                    secret_len: 0,
                },
                &[],
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "untrusted_runtime_peer");
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        worker.join().unwrap();
    }
}
