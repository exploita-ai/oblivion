//! Native process intents are bound to one runtime generation. Backend signals
//! are authorized only by the supervisor's unreaped Child, never these records.
use super::{
    Cleanup, Removal, Settings, identity, private_directory, private_lock, random_id, sidecar,
    try_lock, write_record,
};
use crate::control::Result;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const MANAGER: &str = "OBLIVION_MANAGER_OWNER";
static INTENT: OnceLock<Intent> = OnceLock::new();

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Command,
    Observation,
    Manager,
    Resident,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    Starting,
    Ready,
    Quiescing,
    Recovery,
    StopRequested,
    Stopping,
}

impl Phase {
    fn admitting(self) -> Result<()> {
        match self {
            Self::Starting | Self::Ready => Ok(()),
            Self::Quiescing | Self::StopRequested => Err("Runtime is closing. Wait, or run oblivion runtime stop followed by oblivion runtime recover.".into()),
            Self::Recovery => Err("Runtime shutdown could not be verified. Run oblivion runtime stop, then oblivion runtime recover before opening another client.".into()),
            Self::Stopping => Err("Runtime is stopping. Wait, then run oblivion runtime recover if disconnected sockets remain.".into()),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Generation {
    version: u8,
    id: String,
    runtime_id: String,
    supervisor: Option<identity::Identity>,
    phase: Phase,
    resident: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    version: u8,
    generation: String,
    process: identity::Identity,
    depends_on: Vec<identity::Identity>,
    manager: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ticket {
    version: u8,
    runtime_id: String,
    creator: identity::Identity,
    process: Option<identity::Identity>,
}

impl Owner {
    fn alive(&self) -> Result<bool> {
        if !self.process.alive()? {
            return Ok(false);
        }
        if self.depends_on.len() > 2 {
            return Err("invalid_runtime_owner_dependencies".into());
        }
        for parent in &self.depends_on {
            if !parent.alive()? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

struct Intent {
    registry: PathBuf,
    generation: String,
    path: PathBuf,
    inode: u64,
    resident: bool,
}

struct Registry {
    root: PathBuf,
    socket: PathBuf,
    runtime_id: String,
}

impl Registry {
    fn new(settings: &Settings) -> Result<Self> {
        let root = sidecar(&settings.control_socket, ".lifecycle");
        private_directory(&root)?;
        Ok(Self {
            root,
            socket: settings.control_socket.clone(),
            runtime_id: settings.runtime_id.clone(),
        })
    }

    fn lock(&self) -> Result<fs::File> {
        let file = private_lock(&self.root.join("lock"))?;
        if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(file)
    }

    fn generation(&self) -> Result<Option<Generation>> {
        let path = self.root.join("generation.json");
        let value: Generation = match read(&path) {
            Ok(value) => value,
            Err(error)
                if !path.exists()
                    && error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if value.version != 1 || !super::hex(&value.id, 32) || value.runtime_id != self.runtime_id {
            return Err("invalid_runtime_generation".into());
        }
        Ok(Some(value))
    }

    fn save(&self, value: &Generation) -> Result<()> {
        write_record(&self.root, "generation.json", value)
    }

    fn owners(&self, generation: &Generation) -> Result<Vec<(String, Owner)>> {
        let directory = self.root.join(&generation.id);
        private_directory(&directory)?;
        let mut owners = Vec::new();
        let mut count = 0;
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "invalid_runtime_owner")?;
            if name.starts_with("runtime-") && name.ends_with(".pending") {
                fs::remove_file(entry.path())?;
                continue;
            }
            count += 1;
            if count > 512 || !super::hex(&name, 32) {
                return Err("invalid_runtime_owner".into());
            }
            let owner: Owner = read(&entry.path())?;
            if owner.version != 1 || owner.generation != generation.id {
                return Err("invalid_runtime_owner".into());
            }
            if owner.alive()? {
                owners.push((name, owner));
            } else {
                fs::remove_file(entry.path())?;
                if owner.manager {
                    let path = self.root.join("managers").join(&name);
                    match fs::remove_file(path) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                }
            }
        }
        Ok(owners)
    }

    fn active(&self) -> Result<Generation> {
        let previous = self.generation()?;
        if let Some(current) = &previous {
            if current
                .supervisor
                .as_ref()
                .map(identity::Identity::alive)
                .transpose()?
                .unwrap_or(false)
            {
                current.phase.admitting()?;
                return Ok(current.clone());
            }
            if matches!(
                current.phase,
                Phase::Quiescing | Phase::Recovery | Phase::StopRequested
            ) {
                current.phase.admitting()?;
            }
            if current.supervisor.is_none() && current.phase == Phase::Starting {
                return Ok(current.clone());
            }
        }
        let helper = private_lock(&sidecar(&self.socket, ".lock"))?;
        if !try_lock(&helper)? {
            return Err("runtime_owner_recovery_required".into());
        }
        let value = Generation {
            version: 1,
            id: random_id()?,
            runtime_id: self.runtime_id.clone(),
            supervisor: None,
            phase: Phase::Starting,
            resident: false,
        };
        private_directory(&self.root.join(&value.id))?;
        if let Some(previous) = previous {
            for (name, mut owner) in self.owners(&previous)? {
                if !owner.manager {
                    continue;
                }
                owner.generation.clone_from(&value.id);
                write_record(&self.root.join(&value.id), &name, &owner)?;
            }
        }
        self.save(&value)?;
        Ok(value)
    }
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let info = file.metadata()?;
    if !info.is_file()
        || info.uid() != unsafe { libc::getuid() }
        || info.mode() & 0o077 != 0
        || info.nlink() != 1
        || info.len() > 65536
    {
        return Err("unsafe_runtime_owner_record".into());
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("invalid_runtime_owner_record".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn manager(
    registry: &Registry,
) -> Result<Option<(String, identity::Identity, identity::Identity)>> {
    let Some(value) = std::env::var_os(MANAGER) else {
        return Ok(None);
    };
    let token = value.to_str().ok_or("invalid_manager_owner")?;
    if !super::hex(token, 32) {
        return Err("invalid_manager_owner".into());
    }
    let parent = identity::parent()?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let ticket: Ticket = {
            let _lock = registry.lock()?;
            read(&registry.root.join("managers").join(token))?
        };
        if ticket.version != 1 || ticket.runtime_id != registry.runtime_id {
            return Err("invalid_manager_owner".into());
        }
        if let Some(process) = ticket.process {
            if process != parent || identity::parent()? != parent {
                return Err("manager_owner_changed".into());
            }
            if !ticket.creator.alive()? {
                return Err("manager_handoff_abandoned".into());
            }
            return Ok(Some((token.into(), parent, ticket.creator)));
        }
        if !ticket.creator.alive()? {
            return Err("manager_handoff_abandoned".into());
        }
        if Instant::now() >= deadline {
            return Err("manager_handoff_not_ready".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub(super) fn register(settings: &Settings, kind: Kind) -> Result<()> {
    if INTENT.get().is_some() {
        return Ok(());
    }
    let registry = Registry::new(settings)?;
    let parent = manager(&registry)?;
    let _lock = registry.lock()?;
    let generation = registry.active()?;
    let process = identity::current()?;
    let directory = registry.root.join(&generation.id);
    if let Some((token, parent, creator)) = &parent {
        let owner = Owner {
            version: 1,
            generation: generation.id.clone(),
            process: parent.clone(),
            depends_on: if parent == creator {
                Vec::new()
            } else {
                vec![creator.clone()]
            },
            manager: true,
        };
        write_record(&directory, token, &owner)?;
    }
    let is_manager = matches!(kind, Kind::Manager);
    let owner = Owner {
        version: 1,
        generation: generation.id.clone(),
        process: process.clone(),
        depends_on: if matches!(kind, Kind::Observation) {
            parent
                .map(|(_, process, creator)| {
                    if process == creator {
                        vec![process]
                    } else {
                        vec![process, creator]
                    }
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        },
        manager: is_manager,
    };
    let name = random_id()?;
    write_record(&directory, &name, &owner)?;
    if is_manager {
        let managers = registry.root.join("managers");
        private_directory(&managers)?;
        write_record(
            &managers,
            &name,
            &Ticket {
                version: 1,
                runtime_id: settings.runtime_id.clone(),
                creator: process.clone(),
                process: Some(process),
            },
        )?;
        unsafe {
            std::env::set_var(MANAGER, &name);
        }
    }
    let path = directory.join(name);
    let intent = Intent {
        registry: registry.root,
        generation: generation.id,
        inode: fs::symlink_metadata(&path)?.ino(),
        path,
        resident: matches!(kind, Kind::Resident),
    };
    INTENT
        .set(intent)
        .map_err(|_| "runtime_owner_already_registered")?;
    Ok(())
}

/// An overlay's creator reserves this before spawn, then binds the exact Child
/// birth. Queries cannot turn a pending or inherited unrelated ticket into work.
pub(super) struct Handoff {
    registry: Registry,
    token: String,
    process: Option<identity::Identity>,
}

impl Handoff {
    pub(super) fn new(settings: &Settings, command: &mut Command) -> Result<Self> {
        let registry = Registry::new(settings)?;
        let _lock = registry.lock()?;
        let directory = registry.root.join("managers");
        private_directory(&directory)?;
        let token = random_id()?;
        write_record(
            &directory,
            &token,
            &Ticket {
                version: 1,
                runtime_id: settings.runtime_id.clone(),
                creator: identity::current()?,
                process: None,
            },
        )?;
        command.env(MANAGER, &token);
        Ok(Self {
            registry,
            token,
            process: None,
        })
    }

    pub(super) fn bind(&mut self, child: &Child) -> Result<()> {
        let process = identity::observe(child.id())?.ok_or("manager_handoff_child_exited")?;
        let _lock = self.registry.lock()?;
        let path = self.registry.root.join("managers").join(&self.token);
        let mut ticket: Ticket = read(&path)?;
        if ticket.version != 1
            || ticket.runtime_id != self.registry.runtime_id
            || ticket.creator != identity::current()?
            || ticket.process.is_some()
        {
            return Err("manager_handoff_changed".into());
        }
        self.process = Some(process.clone());
        let generation = self
            .registry
            .generation()?
            .ok_or("runtime_generation_missing")?;
        generation.phase.admitting()?;
        ticket.process = Some(process.clone());
        write_record(&self.registry.root.join("managers"), &self.token, &ticket)?;
        write_record(
            &self.registry.root.join(&generation.id),
            &self.token,
            &Owner {
                version: 1,
                generation: generation.id.clone(),
                process: process.clone(),
                depends_on: vec![ticket.creator.clone()],
                manager: true,
            },
        )?;
        Ok(())
    }
}

impl Drop for Handoff {
    fn drop(&mut self) {
        if let Some(process) = &self.process {
            if !matches!(process.alive(), Ok(false)) {
                return;
            }
        }
        let Ok(_lock) = self.registry.lock() else {
            return;
        };
        let path = self.registry.root.join("managers").join(&self.token);
        let Ok(ticket) = read::<Ticket>(&path) else {
            return;
        };
        if identity::current().ok().as_ref() != Some(&ticket.creator)
            || ticket.process.is_some() && ticket.process != self.process
        {
            return;
        }
        let _ = fs::remove_file(path);
        if let Ok(Some(generation)) = self.registry.generation() {
            let _ = fs::remove_file(self.registry.root.join(generation.id).join(&self.token));
        }
    }
}

pub(super) fn release() -> Result<()> {
    let Some(intent) = INTENT.get() else {
        return Ok(());
    };
    let lock = private_lock(&intent.registry.join("lock"))?;
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    match fs::symlink_metadata(&intent.path) {
        Ok(info) => {
            if info.ino() != intent.inode || !info.is_file() {
                return Err("runtime_owner_changed".into());
            }
            let owner: Owner = read(&intent.path)?;
            fs::remove_file(&intent.path)?;
            if owner.manager {
                let token = intent.path.file_name().ok_or("invalid_manager_owner")?;
                match fs::remove_file(intent.registry.join("managers").join(token)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn own_intent(generation: &Generation) -> Result<bool> {
    let intent = INTENT.get().ok_or("runtime_owner_missing")?;
    if intent.generation != generation.id {
        return Ok(false);
    }
    let owner: Owner = read(&intent.path)?;
    owner.alive()
}

pub(super) fn owner_alive(settings: &Settings) -> Result<bool> {
    let registry = Registry::new(settings)?;
    let _lock = registry.lock()?;
    let generation = registry.generation()?.ok_or("runtime_generation_missing")?;
    generation.phase.admitting()?;
    own_intent(&generation)
}

/// No guest mutation is admitted until this generation is known to be ready.
/// The same lock protects a last-owner shutdown from a concurrent new client.
pub(super) fn admit(settings: &Settings) -> Result<()> {
    let registry = Registry::new(settings)?;
    let _lock = registry.lock()?;
    let mut generation = registry.generation()?.ok_or("runtime_generation_missing")?;
    generation.phase.admitting()?;
    if !own_intent(&generation)? {
        return Err("runtime_owner_lost".into());
    }
    if !generation
        .supervisor
        .as_ref()
        .map(identity::Identity::alive)
        .transpose()?
        .unwrap_or(false)
    {
        return Err("runtime_supervisor_unavailable".into());
    }
    generation.phase = Phase::Ready;
    // A failed explicit start must not leave a resident intent behind.
    if INTENT.get().is_some_and(|intent| intent.resident) {
        generation.resident = true;
    }
    registry.save(&generation)?;
    Ok(())
}

/// The election owner starts a supervisor, not an unowned backend process.
pub(super) fn launch(
    settings: &Settings,
    prepare: impl FnOnce() -> Result<()>,
) -> Result<Option<Child>> {
    let registry = Registry::new(settings)?;
    let _lock = registry.lock()?;
    let mut generation = registry.generation()?.ok_or("runtime_generation_missing")?;
    generation.phase.admitting()?;
    if !own_intent(&generation)? {
        return Err("runtime_owner_lost".into());
    }
    if generation
        .supervisor
        .as_ref()
        .map(identity::Identity::alive)
        .transpose()?
        .unwrap_or(false)
    {
        return Ok(None);
    }
    let helper = private_lock(&sidecar(&settings.control_socket, ".lock"))?;
    if !try_lock(&helper)? {
        return Err("runtime_owner_recovery_required".into());
    }
    prepare()?;
    let mut command = Command::new(crate::desktop_bundle::launcher_path()?);
    command
        .args(["runtime", "supervise", &generation.id])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    generation.supervisor =
        Some(identity::observe(child.id())?.ok_or("runtime_supervisor_start_failed")?);
    registry.save(&generation)?;
    Ok(Some(child))
}

struct Backend {
    child: Child,
    lifetime: Option<UnixStream>,
}

impl Backend {
    fn start(mut command: Command) -> Result<Self> {
        let (owner, inherited) = UnixStream::pair()?;
        let descriptor = inherited.as_raw_fd();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // Both pair endpoints are CLOEXEC. Only the helper's reader survives
        // this one exec; it marks fd3 CLOEXEC before creating any VM child.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(descriptor, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn()?;
        drop(inherited);
        Ok(Self {
            child,
            lifetime: Some(owner),
        })
    }

    fn stop(&mut self) -> Result<()> {
        self.lifetime.take();
        let deadline = Instant::now() + Duration::from_secs(50);
        loop {
            if self.child.try_wait()?.is_some() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                // This is the supervisor's own unreaped Child. PID files and
                // observed owner PIDs never authorize this emergency signal.
                self.child.kill()?;
                self.child.wait()?;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn supervise_backend(
    registry: &Registry,
    identity: &identity::Identity,
    generation_id: &str,
    command: Command,
) -> Result<()> {
    let mut backend = {
        let _lock = registry.lock()?;
        let mut generation = registry.generation()?.ok_or("runtime_generation_missing")?;
        if generation.id != generation_id || generation.supervisor.as_ref() != Some(identity) {
            return Err("runtime_supervisor_changed".into());
        }
        if generation.phase.admitting().is_err()
            || !generation.resident && registry.owners(&generation)?.is_empty()
        {
            generation.phase = Phase::Stopping;
            generation.supervisor = None;
            registry.save(&generation)?;
            return Ok(());
        }
        Backend::start(command)?
    };
    loop {
        if backend.child.try_wait()?.is_some() {
            break;
        }
        let decision = (|| -> Result<Decision> {
            let _lock = registry.lock()?;
            let mut generation = registry.generation()?.ok_or("runtime_generation_missing")?;
            if generation.id != generation_id || generation.supervisor.as_ref() != Some(identity) {
                return Err("runtime_supervisor_changed".into());
            }
            if generation.phase == Phase::Stopping {
                return Ok(Decision::Stop);
            }
            if matches!(
                generation.phase,
                Phase::Quiescing | Phase::Recovery | Phase::StopRequested
            ) {
                return Ok(Decision::Wait);
            }
            if generation.resident || !registry.owners(&generation)?.is_empty() {
                return Ok(Decision::Wait);
            }
            if generation.phase == Phase::Starting {
                generation.phase = Phase::Stopping;
                registry.save(&generation)?;
                return Ok(Decision::Stop);
            }
            // Fence admission before dropping the registry lock. A slow guest
            // RPC cannot hold up other clients or race a newly admitted one.
            generation.phase = Phase::Quiescing;
            registry.save(&generation)?;
            Ok(Decision::Quiesce)
        })();
        if matches!(decision, Ok(Decision::Stop)) {
            backend.stop()?;
            break;
        }
        if matches!(decision, Ok(Decision::Quiesce)) {
            // Open/pinned Safes, jobs and transfers remain work. No reply or
            // an unknown outcome is fenced permanently until explicit recovery:
            // a later busy reply cannot disprove an older in-flight shutdown.
            let result = crate::remote_control::request_with_budget(
                &registry.socket,
                "shutdown-idle",
                None,
                &[],
                None,
                Duration::from_secs(2),
            );
            let _lock = registry.lock()?;
            let mut generation = registry.generation()?.ok_or("runtime_generation_missing")?;
            if generation.id != generation_id || generation.supervisor.as_ref() != Some(identity) {
                return Err("runtime_supervisor_changed".into());
            }
            // An explicit stop may have taken over while the RPC was pending.
            if generation.phase == Phase::Quiescing {
                generation.phase = match result {
                    Ok(_) => Phase::Stopping,
                    Err(error)
                        if matches!(
                            error.to_string().as_str(),
                            "runtime_busy" | "controller_busy"
                        ) =>
                    {
                        Phase::Ready
                    }
                    Err(_) => Phase::Recovery,
                };
                registry.save(&generation)?;
            }
        }
        // Observation errors retain the owned runtime for recovery; they do
        // not reinterpret unknown ownership or work as idle.
        std::thread::sleep(Duration::from_millis(250));
    }
    let _lock = registry.lock()?;
    if let Some(mut generation) = registry.generation()? {
        if generation.id == generation_id && generation.supervisor.as_ref() == Some(identity) {
            generation.phase = Phase::Stopping;
            generation.resident = false;
            generation.supervisor = None;
            registry.save(&generation)?;
        }
    }
    Ok(())
}

pub(super) fn supervise(settings: &Settings, generation_id: &str) -> Result<()> {
    if !super::hex(generation_id, 32) {
        return Err("invalid_runtime_generation".into());
    }
    let registry = Registry::new(settings)?;
    let identity = identity::current()?;
    // The creator records this exact child identity before it can start a VM.
    // If the creator dies first, this process owns no backend and expires.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        {
            let _lock = registry.lock()?;
            let generation = registry.generation()?.ok_or("runtime_generation_missing")?;
            if generation.id != generation_id {
                return Err("runtime_generation_changed".into());
            }
            if let Some(owner) = &generation.supervisor {
                if owner != &identity {
                    return Err("runtime_supervisor_changed".into());
                }
                break;
            }
        }
        if Instant::now() >= deadline {
            return Err("runtime_supervisor_not_adopted".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let mut command = Command::new(super::helper()?);
    command
        .args(["run", "--config"])
        .arg(super::directory()?.join("vm.json"))
        .args(["--lifetime-fd", "3"]);
    supervise_backend(&registry, &identity, generation_id, command)
}

enum Decision {
    Wait,
    Quiesce,
    Stop,
}

/// Explicit stop is also fenced before guest RPCs. An error never restores
/// admission or permits killing the backend on the strength of a timeout.
pub(super) fn begin_stop(settings: &Settings) -> Result<String> {
    let registry = Registry::new(settings)?;
    let _lock = registry.lock()?;
    let mut generation = registry.generation()?.ok_or(
        "Runtime is not owned. Run oblivion runtime recover to inspect disconnected state.",
    )?;
    if generation.phase != Phase::Stopping {
        generation.phase = Phase::StopRequested;
        registry.save(&generation)?;
    }
    Ok(generation.id)
}

pub(super) fn stop_disconnected(settings: &Settings, generation_id: &str) -> Result<bool> {
    let registry = Registry::new(settings)?;
    let _lock = registry.lock()?;
    let generation = registry.generation()?.ok_or("runtime_generation_missing")?;
    if generation.id != generation_id {
        return Err("runtime_generation_changed".into());
    }
    if generation.phase != Phase::Stopping || generation.supervisor.is_some() {
        return Ok(false);
    }
    let helper = private_lock(&sidecar(&registry.socket, ".lock"))?;
    if !try_lock(&helper)? {
        return Ok(false);
    }
    match crate::remote_control::connect_peer(&registry.socket, Duration::from_millis(100)) {
        Ok(_) => Ok(false),
        Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|error| {
            matches!(error.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused)
        }) => Ok(true),
        Err(error) => Err(error),
    }
}

pub(super) fn stopped(settings: &Settings, generation_id: &str) -> Result<()> {
    let registry = Registry::new(settings)?;
    let _lock = registry.lock()?;
    let mut generation = registry.generation()?.ok_or("runtime_generation_missing")?;
    if generation.id != generation_id {
        return Err("runtime_generation_changed".into());
    }
    generation.resident = false;
    generation.phase = Phase::Stopping;
    registry.save(&generation)
}

pub(super) fn recovering(settings: &Settings) -> Result<()> {
    let registry = Registry::new(settings)?;
    let _lock = registry.lock()?;
    if let Some(generation) = registry.generation()? {
        if generation
            .supervisor
            .as_ref()
            .map(identity::Identity::alive)
            .transpose()?
            .unwrap_or(false)
        {
            return Err("Runtime supervisor is still active. Run oblivion runtime stop and wait for it to exit before oblivion runtime recover.".into());
        }
    }
    Ok(())
}

pub(super) fn recovered(settings: &Settings) -> Result<()> {
    let registry = Registry::new(settings)?;
    let _lock = registry.lock()?;
    if let Some(mut generation) = registry.generation()? {
        if generation
            .supervisor
            .as_ref()
            .map(identity::Identity::alive)
            .transpose()?
            .unwrap_or(false)
        {
            return Err("runtime_supervisor_still_active".into());
        }
        generation.resident = false;
        generation.phase = Phase::Stopping;
        generation.supervisor = None;
        registry.save(&generation)?;
    }
    Ok(())
}

/// Atomic removal holds the startup and backend locks before taking this
/// inventory. Keep the registry lock inode so old callers cannot split it.
pub(super) struct AtomicCleanup {
    _lock: Option<fs::File>,
    plan: Cleanup,
}

impl AtomicCleanup {
    pub(super) fn prepare(settings: &Settings) -> Result<Self> {
        let path = sidecar(&settings.control_socket, ".lifecycle");
        if !path.try_exists()? {
            return Ok(Self { _lock: None, plan: Cleanup::default() });
        }
        let registry = Registry::new(settings)?;
        let lock = registry.lock()?;
        let mut plan = Cleanup::default();
        if let Some(generation) = registry.generation()? {
            if generation.supervisor.as_ref().map(identity::Identity::alive).transpose()?.unwrap_or(false) {
                return Err("Stop the protected runtime before Atomic removal".into());
            }
            plan.files.push(Removal::file(path.join("generation.json"))?);
        }
        for (index, entry) in fs::read_dir(&path)?.enumerate() {
            if index >= 256 { return Err("runtime_cleanup_inventory_limit".into()); }
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { plan.retained += 1; continue };
            if matches!(name, "generation.json" | "lock") { continue; }
            if (name != "managers" && !super::hex(name, 32)) || !entry.file_type()?.is_dir() {
                plan.retained += 1;
                continue;
            }
            private_directory(&entry.path())?;
            let retained = plan.retained;
            for (index, child) in fs::read_dir(entry.path())?.enumerate() {
                if index >= 512 { return Err("runtime_cleanup_inventory_limit".into()); }
                let child = child?;
                if !child.file_name().to_str().is_some_and(|name| super::hex(name, 32)) {
                    plan.retained += 1;
                    continue;
                }
                if name == "managers" {
                    let ticket: Ticket = read(&child.path())?;
                    if ticket.version != 1 || ticket.runtime_id != settings.runtime_id {
                        return Err("invalid_manager_owner".into());
                    }
                    if ticket.creator.alive()? || ticket.process.as_ref().map(identity::Identity::alive).transpose()?.unwrap_or(false) {
                        return Err("Close the Oblivion manager before Atomic removal".into());
                    }
                } else {
                    let owner: Owner = read(&child.path())?;
                    if owner.version != 1 || owner.generation != name {
                        return Err("invalid_runtime_owner".into());
                    }
                    if owner.alive()? {
                        return Err("Close all Oblivion clients before Atomic removal".into());
                    }
                }
                plan.files.push(Removal::file(child.path())?);
            }
            if retained == plan.retained {
                plan.directories.insert(entry.path());
            }
        }
        Ok(Self { _lock: Some(lock), plan })
    }

    pub(super) fn retained(&self) -> usize {
        self.plan.retained
    }

    pub(super) fn remove(self) -> Result<()> {
        self.plan.remove()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;
    use std::thread;

    struct Fixture {
        root: PathBuf,
        registry: Registry,
        generation: Generation,
    }
    impl Fixture {
        fn new(phase: Phase) -> Self {
            let root = PathBuf::from("/tmp").join(format!("ob-lifecycle-{}", random_id().unwrap()));
            private_directory(&root).unwrap();
            let settings = super::super::tests::settings(&root);
            let registry = Registry::new(&settings).unwrap();
            let generation = Generation {
                version: 1,
                id: random_id().unwrap(),
                runtime_id: settings.runtime_id,
                supervisor: Some(identity::current().unwrap()),
                phase,
                resident: false,
            };
            private_directory(&registry.root.join(&generation.id)).unwrap();
            registry.save(&generation).unwrap();
            Self {
                root,
                registry,
                generation,
            }
        }
        fn settings(&self) -> Settings {
            super::super::tests::settings(&self.root)
        }
        fn owner(
            &self,
            process: identity::Identity,
            depends_on: Option<identity::Identity>,
            manager: bool,
        ) -> String {
            let name = random_id().unwrap();
            let _lock = self.registry.lock().unwrap();
            self.registry.active().unwrap();
            write_record(
                &self.registry.root.join(&self.generation.id),
                &name,
                &Owner {
                    version: 1,
                    generation: self.generation.id.clone(),
                    process,
                    depends_on: depends_on.into_iter().collect(),
                    manager,
                },
            )
            .unwrap();
            name
        }
        fn start(&self) -> thread::JoinHandle<std::result::Result<(), String>> {
            let registry = Registry {
                root: self.registry.root.clone(),
                socket: self.registry.socket.clone(),
                runtime_id: self.registry.runtime_id.clone(),
            };
            let own = self.generation.supervisor.clone().unwrap();
            let generation = self.generation.id.clone();
            let marker = self.root.join("backend-started");
            let mut command = Command::new("/bin/sh");
            // A real backend process follows the exact inherited-fd contract,
            // without allocating a VM or exposing any user filesystem.
            command
                .args([
                    "-c",
                    "printf started > \"$1\"; read -r value <&3",
                    "backend",
                ])
                .arg(marker);
            thread::spawn(move || {
                supervise_backend(&registry, &own, &generation, command)
                    .map_err(|error| error.to_string())
            })
        }
        fn phase(&self) -> Phase {
            let _lock = self.registry.lock().unwrap();
            self.registry.generation().unwrap().unwrap().phase
        }
        fn wait_for(&self, condition: impl Fn() -> bool) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !condition() {
                assert!(Instant::now() < deadline, "lifecycle fixture timed out");
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    struct Client(Child);
    impl Client {
        fn new() -> Self {
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", "read -r value"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            Self(command.spawn().unwrap())
        }
        fn identity(&self) -> identity::Identity {
            identity::observe(self.0.id()).unwrap().unwrap()
        }
        fn close(&mut self) {
            self.0.stdin.take();
            self.0.wait().unwrap();
        }
    }
    impl Drop for Client {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn cold_boot_manager_loss_closes_owned_backend_despite_live_observation() {
        let fixture = Fixture::new(Phase::Starting);
        let mut manager = Client::new();
        let observer = Client::new();
        fixture.owner(manager.identity(), None, true);
        fixture.owner(observer.identity(), Some(manager.identity()), false);
        let supervisor = fixture.start();
        fixture.wait_for(|| fixture.root.join("backend-started").exists());
        manager.close();
        supervisor.join().unwrap().unwrap();
        assert!(observer.identity().alive().unwrap());
        assert!(
            fixture
                .registry
                .owners(&fixture.generation)
                .unwrap()
                .is_empty()
        );
        assert!(fixture.phase() == Phase::Stopping);
    }

    #[test]
    fn concurrent_second_client_adopts_before_first_closes() {
        let fixture = Fixture::new(Phase::Starting);
        let mut first = Client::new();
        fixture.owner(first.identity(), None, false);
        let supervisor = fixture.start();
        fixture.wait_for(|| fixture.root.join("backend-started").exists());
        let mut second = Client::new();
        fixture.owner(second.identity(), None, false);
        first.close();
        fixture.wait_for(|| fixture.registry.owners(&fixture.generation).unwrap().len() == 1);
        assert!(!supervisor.is_finished());
        second.close();
        supervisor.join().unwrap().unwrap();
        assert!(fixture.phase() == Phase::Stopping);
    }

    #[test]
    fn quiescing_rpc_releases_registry_lock_and_unknown_result_stays_fenced() {
        let fixture = Fixture::new(Phase::Ready);
        let mut client = Client::new();
        fixture.owner(client.identity(), None, false);
        let listener = UnixListener::bind(&fixture.registry.socket).unwrap();
        fs::set_permissions(&fixture.registry.socket, fs::Permissions::from_mode(0o600)).unwrap();
        let (arrived, received) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let remote = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut prefix = [0; 4];
            stream.read_exact(&mut prefix).unwrap();
            let mut header = vec![0; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut header).unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&header).unwrap()["operation"],
                "shutdown-idle"
            );
            arrived.send(()).unwrap();
            wait.recv().unwrap();
            // This deliberately late busy response must not reopen admission.
            let bytes = br#"{"ok":false,"output":"","error":"controller_busy"}"#;
            let _ = stream.write_all(&(bytes.len() as u32).to_be_bytes());
            let _ = stream.write_all(bytes);
        });
        let supervisor = fixture.start();
        fixture.wait_for(|| fixture.root.join("backend-started").exists());
        client.close();
        received.recv_timeout(Duration::from_secs(3)).unwrap();
        let began = Instant::now();
        {
            let _lock = fixture.registry.lock().unwrap();
            assert!(
                fixture
                    .registry
                    .active()
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("runtime stop")
            );
        }
        assert!(
            began.elapsed() < Duration::from_millis(250),
            "RPC held lifecycle flock"
        );
        fixture.wait_for(|| fixture.phase() == Phase::Recovery);
        assert!(!supervisor.is_finished());
        release.send(()).unwrap();
        remote.join().unwrap();
        assert!(
            fixture
                .registry
                .active()
                .err()
                .unwrap()
                .to_string()
                .contains("runtime recover")
        );
        assert!(
            recovering(&fixture.settings())
                .unwrap_err()
                .to_string()
                .contains("runtime stop")
        );
        let generation = begin_stop(&fixture.settings()).unwrap();
        assert!(fixture.phase() == Phase::StopRequested);
        assert!(!supervisor.is_finished());
        stopped(&fixture.settings(), &generation).unwrap();
        supervisor.join().unwrap().unwrap();
    }

    #[test]
    fn confirmed_busy_restores_ready_and_new_owner_retains_backend() {
        let fixture = Fixture::new(Phase::Ready);
        let mut first = Client::new();
        fixture.owner(first.identity(), None, false);
        let listener = UnixListener::bind(&fixture.registry.socket).unwrap();
        fs::set_permissions(&fixture.registry.socket, fs::Permissions::from_mode(0o600)).unwrap();
        let (arrived, received) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let remote = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut prefix = [0; 4];
            stream.read_exact(&mut prefix).unwrap();
            let mut header = vec![0; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut header).unwrap();
            arrived.send(()).unwrap();
            wait.recv().unwrap();
            let bytes = br#"{"ok":false,"output":"","error":"runtime_busy"}"#;
            stream
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(bytes).unwrap();
        });
        let supervisor = fixture.start();
        fixture.wait_for(|| fixture.root.join("backend-started").exists());
        first.close();
        received.recv_timeout(Duration::from_secs(3)).unwrap();
        release.send(()).unwrap();
        remote.join().unwrap();
        fixture.wait_for(|| fixture.phase() == Phase::Ready);
        let mut second = Client::new();
        fixture.owner(second.identity(), None, false);
        assert!(!supervisor.is_finished());
        let generation = begin_stop(&fixture.settings()).unwrap();
        assert!(fixture.registry.active().is_err());
        stopped(&fixture.settings(), &generation).unwrap();
        supervisor.join().unwrap().unwrap();
        second.close();
    }

    #[test]
    fn resident_start_is_not_owned_until_ready_and_explicit_stop_fences_it() {
        let fixture = Fixture::new(Phase::Starting);
        let mut client = Client::new();
        fixture.owner(client.identity(), None, false);
        let supervisor = fixture.start();
        fixture.wait_for(|| fixture.root.join("backend-started").exists());
        {
            let _lock = fixture.registry.lock().unwrap();
            let mut generation = fixture.registry.generation().unwrap().unwrap();
            generation.phase = Phase::Ready;
            generation.resident = true;
            fixture.registry.save(&generation).unwrap();
        }
        client.close();
        assert!(!supervisor.is_finished());
        let generation = begin_stop(&fixture.settings()).unwrap();
        assert!(fixture.phase() == Phase::StopRequested);
        stopped(&fixture.settings(), &generation).unwrap();
        supervisor.join().unwrap().unwrap();
        assert!(!fixture.registry.generation().unwrap().unwrap().resident);
    }

    #[test]
    fn explicit_stop_confirms_only_the_disconnected_generation() {
        let fixture = Fixture::new(Phase::Ready);
        let settings = fixture.settings();
        let generation_id = begin_stop(&settings).unwrap();
        assert!(!stop_disconnected(&settings, &generation_id).unwrap());

        {
            let _lock = fixture.registry.lock().unwrap();
            let mut generation = fixture.registry.generation().unwrap().unwrap();
            generation.phase = Phase::Stopping;
            generation.supervisor = None;
            fixture.registry.save(&generation).unwrap();
        }
        let helper = private_lock(&sidecar(&fixture.registry.socket, ".lock")).unwrap();
        assert!(try_lock(&helper).unwrap());
        assert!(!stop_disconnected(&settings, &generation_id).unwrap());
        drop(helper);

        let listener = UnixListener::bind(&fixture.registry.socket).unwrap();
        fs::set_permissions(&fixture.registry.socket, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!stop_disconnected(&settings, &generation_id).unwrap());
        drop(listener);
        // Parallel process fixtures can briefly retain close-on-exec descriptors
        // between fork and exec even after this thread drops the listener.
        fixture.wait_for(|| stop_disconnected(&settings, &generation_id).unwrap());
        assert_eq!(begin_stop(&settings).unwrap(), generation_id);
        assert!(fixture.phase() == Phase::Stopping);
        assert!(stop_disconnected(&settings, "different-generation").is_err());
    }

    #[test]
    fn recovery_clears_unknown_generation_only_after_verified_supervisor_exit() {
        let fixture = Fixture::new(Phase::Recovery);
        assert!(fixture.registry.active().is_err());
        assert!(recovering(&fixture.settings()).is_err());
        {
            let _lock = fixture.registry.lock().unwrap();
            let mut generation = fixture.registry.generation().unwrap().unwrap();
            generation.supervisor = None;
            fixture.registry.save(&generation).unwrap();
        }
        recovering(&fixture.settings()).unwrap();
        recovered(&fixture.settings()).unwrap();
        assert_ne!(fixture.registry.active().unwrap().id, fixture.generation.id);
    }
    /// Subprocess roles exercise the actual parent/child and environment
    /// handoff. The fixture manager owns no VM, auth or user profile.
    #[test]
    #[ignore = "subprocess fixture, invoked by handoff tests"]
    fn manager_handoff_process() {
        let root = PathBuf::from(std::env::var_os("OBLIVION_LIFECYCLE_FIXTURE").unwrap());
        let settings = super::super::tests::settings(&root);
        let registry = Registry::new(&settings).unwrap();
        let role = std::env::var("OBLIVION_LIFECYCLE_ROLE").unwrap();
        if role == "query" {
            let response = manager(&registry)
                .map(|value| value.unwrap().0)
                .map_err(|error| error.to_string());
            println!("{}", serde_json::to_string(&response).unwrap());
            return;
        }
        if role == "manager" {
            let listener = UnixListener::bind(root.join("overlay.sock")).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            loop {
                let mut action = [0];
                if stream.read_exact(&mut action).is_err() || action[0] == b'x' {
                    return;
                }
                assert_eq!(action[0], b'q');
                let output = fixture_process(&root, "query").output().unwrap();
                assert!(output.status.success());
                // The test runner also writes its footer; only this JSON line
                // is returned on our private fixture channel.
                let text = String::from_utf8(output.stdout).unwrap();
                let json = text
                    .lines()
                    .find(|line| line.starts_with("{\"Ok\"") || line.starts_with("{\"Err\""))
                    .unwrap();
                stream
                    .write_all(&(json.len() as u32).to_be_bytes())
                    .unwrap();
                stream.write_all(json.as_bytes()).unwrap();
            }
        }
        assert_eq!(role, "creator");
        let generation = registry.generation().unwrap().unwrap();
        let own = random_id().unwrap();
        write_record(
            &registry.root.join(&generation.id),
            &own,
            &Owner {
                version: 1,
                generation: generation.id,
                process: identity::current().unwrap(),
                depends_on: Vec::new(),
                manager: false,
            },
        )
        .unwrap();
        let mut command = fixture_process(&root, "manager");
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut handoff = Handoff::new(&settings, &mut command).unwrap();
        let child = command.spawn().unwrap();
        handoff.bind(&child).unwrap();
        write_record(
            &root,
            "handoff.json",
            &serde_json::json!({"token": handoff.token, "pid": child.id()}),
        )
        .unwrap();
        let mut byte = [0];
        let _ = std::io::stdin().read(&mut byte);
        // Reproduce sudden bridge loss without running destructors. The
        // manager remains alive and must be rejected by its creator identity.
        std::process::exit(0);
    }

    fn fixture_process(root: &Path, role: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "native_runtime::lifecycle::tests::manager_handoff_process",
                "--ignored",
                "--nocapture",
            ])
            .env("OBLIVION_LIFECYCLE_FIXTURE", root)
            .env("OBLIVION_LIFECYCLE_ROLE", role);
        command
    }

    fn handoff_chain(nested: bool) {
        let fixture = Fixture::new(Phase::Starting);
        let mut root_manager = if nested { Some(Client::new()) } else { None };
        let root_token = root_manager
            .as_ref()
            .map(|manager| fixture.owner(manager.identity(), None, true));
        let mut command = fixture_process(&fixture.root, "creator");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        // A fresh child ticket must override even an unrelated inherited main
        // manager token, rather than validate that ancestor as its own parent.
        if let Some(token) = &root_token {
            command.env(MANAGER, token);
        }
        let mut creator = command.spawn().unwrap();
        fixture.wait_for(|| {
            fixture.root.join("handoff.json").exists() && fixture.root.join("overlay.sock").exists()
        });
        let handoff: serde_json::Value = read(&fixture.root.join("handoff.json")).unwrap();
        let token = handoff["token"].as_str().unwrap();
        if let Some(root) = &root_token {
            assert_ne!(root, token);
        }
        let process = identity::observe(handoff["pid"].as_u64().unwrap() as u32)
            .unwrap()
            .unwrap();
        let mut connection = UnixStream::connect(fixture.root.join("overlay.sock")).unwrap();
        connection
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let query = |stream: &mut UnixStream| -> serde_json::Value {
            stream.write_all(b"q").unwrap();
            let mut length = [0; 4];
            stream.read_exact(&mut length).unwrap();
            let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
            stream.read_exact(&mut bytes).unwrap();
            serde_json::from_slice(&bytes).unwrap()
        };
        assert_eq!(query(&mut connection)["Ok"], token);
        {
            let _lock = fixture.registry.lock().unwrap();
            let owners = fixture.registry.owners(&fixture.generation).unwrap();
            assert!(owners.iter().any(|(name, _)| name == token));
            if let Some(root) = &root_token {
                assert!(owners.iter().any(|(name, _)| name == root));
            }
        }
        creator.stdin.take();
        assert!(creator.wait().unwrap().success());
        assert!(
            process.alive().unwrap(),
            "fixture overlay did not outlive its creator"
        );
        assert_eq!(query(&mut connection)["Err"], "manager_handoff_abandoned");
        {
            let _lock = fixture.registry.lock().unwrap();
            let owners = fixture.registry.owners(&fixture.generation).unwrap();
            assert_eq!(owners.len(), usize::from(nested));
            if let Some(root) = &root_token {
                assert_eq!(&owners[0].0, root);
            }
        }
        connection.write_all(b"x").unwrap();
        drop(connection);
        fixture.wait_for(|| !process.alive().unwrap());
        if let Some(manager) = &mut root_manager {
            manager.close();
        }
    }

    #[test]
    fn direct_cli_overlay_handoff_follows_creator_lifetime() {
        handoff_chain(false);
    }

    #[test]
    fn nested_manager_agent_overlay_handoff_keeps_original_manager() {
        handoff_chain(true);
    }
}
